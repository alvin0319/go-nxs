package nxs

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nxs/admission"
	"github.com/pion/webrtc/v4"
)

const (
	maxAssistedLifetime = 30 * time.Second
	maxAssistedBytes    = 73728
)

var (
	iceCharPattern     = regexp.MustCompile(`^[A-Za-z0-9+/]+$`)
	joinIDPattern      = regexp.MustCompile(`^[0-9a-f]{32}$`)
	instanceIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	networkIDPattern   = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
	fingerprintPattern = regexp.MustCompile(`^sha-256 (?i:[0-9a-f]{2})(?::(?i:[0-9a-f]{2})){31}$`)
)

// assistedJoin is an offer forwarded by the provider over the WebSocket control transport.
type assistedJoin struct {
	Kind            string `json:"kind"`
	Version         int    `json:"version"`
	ID              string `json:"id"`
	InstanceID      string `json:"instanceId"`
	Generation      int64  `json:"generation"`
	Incarnation     string `json:"incarnation"`
	KeyID           string `json:"keyId"`
	HostFingerprint string `json:"hostFingerprint"`
	ExpiresAt       int64  `json:"expiresAt"`
	NetworkID       string `json:"networkId"`
	CPK             string `json:"cpk,omitempty"`
	LocalUfrag      string `json:"localUfrag"`
	LocalPassword   string `json:"localPassword"`
	Offer           string `json:"offer"`
}

// authority is the registration context that assisted joins must match.
type authority struct {
	instanceID string
	generation int64
	keyID      string
}

// offer is the part of a player offer used by assisted joins.
type offer struct {
	ufrag, password string
	fingerprint     []byte
	candidates      []webrtc.ICECandidate
}

func iceString(s string, minLen int) bool {
	return len(s) >= minLen && len(s) <= 256 && iceCharPattern.MatchString(s)
}

func decodeAssistedJoin(b []byte) (*assistedJoin, error) {
	if len(b) > maxAssistedBytes {
		return nil, errors.New("assisted join too large")
	}
	j := &assistedJoin{}
	if err := json.Unmarshal(b, j); err != nil {
		return nil, fmt.Errorf("decode assisted join: %w", err)
	}
	if j.Kind != "assisted-join" || j.Version != 1 || !joinIDPattern.MatchString(j.ID) || !instanceIDPattern.MatchString(j.InstanceID) ||
		j.Generation < 1 || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(j.Incarnation) || !regexp.MustCompile(`^[A-Z0-9]{4}$`).MatchString(j.KeyID) ||
		!fingerprintPattern.MatchString(j.HostFingerprint) || j.ExpiresAt < 1 || !iceString(j.LocalUfrag, 4) || !iceString(j.LocalPassword, 22) || len(j.Offer) > 65536 {
		return nil, errors.New("invalid assisted join")
	}
	if j.NetworkID == "0" {
		if j.CPK != "" || !strings.HasPrefix(j.LocalUfrag, admission.Prefix+j.KeyID) || len(j.Offer) > 16384 {
			return nil, errors.New("invalid assisted diagnostic")
		}
	} else if !networkIDPattern.MatchString(j.NetworkID) || len(j.CPK) != 160 {
		return nil, errors.New("invalid assisted player identity")
	} else if _, err := strconv.ParseUint(j.NetworkID, 10, 64); err != nil {
		return nil, errors.New("invalid assisted network ID")
	}
	return j, nil
}

// parseOffer parses the bounded SDP profile of an assisted offer.
func parseOffer(sdp string) (*offer, error) {
	lines := strings.Split(strings.TrimRight(sdp, "\r\n"), "\n")
	for i := range lines {
		lines[i] = strings.TrimSuffix(lines[i], "\r")
	}
	if len(lines) > 256 || strings.ContainsRune(sdp, 0) {
		return nil, errors.New("offer too large")
	}
	one := func(prefix string) (string, error) {
		var found []string
		for _, l := range lines {
			if v, ok := strings.CutPrefix(l, prefix); ok {
				found = append(found, v)
			}
		}
		if len(found) != 1 {
			return "", fmt.Errorf("offer needs exactly one %q", prefix)
		}
		return found[0], nil
	}
	values := map[string]string{}
	for _, prefix := range []string{"m=", "a=setup:", "a=sctp-port:", "a=max-message-size:", "a=ice-ufrag:", "a=ice-pwd:", "a=fingerprint:"} {
		v, err := one(prefix)
		if err != nil {
			return nil, err
		}
		values[prefix] = v
	}
	for _, l := range lines {
		if l == "a=ice-lite" {
			return nil, errors.New("ICE-lite offers are not supported")
		}
	}
	if !regexp.MustCompile(`^application [0-9]{1,5} UDP/DTLS/SCTP webrtc-datachannel$`).MatchString(values["m="]) ||
		values["a=setup:"] != "actpass" || values["a=sctp-port:"] != "5000" || values["a=max-message-size:"] != "262144" {
		return nil, errors.New("unsupported offer profile")
	}
	o := &offer{ufrag: values["a=ice-ufrag:"], password: values["a=ice-pwd:"]}
	if !iceString(o.ufrag, 4) || !iceString(o.password, 22) || !fingerprintPattern.MatchString(values["a=fingerprint:"]) {
		return nil, errors.New("invalid offer ICE or DTLS parameters")
	}
	o.fingerprint, _ = hex.DecodeString(strings.ReplaceAll(strings.TrimPrefix(values["a=fingerprint:"], "sha-256 "), ":", ""))
	for _, l := range lines {
		v, ok := strings.CutPrefix(l, "a=candidate:")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) < 8 || len(f) > 24 || f[1] != "1" || !strings.EqualFold(f[2], "udp") || f[6] != "typ" || len(o.candidates) == 32 {
			return nil, errors.New("invalid offer candidate")
		}
		addr, err := netip.ParseAddr(f[4])
		port, perr := strconv.ParseUint(f[5], 10, 16)
		prio, prerr := strconv.ParseUint(f[3], 10, 32)
		if err != nil || perr != nil || prerr != nil || port == 0 {
			return nil, errors.New("invalid offer candidate")
		}
		var typ webrtc.ICECandidateType
		switch f[7] {
		case "host":
			typ = webrtc.ICECandidateTypeHost
		case "srflx":
			typ = webrtc.ICECandidateTypeSrflx
		case "prflx":
			typ = webrtc.ICECandidateTypePrflx
		case "relay":
			typ = webrtc.ICECandidateTypeRelay
		default:
			return nil, errors.New("invalid offer candidate type")
		}
		o.candidates = append(o.candidates, webrtc.ICECandidate{
			Foundation: f[0], Priority: uint32(prio), Address: addr.Unmap().String(), Protocol: webrtc.ICEProtocolUDP,
			Port: uint16(port), Component: 1, Typ: typ,
		})
	}
	if len(o.candidates) == 0 {
		return nil, errors.New("offer needs a numeric candidate")
	}
	return o, nil
}

// parseCPK parses the canonical identity key of an assisted player.
func parseCPK(cpk string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(cpk)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("identity key is not ECDSA")
	}
	if canonical, err := admission.CanonicalPublicKey(pub); err != nil || canonical != cpk {
		return nil, errors.New("identity key is not canonical")
	}
	return pub, nil
}

// assist admits an assisted join and returns the SDP answer and the deadline for sending it.
// Once ctx is canceled, a peer that has not connected yet is stopped.
func (p *Provider) assist(ctx context.Context, j *assistedJoin) (string, time.Time, error) {
	deadline := time.UnixMilli(j.ExpiresAt)
	remaining, limit := time.Until(deadline), maxAssistedLifetime
	if j.NetworkID == "0" {
		limit = maxDiagnosticLifetime
	}
	if remaining <= 0 || remaining > limit {
		return "", deadline, errors.New("assisted join expired")
	}
	auth := p.authority.Load()
	h := p.host
	if !h.accepting() {
		return "", deadline, errors.New("host is not accepting players")
	}
	if !p.assisting() || auth == nil || p.closing.Load() || j.InstanceID != auth.instanceID || j.Generation != auth.generation ||
		j.Incarnation != h.incarnation || j.KeyID != auth.keyID || !strings.EqualFold(j.HostFingerprint, h.fingerprint) {
		return "", deadline, errors.New("assisted join does not match the host")
	}
	o, err := parseOffer(j.Offer)
	if err != nil {
		return "", deadline, err
	}
	var (
		family int
		cands  []candidate
	)
	for _, f := range o.families() {
		if cands = p.answerCandidates(f); len(cands) > 0 {
			family = f
			break
		}
	}
	if len(cands) == 0 {
		return "", deadline, errors.New("no public candidate for the address families of the player")
	}
	adm := nethernet.Admission{
		ICE:        webrtc.ICEParameters{UsernameFragment: o.ufrag, Password: o.password},
		DTLS:       remoteDTLS(o.fingerprint),
		SCTP:       webrtc.SCTPCapabilities{MaxMessageSize: maxMessageSize},
		Candidates: o.candidates,
	}

	if j.NetworkID == "0" {
		if err := p.assistDiagnostic(ctx, j, o, adm, family); err != nil {
			return "", deadline, err
		}
		cands = cands[:1]
	} else {
		pub, err := parseCPK(j.CPK)
		if err != nil {
			return "", deadline, fmt.Errorf("parse identity key: %w", err)
		}
		a, reason := h.reserve(j.LocalUfrag, netip.AddrPort{}, deadline, nil)
		if a == nil {
			return "", deadline, fmt.Errorf("assisted join rejected: %s", reason)
		}
		a.ctx = ctx
		adm.NetworkID, adm.PublicKey = j.NetworkID, pub
		adm.VerifyPublicKey = h.verifier(a, deadline, func(got *ecdsa.PublicKey) bool { return pub.Equal(got) })
		go h.establish(a, adm, j.LocalPassword)
	}
	return answer(j.LocalUfrag, j.LocalPassword, h.fingerprint, cands), deadline, nil
}

// families returns the address families of the candidates of o, in their order.
func (o *offer) families() []int {
	var families []int
	for _, c := range o.candidates {
		f := 4
		if ip, _ := netip.ParseAddr(c.Address); ip.Is6() {
			f = 6
		}
		if !slices.Contains(families, f) {
			families = append(families, f)
		}
	}
	return families
}

// assistDiagnostic admits an assisted diagnostic.
func (p *Provider) assistDiagnostic(ctx context.Context, j *assistedJoin, o *offer, adm nethernet.Admission, family int) error {
	h := p.host
	key, ok := (*h.keys.Load())[j.KeyID]
	if !ok || !key.Usable(time.Now()) {
		return errors.New("unknown admission key")
	}
	claims, err := key.Open(h.audience, j.LocalUfrag, o.ufrag)
	if err != nil || claims.NetworkID != 0 || claims.Diagnostic.Profile != admission.ProfileAssisted ||
		hex.EncodeToString(claims.IdentityBinding[:]) != j.ID || claims.ExpiresAt.UnixMilli() != j.ExpiresAt ||
		key.ICEPassword(h.audience, j.LocalUfrag) != j.LocalPassword || claims.Password != o.password ||
		!bytes.Equal(claims.Fingerprint[:], o.fingerprint) {
		return errors.New("assisted diagnostic does not match its permit")
	}
	if sha256.Sum256([]byte(j.Offer)) != claims.Diagnostic.OfferDigest {
		return errors.New("assisted diagnostic offer does not match its permit")
	}
	if err := checkDiagnosticOffer(j.Offer, o.ufrag, family); err != nil {
		return err
	}
	remote, _ := netip.ParseAddr(o.candidates[0].Address)
	switch {
	case h.reachable(remote):
	case family == 4 && scopeOf(remote) == scopePrivate && o.candidates[0].Typ == webrtc.ICECandidateTypeHost:
		// A private address is not a diagnostic destination, so the public address of the
		// prober is learned from its authenticated checks instead.
		adm.Candidates = nil
	default:
		return errors.New("assisted diagnostic offers no public candidate")
	}
	if err := h.authorizeDiagnostic(key, claims, family); err != nil {
		return err
	}
	a, ok := h.reserveDiagnostic(j.LocalUfrag, netip.AddrPort{}, claims, nil)
	if !ok {
		return errors.New("no capacity for assisted diagnostic")
	}
	a.ctx = ctx
	adm.NetworkID = "0"
	go h.echo(a, adm, j.LocalPassword, key, claims, family)
	return nil
}

var (
	diagnosticMediaPattern      = regexp.MustCompile(`^application [0-9]{1,5} UDP/DTLS/SCTP webrtc-datachannel$`)
	diagnosticFoundationPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{1,32}$`)
	diagnosticNumberPattern     = regexp.MustCompile(`^[0-9]{1,10}$`)
)

// checkDiagnosticOffer checks an assisted diagnostic offer against the closed SDP profile of
// diagnostics, which allows a single host or server-reflexive candidate of the family.
func checkDiagnosticOffer(sdp, ufrag string, family int) error {
	invalid := errors.New("assisted diagnostic offer is outside the diagnostic SDP profile")
	if sdp == "" || len(sdp) > 16384 || !utf8.ValidString(sdp) || strings.ContainsRune(sdp, 0) ||
		strings.ContainsRune(strings.ReplaceAll(sdp, "\r\n", ""), '\r') {
		return invalid
	}
	var lines []string
	for _, l := range strings.Split(sdp, "\n") {
		if l = strings.TrimSuffix(l, "\r"); l != "" {
			lines = append(lines, l)
		}
	}
	one := func(prefix string) (string, bool) {
		var found []string
		for _, l := range lines {
			if v, ok := strings.CutPrefix(l, prefix); ok {
				found = append(found, v)
			}
		}
		return strings.Join(found, "\n"), len(found) == 1
	}
	for prefix, want := range map[string]string{"a=group:": "BUNDLE 0", "a=mid:": "0"} {
		if v, ok := one(prefix); !ok || v != want {
			return invalid
		}
	}
	media, ok := one("m=")
	if !ok || !diagnosticMediaPattern.MatchString(media) {
		return invalid
	}
	if port, _ := strconv.Atoi(strings.Fields(media)[1]); port < 1 || port > 65535 {
		return invalid
	}
	ends := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "a=ice-lite") || strings.HasPrefix(l, "a=identity:") {
			return invalid
		}
		if l == "a=end-of-candidates" {
			ends++
		}
	}
	line, ok := one("a=candidate:")
	if !ok || ends != 1 {
		return invalid
	}
	f := strings.Split(line, " ")
	if len(f) < 8 || len(f) > 20 || len(f)%2 != 0 || !diagnosticFoundationPattern.MatchString(f[0]) || f[1] != "1" ||
		!strings.EqualFold(f[2], "udp") || !diagnosticNumberPattern.MatchString(f[3]) || f[6] != "typ" {
		return invalid
	}
	if _, err := strconv.ParseUint(f[3], 10, 32); err != nil {
		return invalid
	}
	if port, err := strconv.ParseUint(f[5], 10, 16); err != nil || port == 0 || len(f[5]) > 5 {
		return invalid
	}
	reflexive := f[7] == "srflx"
	if f[7] != "host" && !reflexive {
		return invalid
	}
	seen := map[string]bool{}
	for i := 8; i < len(f); i += 2 {
		name, value := f[i], f[i+1]
		if seen[name] {
			return invalid
		}
		seen[name] = true
		switch name {
		case "raddr":
			addr, err := netip.ParseAddr(value)
			if !reflexive || err != nil || addr.Zone() != "" || (family == 6) != (addr.Is6() && !addr.Is4In6()) {
				return invalid
			}
		case "rport":
			if port, err := strconv.ParseUint(value, 10, 16); !reflexive || err != nil || port == 0 || len(value) > 5 {
				return invalid
			}
		case "ufrag":
			if value != ufrag {
				return invalid
			}
		case "generation", "network-id", "network-cost":
			if _, err := strconv.ParseUint(value, 10, 32); err != nil || !diagnosticNumberPattern.MatchString(value) {
				return invalid
			}
		default:
			return invalid
		}
	}
	if seen["raddr"] != seen["rport"] {
		return invalid
	}
	return nil
}

// answerCandidates returns the candidates of an assisted answer, refreshing the STUN mapping
// of the family if possible.
func (p *Provider) answerCandidates(family int) []candidate {
	var out []candidate
	if len(p.conf.Endpoints) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		for _, addr := range p.mappings(ctx) {
			if (family == 6) == addr.Addr().Is6() {
				out = append(out, candidate{Address: addr.Addr().String(), Port: addr.Port(), Type: "srflx"})
			}
		}
		cancel()
	}
	if published := p.published.Load(); published != nil {
		for _, c := range *published {
			addr, err := netip.ParseAddr(c.Address)
			if err != nil || !p.host.reachable(addr) || (family == 6) != addr.Is6() {
				continue
			}
			if !containsEndpoint(out, c) {
				out = append(out, c)
			}
		}
	}
	return out
}

func containsEndpoint(cands []candidate, c candidate) bool {
	for _, o := range cands {
		if o.Address == c.Address && o.Port == c.Port {
			return true
		}
	}
	return false
}

// answer encodes the SDP answer of the host.
func answer(ufrag, password, fingerprint string, cands []candidate) string {
	b := &strings.Builder{}
	b.WriteString("v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=group:BUNDLE 0\r\n")
	b.WriteString("m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\nc=IN IP4 0.0.0.0\r\n")
	b.WriteString("a=ice-ufrag:" + ufrag + "\r\na=ice-pwd:" + password + "\r\na=fingerprint:" + fingerprint + "\r\n")
	b.WriteString("a=setup:active\r\na=mid:0\r\na=sctp-port:5000\r\na=max-message-size:262144\r\n")
	for i, c := range cands {
		fmt.Fprintf(b, "a=candidate:%d 1 UDP %d %s %d typ %s", i+1, 2130706431-i*256, c.Address, c.Port, c.Type)
		if c.Type == "srflx" {
			raddr := "0.0.0.0"
			if strings.Contains(c.Address, ":") {
				raddr = "::"
			}
			b.WriteString(" raddr " + raddr + " rport 0")
		}
		b.WriteString("\r\n")
	}
	b.WriteString("a=end-of-candidates\r\n")
	return b.String()
}
