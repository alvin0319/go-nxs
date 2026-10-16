package nxs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	discoveryPath = "/.well-known/nethernet-external-signaling"

	extensionConnectivity = "dev.opencollab.nxs.connectivity"
	extensionWebSocket    = "dev.opencollab.nxs.websocket"

	schemeAnonymous = "anonymous-proof-of-work"
	schemeBearer    = "bearer-token"

	modeNewService     = "new-service"
	modeAttachInstance = "attach-instance"
	modeRecover        = "recover"

	maxBodyBytes = 65536
)

// extension is an optional protocol extension.
type extension struct {
	Version  int             `json:"version"`
	Critical bool            `json:"critical"`
	Data     json.RawMessage `json:"data"`
}

type discovery struct {
	Provider      string   `json:"provider"`
	Protocols     []string `json:"protocols"`
	Signatures    []string `json:"signatures"`
	Authorization struct {
		Schemes []string `json:"schemes"`
	} `json:"authorization"`
	Limits struct {
		HeartbeatIntervalMs int64 `json:"heartbeatIntervalMs"`
	} `json:"limits"`
	Extensions map[string]extension `json:"extensions"`
}

// validate checks that discovery is usable for the origin and registration scheme.
func (d *discovery) validate(origin, scheme string) error {
	if d.Provider != origin {
		return errors.New("provider origin mismatch")
	}
	for _, c := range []struct {
		name   string
		values []string
		want   string
	}{{"protocol", d.Protocols, Protocol}, {"signature", d.Signatures, SignatureVersion}, {"authorization scheme", d.Authorization.Schemes, scheme}} {
		if !slices.Contains(c.values, c.want) {
			return fmt.Errorf("unsupported %s %q", c.name, c.want)
		}
	}
	if l := d.Limits; l.HeartbeatIntervalMs < 1000 || l.HeartbeatIntervalMs > 30000 {
		return errors.New("unsupported provider limits")
	}
	return checkExtensions(d.Extensions)
}

var extensionNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*){1,7}$`)

// checkExtensions checks the extensions of a provider message, and rejects critical ones that
// are not supported.
func checkExtensions(exts map[string]extension) error {
	if len(exts) > 16 {
		return errors.New("nxs: too many extensions")
	}
	if b, err := json.Marshal(exts); err != nil || len(b) > 16384 {
		return errors.New("nxs: extensions too large")
	}
	for name, ext := range exts {
		if len(name) > 128 || !extensionNamePattern.MatchString(name) || ext.Version < 1 || ext.Version > 999999999 ||
			!bytes.HasPrefix(bytes.TrimSpace(ext.Data), []byte("{")) {
			return fmt.Errorf("nxs: invalid extension %s", name)
		}
		supported := (name == extensionConnectivity || name == extensionWebSocket) && ext.Version == 1
		if ext.Critical && !supported {
			return fmt.Errorf("nxs: unsupported critical extension %s", name)
		}
	}
	return nil
}

// opURL returns the URL of an operation on the provider origin.
func opURL(origin, op string) string {
	return origin + "/v1/nxs/" + op
}

// stunServers returns the STUN servers advertised by the connectivity extension.
func (d *discovery) stunServers() []string {
	ext, ok := d.Extensions[extensionConnectivity]
	if !ok || ext.Version != 1 {
		return nil
	}
	var data struct {
		StunServers []struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		} `json:"stunServers"`
	}
	if json.Unmarshal(ext.Data, &data) != nil {
		return nil
	}
	var servers []string
	for _, s := range data.StunServers[:min(len(data.StunServers), 2)] {
		if s.Host != "" && s.Port > 0 && s.Port < 65536 {
			servers = append(servers, joinHostPort(s.Host, s.Port))
		}
	}
	return servers
}

func (d *discovery) connectivity() bool {
	ext, ok := d.Extensions[extensionConnectivity]
	return ok && ext.Version == 1
}

type authorization struct {
	Scheme    string `json:"scheme"`
	Reference string `json:"reference,omitempty"`
}

func isControl(r rune) bool { return r < 0x20 || (r >= 0x7f && r <= 0x9f) }

type registerRequest struct {
	Protocol       string `json:"protocol"`
	PublicKeyJWK   *jwk   `json:"publicKeyJwk,omitempty"`
	Label          string `json:"label,omitempty"`
	RegistrationID string `json:"registrationId,omitempty"`
}

type challenge struct {
	Protocol      string           `json:"protocol"`
	Signature     string           `json:"signature"`
	ChallengeID   string           `json:"challengeId"`
	Nonce         string           `json:"nonce"`
	Audience      string           `json:"audience"`
	Thumbprint    string           `json:"thumbprint"`
	Context       challengeContext `json:"context"`
	ContextDigest string           `json:"contextDigest"`
	ExpiresAt     int64            `json:"expiresAt"`
	ServerTime    int64            `json:"serverTime"`
	Pow           struct {
		Difficulty int `json:"difficulty"`
	} `json:"pow"`
	Authorization *authorization `json:"authorization,omitempty"`
}

// validate checks that the challenge is bound to the origin and key.
func (c *challenge) validate(origin, thumbprint string) error {
	d, err := c.Context.digest()
	if err != nil {
		return err
	}
	if c.Protocol != Protocol || c.Signature != SignatureVersion || c.Audience != origin || c.Thumbprint != thumbprint ||
		c.ContextDigest != d || c.Pow.Difficulty < 0 || c.Pow.Difficulty > 24 {
		return errors.New("nxs: unbound registration challenge")
	}
	return nil
}

type completeRequest struct {
	Protocol       string `json:"protocol"`
	ChallengeID    string `json:"challengeId"`
	ProofNonce     string `json:"proofNonce"`
	IdempotencyKey string `json:"idempotencyKey"`
	Signature      string `json:"signature"`
}

// Readiness is the provider's latest observation of whether players can be routed to the host.
type Readiness struct {
	Routable bool     `json:"routable"`
	Reasons  []string `json:"reasons"`
}

type ticketKey struct {
	KeyID       string `json:"keyId"`
	Secret      string `json:"secret"`
	NotBefore   int64  `json:"notBefore,omitempty"`
	RetireAfter int64  `json:"retireAfter,omitempty"`
}

// operatorAction is a link the provider offers to the operator of the host. It may carry a
// one-time credential and is never saved.
type operatorAction struct {
	URL       string `json:"url"`
	Text      string `json:"text"`
	ExpiresAt int64  `json:"expiresAt"`
}

type registration struct {
	Protocol        string          `json:"protocol"`
	Provider        string          `json:"provider"`
	RegistrationID  string          `json:"registrationId"`
	InstanceID      string          `json:"instanceId"`
	KeyID           string          `json:"keyId"`
	LeaseGeneration int64           `json:"leaseGeneration"`
	ServiceID       string          `json:"serviceId,omitempty"`
	PublicAddress   string          `json:"publicAddress,omitempty"`
	AdmissionKey    *ticketKey      `json:"admissionKey,omitempty"`
	OperatorAction  *operatorAction `json:"operatorAction,omitempty"`
	// Extensions are optional provider metadata.
	Extensions map[string]extension `json:"extensions,omitempty"`
}

var (
	identifierPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	publicAddressPattern = regexp.MustCompile(`^https://[^/?#@\s]+(?:[/?#]\S*)?$`)
)

func (r *registration) validate(origin string) error {
	if r.Protocol != Protocol || r.Provider != origin || !identifierPattern.MatchString(r.RegistrationID) ||
		!identifierPattern.MatchString(r.InstanceID) || !identifierPattern.MatchString(r.KeyID) ||
		r.LeaseGeneration < 1 || r.LeaseGeneration > 1<<53-1 || (r.ServiceID == "") != (r.PublicAddress == "") {
		return errors.New("nxs: invalid registration")
	}
	if r.ServiceID != "" && (!identifierPattern.MatchString(r.ServiceID) || len(r.PublicAddress) > 2048 || !publicAddressPattern.MatchString(r.PublicAddress)) {
		return errors.New("nxs: invalid public endpoint of registration")
	}
	return checkExtensions(r.Extensions)
}

type candidate struct {
	Foundation string `json:"foundation"`
	Priority   uint32 `json:"priority"`
	Address    string `json:"address"`
	Port       uint16 `json:"port"`
	Type       string `json:"type"`
	ExpiresAt  int64  `json:"expiresAt,omitempty"`
}

type hostProfile struct {
	Candidates         []candidate `json:"candidates"`
	DTLSFingerprint    string      `json:"dtlsFingerprint"`
	AdmissionKeyID     string      `json:"admissionKeyId"`
	SCTPPort           int         `json:"sctpPort"`
	MaxMessageSize     int         `json:"maxMessageSize"`
	StatelessAdmission struct {
		Capability       string `json:"capability"`
		Incarnation      string `json:"incarnation"`
		AssistedFamilies []int  `json:"assistedFamilies,omitempty"`
	} `json:"statelessAdmission"`
}

type connectedPlayers struct {
	Count     int   `json:"count"`
	SampledAt int64 `json:"sampledAt"`
}

// Software identifies the host software reported to the provider.
type Software struct {
	// Name is the name of the host software, 1 to 64 characters.
	Name string `json:"name"`
	// Version is the version of the host software, 1 to 128 characters.
	Version string `json:"version"`
}

func (s *Software) valid() bool {
	return s.Name != "" && utf8.RuneCountInString(s.Name) <= 64 && s.Version != "" && utf8.RuneCountInString(s.Version) <= 128
}

// Location is where the operator says the host runs. It needs a Country, coordinates or both.
type Location struct {
	// Country is an uppercase ISO 3166-1 alpha-2 code.
	Country string `json:"country,omitempty"`
	// City is 1 to 120 characters without control characters.
	City string `json:"city,omitempty"`
	// Latitude (-90 to 90) and Longitude (-180 to 180) are set together.
	Latitude  *float64 `json:"latitude,omitempty"`
	Longitude *float64 `json:"longitude,omitempty"`
}

var countryPattern = regexp.MustCompile(`^[A-Z]{2}$`)

func (l *Location) valid() bool {
	if l.Country != "" && !countryPattern.MatchString(l.Country) {
		return false
	}
	if l.City != "" && (utf8.RuneCountInString(l.City) > 120 || !utf8.ValidString(l.City) || strings.ContainsFunc(l.City, isControl)) {
		return false
	}
	if (l.Latitude == nil) != (l.Longitude == nil) {
		return false
	}
	if l.Latitude != nil && !(*l.Latitude >= -90 && *l.Latitude <= 90 && *l.Longitude >= -180 && *l.Longitude <= 180) {
		return false
	}
	return l.Country != "" || l.Latitude != nil
}

// serverStatus is the public listing metadata of the host.
type serverStatus struct {
	Name           string `json:"name"`
	Level          string `json:"level"`
	MaxPlayerCount int    `json:"maxPlayerCount"`
	GameType       int    `json:"gameType"`
}

type heartbeatRequest struct {
	AcceptingPlayers         bool                 `json:"acceptingPlayers"`
	Capacity                 int                  `json:"capacity"`
	ConnectedPlayers         connectedPlayers     `json:"connectedPlayers"`
	Software                 *Software            `json:"software,omitempty"`
	Location                 json.RawMessage      `json:"location,omitempty"`
	ServerStatus             *serverStatus        `json:"serverStatus,omitempty"`
	GameOutcomes             string               `json:"gameOutcomes,omitempty"`
	HostProfile              *hostProfile         `json:"hostProfile,omitempty"`
	HostProfileRevision      string               `json:"hostProfileRevision,omitempty"`
	InstalledAdmissionKeyIDs []string             `json:"installedAdmissionKeyIds,omitempty"`
	AdmissionKeyRequestID    string               `json:"admissionKeyRequestId,omitempty"`
	Extensions               map[string]extension `json:"extensions,omitempty"`
}

type checkIn struct {
	AfterMillis             int64 `json:"afterMillis"`
	LeaseMillis             int64 `json:"leaseMillis"`
	MinUpdateIntervalMillis int64 `json:"minUpdateIntervalMillis"`
}

func (c *checkIn) valid() bool {
	return c.AfterMillis >= 1000 && c.AfterMillis <= 86400000 && c.LeaseMillis > c.AfterMillis && c.LeaseMillis-c.AfterMillis <= 300000 &&
		c.MinUpdateIntervalMillis >= 1000 && c.MinUpdateIntervalMillis <= c.AfterMillis
}

type heartbeatResponse struct {
	HostProfileRevision     *string   `json:"hostProfileRevision"`
	Readiness               Readiness `json:"readiness"`
	AdmissionKeyRetirements []struct {
		KeyID       string `json:"keyId"`
		RetireAfter int64  `json:"retireAfter"`
	} `json:"admissionKeyRetirements"`
	CheckIn             *checkIn `json:"checkIn"`
	AdmissionKeyRequest *struct {
		ID    string `json:"id"`
		KeyID string `json:"keyId"`
	} `json:"admissionKeyRequest"`
	AdmissionKey            *ticketKey           `json:"admissionKey"`
	OperatorActionAvailable bool                 `json:"operatorActionAvailable"`
	Extensions              map[string]extension `json:"extensions"`
}

// event is an outcome observation of an admission attempt.
type event struct {
	TicketID      string `json:"ticketId"`
	Stage         string `json:"stage"`
	OccurredAt    int64  `json:"occurredAt"`
	Reason        string `json:"reason,omitempty"`
	RemoteAddress string `json:"remoteAddress,omitempty"`
	RemotePort    int    `json:"remotePort,omitempty"`
}

// normalizeOrigin returns the canonical form of a provider origin.
func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("nxs: parse origin: %w", err)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.Hostname() == "" {
		return "", fmt.Errorf("nxs: invalid origin %q", raw)
	}
	scheme, host, port := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname()), u.Port()
	switch scheme {
	case "https":
		if port == "443" {
			port = ""
		}
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", fmt.Errorf("nxs: origin %q must use HTTPS", raw)
		}
		if port == "80" {
			port = ""
		}
	default:
		return "", fmt.Errorf("nxs: origin %q must use HTTPS", raw)
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 || strconv.Itoa(p) != port {
			return "", fmt.Errorf("nxs: invalid origin port %q", port)
		}
		host += ":" + port
	}
	origin := scheme + "://" + host
	if !canonicalOrigin(origin) {
		return "", fmt.Errorf("nxs: origin %q is not canonical", raw)
	}
	return origin, nil
}

var (
	originAuthorityPattern = regexp.MustCompile(`^[a-z0-9.\[\]:-]+$`)
	originPortPattern      = regexp.MustCompile(`^:[1-9][0-9]{0,4}$`)
	dnsLabelPattern        = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	ipv4OctetPattern       = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,2})$`)
	ipv6PiecePattern       = regexp.MustCompile(`^(?:0|[1-9a-f][0-9a-f]{0,3})$`)
)

// canonicalOrigin reports whether value is a canonical origin as defined by the
// specification, which accepts exactly one spelling of every origin.
func canonicalOrigin(value string) bool {
	secure := strings.HasPrefix(value, "https://")
	if !secure && !strings.HasPrefix(value, "http://") {
		return false
	}
	authority := strings.TrimPrefix(strings.TrimPrefix(value, "https://"), "http://")
	if !originAuthorityPattern.MatchString(authority) {
		return false
	}
	var host, port string
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 || !canonicalIPv6(authority[1:end]) {
			return false
		}
		host, port = authority[:end+1], authority[end+1:]
	} else {
		host = authority
		if i := strings.IndexByte(authority, ':'); i >= 0 {
			host, port = authority[:i], authority[i:]
		}
		if !canonicalIPv4(host) && !canonicalDNS(host) {
			return false
		}
	}
	if port != "" {
		n, _ := strconv.Atoi(port[1:])
		if !originPortPattern.MatchString(port) || n > 65535 || (secure && n == 443) || (!secure && n == 80) {
			return false
		}
	}
	return secure || host == "localhost" || host == "127.0.0.1" || host == "[::1]"
}

func canonicalIPv4(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if n, _ := strconv.Atoi(part); !ipv4OctetPattern.MatchString(part) || n > 255 {
			return false
		}
	}
	return true
}

func canonicalDNS(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) || strings.HasPrefix(label, "xn--") {
			return false
		}
	}
	// A numeric final label would make the host an IPv4 address to WHATWG URL parsers.
	last := labels[len(labels)-1]
	return last[0] >= 'a' && last[0] <= 'z'
}

// canonicalIPv6 reports whether s is an IPv6 address in shortest lowercase form, compressing
// the first longest run of at least two zero pieces, without an IPv4 tail.
func canonicalIPv6(s string) bool {
	if s == "" || strings.ContainsFunc(s, func(r rune) bool { return !strings.ContainsRune("0123456789abcdef:", r) }) {
		return false
	}
	pieces := func(s string) ([]uint16, bool) {
		if s == "" {
			return nil, true
		}
		var out []uint16
		for _, v := range strings.Split(s, ":") {
			n, err := strconv.ParseUint(v, 16, 16)
			if err != nil || !ipv6PiecePattern.MatchString(v) {
				return nil, false
			}
			out = append(out, uint16(n))
		}
		return out, len(out) <= 8
	}
	var all []uint16
	if left, right, compressed := strings.Cut(s, "::"); !compressed {
		p, ok := pieces(s)
		if !ok || len(p) != 8 {
			return false
		}
		all = p
	} else {
		l, okL := pieces(left)
		r, okR := pieces(right)
		zeros := 8 - len(l) - len(r)
		if !okL || !okR || strings.Contains(right, "::") || zeros < 2 {
			return false
		}
		all = append(append(l, make([]uint16, zeros)...), r...)
	}
	start, length := -1, 1
	for i := 0; i < len(all); {
		if all[i] != 0 {
			i++
			continue
		}
		j := i
		for j < len(all) && all[j] == 0 {
			j++
		}
		if j-i > length {
			start, length = i, j-i
		}
		i = j
	}
	hexes := make([]string, len(all))
	for i, v := range all {
		hexes[i] = strconv.FormatUint(uint64(v), 16)
	}
	want := strings.Join(hexes, ":")
	if start >= 0 {
		want = strings.Join(hexes[:start], ":") + "::" + strings.Join(hexes[start+length:], ":")
	}
	return s == want
}

// operationURL checks that an operation URL is on the origin.
func operationURL(origin, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.User != nil || u.Fragment != "" {
		return nil, errors.New("URL must not contain userinfo or fragment")
	}
	o, err := normalizeOrigin(u.Scheme + "://" + u.Host)
	if err != nil || o != origin {
		return nil, errors.New("URL is not on the provider origin")
	}
	return u, nil
}

func joinHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

// marshal encodes v as JSON without HTML escaping.
func marshal(v any) ([]byte, error) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
