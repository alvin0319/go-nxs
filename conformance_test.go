package nxs

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/df-mc/go-nxs/admission"
)

type diagnosticFixtures struct {
	Vectors []struct {
		Name, Offer, RemoteUfrag string
	}
	Answers []struct {
		Name, HostFingerprintHex, Answer string
	}
}

func loadDiagnosticFixtures(t testing.TB) diagnosticFixtures {
	b, err := os.ReadFile("testdata/diagnostic-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f diagnosticFixtures
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAnswerFixtures(t *testing.T) {
	for _, a := range loadDiagnosticFixtures(t).Answers {
		if strings.HasSuffix(a.Name, "assisted") {
			continue
		}
		fp, _ := hex.DecodeString(a.HostFingerprintHex)
		line := sdpField(a.Answer, "candidate")
		f := strings.Fields(line)
		c := candidate{Address: f[4], Type: f[7]}
		var port int
		for _, r := range f[5] {
			port = port*10 + int(r-'0')
		}
		c.Port = uint16(port)
		got := answer(sdpField(a.Answer, "ice-ufrag"), sdpField(a.Answer, "ice-pwd"), "sha-256 "+colonHex(fp), []candidate{c})
		if got != a.Answer {
			t.Errorf("%s: answer mismatch:\n got %q\nwant %q", a.Name, got, a.Answer)
		}
	}
}

func TestParseOfferFixtures(t *testing.T) {
	for _, v := range loadDiagnosticFixtures(t).Vectors {
		o, err := parseOffer(v.Offer)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if o.ufrag != v.RemoteUfrag || len(o.candidates) != 1 || len(o.fingerprint) != 32 {
			t.Fatalf("%s: unexpected offer %+v", v.Name, o)
		}
	}
	for _, bad := range []string{
		"",
		strings.Replace(loadDiagnosticFixtures(t).Vectors[0].Offer, "actpass", "active", 1),
		strings.Replace(loadDiagnosticFixtures(t).Vectors[0].Offer, "262144", "65536", 1),
		strings.Replace(loadDiagnosticFixtures(t).Vectors[0].Offer, "a=candidate", "a=x-candidate", 1),
		loadDiagnosticFixtures(t).Vectors[0].Offer + "a=ice-lite\r\n",
	} {
		if _, err := parseOffer(bad); err == nil {
			t.Errorf("offer should be rejected: %q", bad)
		}
	}
}

func TestDiagnosticOfferFixtures(t *testing.T) {
	for _, v := range loadDiagnosticFixtures(t).Vectors {
		o, err := parseOffer(v.Offer)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if err := checkDiagnosticOffer(v.Offer, v.RemoteUfrag, o.families()[0]); err != nil {
			t.Errorf("%s: %v", v.Name, err)
		}
	}
	offer := loadDiagnosticFixtures(t).Vectors[0].Offer
	for name, bad := range map[string]string{
		"second candidate": strings.Replace(offer, "a=end-of-candidates", "a=candidate:2 1 udp 1 192.0.2.1 9 typ host\r\na=end-of-candidates", 1),
		"identity":         offer + "a=identity:x\r\n",
		"no bundle":        strings.Replace(offer, "a=group:BUNDLE 0", "a=group:BUNDLE 1", 1),
		"no end":           strings.Replace(offer, "a=end-of-candidates\r\n", "", 1),
		"relay":            strings.Replace(offer, "typ host", "typ relay", 1),
	} {
		if checkDiagnosticOffer(bad, loadDiagnosticFixtures(t).Vectors[0].RemoteUfrag, 4) == nil {
			t.Errorf("%s: offer accepted", name)
		}
	}
}

func TestDiagnosticExchangeFixtures(t *testing.T) {
	b, err := os.ReadFile("testdata/diagnostic-exchange-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		AttemptIDHex string
		Frames       []struct{ FrameHex string }
	}
	if json.Unmarshal(b, &f) != nil || len(f.Frames) != 2 {
		t.Fatal("invalid fixture")
	}
	var attemptID [16]byte
	id, _ := hex.DecodeString(f.AttemptIDHex)
	copy(attemptID[:], id)
	ping, _ := hex.DecodeString(f.Frames[0].FrameHex)
	pong, _ := hex.DecodeString(f.Frames[1].FrameHex)
	got, err := diagnosticReply(ping[1:], attemptID)
	if err != nil || !bytes.Equal(got, pong[1:]) {
		t.Fatalf("diagnosticReply = %x, %v, want %x", got, err, pong[1:])
	}
	if _, err := diagnosticReply(pong[1:], attemptID); err == nil {
		t.Fatal("a PONG was answered")
	}
	attemptID[0] ^= 1
	if _, err := diagnosticReply(ping[1:], attemptID); err == nil {
		t.Fatal("a PING of another attempt was answered")
	}
}

func TestTokenFreshness(t *testing.T) {
	now := time.UnixMilli(1788484800000)
	for _, c := range []struct {
		expiresAt time.Time
		want      bool
	}{
		{now.Add(30 * time.Second), true},
		{now.Add(admission.MaxTTL), true},
		{now, false},
		{now.Add(-time.Second), false},
		{now.Add(admission.MaxTTL + time.Millisecond), false},
	} {
		if fresh(c.expiresAt, now, admission.MaxTTL) != c.want {
			t.Errorf("fresh(%s) = %v", c.expiresAt.Sub(now), !c.want)
		}
	}
}

func TestOriginFixtures(t *testing.T) {
	b, err := os.ReadFile("testdata/origins.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors []struct {
			Origin   string
			Accepted bool
		}
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for _, v := range f.Vectors {
		if canonicalOrigin(v.Origin) != v.Accepted {
			t.Errorf("canonicalOrigin(%q) = %v", v.Origin, !v.Accepted)
		}
		if got, err := normalizeOrigin(v.Origin); v.Accepted && (err != nil || got != v.Origin) {
			t.Errorf("normalizeOrigin(%q) = %q, %v", v.Origin, got, err)
		}
	}
}

func FuzzParseOffer(f *testing.F) {
	for _, v := range loadDiagnosticFixtures(f).Vectors {
		f.Add(v.Offer)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = parseOffer(s) })
}

func FuzzDecodeAssistedJoin(f *testing.F) {
	f.Add([]byte(`{"kind":"assisted-join","version":1,"id":"0123456789abcdef0123456789abcdef"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = decodeAssistedJoin(b) })
}

func FuzzParsePong(f *testing.F) {
	f.Add([]byte("MCPE;Test;1000;1.26.0;0;10;1;world;Survival;1;0;0;0;0;"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parsePong(b) })
}
