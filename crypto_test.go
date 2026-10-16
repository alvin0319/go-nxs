package nxs

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type nxsFixture struct {
	PublicKeyJwk   jwk
	Challenge      challenge
	ProofNonce     string
	IdempotencyKey string
	Proof          struct{ Payload, Signature string }
	Request        struct {
		Input struct {
			Audience, Method, Path, InstanceID, KeyID, IdempotencyKey, Body string
			Timestamp, Generation, Sequence                                 int64
		}
		Payload, Signature string
	}
	Rotation struct {
		ReplacementPublicKeyJwk jwk
		Input                   struct {
			Audience, InstanceID, OldKeyID, IdempotencyKey string
			Generation                                     int64
		}
		Payload, Signature string
	}
	FleetExamples struct {
		Registration, Heartbeat json.RawMessage
	}
}

func loadNXSFixture(t *testing.T) nxsFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/nxs-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f nxsFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFixtureProof(t *testing.T) {
	f := loadNXSFixture(t)
	pub, err := f.PublicKeyJwk.publicKey()
	if err != nil {
		t.Fatal(err)
	}
	if got := f.PublicKeyJwk.thumbprint(); got != f.Challenge.Thumbprint {
		t.Fatalf("thumbprint: got %s, want %s", got, f.Challenge.Thumbprint)
	}
	if err := f.Challenge.validate("https://provider.example", f.Challenge.Thumbprint); err != nil {
		t.Fatalf("validate challenge: %v", err)
	}
	proof, err := f.Challenge.proof(f.ProofNonce, f.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(proof) != f.Proof.Payload {
		t.Fatalf("proof payload:\n got %s\nwant %s", proof, f.Proof.Payload)
	}
	if !verify(pub, proof, f.Proof.Signature) {
		t.Fatal("fixture proof signature did not verify")
	}
}

func TestFixtureRequest(t *testing.T) {
	f := loadNXSFixture(t)
	in := f.Request.Input
	payload, err := requestPayload(in.Audience, in.Method, in.Path, in.Timestamp, in.InstanceID, in.KeyID, in.IdempotencyKey, in.Generation, in.Sequence, []byte(in.Body))
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != f.Request.Payload {
		t.Fatalf("request payload:\n got %s\nwant %s", payload, f.Request.Payload)
	}
	pub, _ := f.PublicKeyJwk.publicKey()
	if !verify(pub, payload, f.Request.Signature) {
		t.Fatal("fixture request signature did not verify")
	}
}

func TestFixtureRotation(t *testing.T) {
	r := loadNXSFixture(t).Rotation
	pub, err := r.ReplacementPublicKeyJwk.publicKey()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := rotationProof(r.Input.Audience, r.Input.InstanceID, r.Input.OldKeyID, r.ReplacementPublicKeyJwk.thumbprint(), r.Input.Generation, r.Input.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != r.Payload {
		t.Fatalf("rotation payload:\n got %s\nwant %s", payload, r.Payload)
	}
	if !verify(pub, payload, r.Signature) {
		t.Fatal("fixture rotation signature did not verify")
	}
}

func TestFleetExamplesRoundTrip(t *testing.T) {
	f := loadNXSFixture(t).FleetExamples
	for name, c := range map[string]struct {
		raw json.RawMessage
		v   any
	}{"registration": {f.Registration, &registration{}}, "heartbeat": {f.Heartbeat, &heartbeatRequest{}}} {
		if err := json.Unmarshal(c.raw, c.v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, _ := json.Marshal(c.v)
		var want, have any
		_ = json.Unmarshal(c.raw, &want)
		_ = json.Unmarshal(got, &have)
		if !reflect.DeepEqual(want, have) {
			t.Errorf("%s round trip:\n got %s\nwant %s", name, got, c.raw)
		}
	}
}

func TestDiscovery(t *testing.T) {
	const doc = `{"provider":"https://agent.warden.cloud","protocols":["nethernet-external-signaling-v1"],"signatures":["nxs-es384-v1"],` +
		`"authorization":{"schemes":["anonymous-proof-of-work","bearer-token"]},"limits":{"heartbeatIntervalMs":10000},` +
		`"extensions":{"dev.opencollab.nxs.connectivity":{"version":1,"critical":false,"data":{"stunServers":[{"host":"stun.cloudflare.com","port":3478}]}},` +
		`"dev.opencollab.nxs.websocket":{"version":1,"critical":false,"data":{}},"com.example.future":{"version":3,"critical":false,"data":{"x":1}}},"unknown":true}`
	var d discovery
	if err := json.Unmarshal([]byte(doc), &d); err != nil {
		t.Fatal(err)
	}
	for _, scheme := range []string{schemeAnonymous, schemeBearer} {
		if err := d.validate("https://agent.warden.cloud", scheme); err != nil {
			t.Errorf("%s: %v", scheme, err)
		}
	}
	if got := d.stunServers(); len(got) != 1 || got[0] != "stun.cloudflare.com:3478" {
		t.Errorf("stun servers: %v", got)
	}
	if d.validate("https://other.example", schemeBearer) == nil {
		t.Error("discovery for another provider accepted")
	}
	d.Extensions["com.example.required"] = extension{Version: 1, Critical: true}
	if d.validate("https://agent.warden.cloud", schemeBearer) == nil {
		t.Error("unsupported critical extension accepted")
	}
}

func TestSign(t *testing.T) {
	key, err := generateMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(key, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicJWK(&key.PublicKey).publicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !verify(pub, []byte("payload"), sig) || verify(pub, []byte("other"), sig) {
		t.Fatal("signature verification mismatch")
	}
	encoded, err := encodePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePrivateKey(encoded)
	if err != nil || !decoded.Equal(key) {
		t.Fatalf("private key round trip: %v", err)
	}
}

func TestProofOfWork(t *testing.T) {
	f := loadNXSFixture(t)
	c := f.Challenge
	c.Pow.Difficulty = 12
	nonce, err := c.solve("intent", func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	p, _ := c.proof(nonce, "intent")
	if leadingZeroBits(sha256.Sum256(p)) < 12 {
		t.Fatal("proof does not meet difficulty")
	}
}

func TestNormalizeOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://Provider.Example":       "https://provider.example",
		"https://provider.example:443":   "https://provider.example",
		"https://provider.example:8443/": "https://provider.example:8443",
		"http://127.0.0.1:8080":          "http://127.0.0.1:8080",
		"http://[::1]:80":                "http://[::1]",
	} {
		if got, err := normalizeOrigin(in); err != nil || got != want {
			t.Errorf("normalizeOrigin(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"http://provider.example", "https://user@provider.example", "https://provider.example/path", "https://provider.example?q", "ftp://provider.example"} {
		if _, err := normalizeOrigin(in); err == nil {
			t.Errorf("normalizeOrigin(%q) should fail", in)
		}
	}
}

func TestParsePong(t *testing.T) {
	s, ok := parsePong([]byte("MCPE;My Server;1000;1.26.0;3;20;123;world;Creative;1;19132;19132;0;0;"))
	if !ok || s.Name != "My Server" || s.Level != "world" || s.MaxPlayerCount != 20 || s.GameType != 1 {
		t.Fatalf("unexpected status %+v", s)
	}
}
