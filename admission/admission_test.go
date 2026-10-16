package admission

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	Context struct {
		KeyID, Secret, Audience string
	}
	Claims struct {
		ExpiresAt            int64
		ClientFingerprintHex string
		ClientIcePwd         string
		ClientSctpPort       uint16
		ClientMaxMessageSize uint32
		NetworkID            string `json:"networkId"`
		IdentityBindingHex   string
	}
	ClientIceUfrag string
	NonceHex       string
	Expected       struct {
		LocalUfrag, IcePwd string
		UfragLength        int
	}
	Identity struct {
		PublicKeyJwk struct{ X, Y string }
		CanonicalCpk string
	}
}

func loadFixture(t testing.TB) (fixture, Key, Claims) {
	t.Helper()
	b, err := os.ReadFile("testdata/stateless-admission-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	c := Claims{
		ExpiresAt:      time.UnixMilli(f.Claims.ExpiresAt),
		SCTPPort:       f.Claims.ClientSctpPort,
		MaxMessageSize: f.Claims.ClientMaxMessageSize,
		Password:       f.Claims.ClientIcePwd,
	}
	c.NetworkID, _ = strconv.ParseUint(f.Claims.NetworkID, 10, 64)
	fp, _ := hex.DecodeString(f.Claims.ClientFingerprintHex)
	copy(c.Fingerprint[:], fp)
	binding, _ := hex.DecodeString(f.Claims.IdentityBindingHex)
	copy(c.IdentityBinding[:], binding)
	return f, Key{ID: f.Context.KeyID, Secret: f.Context.Secret}, c
}

func TestFixture(t *testing.T) {
	f, key, claims := loadFixture(t)
	var nonce [12]byte
	n, _ := hex.DecodeString(f.NonceHex)
	copy(nonce[:], n)

	token, err := key.Seal(f.Context.Audience, f.ClientIceUfrag, claims, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if token != f.Expected.LocalUfrag || len(token) != f.Expected.UfragLength {
		t.Fatalf("token mismatch:\n got %s\nwant %s", token, f.Expected.LocalUfrag)
	}
	if pwd := key.ICEPassword(f.Context.Audience, token); pwd != f.Expected.IcePwd {
		t.Fatalf("ICE password mismatch: got %s, want %s", pwd, f.Expected.IcePwd)
	}

	opened, err := key.Open(f.Context.Audience, token, f.ClientIceUfrag)
	if err != nil {
		t.Fatal(err)
	}
	if !opened.ExpiresAt.Equal(claims.ExpiresAt) || opened != (Claims{ExpiresAt: opened.ExpiresAt, Fingerprint: claims.Fingerprint,
		SCTPPort: claims.SCTPPort, MaxMessageSize: claims.MaxMessageSize, IdentityBinding: claims.IdentityBinding,
		NetworkID: claims.NetworkID, Password: claims.Password}) {
		t.Fatalf("claims mismatch: %+v", opened)
	}

	x, _ := base64.RawURLEncoding.DecodeString(f.Identity.PublicKeyJwk.X)
	y, _ := base64.RawURLEncoding.DecodeString(f.Identity.PublicKeyJwk.Y)
	pub := &ecdsa.PublicKey{Curve: elliptic.P384(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	cpk, err := CanonicalPublicKey(pub)
	if err != nil || cpk != f.Identity.CanonicalCpk {
		t.Fatalf("canonical key mismatch: %s, %v", cpk, err)
	}
	if !key.VerifyBinding(f.Context.Audience, pub, opened.IdentityBinding) {
		t.Fatal("identity binding did not verify")
	}
}

func TestRejections(t *testing.T) {
	f, key, _ := loadFixture(t)
	token := f.Expected.LocalUfrag
	tampered := []byte(token)
	tampered[20] ^= 1

	cases := map[string]struct {
		key                     Key
		audience, token, client string
	}{
		"tampered-ciphertext":       {key, f.Context.Audience, string(tampered), f.ClientIceUfrag},
		"wrong-host":                {key, "nxs-stateless-host-v1/ffffffffffffffffffffffffffffffff", token, f.ClientIceUfrag},
		"wrong-profile-incarnation": {key, Audience("0123456789abcdef0123456789abcdee"), token, f.ClientIceUfrag},
		"wrong-key":                 {Key{ID: key.ID, Secret: key.Secret + "x"}, f.Context.Audience, token, f.ClientIceUfrag},
		"wrong-key-id":              {Key{ID: "K002", Secret: key.Secret}, f.Context.Audience, token, f.ClientIceUfrag},
		"wrong-client-ufrag":        {key, f.Context.Audience, token, "otherClientUfrag"},
		"noncanonical-base64":       {key, f.Context.Audience, token[:len(token)-1] + "r", f.ClientIceUfrag},
		"padding":                   {key, f.Context.Audience, token + "=", f.ClientIceUfrag},
	}
	for name, c := range cases {
		if _, err := c.key.Open(c.audience, c.token, c.client); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
}

func TestDiagnosticRejected(t *testing.T) {
	f, key, claims := loadFixture(t)
	claims.NetworkID = 0
	if _, err := key.Seal(f.Context.Audience, f.ClientIceUfrag, claims, [12]byte{}); err == nil {
		t.Fatal("expected Seal to refuse network ID zero")
	}
}

func TestExpiryAndBudget(t *testing.T) {
	f, key, claims := loadFixture(t)
	claims.Password = strings.Repeat("a", 92)
	if _, err := key.Seal(f.Context.Audience, f.ClientIceUfrag, claims, [12]byte{}); err == nil {
		t.Fatal("expected Seal to refuse a password over budget")
	}
	claims.Password = f.Claims.ClientIcePwd
	claims.ExpiresAt = time.Unix(0, 0)
	if _, err := key.Seal(f.Context.Audience, f.ClientIceUfrag, claims, [12]byte{}); err == nil {
		t.Fatal("expected Seal to refuse a zero expiry")
	}
}

func TestKeySecretFormat(t *testing.T) {
	_, key, _ := loadFixture(t)
	if !key.Valid() {
		t.Fatal("fixture key rejected")
	}
	for _, secret := range []string{
		"stateless-fixture-secret-32-bytes-minimum",
		key.Secret + "A",
		key.Secret[:42] + "B",
		strings.Replace(key.Secret, "A", "+", 1),
	} {
		if (Key{ID: key.ID, Secret: secret}).Valid() {
			t.Errorf("secret %q accepted", secret)
		}
	}
}

func FuzzOpen(f *testing.F) {
	fx, key, _ := loadFixture(f)
	f.Add(fx.Expected.LocalUfrag, fx.ClientIceUfrag)
	f.Fuzz(func(t *testing.T, token, ufrag string) {
		if c, err := key.Open(fx.Context.Audience, token, ufrag); err == nil && !c.valid() {
			t.Fatal("Open returned invalid claims")
		}
	})
}
