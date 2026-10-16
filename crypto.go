package nxs

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"math/bits"

	"github.com/df-mc/go-nxs/internal/canon"
)

const (
	// Protocol is the NXS protocol identifier.
	Protocol = "nethernet-external-signaling-v1"
	// SignatureVersion is the machine request signature identifier.
	SignatureVersion = "nxs-es384-v1"
	// Capability is the stateless admission capability published in host profiles.
	Capability = "nethernet.stateless-admission.v1"
)

var b64 = base64.RawURLEncoding

// jwk is a public P-384 key in JWK form. Its members are in thumbprint order.
type jwk struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func publicJWK(pub *ecdsa.PublicKey) jwk {
	return jwk{Crv: "P-384", Kty: "EC", X: b64.EncodeToString(pub.X.FillBytes(make([]byte, 48))), Y: b64.EncodeToString(pub.Y.FillBytes(make([]byte, 48)))}
}

func (k jwk) publicKey() (*ecdsa.PublicKey, error) {
	x, errX := decodeB64(k.X)
	y, errY := decodeB64(k.Y)
	if k.Crv != "P-384" || k.Kty != "EC" || errX != nil || errY != nil || len(x) != 48 || len(y) != 48 {
		return nil, errors.New("nxs: invalid P-384 JWK")
	}
	if _, err := ecdh.P384().NewPublicKey(append(append([]byte{4}, x...), y...)); err != nil {
		return nil, errors.New("nxs: JWK point is not on P-384")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P384(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

// thumbprint returns the RFC 7638 thumbprint of the key.
func (k jwk) thumbprint() string {
	sum := sha256.Sum256([]byte(`{"crv":"` + k.Crv + `","kty":"` + k.Kty + `","x":"` + k.X + `","y":"` + k.Y + `"}`))
	return b64.EncodeToString(sum[:])
}

func generateMachineKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func encodePrivateKey(key *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(der), nil
}

func decodePrivateKey(s string) (*ecdsa.PrivateKey, error) {
	der, err := decodeB64(s)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P384() {
		return nil, errors.New("nxs: machine key is not P-384")
	}
	return ec, nil
}

// sign returns the unpadded base64url ES384 signature of payload in IEEE P1363 form.
func sign(key *ecdsa.PrivateKey, payload []byte) (string, error) {
	sum := sha512.Sum384(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	s.FillBytes(sig[48:])
	return b64.EncodeToString(sig), nil
}

func verify(pub *ecdsa.PublicKey, payload []byte, signature string) bool {
	sig, err := decodeB64(signature)
	if err != nil || len(sig) != 96 {
		return false
	}
	sum := sha512.Sum384(payload)
	return ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:48]), new(big.Int).SetBytes(sig[48:]))
}

// decodeB64 decodes canonical unpadded base64url.
func decodeB64(s string) ([]byte, error) {
	b, err := b64.Strict().DecodeString(s)
	if err != nil || b64.EncodeToString(b) != s {
		return nil, errors.New("nxs: noncanonical base64url")
	}
	return b, nil
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return b64.EncodeToString(sum[:])
}

// challengeContext is the registration context bound into a challenge.
type challengeContext struct {
	Mode            string `json:"mode"`
	Label           string `json:"label"`
	AuthorizationID string `json:"authorizationId"`
	ServiceID       string `json:"serviceId"`
	RegistrationID  string `json:"registrationId"`
}

func (c challengeContext) digest() (string, error) {
	b, err := canon.Array(c.Mode, c.Label, c.AuthorizationID, c.ServiceID, c.RegistrationID)
	if err != nil {
		return "", err
	}
	return digest(b), nil
}

// proof returns the completion proof bytes of a challenge.
func (c *challenge) proof(proofNonce, idempotencyKey string) ([]byte, error) {
	return canon.Array(Protocol, "complete", c.Audience, c.ChallengeID, c.Nonce, c.Thumbprint, c.ContextDigest, c.ExpiresAt, proofNonce, idempotencyKey)
}

// solve finds a proof nonce meeting the challenge difficulty.
func (c *challenge) solve(idempotencyKey string, deadline func() bool) (string, error) {
	for i := uint64(0); ; i++ {
		if i%4096 == 0 && deadline() {
			return "", errors.New("nxs: challenge expired before proof of work completed")
		}
		nonce := fmt.Sprint(i)
		p, err := c.proof(nonce, idempotencyKey)
		if err != nil {
			return "", err
		}
		if leadingZeroBits(sha256.Sum256(p)) >= c.Pow.Difficulty {
			return nonce, nil
		}
	}
}

func leadingZeroBits(sum [32]byte) int {
	n := 0
	for _, b := range sum {
		if b != 0 {
			return n + bits.LeadingZeros8(b)
		}
		n += 8
	}
	return n
}

// requestPayload returns the bytes signed for an operational request.
func requestPayload(audience, method, path string, timestamp int64, instanceID, keyID, idempotencyKey string, generation, sequence int64, body []byte) ([]byte, error) {
	return canon.Array(Protocol, SignatureVersion, audience, method, path, timestamp, instanceID, keyID, idempotencyKey, generation, sequence, digest(body))
}
