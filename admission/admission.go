// Package admission implements the NXS1 stateless admission carrier. A provider seals
// the client's transport parameters into the ICE ufrag of its SDP answer, and the host
// opens it from the client's first STUN binding request.
package admission

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"
)

const (
	// Prefix is the prefix of every NXS1 ufrag.
	Prefix = "NXS1"
	// MaxTTL is the maximum lifetime of a token.
	MaxTTL = 120 * time.Second
	// MaxUfragLength is the maximum length of a token.
	MaxUfragLength = 256
)

// ErrInvalid is returned for any token that fails validation.
var ErrInvalid = errors.New("nxs/admission: invalid token")

var (
	keyIDPattern    = regexp.MustCompile(`^[A-Z0-9]{4}$`)
	tokenPattern    = regexp.MustCompile(`^NXS1[A-Z0-9]{4}[A-Za-z0-9+/]+$`)
	diagPwdPattern  = regexp.MustCompile(`^[A-Za-z0-9+/]{22,30}$`)
	ufragPattern    = regexp.MustCompile(`^[A-Za-z0-9+/]{4,256}$`)
	passwordPattern = regexp.MustCompile(`^[A-Za-z0-9+/]{22,91}$`)
)

const (
	nonceSize       = 12
	tagSize         = 16
	fixedPlaintext  = 67
	diagnosticBytes = 59
	maxPassword     = 91
	minPassword     = 22
)

// Key is an admission key epoch shared between the host and the provider.
type Key struct {
	// ID is the four-character epoch ID.
	ID string
	// Secret is 32 random bytes in 43 characters of unpadded base64url. Derivations use the
	// ASCII bytes of this string, not its decoding.
	Secret string
	// NotBefore and RetireAfter bound the use of the key. Zero values are unbounded.
	NotBefore, RetireAfter time.Time
}

// Valid reports whether k is well-formed.
func (k Key) Valid() bool {
	if !keyIDPattern.MatchString(k.ID) || len(k.Secret) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(k.Secret)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == k.Secret
}

// Usable reports whether k may admit tokens at t.
func (k Key) Usable(t time.Time) bool {
	return (k.NotBefore.IsZero() || !t.Before(k.NotBefore)) && (k.RetireAfter.IsZero() || t.Before(k.RetireAfter))
}

// Claims are the client parameters sealed into a token.
type Claims struct {
	ExpiresAt       time.Time
	Fingerprint     [32]byte
	SCTPPort        uint16
	MaxMessageSize  uint32
	IdentityBinding [16]byte
	// NetworkID is the NetherNet network ID of the client. It is zero for diagnostics.
	NetworkID uint64
	// Password is the client's ICE password.
	Password string
	// Diagnostic is the diagnostic extension, present only if NetworkID is zero. The
	// IdentityBinding then holds the attempt ID.
	Diagnostic *Diagnostic
}

func (c Claims) valid() bool {
	if c.ExpiresAt.Unix() < 1 || c.ExpiresAt.Unix() > 0xffffffff || c.SCTPPort == 0 ||
		c.MaxMessageSize < 1 || c.MaxMessageSize > 262144 || !passwordPattern.MatchString(c.Password) {
		return false
	}
	if c.NetworkID == 0 {
		return c.Diagnostic != nil && c.Diagnostic.valid() && diagPwdPattern.MatchString(c.Password)
	}
	return c.Diagnostic == nil
}

// Audience returns the audience of a host endpoint incarnation.
func Audience(incarnation string) string {
	return "nxs-stateless-host-v1/" + incarnation
}

// KeyID returns the key epoch ID of a token.
func KeyID(token string) (string, bool) {
	if len(token) < 8 || token[:4] != Prefix {
		return "", false
	}
	return token[4:8], true
}

// Open authenticates and decodes a token received with the client's ufrag. It does not
// check the expiry.
func (k Key) Open(audience, token, clientUfrag string) (Claims, error) {
	if len(token) > MaxUfragLength || !tokenPattern.MatchString(token) || token[4:8] != k.ID {
		return Claims{}, ErrInvalid
	}
	encoded := token[8:]
	envelope, err := base64.RawStdEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawStdEncoding.EncodeToString(envelope) != encoded ||
		len(envelope) < nonceSize+fixedPlaintext+minPassword+tagSize ||
		len(envelope) > nonceSize+fixedPlaintext+maxPassword+diagnosticBytes+tagSize {
		return Claims{}, ErrInvalid
	}
	aad, err := additionalData(token[:8], audience, clientUfrag)
	if err != nil {
		return Claims{}, err
	}
	aead, err := k.aead(audience)
	if err != nil {
		return Claims{}, err
	}
	plain, err := aead.Open(nil, envelope[:nonceSize], envelope[nonceSize:], aad)
	if err != nil || len(plain) < fixedPlaintext+minPassword {
		return Claims{}, ErrInvalid
	}

	var c Claims
	c.ExpiresAt = time.Unix(int64(binary.BigEndian.Uint32(plain[0:4])), 0)
	copy(c.Fingerprint[:], plain[4:36])
	c.SCTPPort = binary.BigEndian.Uint16(plain[36:38])
	c.MaxMessageSize = binary.BigEndian.Uint32(plain[38:42])
	copy(c.IdentityBinding[:], plain[42:58])
	c.NetworkID = binary.BigEndian.Uint64(plain[58:66])
	n := int(plain[66])
	if fixedPlaintext+n > len(plain) {
		return Claims{}, ErrInvalid
	}
	c.Password = string(plain[fixedPlaintext : fixedPlaintext+n])
	if trailing := plain[fixedPlaintext+n:]; c.NetworkID == 0 {
		if c.Diagnostic, err = decodeDiagnostic(trailing); err != nil {
			return Claims{}, err
		}
	} else if len(trailing) != 0 {
		return Claims{}, ErrInvalid
	}
	if !c.valid() {
		return Claims{}, ErrInvalid
	}
	return c, nil
}

// Seal encodes the claims into a token for the client's ufrag, as a provider does.
func (k Key) Seal(audience, clientUfrag string, c Claims, nonce [nonceSize]byte) (string, error) {
	if !k.Valid() || !c.valid() || c.ExpiresAt.Nanosecond() != 0 {
		return "", ErrInvalid
	}
	header := Prefix + k.ID
	aad, err := additionalData(header, audience, clientUfrag)
	if err != nil {
		return "", err
	}
	aead, err := k.aead(audience)
	if err != nil {
		return "", err
	}
	plain := make([]byte, fixedPlaintext, fixedPlaintext+len(c.Password))
	binary.BigEndian.PutUint32(plain[0:4], uint32(c.ExpiresAt.Unix()))
	copy(plain[4:36], c.Fingerprint[:])
	binary.BigEndian.PutUint16(plain[36:38], c.SCTPPort)
	binary.BigEndian.PutUint32(plain[38:42], c.MaxMessageSize)
	copy(plain[42:58], c.IdentityBinding[:])
	binary.BigEndian.PutUint64(plain[58:66], c.NetworkID)
	plain[66] = byte(len(c.Password))
	plain = append(plain, c.Password...)
	if c.Diagnostic != nil {
		plain = append(plain, c.Diagnostic.encode()...)
	}

	envelope := aead.Seal(nonce[:], nonce[:], plain, aad)
	token := header + base64.RawStdEncoding.EncodeToString(envelope)
	if len(token) > MaxUfragLength {
		return "", ErrInvalid
	}
	return token, nil
}

// ICEPassword returns the host's ICE password for a token.
func (k Key) ICEPassword(audience, token string) string {
	mac := k.mac("nxs-stateless-ice-v1\x00" + audience + "\x00" + token)
	return base64.RawStdEncoding.EncodeToString(mac[:24])
}

// Binding returns the identity binding of a client identity key.
func (k Key) Binding(audience string, pub *ecdsa.PublicKey) ([16]byte, error) {
	var b [16]byte
	cpk, err := CanonicalPublicKey(pub)
	if err != nil {
		return b, err
	}
	copy(b[:], k.mac("nxs-identity-binding-v1\x00"+audience+"\x00"+cpk))
	return b, nil
}

// VerifyBinding reports whether pub matches the identity binding of a token.
func (k Key) VerifyBinding(audience string, pub *ecdsa.PublicKey, binding [16]byte) bool {
	b, err := k.Binding(audience, pub)
	return err == nil && hmac.Equal(b[:], binding[:])
}

// CanonicalPublicKey returns the standard base64 encoding of the SPKI DER of a P-384 key.
func CanonicalPublicKey(pub *ecdsa.PublicKey) (string, error) {
	if pub == nil || pub.Curve == nil || pub.Curve.Params().Name != "P-384" {
		return "", errors.New("nxs/admission: identity key must be P-384")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("nxs/admission: encode identity key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// TicketID returns the correlation ID of a token used in outcome reports.
func TicketID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:16])
}

func (k Key) mac(data string) []byte {
	h := hmac.New(sha256.New, []byte(k.Secret))
	h.Write([]byte(data))
	return h.Sum(nil)
}

func (k Key) aead(audience string) (cipher.AEAD, error) {
	if !k.Valid() {
		return nil, ErrInvalid
	}
	block, err := aes.NewCipher(k.mac("nxs-stateless-aead-v1\x00" + audience))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func additionalData(header, audience, clientUfrag string) ([]byte, error) {
	if audience == "" || len(audience) > 512 || !ufragPattern.MatchString(clientUfrag) {
		return nil, ErrInvalid
	}
	for i := 0; i < len(audience); i++ {
		if audience[i] == 0 {
			return nil, ErrInvalid
		}
	}
	return []byte("nxs-stateless-admission-v1\x00" + header + "\x00" + audience + "\x00" + clientUfrag), nil
}
