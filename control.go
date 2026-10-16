package nxs

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// signed performs an operation signed with the machine key. opMu must be held.
func (p *Provider) signed(ctx context.Context, op string, body, v any, attempts int, timeout time.Duration) error {
	return p.signedRequest(ctx, http.MethodPost, opURL(p.origin, op), p.ws.carrier(op), body, v, attempts, timeout, randomID())
}

// signedRequest performs a request signed with the machine key. opMu must be held.
func (p *Provider) signedRequest(ctx context.Context, method, u string, carrier func(context.Context, http.Header, []byte) (int, http.Header, []byte, error), body, v any, attempts int, timeout time.Duration, idempotencyKey string) error {
	if p.st.Registration == nil {
		return errUnregistered
	}
	var b []byte
	if body != nil {
		var err error
		if b, err = marshal(body); err != nil {
			return err
		}
	}
	// The sequence number must be saved before it is used.
	p.st.Sequence++
	if err := p.store.save(p.st); err != nil {
		return err
	}
	reg, gen, seq, key := p.st.Registration, p.st.Generation, p.st.Sequence, p.key
	err := p.client.do(ctx, request{
		method:   method,
		url:      u,
		body:     b,
		attempts: attempts,
		timeout:  timeout,
		carrier:  carrier,
		sign: func(h http.Header, path string) error {
			return signHeaders(h, p.origin, method, path, reg, key, idempotencyKey, gen, seq, b)
		},
	}, v)
	if hasCode(err, codeGenerationFenced) {
		p.fence()
	}
	return err
}

// ErrReplaced is the cause of the canceled context of a Provider that stopped because another
// process took over its registration.
var ErrReplaced = errors.New("nxs: another process took over the registration")

// fence stops a Provider whose registration another process took over, without draining or
// deregistering the registration, which now belongs to that process. opMu must be held.
func (p *Provider) fence() {
	if p.fenced.Swap(true) {
		return
	}
	p.log.Error("another process took over this registration, stopping")
	p.authority.Store(nil)
	p.host.stop()
	p.cancel(ErrReplaced)
}

// upgradeHeaders returns the signed headers of a WebSocket upgrade. opMu must be held.
func (p *Provider) upgradeHeaders(rawURL string) (http.Header, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	if err := signHeaders(h, p.origin, http.MethodGet, u.EscapedPath(), p.st.Registration, p.key, randomID(), p.st.Generation, p.st.Sequence, nil); err != nil {
		return nil, err
	}
	if p.assisting() {
		h.Set("nxs-assisted", "1")
	}
	return h, nil
}

// signHeaders adds the machine signature headers of a request.
func signHeaders(h http.Header, origin, method, path string, reg *registration, key *ecdsa.PrivateKey, idempotencyKey string, gen, seq int64, body []byte) error {
	ts := time.Now().UnixMilli()
	payload, err := requestPayload(origin, method, path, ts, reg.InstanceID, reg.KeyID, idempotencyKey, gen, seq, body)
	if err != nil {
		return err
	}
	sig, err := sign(key, payload)
	if err != nil {
		return err
	}
	for k, v := range map[string]string{
		"nxs-instance-id":       reg.InstanceID,
		"nxs-key-id":            reg.KeyID,
		"nxs-timestamp":         fmt.Sprint(ts),
		"nxs-signature-version": SignatureVersion,
		"nxs-generation":        fmt.Sprint(gen),
		"nxs-sequence":          fmt.Sprint(seq),
		"nxs-signature":         sig,
		"idempotency-key":       idempotencyKey,
	} {
		h.Set(k, v)
	}
	return nil
}

const (
	codeRecoveryRequired    = "recovery_required"
	codeRecoveryUnavailable = "recovery_unavailable"
	codeGenerationFenced    = "generation_fenced"
)

// hasCode reports whether err is a provider error with the code.
func hasCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// errUnregistered is returned for operations while the instance has no registration.
var errUnregistered = errors.New("nxs: not registered with the provider")

// recoverable reports whether err suggests the registration must be resumed in a new
// generation, or registered again. A generation fenced by another process is never recovered.
func recoverable(err error) bool {
	if errors.Is(err, errUnregistered) {
		return true
	}
	var e *Error
	if !errors.As(err, &e) || e.Code == codeGenerationFenced {
		return false
	}
	return e.Status == http.StatusUnauthorized || e.Code == codeRecoveryRequired
}

// recoverSession resumes the registration in a new generation after it was fenced. opMu
// must be held.
func (p *Provider) recoverSession(ctx context.Context) error {
	if time.Since(p.lastRecovery) < 30*time.Second {
		return errors.New("nxs: recovery attempted recently")
	}
	p.lastRecovery = time.Now()
	err := errNothingToRecover
	if p.st.Registration != nil {
		err = p.recover(ctx, p.st.Registration.RegistrationID, p.thumbprint(), false)
	}
	if errors.Is(err, errNothingToRecover) {
		err = nil
		if p.st.Registration != nil {
			p.log.Warn("provider no longer holds this registration, registering as a new instance")
			err = p.resetState()
		}
		if err == nil {
			err = p.register(ctx)
		}
		p.host.setKeys(p.st.keys())
		if err == nil {
			p.log.Info("registered with provider", "instance", p.st.Registration.InstanceID, "publicAddress", p.st.Registration.PublicAddress)
		}
	}
	if err != nil {
		return fmt.Errorf("nxs: recover registration: %w", err)
	}
	if err := p.startGeneration(); err != nil {
		return err
	}
	p.host.setDiagnostics(nil)
	p.log.Info("recovered registration in a new generation", "generation", p.st.Generation)
	return nil
}
