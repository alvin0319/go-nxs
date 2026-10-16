package nxs

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/df-mc/go-nxs/admission"
)

// unsigned performs an enrollment operation, which is not signed with the machine key.
func (p *Provider) unsigned(ctx context.Context, op string, body any, bearer string, v any) error {
	b, err := marshal(body)
	if err != nil {
		return err
	}
	return p.client.do(ctx, request{method: http.MethodPost, url: opURL(p.origin, op), body: b, bearer: bearer}, v)
}

// errNothingToRecover is returned by recover if the provider holds nothing to recover.
var errNothingToRecover = errors.New("nxs: provider holds nothing to recover")

// register obtains a registration, recovering the saved one if present. opMu must be held, or
// the Provider not yet running.
func (p *Provider) register(ctx context.Context) error {
	if p.st.Registration != nil {
		err := p.recover(ctx, p.st.Registration.RegistrationID, p.thumbprint(), false)
		if !errors.Is(err, errNothingToRecover) {
			return err
		}
		p.log.Warn("provider no longer holds the saved registration, registering as a new instance", "registrationId", p.st.Registration.RegistrationID)
		if err := p.resetState(); err != nil {
			return err
		}
	}
	if c := p.st.Challenge; c != nil {
		// The completion of this challenge may have been lost.
		err := p.recover(ctx, c.ChallengeID, p.thumbprint(), true)
		if !errors.Is(err, errNothingToRecover) {
			return err
		}
		if time.Now().UnixMilli() < c.ExpiresAt {
			return p.enroll(ctx, c, p.thumbprint())
		}
		p.st.Challenge = nil
	}
	return p.enroll(ctx, nil, p.thumbprint())
}

func (p *Provider) thumbprint() string { return publicJWK(&p.key.PublicKey).thumbprint() }

// resetState replaces the state of a registration the provider no longer holds, as a new
// logical instance needs a fresh machine key and must not report the outcomes of the old one.
// opMu must be held, or the Provider not yet running.
func (p *Provider) resetState() error {
	key, err := generateMachineKey()
	if err != nil {
		return err
	}
	encoded, err := encodePrivateKey(key)
	if err != nil {
		return err
	}
	*p.st = state{Version: stateVersion, Provider: p.origin, PrivateKey: encoded}
	p.key = key
	p.mu.Lock()
	p.events = nil
	p.mu.Unlock()
	return p.store.save(p.st)
}

func (p *Provider) enroll(ctx context.Context, c *challenge, thumbprint string) error {
	bearer := p.conf.Token != ""
	if c == nil {
		pub := publicJWK(&p.key.PublicKey)
		c = &challenge{}
		if err := p.unsigned(ctx, "register", registerRequest{
			Protocol:     Protocol,
			PublicKeyJWK: &pub,
			Label:        p.conf.Label,
		}, p.conf.Token, c); err != nil {
			return fmt.Errorf("nxs: register: %w", err)
		}
		p.st.Challenge = c
		if err := p.store.save(p.st); err != nil {
			return err
		}
	}
	if err := checkChallenge(c, p.origin, thumbprint, bearer); err != nil {
		return err
	}

	idempotencyKey := randomID()
	nonce, err := c.solve(idempotencyKey, func() bool { return time.Now().UnixMilli() >= c.ExpiresAt })
	if err != nil {
		return err
	}
	reg, err := p.complete(ctx, c, p.key, nonce, idempotencyKey)
	if hasCode(err, codeRecoveryRequired) {
		// The completion was committed, but its reply was lost.
		rerr := p.recover(ctx, c.ChallengeID, thumbprint, true)
		if !errors.Is(rerr, errNothingToRecover) {
			return rerr
		}
		// The challenge was consumed without a recoverable registration, so the next start
		// registers afresh.
		p.st.Challenge = nil
		if serr := p.store.save(p.st); serr != nil {
			return serr
		}
		return err
	}
	if err != nil {
		return err
	}
	p.st.TicketKeys, p.st.KeyRequestID = nil, ""
	if k := reg.AdmissionKey; k != nil {
		if !(admission.Key{ID: k.KeyID, Secret: k.Secret}).Valid() {
			return errors.New("nxs: invalid admission key in registration")
		}
		p.st.TicketKeys = []ticketKey{{KeyID: k.KeyID, Secret: k.Secret}}
	}
	p.showOperatorAction(reg.OperatorAction)
	reg.AdmissionKey, reg.OperatorAction = nil, nil
	p.st.Registration, p.st.Challenge = reg, nil
	return p.store.save(p.st)
}

// checkChallenge checks that an enrollment challenge is bound to the host and selects a mode
// the host can use.
func checkChallenge(c *challenge, origin, thumbprint string, bearer bool) error {
	if err := c.validate(origin, thumbprint); err != nil {
		return err
	}
	if c.ExpiresAt <= time.Now().UnixMilli() {
		return errors.New("nxs: registration challenge expired")
	}
	switch mode := c.Context.Mode; {
	case mode == modeNewService:
	case mode == modeAttachInstance && bearer:
	default:
		return fmt.Errorf("nxs: challenge selected unexpected mode %q", mode)
	}
	if bearer {
		if a := c.Authorization; a == nil || a.Scheme != schemeBearer || a.Reference == "" || a.Reference != c.Context.AuthorizationID || c.Pow.Difficulty != 0 {
			return errors.New("nxs: challenge does not reflect bearer authorization")
		}
	} else if c.Context.AuthorizationID != "" {
		return errors.New("nxs: anonymous challenge carries an authorization")
	}
	return nil
}

// recover proves ownership of the machine key to resume a registration in a new generation.
// If byChallenge is set, id is the challenge ID of an enrollment whose completion was lost,
// and the registration ID is adopted from the recovery challenge. It returns
// errNothingToRecover if the provider holds nothing to recover.
func (p *Provider) recover(ctx context.Context, id, thumbprint string, byChallenge bool) error {
	err := p.recoverOnce(ctx, id, thumbprint, byChallenge)
	if hasCode(err, codeRecoveryRequired) {
		// The completion of the recovery itself was committed but its reply was lost, which a
		// fresh challenge resolves.
		err = p.recoverOnce(ctx, id, thumbprint, byChallenge)
	}
	return err
}

func (p *Provider) recoverOnce(ctx context.Context, id, thumbprint string, byChallenge bool) error {
	c := &challenge{}
	if err := p.unsigned(ctx, "register", registerRequest{Protocol: Protocol, RegistrationID: id}, "", c); err != nil {
		if hasCode(err, codeRecoveryUnavailable) {
			return errNothingToRecover
		}
		return fmt.Errorf("nxs: recover: %w", err)
	}
	// A rotation may have been interrupted after the provider installed the pending key.
	key, pending := p.key, false
	if p.st.PendingPrivateKey != "" {
		if k, err := decodePrivateKey(p.st.PendingPrivateKey); err == nil && publicJWK(&k.PublicKey).thumbprint() == c.Thumbprint {
			key, thumbprint, pending = k, c.Thumbprint, true
		}
	}
	if err := c.validate(p.origin, thumbprint); err != nil {
		return err
	}
	registrationID := c.Context.RegistrationID
	if c.Context.Mode != modeRecover || registrationID == "" || (!byChallenge && registrationID != id) || c.Pow.Difficulty != 0 || c.ExpiresAt <= time.Now().UnixMilli() {
		return errors.New("nxs: unbound recovery challenge")
	}
	reg, err := p.complete(ctx, c, key, "0", randomID())
	if err != nil {
		return err
	}
	if reg.RegistrationID != registrationID || (p.st.Registration != nil && reg.InstanceID != p.st.Registration.InstanceID) {
		return errors.New("nxs: recovered registration identity changed")
	}
	// One-time secrets are only accepted from a fresh enrollment, and recovery never returns
	// an operator action.
	reg.AdmissionKey, reg.OperatorAction = nil, nil
	p.st.Registration, p.st.Challenge = reg, nil
	if pending {
		p.st.PrivateKey, p.st.PendingPrivateKey, p.key = p.st.PendingPrivateKey, "", key
	}
	return p.store.save(p.st)
}

func (p *Provider) complete(ctx context.Context, c *challenge, key *ecdsa.PrivateKey, nonce, idempotencyKey string) (*registration, error) {
	proof, err := c.proof(nonce, idempotencyKey)
	if err != nil {
		return nil, err
	}
	sig, err := sign(key, proof)
	if err != nil {
		return nil, err
	}
	reg := &registration{}
	if err := p.unsigned(ctx, "complete", completeRequest{
		Protocol:       Protocol,
		ChallengeID:    c.ChallengeID,
		ProofNonce:     nonce,
		IdempotencyKey: idempotencyKey,
		Signature:      sig,
	}, "", reg); err != nil {
		return nil, fmt.Errorf("nxs: complete: %w", err)
	}
	if err := reg.validate(p.origin); err != nil {
		return nil, err
	}
	return reg, nil
}
