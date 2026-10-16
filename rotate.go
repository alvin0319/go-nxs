package nxs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/df-mc/go-nxs/internal/canon"
)

// RotateMachineKey replaces the machine key that authenticates this instance, then retires
// the previous one. The replacement is saved before the provider is asked to install it.
func (p *Provider) RotateMachineKey(ctx context.Context) error {
	p.opMu.Lock()
	defer p.opMu.Unlock()
	next, err := generateMachineKey()
	if err != nil {
		return err
	}
	if p.st.PendingPrivateKey, err = encodePrivateKey(next); err != nil {
		return err
	}
	if err := p.store.save(p.st); err != nil {
		return err
	}
	pub := publicJWK(&next.PublicKey)
	oldKeyID, idempotencyKey := p.st.Registration.KeyID, randomID()
	proof, err := rotationProof(p.origin, p.st.Registration.InstanceID, oldKeyID, pub.thumbprint(), p.st.Generation, idempotencyKey)
	if err != nil {
		return err
	}
	sig, err := sign(next, proof)
	if err != nil {
		return err
	}
	var resp struct {
		KeyID string `json:"keyId"`
	}
	body := map[string]any{"publicKeyJwk": pub, "proof": sig}
	if err := p.signedRequest(ctx, http.MethodPost, opURL(p.origin, "rotate"), p.ws.carrier("rotate"), body, &resp, 3, 15*time.Second, idempotencyKey); err != nil {
		return fmt.Errorf("nxs: rotate machine key: %w", err)
	}
	if resp.KeyID == "" {
		return errors.New("nxs: rotate machine key: no key ID returned")
	}
	p.st.PrivateKey, p.st.PendingPrivateKey, p.key = p.st.PendingPrivateKey, "", next
	p.st.Registration.KeyID = resp.KeyID
	if err := p.store.save(p.st); err != nil {
		return err
	}
	// The previous key is retired with a request signed by its replacement.
	if err := p.signed(ctx, "retire", map[string]string{"keyId": oldKeyID}, nil, 3, 15*time.Second); err != nil {
		return fmt.Errorf("nxs: retire previous machine key: %w", err)
	}
	p.log.Info("rotated machine key", "keyID", resp.KeyID)
	return nil
}

// rotationProof returns the bytes the replacement machine key signs to prove its possession.
func rotationProof(audience, instanceID, oldKeyID, newThumbprint string, generation int64, idempotencyKey string) ([]byte, error) {
	return canon.Array(Protocol, "rotate", audience, instanceID, oldKeyID, newThumbprint, generation, idempotencyKey)
}

// ExtensionRequest performs an operation advertised by a provider extension in discovery,
// such as refreshing a claim link. It is signed with the machine key. The operation URL
// must be on the provider origin. body may be nil, and the response is decoded into v.
func (p *Provider) ExtensionRequest(ctx context.Context, namespace, operation, method string, body, v any) error {
	if method != http.MethodGet && method != http.MethodPost {
		return errors.New("nxs: unsupported extension method")
	}
	ext, ok := p.disc.Extensions[namespace]
	if !ok {
		return fmt.Errorf("nxs: extension %s not advertised", namespace)
	}
	var data struct {
		Operations map[string]string `json:"operations"`
	}
	if err := json.Unmarshal(ext.Data, &data); err != nil {
		return fmt.Errorf("nxs: decode extension %s: %w", namespace, err)
	}
	u, ok := data.Operations[operation]
	if !ok {
		return fmt.Errorf("nxs: extension %s has no operation %s", namespace, operation)
	}
	if _, err := operationURL(p.origin, u); err != nil {
		return fmt.Errorf("nxs: extension operation: %w", err)
	}
	p.opMu.Lock()
	defer p.opMu.Unlock()
	return p.signedRequest(ctx, method, u, nil, body, v, 3, 15*time.Second, randomID())
}
