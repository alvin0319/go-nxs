package nxs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// OperatorAction is a link the provider offers to the operator of the host, such as one that
// takes ownership of a newly created service. The link may carry a one-time credential: show
// it to the operator, but never open, forward or save it.
type OperatorAction struct {
	// URL is the link for the operator.
	URL string
	// Text describes the link to the operator.
	Text string
	// ExpiresAt is when the link stops working.
	ExpiresAt time.Time
}

// RequestOperatorAction returns the latest operator link while it is valid, or requests a
// fresh one if the provider offered one in its latest heartbeat reply.
func (p *Provider) RequestOperatorAction(ctx context.Context) (*OperatorAction, error) {
	p.opMu.Lock()
	defer p.opMu.Unlock()
	if a := p.operatorAction; a != nil && time.Now().Before(a.ExpiresAt) {
		return &OperatorAction{URL: a.URL, Text: a.Text, ExpiresAt: a.ExpiresAt}, nil
	}
	p.operatorAction = nil
	if !p.operatorActionAvailable {
		return nil, errors.New("nxs: the provider offers no operator action")
	}
	var resp struct {
		OperatorAction *operatorAction `json:"operatorAction"`
	}
	// A retry with the same idempotency key never returns the link again, so a lost reply is
	// answered with a fresh request rather than a retry.
	if err := p.signedRequest(ctx, http.MethodPost, opURL(p.origin, "operator-action"), nil, struct{}{}, &resp, 1, 15*time.Second, randomID()); err != nil {
		return nil, fmt.Errorf("nxs: operator action: %w", err)
	}
	a := resp.OperatorAction
	if a == nil {
		return nil, errors.New("nxs: the provider issued no operator action")
	}
	if !validOperatorAction(a) {
		return nil, errors.New("nxs: invalid operator action")
	}
	p.operatorAction = &OperatorAction{URL: a.URL, Text: a.Text, ExpiresAt: time.UnixMilli(a.ExpiresAt)}
	return &OperatorAction{URL: a.URL, Text: a.Text, ExpiresAt: p.operatorAction.ExpiresAt}, nil
}

// showOperatorAction logs the operator link returned with a registration. opMu must be held,
// or the Provider not yet running.
func (p *Provider) showOperatorAction(a *operatorAction) {
	if a == nil || !validOperatorAction(a) {
		return
	}
	p.operatorAction = &OperatorAction{URL: a.URL, Text: a.Text, ExpiresAt: time.UnixMilli(a.ExpiresAt)}
	p.log.Info(a.Text, "url", a.URL, "expiresAt", p.operatorAction.ExpiresAt)
}

// validOperatorAction reports whether a is an unexpired link on HTTPS, or on HTTP to a loopback
// host.
func validOperatorAction(a *operatorAction) bool {
	if a.ExpiresAt <= time.Now().UnixMilli() || len(a.URL) > 2048 || a.Text == "" ||
		utf8.RuneCountInString(a.Text) > 256 || strings.ContainsFunc(a.Text, isControl) {
		return false
	}
	u, err := url.Parse(a.URL)
	if err != nil || u.User != nil || u.Host == "" {
		return false
	}
	_, err = normalizeOrigin(u.Scheme + "://" + u.Host)
	return err == nil
}
