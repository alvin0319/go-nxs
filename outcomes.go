package nxs

import (
	"context"
	"errors"
	"slices"
	"time"
)

// maxEvents bounds the queued outcome observations.
const maxEvents = 1000

// record queues an outcome observation.
func (p *Provider) record(e event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.events) < maxEvents {
		p.events = append(p.events, e)
	}
}

// flush reports up to 100 queued outcome observations.
func (p *Provider) flush(ctx context.Context) error {
	p.mu.Lock()
	batch := slices.Clone(p.events[:min(len(p.events), 100)])
	pending := slices.Clone(p.events)
	p.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	if !p.disc.connectivity() {
		for i := range batch {
			batch[i].RemoteAddress, batch[i].RemotePort = "", 0
		}
	}
	p.opMu.Lock()
	defer p.opMu.Unlock()
	p.st.PendingEvents = pending
	if err := p.signed(ctx, "outcomes", map[string]any{"events": batch}, nil, 1, 3*time.Second); err != nil {
		var e *Error
		if !errors.As(err, &e) || e.Status < 400 || e.Status > 499 || e.retryable() || p.fenced.Load() {
			return err
		}
		// The provider permanently rejected the batch, so retrying it can never succeed.
		p.log.Debug("provider rejected outcome reports", "error", err, "events", len(batch))
	}
	p.mu.Lock()
	p.events = p.events[len(batch):]
	p.st.PendingEvents = slices.Clone(p.events)
	p.mu.Unlock()
	return nil
}
