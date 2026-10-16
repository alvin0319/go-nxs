package nxs

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"time"
)

const (
	// mappingLifetime is the lifetime published for a STUN mapping.
	mappingLifetime = 2 * time.Minute
	// refreshInterval keeps STUN mappings warm on the gameplay socket.
	refreshInterval = 25 * time.Second
)

// endpointState holds the candidates of the host and the connectivity feedback about them.
type endpointState struct {
	// all are every usable candidate, which remain diagnostic targets.
	all []candidate
	// published are the candidates offered to players.
	published []candidate
	revision  int64
	checks    map[checkKey]connectivityCheck
}

type checkKey struct {
	region, method string
	target         netip.AddrPort
}

type connectivityCheck struct {
	Region    string `json:"region"`
	Family    int    `json:"family"`
	Method    string `json:"method,omitempty"`
	Outcome   string `json:"outcome"`
	CheckedAt int64  `json:"checkedAt"`
	ExpiresAt int64  `json:"expiresAt"`
	Target    *struct {
		Address string `json:"address"`
		Port    uint16 `json:"port"`
	} `json:"target,omitempty"`
}

// method returns the method summarizing how the candidates were found.
func (p *Provider) method() string {
	switch {
	case len(p.conf.Endpoints) > 0:
		return "defined"
	case slices.ContainsFunc(p.endpoints.all, func(c candidate) bool { return c.Type == "srflx" }):
		return "warm_stun"
	}
	return "discovered"
}

// assisting reports whether assisted joins are enabled and possible.
func (p *Provider) assisting() bool { return p.conf.AssistedJoins && p.ws != nil }

// refreshEndpoints updates the candidates of the host and republishes them if they changed.
func (p *Provider) refreshEndpoints(ctx context.Context) {
	var reflexive []netip.AddrPort
	public, private := p.host.localEndpoints()
	// Assistance discovers mappings per join instead of keeping them warm.
	if len(p.conf.Endpoints) == 0 && !p.assisting() {
		reflexive = p.mappings(ctx)
	}
	c := candidates(p.conf.Endpoints, public, reflexive, private)
	now := time.Now()

	p.opMu.Lock()
	defer p.opMu.Unlock()
	e := &p.endpoints
	if e.revision == 0 || !sameCandidates(c, e.all) {
		for i := range c {
			if c[i].Type == "srflx" {
				c[i].ExpiresAt = now.Add(mappingLifetime).UnixMilli()
			}
		}
		// A replaced mapping discards the feedback about the previous one.
		e.all, e.checks = c, nil
		e.revision++
		p.logEndpoints()
	} else {
		for i := range e.all {
			if e.all[i].Type == "srflx" && time.UnixMilli(e.all[i].ExpiresAt).Sub(now) < mappingLifetime/2 {
				e.all[i].ExpiresAt = now.Add(mappingLifetime).UnixMilli()
			}
		}
	}
	p.publish()
}

// mappings returns the STUN mappings of the gameplay socket from the advertised servers.
func (p *Provider) mappings(ctx context.Context) []netip.AddrPort {
	var addrs []netip.AddrPort
	for _, server := range p.disc.stunServers() {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		addr, err := p.host.mapping(ctx, server)
		cancel()
		if err != nil {
			p.log.Debug("STUN mapping failed", "server", server, "error", err)
			continue
		}
		if !p.host.reachable(addr.Addr()) {
			p.log.Debug("STUN mapping is not a public address", "server", server, "mapping", addr)
			continue
		}
		if !slices.Contains(addrs, addr) {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// publish updates the published candidates, withholding public endpoints that failed
// every completed check. Discovered private endpoints are only published if no public
// endpoint exists or one failed. opMu must be held.
func (p *Provider) publish() {
	e := &p.endpoints
	public, failed := false, false
	for _, c := range e.all {
		if addr, err := netip.ParseAddr(c.Address); err == nil && p.host.reachable(addr) {
			public = true
			failed = failed || p.withheld(netip.AddrPortFrom(addr, c.Port))
		}
	}
	published := slices.DeleteFunc(slices.Clone(e.all), func(c candidate) bool {
		addr, err := netip.ParseAddr(c.Address)
		if err != nil {
			return false
		}
		if !p.host.reachable(addr) {
			return len(p.conf.Endpoints) == 0 && public && !failed
		}
		return !p.assisting() && p.withheld(netip.AddrPortFrom(addr, c.Port))
	})
	if !slices.Equal(published, e.published) {
		e.published = published
		p.published.Store(&published)
		p.pokeNow()
	}
}

// withheld reports whether a target failed a check without succeeding in any region.
func (p *Provider) withheld(target netip.AddrPort) bool {
	failed := false
	for k, c := range p.endpoints.checks {
		if k.target != target {
			continue
		}
		switch c.Outcome {
		case "established":
			return false
		case "not-established":
			failed = true
		}
	}
	return failed
}

// applyFeedback records the regional checks returned in a heartbeat response. opMu must be held.
func (p *Provider) applyFeedback(exts map[string]extension) {
	ext, ok := exts[extensionConnectivity]
	if !ok || ext.Version != 1 {
		return
	}
	var data struct {
		CandidateRevision int64               `json:"candidateRevision"`
		Checks            []connectivityCheck `json:"checks"`
	}
	e := &p.endpoints
	if json.Unmarshal(ext.Data, &data) != nil || data.CandidateRevision != e.revision || len(data.Checks) > 18 {
		return
	}
	if len(data.Checks) > 0 {
		p.log.Debug("received connectivity checks", "checks", len(data.Checks))
	}
	now := time.Now().UnixMilli()
	for _, c := range data.Checks {
		if c.Target == nil || c.CheckedAt > now || c.ExpiresAt <= now {
			continue
		}
		addr, err := netip.ParseAddr(c.Target.Address)
		if err != nil || (c.Outcome != "established" && c.Outcome != "not-established") {
			// Inconclusive results leave the previous decision intact.
			continue
		}
		if c.Method == "" {
			c.Method = "defined"
		}
		k := checkKey{region: c.Region, method: c.Method, target: netip.AddrPortFrom(addr.Unmap(), c.Target.Port)}
		prev, ok := e.checks[k]
		// Newer results replace older ones, and a failure wins equal timestamps.
		if ok && (c.CheckedAt < prev.CheckedAt || (c.CheckedAt == prev.CheckedAt && prev.Outcome == "not-established")) {
			continue
		}
		if e.checks == nil {
			e.checks = make(map[checkKey]connectivityCheck)
		}
		e.checks[k] = c
	}
	p.publish()
}

// assistedFamilies returns the address families that assisted joins can be answered in:
// those of public candidates, or of the STUN servers used for per-join discovery.
func (p *Provider) assistedFamilies() []int {
	families := []int{}
	if !p.assisting() {
		return families
	}
	add := func(addr netip.Addr) {
		f := 4
		if addr.Is6() && !addr.Is4In6() {
			f = 6
		}
		if !slices.Contains(families, f) {
			families = append(families, f)
		}
	}
	for _, c := range p.endpoints.all {
		if addr, err := netip.ParseAddr(c.Address); err == nil && p.host.reachable(addr) {
			add(addr)
		}
	}
	if len(p.conf.Endpoints) == 0 && len(p.disc.stunServers()) > 0 {
		add(netip.IPv4Unspecified())
	}
	slices.Sort(families)
	return families
}

func (p *Provider) logEndpoints() {
	c := p.endpoints.all
	if len(c) == 0 {
		p.log.Warn("no usable endpoints to advertise; set Config.Endpoints")
		return
	}
	addrs := make([]string, len(c))
	for i, c := range c {
		addrs[i] = joinHostPort(c.Address, int(c.Port)) + " (" + c.Type + ")"
	}
	p.log.Debug("advertising endpoints", "endpoints", addrs)
}

// sameCandidates reports whether a and b are equal apart from their expiry.
func sameCandidates(a, b []candidate) bool {
	return slices.EqualFunc(a, b, func(x, y candidate) bool {
		x.ExpiresAt, y.ExpiresAt = 0, 0
		return x == y
	})
}
