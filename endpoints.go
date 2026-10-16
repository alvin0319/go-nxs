package nxs

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/pion/stun/v4"
)

// mapping returns the server-reflexive address of the gameplay socket as observed by
// a STUN server.
func (h *host) mapping(ctx context.Context, server string) (netip.AddrPort, error) {
	network := "udp4"
	if local := h.Addr(); local.IP != nil && local.IP.To4() == nil && !local.IP.IsUnspecified() {
		network = "udp6"
	}
	raddr, err := net.ResolveUDPAddr(network, server)
	if err != nil {
		return netip.AddrPort{}, err
	}
	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	responses := make(chan *stun.Message, 1)
	defer h.conn.expect(msg.TransactionID, responses)()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := h.conn.WriteToUDPAddrPort(msg.Raw, raddr.AddrPort()); err != nil {
			return netip.AddrPort{}, err
		}
		select {
		case resp := <-responses:
			var addr stun.XORMappedAddress
			if resp.Type.Class != stun.ClassSuccessResponse || addr.GetFrom(resp) != nil {
				return netip.AddrPort{}, errors.New("nxs: invalid STUN response")
			}
			ip, ok := netip.AddrFromSlice(addr.IP)
			if !ok {
				return netip.AddrPort{}, errors.New("nxs: invalid STUN mapped address")
			}
			return netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)), nil
		case <-ticker.C:
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		}
	}
}

// localEndpoints returns the usable addresses of the gameplay socket, public ones first.
func (h *host) localEndpoints() (public, private []netip.AddrPort) {
	local := h.Addr()
	port := uint16(local.Port)
	var addrs []netip.Addr
	if ip, ok := netip.AddrFromSlice(local.IP); ok && !ip.IsUnspecified() {
		addrs = []netip.Addr{ip.Unmap()}
	} else if ifaces, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifaces {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					addrs = append(addrs, ip.Unmap())
				}
			}
		}
	}
	for _, ip := range addrs {
		switch scopeOf(ip) {
		case scopePrivate:
			private = append(private, netip.AddrPortFrom(ip, port))
		case scopePublic:
			public = append(public, netip.AddrPortFrom(ip, port))
		}
	}
	return public, private
}

// reachable reports whether players may be sent to addr, or receive traffic from the host at
// it: a public address, or a loopback one if the host itself is bound to loopback.
func (h *host) reachable(addr netip.Addr) bool {
	switch scopeOf(addr) {
	case scopePublic:
		return true
	case scopeLoopback:
		return h.Addr().IP.IsLoopback()
	}
	return false
}

type scope int

const (
	scopeUnusable scope = iota
	scopePublic
	scopePrivate
	scopeLoopback
)

var (
	privatePrefixes = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fc00::/7"),
	}
	unusablePrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("224.0.0.0/3"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("3fff::/20"),
	}
	globalUnicast = netip.MustParsePrefix("2000::/3")
	protocolBlock = netip.MustParsePrefix("192.0.0.0/24")
)

// scopeOf classifies addr like the reference host of the specification.
func scopeOf(addr netip.Addr) scope {
	addr = addr.Unmap()
	for _, p := range privatePrefixes {
		if p.Contains(addr) {
			return scopePrivate
		}
	}
	if addr.IsLoopback() {
		return scopeLoopback
	}
	for _, p := range unusablePrefixes {
		if p.Contains(addr) {
			return scopeUnusable
		}
	}
	if addr.Is6() && !globalUnicast.Contains(addr) {
		return scopeUnusable
	}
	// 192.0.0.9 and 192.0.0.10 are the PCP and TURN anycast addresses, which players can reach.
	if protocolBlock.Contains(addr) && addr != netip.AddrFrom4([4]byte{192, 0, 0, 9}) && addr != netip.AddrFrom4([4]byte{192, 0, 0, 10}) {
		return scopeUnusable
	}
	return scopePublic
}

// candidates returns the candidates published in the host profile.
func candidates(defined []netip.AddrPort, public, reflexive, private []netip.AddrPort) []candidate {
	type endpoint struct {
		addr netip.AddrPort
		typ  string
	}
	var endpoints []endpoint
	add := func(addrs []netip.AddrPort, typ string) {
		for _, a := range addrs {
			if !slices.ContainsFunc(endpoints, func(e endpoint) bool { return e.addr == a }) {
				endpoints = append(endpoints, endpoint{a, typ})
			}
		}
	}
	if len(defined) > 0 {
		add(defined, "host")
	} else {
		add(public, "host")
		add(reflexive, "srflx")
		// Private addresses remain useful for players on the same network.
		add(private, "host")
	}
	out := make([]candidate, 0, min(len(endpoints), 32))
	for i, e := range endpoints[:min(len(endpoints), 32)] {
		out = append(out, candidate{
			Foundation: strconv.Itoa(i + 1),
			Priority:   uint32(2130706431 - i*256),
			Address:    e.addr.Addr().String(),
			Port:       e.addr.Port(),
			Type:       e.typ,
		})
	}
	return out
}
