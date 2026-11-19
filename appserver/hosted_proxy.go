package appserver

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Client-address headers a HostedProxy can trust.
const (
	// HostedProxyXForwardedFor trusts the rightmost X-Forwarded-For entry, the
	// one the nearest proxy appended (for example an AWS Application Load
	// Balancer). Entries to its left are client-supplied and never read.
	HostedProxyXForwardedFor = "X-Forwarded-For"
	// HostedProxyCFConnectingIP trusts a single CF-Connecting-IP value, which
	// Cloudflare sets to the connecting client.
	HostedProxyCFConnectingIP = "CF-Connecting-IP"
)

// hostedIdleTimeout is the hosted plain HTTP server's keep-alive idle timeout.
// It is longer than common proxy idle timeouts (60 s for an AWS Application
// Load Balancer), so the proxy, not the server, closes an idle upstream
// connection; otherwise a request racing the server's close gets a 502.
const hostedIdleTimeout = 120 * time.Second

// HostedProxy is the TLS-terminating reverse proxy in front of hosted plain
// HTTP serving. Requests whose peer address is inside Networks take their
// client address from Header; every other request keeps its peer address.
// Native HTTPS serving never uses it. The zero value is invalid; a nil
// *HostedProxy trusts no header.
type HostedProxy struct {
	// Header is exactly HostedProxyXForwardedFor or HostedProxyCFConnectingIP.
	Header string
	// Networks are the proxy's peer networks, for example the load balancer's
	// subnets or 127.0.0.0/8. Required; 0.0.0.0/0 and ::/0 are refused.
	Networks []netip.Prefix
}

// Validate checks the header name and trusted networks.
func (p *HostedProxy) Validate() error {
	if p == nil {
		return errors.New("hosted proxy is not set")
	}
	if p.Header != HostedProxyXForwardedFor && p.Header != HostedProxyCFConnectingIP {
		return fmt.Errorf("hosted proxy header must be %s or %s", HostedProxyXForwardedFor, HostedProxyCFConnectingIP)
	}
	if len(p.Networks) == 0 {
		return errors.New("hosted proxy requires at least one trusted peer network")
	}
	for _, network := range p.Networks {
		switch {
		case !network.IsValid():
			return errors.New("hosted proxy network is invalid")
		case network.Bits() == 0:
			return fmt.Errorf("hosted proxy network %s would trust every peer", network)
		case network.Addr().Is4In6():
			return fmt.Errorf("hosted proxy network %s must use its IPv4 form", network)
		case network.Addr().Zone() != "":
			return fmt.Errorf("hosted proxy network %s must not have a zone", network)
		case network != network.Masked():
			return fmt.Errorf("hosted proxy network %s has host bits set; use %s", network, network.Masked())
		}
	}
	return nil
}

// ParseHostedProxy builds a HostedProxy from command-line values: a header
// name and a comma-separated list of CIDR networks. Both empty returns nil (no
// proxy); one without the other is an error.
func ParseHostedProxy(header, networks string) (*HostedProxy, error) {
	header, networks = strings.TrimSpace(header), strings.TrimSpace(networks)
	if header == "" && networks == "" {
		return nil, nil
	}
	if header == "" || networks == "" {
		return nil, errors.New("a hosted proxy needs both its header and its trusted networks")
	}
	p := &HostedProxy{Header: header}
	for _, field := range strings.Split(networks, ",") {
		network, err := netip.ParsePrefix(strings.TrimSpace(field))
		if err != nil {
			return nil, fmt.Errorf("hosted proxy network %q is not a CIDR prefix", strings.TrimSpace(field))
		}
		p.Networks = append(p.Networks, network)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// ValidateHostedHTTPAddress accepts a literal IP and a port from 1 to 65535,
// such as 0.0.0.0:8080, 127.0.0.1:8098 or [::]:8080. Host names are refused
// so the listen address never depends on name resolution.
func ValidateHostedHTTPAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.Atoi(port)
	ip, ipErr := netip.ParseAddr(host)
	if err != nil || portErr != nil || n < 1 || n > 65535 || ipErr != nil || ip.Zone() != "" || ip.IsMulticast() {
		return errors.New("hosted HTTP address must be a literal IP with a port from 1 to 65535, such as 0.0.0.0:8080")
	}
	return nil
}

// validateHostedServing keeps the proxy options to hosted plain HTTP serving.
func validateHostedServing(opts ServeOptions) error {
	if opts.HostedHTTPAddress == "" && opts.HostedProxy == nil {
		return nil
	}
	if !opts.Hosted {
		return errors.New("the hosted HTTP address and hosted proxy require --hosted")
	}
	if opts.HostedHTTPAddress != "" {
		if opts.DevHTTPAddress != "" {
			return errors.New("the hosted HTTP address excludes --dev-http-address")
		}
		if err := ValidateHostedHTTPAddress(opts.HostedHTTPAddress); err != nil {
			return err
		}
	}
	if opts.HostedProxy != nil {
		return opts.HostedProxy.Validate()
	}
	return nil
}

// trusts reports whether the request's peer is the configured proxy.
func (p *HostedProxy) trusts(remoteAddr string) bool {
	peer, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return false
	}
	addr := peer.Addr().Unmap().WithZone("")
	for _, network := range p.Networks {
		if network.Contains(addr) {
			return true
		}
	}
	return false
}

// remoteAddr returns the address the request's limiters should key on: the
// client from the trusted header when the peer is the proxy and the value is a
// usable client address, otherwise the unchanged peer address.
func (p *HostedProxy) remoteAddr(r *http.Request) string {
	if !p.trusts(r.RemoteAddr) {
		return r.RemoteAddr
	}
	values := r.Header.Values(p.Header)
	var raw string
	switch p.Header {
	case HostedProxyXForwardedFor:
		if len(values) == 0 {
			return r.RemoteAddr
		}
		// Several header lines form one list; the proxy appends last.
		list := strings.Join(values, ",")
		raw = list[strings.LastIndex(list, ",")+1:]
	case HostedProxyCFConnectingIP:
		if len(values) != 1 {
			return r.RemoteAddr
		}
		raw = values[0]
	default:
		return r.RemoteAddr
	}
	client, ok := hostedClientIP(raw)
	if !ok {
		return r.RemoteAddr
	}
	return netip.AddrPortFrom(client, 0).String()
}

// hostedClientIP parses exactly one IP address without a port or zone and
// refuses values no remote client can have.
func hostedClientIP(raw string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.Addr{}, false
	}
	return ip, true
}
