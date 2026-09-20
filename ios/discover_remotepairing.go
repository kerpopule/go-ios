package ios

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/danielpaulus/go-ios/ios/golog"
	"github.com/grandcat/zeroconf"
)

// remotePairingServiceName is what an iPhone advertises over Wi-Fi.
//
// It is NOT the service FindDeviceInterfaceAddress browses. "_remoted._tcp" is
// published only on the USB-attached ethernet (NCM) interface, so every attempt
// to reach a device over Wi-Fi through that path searched for something that
// was never there and timed out looking. That is the whole reason phone control
// has needed a cable.
const remotePairingServiceName = "_remotepairing._tcp"

// RemotePairingEndpoint is one device answering on the Wi-Fi control channel.
//
// NOTE ON IDENTITY: none of these fields is the device UDID. The TXT record
// carries a RemotePairing UUID and an authTag, and validating the authTag needs
// the device's identity resolving key, which is only learned by pairing. So a
// caller that must reach ONE known device either has a single endpoint to
// choose from, or confirms the UDID after the tunnel is up (the RSD handshake
// inside the tunnel reports it). Nothing here should be treated as proof of
// which phone answered.
type RemotePairingEndpoint struct {
	// Instance is the mDNS instance name, which on an iPhone is a random hex
	// string rather than anything the owner would recognise.
	Instance string
	// HostName is the ".local." name, useful for logs and for a human deciding
	// which device they are looking at.
	HostName string
	Port     int
	// Addresses are dialable host strings, best first: routable IPv4 or global
	// IPv6 ahead of link-local. A link-local IPv6 address already carries its
	// zone (for example "fe80::1%en0"), because one without a zone is not
	// routable and fails at dial.
	Addresses []string
	// Text is the raw TXT record. `ver` here is the RemotePairing WIRE PROTOCOL
	// version, NOT the iOS version — a phone on iOS 27 reporting ver=26 is
	// reporting the protocol, and reading it as an OS version is a trap.
	Text []string
}

// Address is the first dialable "host:port" for this endpoint, or "" when the
// advertisement carried no usable address.
func (e RemotePairingEndpoint) Address() string {
	if len(e.Addresses) == 0 {
		return ""
	}
	return net.JoinHostPort(e.Addresses[0], fmt.Sprint(e.Port))
}

// FindRemotePairingEndpoints browses every interface for devices offering the
// RemotePairing control channel over Wi-Fi and returns what answered before ctx
// expired.
//
// Unlike FindDeviceInterfaceAddress this does NOT connect to anything and does
// not filter by UDID — it cannot, see RemotePairingEndpoint. It also browses
// IPv4 AND IPv6: that service is commonly reachable on the phone's ordinary
// Wi-Fi v4 address, and the IPv6-only browse used for the USB path would miss
// it entirely.
//
// AN ADVERTISEMENT IS NOT REACHABILITY. A sleeping iPhone keeps answering mDNS
// (the network's sleep proxy does it for them) long after it stops answering
// TCP, so an endpoint here can still refuse to connect. Callers must dial with
// a timeout and say "the phone is asleep" rather than "no device found".
func FindRemotePairingEndpoints(ctx context.Context) ([]RemotePairingEndpoint, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("FindRemotePairingEndpoints: failed to get network interfaces: %w", err)
	}

	// ONE CHANNEL PER BROWSER, fanned in. zeroconf CLOSES the channel it was
	// given when that browse's context ends, so handing the same channel to
	// every interface makes the second one close an already-closed channel and
	// panic the process. discover.go avoids this the same way, with a separate
	// channel per interface.
	entries := make(chan *zeroconf.ServiceEntry, 32)
	var browsers sync.WaitGroup
	browsing := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		resolver, err := zeroconf.NewResolver(
			zeroconf.SelectIfaces([]net.Interface{iface}),
			zeroconf.SelectIPTraffic(zeroconf.IPv4AndIPv6),
		)
		if err != nil {
			golog.Debug("failed to initialize resolver", "module", logModule, "interface", iface.Name, "err", err)
			continue
		}
		mine := make(chan *zeroconf.ServiceEntry, 8)
		if err := resolver.Browse(ctx, remotePairingServiceName, "local.", mine); err != nil {
			golog.Debug("failed to browse", "module", logModule, "interface", iface.Name, "err", err)
			continue
		}
		browsing++
		browsers.Add(1)
		go func() {
			defer browsers.Done()
			for entry := range mine {
				select {
				case entries <- entry:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	if browsing == 0 {
		return nil, fmt.Errorf("FindRemotePairingEndpoints: no usable network interface to browse on")
	}
	go func() { browsers.Wait(); close(entries) }()

	found := map[string]RemotePairingEndpoint{}
	for {
		select {
		case <-ctx.Done():
			return collectEndpoints(found), nil
		case entry, open := <-entries:
			if !open {
				return collectEndpoints(found), nil
			}
			if entry == nil || entry.Port == 0 {
				continue
			}
			endpoint := RemotePairingEndpoint{
				Instance:  entry.Instance,
				HostName:  entry.HostName,
				Port:      entry.Port,
				Addresses: dialableAddresses(entry),
				Text:      append([]string(nil), entry.Text...),
			}
			// Several interfaces can see the same device; keep the answer that
			// carries a dialable address over one that carries none.
			if existing, seen := found[entry.Instance]; !seen || len(existing.Addresses) < len(endpoint.Addresses) {
				found[entry.Instance] = endpoint
			}
		}
	}
}

// FindRemotePairingEndpoint browses for at most `wait` and returns exactly one
// endpoint, refusing rather than guessing when the answer is ambiguous. Use it
// where a single phone is expected; use FindRemotePairingEndpoints and choose
// deliberately where more than one may answer.
func FindRemotePairingEndpoint(ctx context.Context, wait time.Duration) (RemotePairingEndpoint, error) {
	browseCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	endpoints, err := FindRemotePairingEndpoints(browseCtx)
	if err != nil {
		return RemotePairingEndpoint{}, err
	}
	usable := endpoints[:0]
	for _, endpoint := range endpoints {
		if endpoint.Address() != "" {
			usable = append(usable, endpoint)
		}
	}
	switch len(usable) {
	case 0:
		return RemotePairingEndpoint{}, fmt.Errorf(
			"FindRemotePairingEndpoint: no device advertised %s in %v — the phone must be awake, unlocked at least once since boot, on this Wi-Fi network, and have Developer Mode on",
			remotePairingServiceName, wait)
	case 1:
		return usable[0], nil
	default:
		names := make([]string, 0, len(usable))
		for _, endpoint := range usable {
			names = append(names, endpoint.HostName)
		}
		return RemotePairingEndpoint{}, fmt.Errorf(
			"FindRemotePairingEndpoint: %d devices answered (%v) — name the one you mean rather than letting this pick", len(usable), names)
	}
}

// dialableAddresses turns an mDNS answer into host strings that net.Dial will
// accept, best first. A link-local IPv6 address is given the zone of the
// interface it was heard on; without one the kernel has no way to know which
// link "fe80::…" is on and the dial fails.
func dialableAddresses(entry *zeroconf.ServiceEntry) []string {
	type scored struct {
		host string
		rank int
	}
	var out []scored
	for _, ip := range entry.AddrIPv4 {
		if ip.IsUnspecified() {
			continue
		}
		out = append(out, scored{host: ip.String(), rank: 0})
	}
	for _, ip := range entry.AddrIPv6 {
		if ip.IsUnspecified() {
			continue
		}
		host := ip.String()
		rank := 1
		if ip.IsLinkLocalUnicast() {
			rank = 2
			if zone := zoneFor(ip); zone != "" {
				host = host + "%" + zone
			}
		}
		out = append(out, scored{host: host, rank: rank})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].rank < out[j].rank })
	hosts := make([]string, 0, len(out))
	for _, s := range out {
		hosts = append(hosts, s.host)
	}
	return hosts
}

// zoneFor finds an interface that carries a link-local address on the same
// link, so an fe80:: address can be dialed. Best effort: with no answer the
// address is returned unzoned and the dial reports the real problem.
func zoneFor(target net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() != nil || !ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			return iface.Name
		}
	}
	return ""
}

func collectEndpoints(found map[string]RemotePairingEndpoint) []RemotePairingEndpoint {
	out := make([]RemotePairingEndpoint, 0, len(found))
	for _, endpoint := range found {
		out = append(out, endpoint)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Instance < out[j].Instance })
	return out
}
