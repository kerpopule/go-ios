// coagent-rppair: give this Mac its own RemotePairing record for the owner's iPhone WITHOUT a cable,
// check it, and use it to bring up the CoreDevice tunnel on a road Bonjour cannot see.
//
// WHY THIS EXISTS (2026-09-22). Away-from-desk control reaches the phone at 10.71.0.2 through the
// Co-Agent packet tunnel. lockdownd accepts the TCP connection there but resets the session, while
// the RemotePairing control channel (port 49152) answers identically through the tunnel and over
// Wi-Fi — so RemotePairing is the road that works through the tunnel. It needs a pair record, and
// the Wi-Fi channel refuses pair-setup (it resets on setupManualPairing, measured on iOS 27). The
// setup is done instead through the Wi-Fi CoreDeviceProxy tunnel that already works with no cable,
// whose RSD lists the untrusted tunnelservice. The phone asks the owner to Trust + enter the
// passcode; that decision is theirs and this tool only waits for it.
//
//	coagent-rppair pair   --address ADDR --rsd-port N [--udid U] [--records DIR]
//	    one-time pair-setup through an existing tunnel (from `ios tunnel ls`); prompts on the phone
//	coagent-rppair verify --at HOST:PORT [--records DIR]
//	    pair-verify only against a RemotePairing channel; never prompts
//	coagent-rppair tunnel --at HOST:PORT [--udid U] [--records DIR]
//	    bring up the CoreDevice tunnel over RemotePairing at HOST:PORT and hold it (needs root);
//	    prints the same JSON shape as `ios tunnel ls`
//
//	coagent-rppair verify --via-streams SOCK [--at phone:49152] --records DIR [--timeout 15s]
//	coagent-rppair tunnel --via-streams SOCK [--at phone:49152] [--udid U] --records DIR
//	    the same, on the loopback-streams road (tunnel contract rev 4): the phone's tunnel extension
//	    connects to its OWN loopback and the desk peer carries the bytes, exposed here as a SOCKS5
//	    unix socket. Both the control channel and the TLS-PSK tunnel port go through SOCK. --at is
//	    optional and must be phone:PORT or 127.0.0.1:PORT, PORT in 49152-65535.
//
// Every result is one JSON line: {"ok":true,...} or {"ok":false,"reason":...,"error":...}. The one
// exception is a streams tunnel that came up and later died, which adds a second line (see below).
//
// With --via-streams, success gains "via":"streams" (for tunnel, on each tunnel object), and failure
// keeps its reason and adds "via":"streams" plus "streams":<word>:
//
//	socket_unavailable | socks_protocol | general_failure | not_allowed | phone_not_linked |
//	timeout | connection_refused | command_not_supported | address_type_not_supported
//
// with "rep" (the SOCKS reply code, when there was one), "leg" ("control" = the :49152 front door,
// "tunnel_port" = the per-session TLS-PSK listener) and "target". "streams":"opened" means every
// stream opened and the failure came from RemotePairing, TLS or the utun above it; an EOF there
// usually means the relay epoch ended mid-exchange. A --at the streams road cannot reach fails with
// reason "via_streams_bad_target". The phone's own reason for a refusal is in the desk peer's
// tunnel-peer-status.json, streams.lastFailure.
//
// Bounds on the streams road: verify finishes within --timeout (the stream's open and the pair-verify
// exchange share it). tunnel gives the control channel 30 s to open and 30 s for its handshake, and
// the tunnel port 15 s to open and 15 s for TLS-PSK plus the CDTunnel parameter exchange.
//
// A streams tunnel does not outlive the relay epoch. When its data plane stops (the desk closes every
// stream at an epoch end) `tunnel --via-streams` removes its interface, prints a SECOND line
// {"ok":false,"reason":"tunnel_ended","via":"streams","streams":"opened","error":...} and exits 1, so a
// supervisor sees the exit and runs it again. Without --via-streams, tunnel holds until a signal, as
// it always has.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/danielpaulus/go-ios/ios/tunnel"
)

func emit(out map[string]any) {
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}

func fail(reason string, err error) {
	out := map[string]any{"ok": false, "reason": reason}
	if err != nil {
		out["error"] = err.Error()
	}
	emit(out)
	os.Exit(1)
}

// streamsDefaultAt is the RemotePairing front door on the phone's loopback, as the desk names it.
const streamsDefaultAt = "phone:49152"

// streamsFailure is the failure line for the loopback-streams road: the ordinary reason and error,
// plus which streams step failed.
func streamsFailure(reason string, err error) map[string]any {
	out := map[string]any{"ok": false, "reason": reason, "via": "streams"}
	if err != nil {
		out["error"] = err.Error()
	}
	var se *tunnel.StreamsError
	if errors.As(err, &se) {
		out["streams"] = se.Word
		if se.Rep >= 0 {
			out["rep"] = se.Rep
		}
		if se.Leg != "" {
			out["leg"] = se.Leg
		}
		if se.Target != "" {
			out["target"] = se.Target
		}
	} else {
		out["streams"] = "opened"
	}
	return out
}

func failStreams(reason string, err error) {
	emit(streamsFailure(reason, err))
	os.Exit(1)
}

// holdStreamsTunnel waits until a signal asks this process to stop (false) or the tunnel stops on its
// own (true).
func holdStreamsTunnel(signals <-chan os.Signal, done <-chan struct{}) bool {
	select {
	case <-signals:
		return false
	case <-done:
		return true
	}
}

// tunnelEndedLine is the second JSON line of a streams tunnel that came up and then died. Every stream
// had opened, so "streams" is "opened"; the error is the data plane's own reason.
func tunnelEndedLine(reason error) map[string]any {
	msg := "the tunnel stopped carrying packets"
	if reason != nil {
		msg += ": " + reason.Error()
	}
	msg += " — on the streams road this is usually the relay epoch ending (a Wi-Fi<->cellular change or a desk peer restart); run tunnel again"
	return streamsFailure("tunnel_ended", errors.New(msg))
}

// withVia marks each tunnel object with the road it came up on, keeping the `ios tunnel ls` fields.
func withVia(tunnels []tunnel.Tunnel, via string) []map[string]any {
	out := make([]map[string]any, 0, len(tunnels))
	for _, t := range tunnels {
		b, _ := json.Marshal(t)
		m := map[string]any{}
		_ = json.Unmarshal(b, &m)
		m["via"] = via
		out = append(out, m)
	}
	return out
}

func records(dir string) tunnel.PairRecordManager {
	if err := os.MkdirAll(dir+"/peers", 0o700); err != nil {
		fail("records_dir_unwritable", err)
	}
	pm, err := tunnel.NewPairRecordManager(dir)
	if err != nil {
		fail("records_unreadable", err)
	}
	return pm
}

func device(udid string) ios.DeviceEntry {
	d := ios.DeviceEntry{}
	d.Properties.SerialNumber = udid
	return d
}

func main() {
	if len(os.Args) < 2 {
		fail("usage: coagent-rppair pair|verify|tunnel [flags]", nil)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	address := fs.String("address", "", "tunnel address from `ios tunnel ls` (pair)")
	rsdPort := fs.Int("rsd-port", 0, "RSD port from `ios tunnel ls` (pair)")
	at := fs.String("at", "", "RemotePairing HOST:PORT, e.g. 10.71.0.2:49152 (verify, tunnel)")
	udid := fs.String("udid", "", "phone UDID")
	dir := fs.String("records", "", "pair record directory")
	timeout := fs.Duration("timeout", 15*time.Second, "verify timeout (with --via-streams: the whole verify, stream open included)")
	viaStreams := fs.String("via-streams", "", "desk peer loopback-streams SOCKS5 unix socket (verify, tunnel)")
	_ = fs.Parse(os.Args[2:])
	if *dir == "" {
		fail("--records is required: this Mac's RemotePairing identity lives there", nil)
	}
	if *viaStreams != "" {
		if cmd != "verify" && cmd != "tunnel" {
			fail("--via-streams applies to verify and tunnel only", nil)
		}
		if *at == "" {
			*at = streamsDefaultAt
		}
		if err := tunnel.ValidateStreamsTarget(*at); err != nil {
			failStreams("via_streams_bad_target", err)
		}
	}

	switch cmd {
	case "pair":
		if *address == "" || *rsdPort == 0 {
			fail("pair needs --address and --rsd-port from a tunnel that is already up", nil)
		}
		pm := records(*dir)
		if err := tunnel.PairThroughTunnel(*address, *rsdPort, device(*udid), pm); err != nil {
			fail("pair_failed", err)
		}
		emit(map[string]any{"ok": true, "paired": true, "records": *dir})
	case "verify":
		if *at == "" {
			fail("verify needs --at HOST:PORT", nil)
		}
		pm := records(*dir)
		if *viaStreams != "" {
			if err := tunnel.VerifyRemotePairingVia(*at, *timeout, pm, tunnel.StreamsDialer(*viaStreams)); err != nil {
				failStreams("verify_failed", err)
			}
			emit(map[string]any{"ok": true, "verified": true, "at": *at, "via": "streams"})
			return
		}
		if err := tunnel.VerifyRemotePairing(*at, *timeout, pm); err != nil {
			fail("verify_failed", err)
		}
		emit(map[string]any{"ok": true, "verified": true, "at": *at})
	case "tunnel":
		if *at == "" {
			fail("tunnel needs --at HOST:PORT", nil)
		}
		pm := records(*dir)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var t tunnel.Tunnel
		var err error
		if *viaStreams != "" {
			t, err = tunnel.ConnectToTunnelOverRemotePairingAtVia(ctx, *at, device(*udid), pm, tunnel.StreamsDialer(*viaStreams))
			if err != nil {
				failStreams("tunnel_failed", err)
			}
		} else {
			t, err = tunnel.ConnectToTunnelOverRemotePairingAt(ctx, *at, device(*udid), pm)
			if err != nil {
				fail("tunnel_failed", err)
			}
		}
		defer func() { _ = t.Close() }()
		var info []byte
		if *viaStreams != "" {
			info, _ = json.Marshal(withVia([]tunnel.Tunnel{t}, "streams"))
		} else {
			info, _ = json.Marshal([]tunnel.Tunnel{t})
		}
		fmt.Println(string(info))
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		if *viaStreams == "" {
			<-signals
			return
		}
		// Contract §9, Lifetime: a streams tunnel dies with the relay epoch (every Wi-Fi<->cellular
		// change, every peer restart), and the daemon re-runs this when it exits. So it must exit.
		if holdStreamsTunnel(signals, t.Done()) {
			reason := t.Err()
			_ = t.Close()
			emit(tunnelEndedLine(reason))
			os.Exit(1)
		}
	default:
		fail("unknown command "+cmd, nil)
	}
}
