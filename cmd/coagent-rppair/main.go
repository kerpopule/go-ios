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
// Every result is one JSON line: {"ok":true,...} or {"ok":false,"reason":...,"error":...}.
package main

import (
	"context"
	"encoding/json"
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
	timeout := fs.Duration("timeout", 15*time.Second, "verify timeout")
	_ = fs.Parse(os.Args[2:])
	if *dir == "" {
		fail("--records is required: this Mac's RemotePairing identity lives there", nil)
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
		t, err := tunnel.ConnectToTunnelOverRemotePairingAt(ctx, *at, device(*udid), pm)
		if err != nil {
			fail("tunnel_failed", err)
		}
		defer func() { _ = t.Close() }()
		info, _ := json.Marshal([]tunnel.Tunnel{t})
		fmt.Println(string(info))
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		<-signals
	default:
		fail("unknown command "+cmd, nil)
	}
}
