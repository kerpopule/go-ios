package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios/tunnel"
)

// The CLI is tested as the program it is: the test binary re-executes itself as coagent-rppair, so the
// JSON line, the exit code and flag handling are exactly what the daemon sees.
func TestMain(m *testing.M) {
	if os.Getenv("COAGENT_RPPAIR_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runCLI(t *testing.T, args ...string) (map[string]any, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "COAGENT_RPPAIR_RUN_MAIN=1")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	err := cmd.Run()
	code := 0
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatalf("run: %v", err)
	}
	line := strings.TrimSpace(stdout.String())
	out := map[string]any{}
	if err := json.Unmarshal([]byte(line), &out); err != nil {
		t.Fatalf("output is not one JSON object: %q", line)
	}
	return out, code
}

func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rp")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "s.sock")
}

// fakeDesk answers every SOCKS request with rep and records each request's target as "host:port".
func fakeDesk(t *testing.T, rep byte) (string, <-chan string) {
	t.Helper()
	path := socketPath(t)
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	targets := make(chan string, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(c, greeting); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00})
				head := make([]byte, 4)
				if _, err := io.ReadFull(c, head); err != nil {
					return
				}
				var host string
				switch head[3] {
				case 0x01:
					a := make([]byte, 4)
					_, _ = io.ReadFull(c, a)
					host = net.IP(a).String()
				case 0x03:
					n := make([]byte, 1)
					_, _ = io.ReadFull(c, n)
					a := make([]byte, n[0])
					_, _ = io.ReadFull(c, a)
					host = string(a)
				}
				p := make([]byte, 2)
				_, _ = io.ReadFull(c, p)
				targets <- fmt.Sprintf("%s:%d", host, int(p[0])<<8|int(p[1]))
				_, _ = c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				if rep == 0x00 {
					// A stream that opens and is then ended by the desk (epoch end reads as EOF).
					return
				}
			}()
		}
	}()
	return path, targets
}

func expectTarget(t *testing.T, targets <-chan string, want string) {
	t.Helper()
	select {
	case got := <-targets:
		if got != want {
			t.Fatalf("SOCKS target %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the desk never saw a request for %s", want)
	}
}

func TestVerifyViaStreamsReportsTheReplyWord(t *testing.T) {
	sock, targets := fakeDesk(t, 0x03)
	out, code := runCLI(t, "verify", "--via-streams", sock, "--records", t.TempDir(), "--timeout", "3s")
	if code != 1 || out["ok"] != false || out["reason"] != "verify_failed" || out["via"] != "streams" ||
		out["streams"] != "phone_not_linked" || out["rep"] != float64(3) || out["leg"] != "control" || out["target"] != "phone:49152" {
		t.Fatalf("exit %d, got %v", code, out)
	}
	// --at defaults to the front door on the phone's loopback, by name.
	expectTarget(t, targets, "phone:49152")
}

func TestTunnelViaStreamsReportsTheReplyWord(t *testing.T) {
	sock, targets := fakeDesk(t, 0x05)
	out, code := runCLI(t, "tunnel", "--via-streams", sock, "--at", "127.0.0.1:49152", "--records", t.TempDir())
	if code != 1 || out["reason"] != "tunnel_failed" || out["via"] != "streams" ||
		out["streams"] != "connection_refused" || out["rep"] != float64(5) || out["leg"] != "control" {
		t.Fatalf("exit %d, got %v", code, out)
	}
	expectTarget(t, targets, "127.0.0.1:49152")
}

func TestViaStreamsMapsEveryReplyToItsWord(t *testing.T) {
	for rep, word := range map[byte]string{
		0x01: "general_failure", 0x02: "not_allowed", 0x04: "timeout",
		0x07: "command_not_supported", 0x08: "address_type_not_supported",
	} {
		sock, _ := fakeDesk(t, rep)
		out, _ := runCLI(t, "verify", "--via-streams", sock, "--records", t.TempDir(), "--timeout", "3s")
		if out["streams"] != word || out["rep"] != float64(rep) {
			t.Fatalf("REP 0x%02x: got %v, want streams=%s", rep, out, word)
		}
	}
}

// A stream that opened and then ended is not a SOCKS failure; it says so, so the daemon does not
// blame the socket for what the relay epoch did.
func TestVerifyViaStreamsSaysTheStreamOpened(t *testing.T) {
	sock, _ := fakeDesk(t, 0x00)
	out, code := runCLI(t, "verify", "--via-streams", sock, "--records", t.TempDir(), "--timeout", "3s")
	if code != 1 || out["reason"] != "verify_failed" || out["streams"] != "opened" {
		t.Fatalf("exit %d, got %v", code, out)
	}
	if _, has := out["rep"]; has {
		t.Fatalf("a stream that opened carries no reply code: %v", out)
	}
}

func TestViaStreamsRefusesATargetTheDeskCannotReach(t *testing.T) {
	sock, targets := fakeDesk(t, 0x00)
	for _, at := range []string{"10.71.0.2:49152", "phone:62077x", "phone:22", "[::1]:49152"} {
		out, code := runCLI(t, "verify", "--via-streams", sock, "--at", at, "--records", t.TempDir())
		if code != 1 || out["reason"] != "via_streams_bad_target" || out["streams"] != "bad_target" {
			t.Fatalf("--at %s: exit %d, got %v", at, code, out)
		}
	}
	select {
	case got := <-targets:
		t.Fatalf("a bad --at still reached the socket (%s)", got)
	default:
	}
}

func TestViaStreamsReportsAMissingSocket(t *testing.T) {
	out, code := runCLI(t, "verify", "--via-streams", filepath.Join(t.TempDir(), "absent.sock"), "--records", t.TempDir(), "--timeout", "2s")
	if code != 1 || out["reason"] != "verify_failed" || out["streams"] != "socket_unavailable" {
		t.Fatalf("exit %d, got %v", code, out)
	}
}

func TestViaStreamsIsOnlyForVerifyAndTunnel(t *testing.T) {
	out, code := runCLI(t, "pair", "--via-streams", "/nonexistent", "--records", t.TempDir(), "--address", "fd00::1", "--rsd-port", "1")
	if code != 1 || out["ok"] != false || !strings.Contains(fmt.Sprint(out["reason"]), "verify and tunnel only") {
		t.Fatalf("exit %d, got %v", code, out)
	}
}

// Without the flag nothing changed: the same required --at, the same reason, no streams fields.
func TestWithoutTheFlagVerifyIsUnchanged(t *testing.T) {
	out, code := runCLI(t, "verify", "--records", t.TempDir())
	if code != 1 || out["reason"] != "verify needs --at HOST:PORT" {
		t.Fatalf("exit %d, got %v", code, out)
	}
	out, _ = runCLI(t, "verify", "--at", "192.0.2.1:49152", "--records", t.TempDir(), "--timeout", "300ms")
	if out["reason"] != "verify_failed" {
		t.Fatalf("got %v", out)
	}
	for _, key := range []string{"via", "streams", "rep", "leg"} {
		if _, has := out[key]; has {
			t.Fatalf("the direct road grew a %q field: %v", key, out)
		}
	}
}

func TestStreamsFailureShape(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &tunnel.StreamsError{Word: tunnel.StreamsTimeout, Rep: -1, Target: "phone:58783", Leg: tunnel.StreamsLegTunnelPort})
	out := streamsFailure("tunnel_failed", err)
	if out["streams"] != "timeout" || out["leg"] != "tunnel_port" || out["target"] != "phone:58783" {
		t.Fatalf("got %v", out)
	}
	if _, has := out["rep"]; has {
		t.Fatalf("a local deadline has no reply code: %v", out)
	}
}

func TestWithViaKeepsTheTunnelFields(t *testing.T) {
	got := withVia([]tunnel.Tunnel{{Address: "fd00::1", RsdPort: 58000, Udid: "U"}}, "streams")
	if len(got) != 1 || got[0]["address"] != "fd00::1" || got[0]["rsdPort"] != float64(58000) || got[0]["udid"] != "U" || got[0]["via"] != "streams" {
		t.Fatalf("got %v", got)
	}
}
