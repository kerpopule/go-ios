package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
)

// LIFETIME AND SETUP BOUNDS on the loopback-streams road (contract rev 4, §9). A streams tunnel dies
// with every relay epoch, so its data plane must say when it has stopped; and every read during
// setup — TLS-PSK and the CDTunnel parameter exchange after it — must be bounded, because a stream
// can open and then carry nothing.

func testTunnelParameters() tunnelParameters {
	var p tunnelParameters
	p.ServerAddress = "fd00::1"
	p.ServerRSDPort = 58000
	p.ClientParameters.Address = "fd00::2"
	p.ClientParameters.Netmask = "ffff:ffff:ffff:ffff::"
	p.ClientParameters.Mtu = 1280
	return p
}

func waitDone(t *testing.T, tun Tunnel, within time.Duration) {
	t.Helper()
	select {
	case <-tun.Done():
	case <-time.After(within):
		t.Fatalf("Done was not closed within %v", within)
	}
}

// The desk closes every stream at an epoch end. The data plane must notice, close Done, and keep
// the reason — that is what lets `coagent-rppair tunnel --via-streams` exit so the daemon re-runs it.
func TestLockdownTunnelReportsWhenTheDeviceConnectionEnds(t *testing.T) {
	hostDev, phone := net.Pipe()
	hostTun, kernel := net.Pipe()
	defer func() { _ = phone.Close(); _ = kernel.Close() }()

	tun := startLockdownForwarding(context.Background(), ios.DeviceEntry{}, testTunnelParameters(), hostDev, hostTun)
	defer func() { _ = tun.Close() }()

	// It forwards while the stream is alive: one IPv6 packet from the phone reaches the interface.
	packet := make([]byte, 44)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 4)
	copy(packet[40:], "ping")
	go func() { _, _ = phone.Write(packet) }()
	got := make([]byte, len(packet))
	_ = kernel.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(kernel, got); err != nil || !bytes.Equal(got, packet) {
		t.Fatalf("interface got %x (%v), want the phone's packet", got, err)
	}
	select {
	case <-tun.Done():
		t.Fatalf("Done closed while the tunnel was carrying packets: %v", tun.Err())
	default:
	}
	if tun.Err() != nil {
		t.Fatalf("Err while up: %v", tun.Err())
	}

	_ = phone.Close() // the epoch ends: the desk closes the stream
	waitDone(t, tun, 5*time.Second)
	err := tun.Err()
	if err == nil || !errors.Is(err, io.EOF) || !strings.Contains(err.Error(), "forwarding from the device stopped") {
		t.Fatalf("Err = %v, want the device connection's EOF, named", err)
	}

	// Close still tears down the interface (the other pump is blocked on it) and keeps the reason.
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_ = kernel.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := kernel.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("interface not closed after Close: %v", err)
	}
	if !errors.Is(tun.Err(), io.EOF) {
		t.Fatalf("Close replaced the reason: %v", tun.Err())
	}
}

// The interface failing ends the tunnel too, named as the other direction.
func TestLockdownTunnelReportsWhenTheInterfaceFails(t *testing.T) {
	hostDev, phone := net.Pipe()
	hostTun, kernel := net.Pipe()
	defer func() { _ = phone.Close() }()

	tun := startLockdownForwarding(context.Background(), ios.DeviceEntry{}, testTunnelParameters(), hostDev, hostTun)
	defer func() { _ = tun.Close() }()
	_ = kernel.Close()
	waitDone(t, tun, 5*time.Second)
	if err := tun.Err(); err == nil || !strings.Contains(err.Error(), "forwarding to the device stopped") {
		t.Fatalf("Err = %v, want the interface side named", err)
	}
}

// A caller's own Close is not a failure: Done closes, Err stays nil.
func TestLockdownTunnelCloseIsNotAFailure(t *testing.T) {
	hostDev, phone := net.Pipe()
	hostTun, kernel := net.Pipe()
	defer func() { _ = phone.Close(); _ = kernel.Close() }()

	tun := startLockdownForwarding(context.Background(), ios.DeviceEntry{}, testTunnelParameters(), hostDev, hostTun)
	if err := tun.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitDone(t, tun, 5*time.Second)
	if err := tun.Err(); err != nil {
		t.Fatalf("Err after Close = %v, want nil", err)
	}
}

// Tunnels built elsewhere (QUIC, userspace) do not report their end: Done is nil, which a select
// never picks, so holding them is exactly as before.
func TestTunnelsThatDoNotReportTheirEnd(t *testing.T) {
	tun := Tunnel{closer: func() error { return nil }}
	if tun.Done() != nil || tun.Err() != nil {
		t.Fatalf("Done %v Err %v, want nil nil", tun.Done(), tun.Err())
	}
}

// deadlineRecorder notes, at each deadline cleared, how many bytes had been read by then.
type deadlineRecorder struct {
	net.Conn
	mu        sync.Mutex
	read      int
	clearedAt []int
}

func (d *deadlineRecorder) Read(p []byte) (int, error) {
	n, err := d.Conn.Read(p)
	d.mu.Lock()
	d.read += n
	d.mu.Unlock()
	return n, err
}

func (d *deadlineRecorder) SetDeadline(t time.Time) error {
	if t.IsZero() {
		d.mu.Lock()
		d.clearedAt = append(d.clearedAt, d.read)
		d.mu.Unlock()
	}
	return d.Conn.SetDeadline(t)
}

// fakeCDTunnelPhone answers one CDTunnel parameter request and returns how many bytes it sent.
func fakeCDTunnelPhone(t *testing.T, c net.Conn) <-chan int {
	sent := make(chan int, 1)
	go func() {
		defer close(sent)
		head := make([]byte, len("CDTunnel\000")+1)
		if _, err := io.ReadFull(c, head); err != nil {
			return
		}
		if _, err := io.ReadFull(c, make([]byte, head[len(head)-1])); err != nil {
			return
		}
		body, _ := json.Marshal(testTunnelParameters())
		reply := append([]byte("CDTunnel\000"), byte(len(body)))
		reply = append(reply, body...)
		if _, err := c.Write(reply); err != nil {
			return
		}
		sent <- len(reply)
		_, _ = io.Copy(io.Discard, c)
	}()
	return sent
}

// The setup deadline stays on through the parameter exchange and is cleared only once the
// parameters are in, before the interface exists. Reaching the interface step needs no root: as an
// ordinary user it fails, which is how this test knows the hook had already run.
func TestStreamedLockdownClearsTheDeadlineOnlyAfterTheParameters(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("relies on utun/tun creation failing for an ordinary user")
	}
	if os.Geteuid() == 0 {
		t.Skip("as root this would create a real interface")
	}
	host, phone := net.Pipe()
	defer func() { _ = phone.Close() }()
	sent := fakeCDTunnelPhone(t, phone)
	rec := &deadlineRecorder{Conn: host}
	_ = rec.SetReadDeadline(time.Now().Add(5 * time.Second)) // what dialTunnelPortVia leaves on

	_, err := connectStreamedTunnelLockdown(context.Background(), ios.DeviceEntry{}, rec)
	if err == nil || !strings.Contains(err.Error(), "could not setup tunnel interface") {
		t.Fatalf("want the (unprivileged) interface step to be reached, got %v", err)
	}
	replyLen := <-sent
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.clearedAt) != 1 || rec.clearedAt[0] != replyLen {
		t.Fatalf("deadline cleared after %v bytes read, want exactly once after the whole %d-byte reply", rec.clearedAt, replyLen)
	}
}

// A connection that cannot be prepared never gets an interface.
func TestLockdownStopsWhenPreparingTheConnectionFails(t *testing.T) {
	host, phone := net.Pipe()
	defer func() { _ = phone.Close(); _ = host.Close() }()
	fakeCDTunnelPhone(t, phone)
	_, err := connectToTunnelLockdownThen(context.Background(), ios.DeviceEntry{}, host, func() error { return errors.New("boom") })
	if err == nil || !strings.Contains(err.Error(), "could not prepare the connection") || strings.Contains(err.Error(), "interface") {
		t.Fatalf("want the prepare failure, before any interface, got %v", err)
	}
}

// REVIEW FINDING (2026-09-23): a tunnel-port stream that completes TLS-PSK and then carries nothing
// hung `tunnel --via-streams` forever, because the setup deadline was cleared before the CDTunnel
// exchange. This drives the real TLS-PSK client against OpenSSL (PSK-AES256-GCM-SHA384, the suite
// iOS uses), which completes the handshake and then never answers. Skipped where openssl lacks the
// suite (macOS LibreSSL); Homebrew OpenSSL 3 has it.
func TestStreamedTunnelPortBoundsTheParameterExchange(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found")
	}
	if out, err := exec.Command(openssl, "ciphers", "PSK-AES256-GCM-SHA384").CombinedOutput(); err != nil || !strings.Contains(string(out), "PSK-AES256-GCM-SHA384") {
		t.Skipf("openssl lacks PSK-AES256-GCM-SHA384 (%v)", err)
	}
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	srv := exec.Command(openssl, "s_server", "-accept", strconv.Itoa(port),
		"-psk", hex.EncodeToString(psk), "-psk_identity", "",
		"-cipher", "PSK-AES256-GCM-SHA384", "-tls1_2", "-nocert", "-quiet")
	stdin, err := srv.StdinPipe() // held open and never written: the server never sends a byte
	if err != nil {
		t.Fatal(err)
	}
	srv.Stdout = io.Discard
	if err := srv.Start(); err != nil {
		t.Fatalf("start openssl s_server: %v", err)
	}
	defer func() {
		_ = srv.Process.Kill()
		_ = stdin.Close()
		_ = srv.Wait()
	}()

	var conns []net.Conn
	defer func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}()
	toServer := func(ctx context.Context, address string) (net.Conn, error) {
		var c net.Conn
		var err error
		for i := 0; i < 50; i++ {
			if c, err = net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond); err == nil {
				conns = append(conns, c)
				return shortDeadlineConn{Conn: c, max: 2 * time.Second}, nil
			}
			time.Sleep(100 * time.Millisecond)
		}
		return nil, err
	}

	tlsConn, err := dialTunnelPortVia(context.Background(), toServer, "phone", 58783, psk)
	if err != nil {
		t.Fatalf("TLS-PSK against openssl should complete: %v", err)
	}
	result := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := connectStreamedTunnelLockdown(context.Background(), ios.DeviceEntry{}, tlsConn)
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "could not exchange tunnel parameters") {
			t.Fatalf("want the parameter exchange to fail, got %v", err)
		}
		if !errors.Is(err, os.ErrDeadlineExceeded) && !strings.Contains(err.Error(), "timeout") {
			t.Fatalf("want the setup deadline to be what ended it, got %v", err)
		}
		t.Logf("silent peer after TLS-PSK gave up after %v: %v", time.Since(start).Round(time.Millisecond), err)
	case <-time.After(8 * time.Second):
		_ = tlsConn.Close()
		t.Fatal("the CDTunnel exchange on a silent stream is unbounded")
	}
}

// REVIEW FINDING (2026-09-23): verify --via-streams --timeout T took up to 2T (the dial had T, then
// the exchange got a fresh T). The desk may hold the SOCKS reply for most of the budget; the
// exchange must get only what is left.
func TestVerifyRemotePairingViaSpendsOneBudget(t *testing.T) {
	desk := newFakeDesk(t, func(c net.Conn) error {
		if _, err := readSocksRequest(c); err != nil {
			return err
		}
		time.Sleep(time.Second) // the phone takes its time to open the stream
		if _, err := c.Write(socksReply(0x00)); err != nil {
			return err
		}
		return drainUntilClosed(c) // then says nothing
	})
	const budget = 1500 * time.Millisecond
	start := time.Now()
	err := VerifyRemotePairingVia("phone:49152", budget, testPairRecords(t), StreamsDialer(desk.path))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("a silent phone must fail verify")
	}
	var se *StreamsError
	if errors.As(err, &se) {
		t.Fatalf("the stream opened, so this is not a streams failure: %v", err)
	}
	if elapsed > budget+600*time.Millisecond {
		t.Fatalf("verify took %v on a %v budget (the dial and the exchange must share it)", elapsed, budget)
	}
	desk.wait(t, 1)
}
