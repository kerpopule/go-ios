package installationproxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/danielpaulus/go-ios/ios"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"howett.net/plist"
)

func shimWrite(w io.Writer, v any) error {
	payload, err := plist.Marshal(v, plist.XMLFormat)
	if err != nil {
		return err
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint32(len(payload)))
	buf.Write(payload)
	_, err = w.Write(buf.Bytes())
	return err
}

func shimRead(r io.Reader) (map[string]any, error) {
	var n uint32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	var m map[string]any
	_, err := plist.Unmarshal(payload, &m)
	return m, err
}

// fakeInstallProxyShim is the device side of the shim: it answers the
// RSDCheckin exchange, then answers every Browse with one Complete chunk
// holding one app named after the ApplicationType asked for.
func fakeInstallProxyShim(t *testing.T) (port int, got chan map[string]any) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	got = make(chan map[string]any, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				checkin, err := shimRead(c)
				if err != nil {
					return
				}
				got <- checkin
				shimWrite(c, map[string]any{"Request": "RSDCheckin"})
				shimWrite(c, map[string]any{"Request": "StartService"})
				for {
					req, err := shimRead(c)
					if err != nil {
						return
					}
					got <- req
					kind := ""
					if opts, ok := req["ClientOptions"].(map[string]any); ok {
						kind, _ = opts["ApplicationType"].(string)
					}
					shimWrite(c, browseResponsePlist("Complete", 0, 1,
						[]map[string]interface{}{{"CFBundleIdentifier": "com.example." + kind}}))
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, got
}

func shimDevice(port int) ios.DeviceEntry {
	return ios.DeviceEntry{
		Address: "127.0.0.1",
		Rsd: ios.RsdHandshakeResponse{Services: map[string]ios.RsdServiceEntry{
			ShimServiceName: {Port: uint32(port)},
		}},
	}
}

// The shim road checks in first and then speaks the same Browse protocol New's
// usbmuxd road does, over a plain connection: no lockdown, no pair record.
func TestNewWithShimConnectionChecksInThenBrowses(t *testing.T) {
	port, got := fakeInstallProxyShim(t)
	conn, err := NewWithShimConnection(shimDevice(port))
	require.NoError(t, err)
	defer conn.Close()
	assert.Equal(t, "RSDCheckin", (<-got)["Request"])

	apps, err := conn.BrowseUserApps()
	require.NoError(t, err)
	require.Len(t, apps, 1)
	assert.Equal(t, "com.example.User", apps[0].CFBundleIdentifier())
	assert.Equal(t, "Browse", (<-got)["Command"])
}

func TestNewWithConnectionWrapsABoundedShimConnection(t *testing.T) {
	port, got := fakeInstallProxyShim(t)
	dc, err := ios.ConnectToShimServiceWithTimeout(shimDevice(port), ShimServiceName, 2*time.Second)
	require.NoError(t, err)
	conn := NewWithConnection(dc)
	defer conn.Close()
	<-got
	apps, err := conn.BrowseSystemApps()
	require.NoError(t, err)
	require.Len(t, apps, 1)
	assert.Equal(t, "com.example.System", apps[0].CFBundleIdentifier())
}

func TestNewWithShimConnectionNeedsTheShimInRsd(t *testing.T) {
	d := ios.DeviceEntry{Address: "127.0.0.1", Rsd: ios.RsdHandshakeResponse{Services: map[string]ios.RsdServiceEntry{}}}
	_, err := NewWithShimConnection(d)
	require.Error(t, err)
	assert.Contains(t, err.Error(), ShimServiceName)
}
