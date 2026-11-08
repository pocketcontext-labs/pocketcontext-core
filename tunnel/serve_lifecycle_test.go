package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/tailscale/tailcat"
)

func TestServeCancelledBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := ServeBackend(ctx, 8096, nil, func(tailcat.Addr) { t.Error("reported ready after cancellation") }, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestServeProxyCancellationClosesBothEnds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local, backend := net.Pipe()
	defer local.Close()
	defer backend.Close()
	done := make(chan error, 1)
	go func() { done <- serveTunnelConnections(ctx, ln, func() (net.Conn, error) { return local, nil }) }()
	remote, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if _, err := remote.Write([]byte("test")); err != nil {
		t.Fatal(err)
	}
	backend.SetReadDeadline(time.Now().Add(5 * time.Second))
	var payload [4]byte
	if _, err := io.ReadFull(backend, payload[:]); err != nil || string(payload[:]) != "test" {
		t.Fatalf("proxy did not carry data: %q %v", payload, err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("proxy handlers did not finish after cancellation")
	}
	for _, conn := range []net.Conn{remote, backend} {
		conn.SetReadDeadline(time.Now().Add(time.Second))
		_, err := conn.Read(payload[:])
		if err == nil {
			t.Fatal("proxy end remained open")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatalf("proxy end timed out instead of closing: %v", err)
		}
	}
}

func TestServeListenerFailurePropagates(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	err = serveTunnelConnections(context.Background(), ln, func() (net.Conn, error) {
		t.Error("closed listener attempted a backend connection")
		return nil, errors.New("unexpected dial")
	})
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("lost listener failure: %v", err)
	}
}
