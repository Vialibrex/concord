//go:build ctstest

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/tailscale-wireguard-go/conn"
	"github.com/metacubex/tailscale-wireguard-go/device"
	"github.com/metacubex/tailscale-wireguard-go/tun"
)

type stubEndpoint netip.AddrPort

func (e stubEndpoint) ClearSrc()           {}
func (e stubEndpoint) SrcToString() string { return "" }
func (e stubEndpoint) DstToString() string { return netip.AddrPort(e).String() }
func (e stubEndpoint) DstToBytes() []byte  { return nil }
func (e stubEndpoint) DstIP() netip.Addr   { return netip.AddrPort(e).Addr() }
func (e stubEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type stubTun struct {
	events chan tun.Event
	closed chan struct{}
	once   sync.Once
}

func newStubTun() *stubTun {
	return &stubTun{
		events: make(chan tun.Event, 1),
		closed: make(chan struct{}),
	}
}

func (s *stubTun) File() *os.File { return nil }
func (s *stubTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-s.closed
	return 0, os.ErrClosed
}
func (s *stubTun) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }
func (s *stubTun) MTU() (int, error)                            { return 1280, nil }
func (s *stubTun) Name() (string, error)                        { return "stub", nil }
func (s *stubTun) Events() <-chan tun.Event                     { return s.events }
func (s *stubTun) BatchSize() int                               { return 1 }
func (s *stubTun) Close() error {
	s.once.Do(func() {
		close(s.closed)
		close(s.events)
	})
	return nil
}

type viaBind struct {
	mu       sync.Mutex
	pc       *viaPacketConn
	received atomic.Int64
	gotPkt   chan struct{}
}

func (b *viaBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	raw, err := testVia().listenPacket(context.Background(), "udp4", "")
	if err != nil {
		return nil, 0, err
	}
	pc := raw.(*viaPacketConn)
	b.mu.Lock()
	b.pc = pc
	b.mu.Unlock()
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := pc.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = stubEndpoint(addr)
		if b.received.Add(1) == 1 && b.gotPkt != nil {
			close(b.gotPkt)
		}
		return 1, nil
	}
	return []conn.ReceiveFunc{fn}, 1, nil
}

func (b *viaBind) Close() error {
	b.mu.Lock()
	pc := b.pc
	b.pc = nil
	b.mu.Unlock()
	if pc == nil {
		return nil
	}
	return pc.Close()
}
func (b *viaBind) SetMark(mark uint32) error { return nil }
func (b *viaBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	ap := netip.AddrPort(ep.(stubEndpoint))
	for _, buf := range bufs {
		if _, err := pc.WriteToUDPAddrPort(buf[offset:], ap); err != nil {
			return err
		}
	}
	return nil
}
func (b *viaBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	return stubEndpoint(ap), err
}
func (b *viaBind) BatchSize() int { return 1 }

func TestWireGuardReceiveExitsAfterRepeatedViaFailures(t *testing.T) {
	var reads atomic.Int64
	var failMode atomic.Bool
	failMode.Store(true)
	stopped := make(chan struct{})
	var stopOnce sync.Once
	var failedLogs atomic.Int64

	setTestViaOps(&testViaOps{
		open: func(datagram bool, addr string, timeout int64) int64 { return 1 },
		read: func(conn int64, buf []byte) (int64, string) {
			reads.Add(1)
			if failMode.Load() {
				return testIoFailed, ""
			}
			n := copy(buf, []byte("late-packet-after-deathspiral"))
			return int64(n), "192.0.2.1:41641"
		},
		write: func(conn int64, data []byte, to string) int64 { return int64(len(data)) },
		close: func(conn int64) {},
	})
	defer setTestViaOps(nil)

	bind := &viaBind{}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			line := fmt.Sprintf(format, args...)
			if strings.Contains(line, "Failed to receive") && strings.Contains(line, errViaFailed.Error()) {
				failedLogs.Add(1)
			}
			if strings.Contains(line, "Routine: receive incoming") && strings.Contains(line, "stopped") {
				stopOnce.Do(func() { close(stopped) })
			}
		},
		Errorf: func(string, ...any) {},
	}
	dev := device.NewDevice(newStubTun(), bind, logger)
	defer dev.Close()
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatalf("RoutineReceiveIncoming did not exit after repeated errViaFailed (reads=%d, logs=%d)", reads.Load(), failedLogs.Load())
	}
	if reads.Load() != 11 || failedLogs.Load() != 11 {
		t.Fatalf("expected 11 failed reads before deathSpiral exit, got reads=%d logs=%d", reads.Load(), failedLogs.Load())
	}

	failMode.Store(false)
	time.Sleep(100 * time.Millisecond)
	if reads.Load() != 11 || bind.received.Load() != 0 {
		t.Fatalf("expected dead receive loop to stay exited, got reads=%d received=%d", reads.Load(), bind.received.Load())
	}
}

func TestViaPacketConnCloseEndsBlockedReadWithNetErrClosed(t *testing.T) {
	reading := make(chan struct{})
	closed := make(chan struct{})
	var closeOnce sync.Once

	setTestViaOps(&testViaOps{
		open: func(datagram bool, addr string, timeout int64) int64 { return 1 },
		read: func(conn int64, buf []byte) (int64, string) {
			close(reading)
			<-closed
			return testIoFailed, ""
		},
		close: func(conn int64) {
			closeOnce.Do(func() { close(closed) })
		},
	})
	defer setTestViaOps(nil)

	raw, err := testVia().listenPacket(context.Background(), "udp4", "")
	if err != nil {
		t.Fatal(err)
	}
	pc := raw.(*viaPacketConn)
	errCh := make(chan error, 1)
	go func() {
		var buf [64]byte
		_, _, err := pc.ReadFromUDPAddrPort(buf[:])
		errCh <- err
	}()
	<-reading
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFromUDPAddrPort after Close = %v, want net.ErrClosed", err)
	}
}

func TestViaPacketConnHostClosedReturnsNetErrClosed(t *testing.T) {
	setTestViaOps(&testViaOps{
		open:  func(datagram bool, addr string, timeout int64) int64 { return 1 },
		read:  func(conn int64, buf []byte) (int64, string) { return testIoClosed, "" },
		write: func(conn int64, data []byte, to string) int64 { return testIoClosed },
		close: func(conn int64) {},
	})
	defer setTestViaOps(nil)

	raw, err := testVia().listenPacket(context.Background(), "udp4", "")
	if err != nil {
		t.Fatal(err)
	}
	pc := raw.(*viaPacketConn)
	defer pc.Close()
	var buf [64]byte
	if _, _, err := pc.ReadFromUDPAddrPort(buf[:]); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFromUDPAddrPort on host close = %v, want net.ErrClosed", err)
	}
	if _, err := pc.WriteToUDPAddrPort([]byte("x"), netip.MustParseAddrPort("192.0.2.2:41641")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteToUDPAddrPort on host close = %v, want net.ErrClosed", err)
	}
}

func TestWireGuardReceiveSurvivesReconnectWaitAndStopsOnClose(t *testing.T) {
	deliver := make(chan []byte, 1)
	closed := make(chan struct{})
	var closeOnce sync.Once
	var failedLogs atomic.Int64

	setTestViaOps(&testViaOps{
		open: func(datagram bool, addr string, timeout int64) int64 { return 1 },
		read: func(conn int64, buf []byte) (int64, string) {
			select {
			case pkt := <-deliver:
				return int64(copy(buf, pkt)), "192.0.2.2:41641"
			case <-closed:
				return testIoClosed, ""
			}
		},
		write: func(conn int64, data []byte, to string) int64 { return int64(len(data)) },
		close: func(conn int64) {
			closeOnce.Do(func() { close(closed) })
		},
	})
	defer setTestViaOps(nil)

	gotPkt := make(chan struct{})
	bind := &viaBind{gotPkt: gotPkt}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			if strings.Contains(fmt.Sprintf(format, args...), "Failed to receive") {
				failedLogs.Add(1)
			}
		},
		Errorf: func(string, ...any) {},
	}
	dev := device.NewDevice(newStubTun(), bind, logger)
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}

	bind.mu.Lock()
	pc := bind.pc
	bind.mu.Unlock()
	if _, err := pc.WriteToUDPAddrPort([]byte("probe"), netip.MustParseAddrPort("192.0.2.2:41641")); err != nil {
		t.Fatalf("WriteToUDPAddrPort during reconnect = %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	deliver <- []byte("recovered-packet")

	select {
	case <-gotPkt:
	case <-time.After(3 * time.Second):
		t.Fatal("RoutineReceiveIncoming did not receive packet after reconnect wait")
	}

	dev.Close()
	if failedLogs.Load() != 0 {
		t.Fatalf("expected 0 receive errors across reconnect wait and Close, got %d", failedLogs.Load())
	}
}
