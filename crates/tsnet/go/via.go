package main

/*
#include "cts.h"
*/
import "C"

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
	"unsafe"
)

// via carries the node's own connections (control, DERP, WireGuard's UDP) through Concord
// when the node has a dialer-proxy, as mihomo hands tsnet's SystemDialer and
// SystemPacketListener to a dialer that honours it.
type via struct {
	cb   *C.cts_callbacks
	gate *gate
}

var errViaFailed = errors.New("concord: the connection through the dialer-proxy failed")

func newVia(cb *C.cts_callbacks, g *gate) *via {
	return &via{cb: cb, gate: g}
}

func (v *via) open(ctx context.Context, datagram bool, address string) (viaEnd, error) {
	if !v.gate.enter() {
		return viaEnd{}, net.ErrClosed
	}
	defer v.gate.leave()
	timeout := int64(-1)
	if deadline, ok := ctx.Deadline(); ok {
		timeout = max(time.Until(deadline).Milliseconds(), 0)
	}
	dg := C.int32_t(0)
	if datagram {
		dg = 1
	}
	p, l := cstr(address)
	id := C.cts_call_conn_open(v.cb, dg, p, l, C.int64_t(timeout))
	if id <= 0 {
		return viaEnd{}, errViaFailed
	}
	return viaEnd{v: v, id: id, closed: new(atomic.Bool)}, nil
}

func (v *via) dial(ctx context.Context, network, address string) (net.Conn, error) {
	end, err := v.open(ctx, false, address)
	if err != nil {
		return nil, err
	}
	return &viaConn{viaEnd: end, remote: viaAddr{network, address}}, nil
}

func (v *via) listenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	local := &net.UDPAddr{IP: net.IPv4zero}
	hint := "0.0.0.0:0"
	if network == "udp6" {
		local, hint = &net.UDPAddr{IP: net.IPv6zero}, "[::]:0"
	}
	end, err := v.open(ctx, true, hint)
	if err != nil {
		return nil, err
	}
	return &viaPacketConn{viaEnd: end, local: local}, nil
}

type viaEnd struct {
	v      *via
	id     C.int64_t
	closed *atomic.Bool
}

func bytesPtr(p []byte) *C.uint8_t {
	return (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(p)))
}

func outcome(got C.int64_t) (int, error) {
	switch {
	case got >= 0:
		return int(got), nil
	case got == C.CTS_IO_TIMEOUT:
		return 0, os.ErrDeadlineExceeded
	case got == C.CTS_IO_CLOSED:
		return 0, net.ErrClosed
	default:
		return 0, errViaFailed
	}
}

func (e viaEnd) read(p []byte, from []byte) (int, int, error) {
	if e.closed.Load() || !e.v.gate.enter() {
		return 0, 0, net.ErrClosed
	}
	defer e.v.gate.leave()
	fromLen := C.size_t(len(from))
	got := C.cts_call_conn_read(e.v.cb, e.id, bytesPtr(p), C.size_t(len(p)),
		(*C.char)(unsafe.Pointer(unsafe.SliceData(from))), &fromLen)
	if got < 0 && e.closed.Load() {
		return 0, 0, net.ErrClosed
	}
	n, err := outcome(got)
	return n, int(fromLen), err
}

func (e viaEnd) write(p []byte, to string) (int, error) {
	if e.closed.Load() || !e.v.gate.enter() {
		return 0, net.ErrClosed
	}
	defer e.v.gate.leave()
	tp, tl := cstr(to)
	got := C.cts_call_conn_write(e.v.cb, e.id, bytesPtr(p), C.size_t(len(p)), tp, tl)
	if got < 0 && e.closed.Load() {
		return 0, net.ErrClosed
	}
	return outcome(got)
}

func (e viaEnd) deadline(dir C.int32_t, t time.Time) error {
	ns := int64(-1)
	if !t.IsZero() {
		ns = max(int64(time.Until(t)), 0)
	}
	if e.closed.Load() || !e.v.gate.enter() {
		return net.ErrClosed
	}
	defer e.v.gate.leave()
	C.cts_call_conn_deadline(e.v.cb, e.id, dir, C.int64_t(ns))
	return nil
}

func (e viaEnd) Close() error {
	if e.closed.Swap(true) {
		return net.ErrClosed
	}
	if e.v.gate.enter() {
		C.cts_call_conn_close(e.v.cb, e.id)
		e.v.gate.leave()
	}
	return nil
}

func (e viaEnd) SetDeadline(t time.Time) error      { return e.deadline(C.CTS_IO_BOTH, t) }
func (e viaEnd) SetReadDeadline(t time.Time) error  { return e.deadline(C.CTS_IO_READ, t) }
func (e viaEnd) SetWriteDeadline(t time.Time) error { return e.deadline(C.CTS_IO_WRITE, t) }

type viaAddr struct{ network, address string }

func (a viaAddr) Network() string { return a.network }
func (a viaAddr) String() string  { return a.address }

type viaConn struct {
	viaEnd
	remote net.Addr
}

func (c *viaConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	n, _, err := c.read(p, nil)
	if n == 0 && err == nil {
		return 0, io.EOF
	}
	return n, err
}

func (c *viaConn) Write(p []byte) (int, error) {
	done := 0
	for done < len(p) {
		n, err := c.write(p[done:], "")
		done += n
		if err != nil {
			return done, err
		}
	}
	return done, nil
}

func (c *viaConn) LocalAddr() net.Addr  { return viaAddr{c.remote.Network(), ""} }
func (c *viaConn) RemoteAddr() net.Addr { return c.remote }

// viaPacketConn is a UDP socket of the node; Concord's session sends to any address.
type viaPacketConn struct {
	viaEnd
	local *net.UDPAddr
}

func (c *viaPacketConn) ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error) {
	var from [64]byte
	n, l, err := c.read(p, from[:])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	addr, err := netip.ParseAddrPort(string(from[:l]))
	return n, addr, err
}

func (c *viaPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.ReadFromUDPAddrPort(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(addr), nil
}

func (c *viaPacketConn) WriteToUDPAddrPort(p []byte, addr netip.AddrPort) (int, error) {
	return c.write(p, addr.String())
}

func (c *viaPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.write(p, addr.String())
}

func (c *viaPacketConn) LocalAddr() net.Addr { return c.local }
