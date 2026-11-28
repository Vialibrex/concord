package main

/*
#include <stdlib.h>
#include "cts.h"
*/
import "C"

import (
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/metacubex/tailscale-wireguard-go/tun"
)

const (
	tunMTU   = 1280
	tunBatch = C.CTS_BATCH
)

// packetTun is the tun.Device wireguard-go reads Concord's packets from and writes the
// tailnet's packets to. Concord's own userspace stack sits on the other side of the C ABI.
//
// Outbound packets are copied once, by cts_send straight into the buffers of the Read that
// waits for them; with no Read waiting, cts_send takes nothing and Concord keeps the packets
// queued in its stack until `writable`.
type packetTun struct {
	cb       *C.cts_callbacks
	gate     *gate
	writable func()
	events   chan tun.Event
	closed   chan struct{}
	once     sync.Once

	mu      sync.Mutex
	reader  *pendingRead
	starved bool
	read    pendingRead
	// views is cts_send's, which Concord calls from one task at a time.
	views [tunBatch][]byte

	writeMu sync.Mutex
	// ptrs and lens are C memory for deliver; free clears them.
	ptrs   *C.uintptr_t
	lens   *C.size_t
	pinner runtime.Pinner
}

// pendingRead is wireguard-go's Read while it waits; only one goroutine reads the device.
type pendingRead struct {
	bufs   [][]byte
	sizes  []int
	offset int
	n      int
	done   chan struct{}
}

func newPacketTun(cb *C.cts_callbacks, g *gate) *packetTun {
	t := newTun(func() {
		if g.enter() {
			C.cts_call_writable(cb)
			g.leave()
		}
	})
	t.cb, t.gate = cb, g
	t.ptrs = (*C.uintptr_t)(C.malloc(C.size_t(tunBatch) * C.size_t(unsafe.Sizeof(C.uintptr_t(0)))))
	t.lens = (*C.size_t)(C.malloc(C.size_t(tunBatch) * C.size_t(unsafe.Sizeof(C.size_t(0)))))
	return t
}

func newTun(writable func()) *packetTun {
	t := &packetTun{
		writable: writable,
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
		read:     pendingRead{done: make(chan struct{}, 1)},
	}
	t.events <- tun.EventUp
	return t
}

// send views Concord's packets in place, valid for the call, and pushes them.
func (t *packetTun) send(packets []unsafe.Pointer, lens []C.size_t) int {
	n := min(len(packets), tunBatch)
	for i := range n {
		t.views[i] = unsafe.Slice((*byte)(packets[i]), int(lens[i]))
	}
	took := t.push(t.views[:n])
	clear(t.views[:n])
	return took
}

// push copies packets handed over by Concord into the waiting Read and returns how many it
// took; with no Read waiting it takes none and owes Concord a `writable` call.
func (t *packetTun) push(packets [][]byte) int {
	t.mu.Lock()
	r := t.reader
	t.reader = nil
	if r == nil {
		select {
		case <-t.closed:
		default:
			t.starved = true
		}
	}
	t.mu.Unlock()
	if r == nil {
		return 0
	}
	n := min(len(packets), len(r.bufs))
	for i := range n {
		r.sizes[i] = copy(r.bufs[i][r.offset:], packets[i])
	}
	r.n = n
	r.done <- struct{}{}
	return n
}

func (t *packetTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	r := &t.read
	r.bufs, r.sizes, r.offset = bufs, sizes, offset
	t.mu.Lock()
	t.reader = r
	starved := t.starved
	t.starved = false
	t.mu.Unlock()
	if starved && !t.isClosed() {
		t.writable()
	}
	select {
	case <-r.done:
		return r.n, nil
	case <-t.closed:
	}
	t.mu.Lock()
	taken := t.reader != r
	t.reader = nil
	t.mu.Unlock()
	if taken {
		<-r.done
		return r.n, nil
	}
	return 0, os.ErrClosed
}

// Write hands wireguard-go's decrypted packets to Concord in one call; the buffers are pinned
// for the call only, and Concord copies them before it returns.
func (t *packetTun) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	default:
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if t.ptrs == nil || !t.gate.enter() {
		return 0, os.ErrClosed
	}
	defer t.gate.leave()
	ptrs := unsafe.Slice(t.ptrs, tunBatch)
	lens := unsafe.Slice(t.lens, tunBatch)
	done := 0
	for done < len(bufs) {
		n := 0
		for n < tunBatch && done+n < len(bufs) {
			p := bufs[done+n][offset:]
			if len(p) == 0 {
				done++
				continue
			}
			t.pinner.Pin(&p[0])
			ptrs[n] = C.uintptr_t(uintptr(unsafe.Pointer(&p[0])))
			lens[n] = C.size_t(len(p))
			n++
		}
		if n > 0 {
			C.cts_call_deliver(t.cb, (**C.uint8_t)(unsafe.Pointer(t.ptrs)), t.lens, C.size_t(n))
			t.pinner.Unpin()
		}
		done += n
	}
	return len(bufs), nil
}

func (t *packetTun) MTU() (int, error)        { return tunMTU, nil }
func (t *packetTun) Name() (string, error)    { return "concord", nil }
func (t *packetTun) Events() <-chan tun.Event { return t.events }
func (t *packetTun) BatchSize() int           { return tunBatch }
func (t *packetTun) File() *os.File           { return nil }

func (t *packetTun) Close() error {
	t.once.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

func (t *packetTun) isClosed() bool {
	select {
	case <-t.closed:
		return true
	default:
		return false
	}
}

func (t *packetTun) free() {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	C.free(unsafe.Pointer(t.ptrs))
	C.free(unsafe.Pointer(t.lens))
	t.ptrs, t.lens = nil, nil
}
