//go:build ctstest

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/store/mem"
	"github.com/metacubex/tailscale/tsnet"
	"golang.org/x/net/dns/dnsmessage"
)

// A control server nobody listens on: the node keeps trying, so it is busy when stopped.
const deadControl = "http://127.0.0.1:9"

func nodeJSON(t *testing.T, stateDir string, inMemory bool) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"hostname":        "test",
		"control_url":     deadControl,
		"state_dir":       stateDir,
		"state_in_memory": inMemory,
		"ephemeral":       inMemory,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func startNode(t *testing.T, config string) int64 {
	t.Helper()
	h, why := testStart(config)
	if h <= 0 {
		t.Fatalf("cts_start refused the node: %s", why)
	}
	return h
}

// stopAndWatch stops the node and fails the test if a callback arrives after cts_stop returned.
func stopAndWatch(t *testing.T, h int64) {
	t.Helper()
	testStop(h)
	testMarkStopped()
	time.Sleep(500 * time.Millisecond)
	if late := testLateCalls(); late != 0 {
		t.Fatalf("%d callbacks ran after cts_stop returned", late)
	}
}

func TestStoppingANodeWhoseStartFailedDoesNotCrash(t *testing.T) {
	testReset()
	file := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	h := startNode(t, nodeJSON(t, file, false))
	deadline := time.Now().Add(10 * time.Second)
	for testFailedEvents() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if testFailedEvents() == 0 {
		t.Fatal("a state directory that is a file did not fail the start")
	}
	stopAndWatch(t, h)
}

func TestNoCallbackRunsAfterANodeStoppedWhileStarting(t *testing.T) {
	for _, after := range []time.Duration{0, time.Millisecond, 10 * time.Millisecond, 50 * time.Millisecond, 300 * time.Millisecond} {
		testReset()
		h := startNode(t, nodeJSON(t, t.TempDir(), true))
		time.Sleep(after)
		stopAndWatch(t, h)
	}
}

func dnsQuery(t *testing.T) []byte {
	t.Helper()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("peer.tailnet.test."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAQueryInFlightDoesNotAnswerAfterStop(t *testing.T) {
	testReset()
	h := startNode(t, nodeJSON(t, t.TempDir(), true))
	time.Sleep(200 * time.Millisecond)
	if testFailedEvents() != 0 {
		t.Fatalf("the node did not start: %s", testLastFailure())
	}
	if testQuery(h, 1, dnsQuery(t)) != 0 {
		t.Fatal("a running node refused a query")
	}
	stopAndWatch(t, h)
	if testQuery(h, 2, dnsQuery(t)) != -1 {
		t.Fatal("a stopped node took a query it will never answer")
	}
}

func TestALinkChangeBeforeOrDuringStopIsHarmless(t *testing.T) {
	for _, after := range []time.Duration{0, 300 * time.Millisecond} {
		testReset()
		h := startNode(t, nodeJSON(t, t.TempDir(), true))
		testLinkChanged(h)
		time.Sleep(after)
		if testFailedEvents() != 0 {
			t.Fatalf("the node did not start: %s", testLastFailure())
		}
		testLinkChanged(h)
		stopAndWatch(t, h)
		testLinkChanged(h)
	}
}

func TestWriteDeliversInBatchesAndSkipsEmptyBuffers(t *testing.T) {
	testReset()
	tun := testTun()
	defer tun.free()
	bufs := make([][]byte, 300)
	want := int64(0)
	for i := range bufs {
		if i%7 == 3 {
			bufs[i] = make([]byte, 4)
			continue
		}
		bufs[i] = make([]byte, 4+40)
		want++
	}
	n, err := tun.Write(bufs, 4)
	if err != nil || n != len(bufs) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	packets, batches := testDelivered()
	if packets != want || batches != (want+tunBatch-1)/tunBatch {
		t.Fatalf("delivered %d packets in %d calls, want %d in %d", packets, batches, want, (want+tunBatch-1)/tunBatch)
	}
}

func TestWriteAfterTheBuffersAreFreedIsClosed(t *testing.T) {
	tun := testTun()
	tun.free()
	if _, err := tun.Write([][]byte{make([]byte, 20)}, 0); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after free = %v", err)
	}
}

func TestQueryDNSDoesNotStartANodeWhoseStartWasSkipped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	startDone := make(chan struct{})
	close(startDone)
	s := &tsnet.Server{
		Dir:        t.TempDir(),
		Hostname:   "test",
		ControlURL: deadControl,
		Ephemeral:  true,
		Store:      new(mem.Store),
		Logf:       func(string, ...any) {},
		UserLogf:   func(string, ...any) {},
	}
	defer func() {
		if s.Sys() != nil {
			_ = s.Close()
		}
	}()
	n := &node{
		server:    s,
		ctx:       ctx,
		cancel:    cancel,
		startDone: startDone,
		started:   false,
	}
	if _, err := n.queryDNS(dnsQuery(t)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("queryDNS on unstarted node = %v, want net.ErrClosed", err)
	}
	if s.Sys() != nil {
		t.Fatal("queryDNS implicitly started tsnet.Server when Start was skipped")
	}
}

func TestLinkChangeBeforeStartCompletesIsDeliveredOnceStarted(t *testing.T) {
	testReset()
	makeNode := func() (*node, int64) {
		ctx, cancel := context.WithCancel(context.Background())
		n := &node{
			cb:        testCallbacks(),
			gate:      newGate(),
			ctx:       ctx,
			cancel:    cancel,
			tun:       testTun(),
			startDone: make(chan struct{}),
		}
		n.server = &tsnet.Server{
			Dir:        t.TempDir(),
			Hostname:   "test",
			ControlURL: deadControl,
			Ephemeral:  true,
			Tun:        n.tun,
			Store:      new(mem.Store),
			UserLogf:   func(string, ...any) {},
			Logf:       func(string, ...any) {},
		}
		id := nextID.Add(1)
		nodesMu.Lock()
		nodes[id] = n
		nodesMu.Unlock()
		return n, id
	}

	queued, qid := makeNode()
	defer stopAndWatch(t, qid)
	testLinkChanged(qid)
	testLinkChanged(qid)
	queued.wg.Add(1)
	go queued.run()

	deadline := time.Now().Add(3 * time.Second)
	for queued.linkChanges.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got := queued.linkChanges.Load(); got != 1 {
		t.Fatalf("queued link changes delivered = %d, want 1", got)
	}

	quiet, quietID := makeNode()
	defer stopAndWatch(t, quietID)
	quiet.wg.Add(1)
	go quiet.run()
	<-quiet.startDone
	time.Sleep(200 * time.Millisecond)
	if got := quiet.linkChanges.Load(); got != 0 {
		t.Fatalf("unexpected link changes without cts_link_changed = %d", got)
	}
}

func TestAddrsTrackerTransitions(t *testing.T) {
	statePtr := func(s ipn.State) *ipn.State { return &s }
	v4a := netip.MustParseAddr("100.64.0.2")
	v4b := netip.MustParseAddr("100.64.0.3")

	steps := []struct {
		name           string
		loginURL       bool
		state          *ipn.State
		v4             netip.Addr
		wantCheckAddrs bool
		wantStartLogin bool
		wantEmit       bool
		wantIPv4       string
	}{
		{
			name:  "startup NoState does nothing",
			state: statePtr(ipn.NoState),
		},
		{
			name:  "startup NeedsLogin before Running does not call StartLoginInteractive",
			state: statePtr(ipn.NeedsLogin),
		},
		{
			name: "nil state while NeedsLogin does not check addrs",
		},
		{
			name:           "first Running emits initial address",
			state:          statePtr(ipn.Running),
			v4:             v4a,
			wantCheckAddrs: true,
			wantEmit:       true,
			wantIPv4:       "100.64.0.2",
		},
		{
			name:           "nil state while Running with unchanged IP suppresses duplicate",
			v4:             v4a,
			wantCheckAddrs: true,
			wantEmit:       false,
		},
		{
			name:           "nil state while Running with new IP emits update",
			v4:             v4b,
			wantCheckAddrs: true,
			wantEmit:       true,
			wantIPv4:       "100.64.0.3",
		},
		{
			name:           "Running to NeedsLogin triggers StartLoginInteractive once",
			state:          statePtr(ipn.NeedsLogin),
			wantStartLogin: true,
		},
		{
			name:  "repeated NeedsLogin without re-entering Running does not re-trigger",
			state: statePtr(ipn.NeedsLogin),
		},
		{
			name:           "same-IP recovery after NeedsLogin re-emits ADDRS and rearms tracker",
			state:          statePtr(ipn.Running),
			v4:             v4b,
			wantCheckAddrs: true,
			wantEmit:       true,
			wantIPv4:       "100.64.0.3",
		},
		{
			name:     "LoginURL followed by NeedsLogin skips duplicate StartLoginInteractive",
			loginURL: true,
			state:    statePtr(ipn.NeedsLogin),
		},
		{
			name:           "same-IP recovery after LoginURL re-emits ADDRS and rearms tracker",
			state:          statePtr(ipn.Running),
			v4:             v4b,
			wantCheckAddrs: true,
			wantEmit:       true,
			wantIPv4:       "100.64.0.3",
		},
		{
			name:           "second Running to NeedsLogin triggers StartLoginInteractive again",
			state:          statePtr(ipn.NeedsLogin),
			wantStartLogin: true,
		},
	}

	var tr addrsTracker
	for _, step := range steps {
		if step.loginURL {
			tr.onLoginURL()
		}
		act := tr.onNotify(step.state)
		if act.checkAddrs != step.wantCheckAddrs || act.startLogin != step.wantStartLogin {
			t.Fatalf("%s: onNotify = %+v, want checkAddrs=%v startLogin=%v",
				step.name, act, step.wantCheckAddrs, step.wantStartLogin)
		}
		if !act.checkAddrs {
			continue
		}
		addrs, emit := tr.onAddrs(step.v4, netip.Addr{})
		if emit != step.wantEmit || addrs.IPv4 != step.wantIPv4 {
			t.Fatalf("%s: onAddrs = (%+v, %v), want (%q, %v)",
				step.name, addrs, emit, step.wantIPv4, step.wantEmit)
		}
	}
}
