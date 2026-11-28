//go:build ctstest

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	testReset()
	h := startNode(t, nodeJSON(t, t.TempDir(), true))
	time.Sleep(300 * time.Millisecond)
	if testFailedEvents() != 0 {
		t.Fatalf("the node did not start: %s", testLastFailure())
	}
	testLinkChanged(h)
	stopAndWatch(t, h)
	testLinkChanged(h)
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
