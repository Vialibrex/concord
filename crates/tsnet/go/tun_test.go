package main

import (
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func reading(t *packetTun, bufs [][]byte, sizes []int) chan error {
	done := make(chan error, 1)
	go func() {
		n, err := t.Read(bufs, sizes, 0)
		if err == nil && n == 0 {
			err = errors.New("read returned nothing")
		}
		done <- err
	}()
	return done
}

func waitReader(t *testing.T, tun *packetTun) {
	t.Helper()
	for range 1000 {
		tun.mu.Lock()
		waiting := tun.reader != nil
		tun.mu.Unlock()
		if waiting {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Read never started waiting")
}

func TestPushWithoutReaderOwesWritable(t *testing.T) {
	var calls atomic.Int32
	tun := newTun(func() { calls.Add(1) })
	if took := tun.push([][]byte{{1}}); took != 0 {
		t.Fatalf("took %d with no Read waiting", took)
	}
	bufs, sizes := [][]byte{make([]byte, 8)}, make([]int, 1)
	done := reading(tun, bufs, sizes)
	waitReader(t, tun)
	if calls.Load() != 1 {
		t.Fatalf("writable called %d times", calls.Load())
	}
	if took := tun.push([][]byte{{7, 8}, {9}}); took != 1 {
		t.Fatalf("took %d into a one-buffer Read", took)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if sizes[0] != 2 || bufs[0][1] != 8 {
		t.Fatalf("read %v %v", sizes, bufs[0][:2])
	}
}

func TestCloseEndsAWaitingRead(t *testing.T) {
	tun := newTun(func() {})
	done := reading(tun, [][]byte{make([]byte, 8)}, make([]int, 1))
	waitReader(t, tun)
	tun.Close()
	if err := <-done; !errors.Is(err, os.ErrClosed) {
		t.Fatalf("got %v", err)
	}
	if took := tun.push([][]byte{{1}}); took != 0 {
		t.Fatalf("took %d after close", took)
	}
}
