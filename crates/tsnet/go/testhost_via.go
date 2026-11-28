//go:build ctstest

package main

/*
#include "cts.h"
*/
import "C"

import (
	"sync"
	"unsafe"
)

const (
	testIoFailed = int64(C.CTS_IO_FAILED)
	testIoClosed = int64(C.CTS_IO_CLOSED)
)

type testViaOps struct {
	open  func(datagram bool, addr string, timeout int64) int64
	read  func(conn int64, buf []byte) (n int64, from string)
	write func(conn int64, data []byte, to string) int64
	close func(conn int64)
}

var (
	testViaMu  sync.RWMutex
	testViaCur *testViaOps
)

func setTestViaOps(ops *testViaOps) {
	testViaMu.Lock()
	testViaCur = ops
	testViaMu.Unlock()
}

func currentTestViaOps() *testViaOps {
	testViaMu.RLock()
	ops := testViaCur
	testViaMu.RUnlock()
	return ops
}

//export cts_test_go_via_open
func cts_test_go_via_open(d C.int32_t, a *C.char, l C.size_t, t C.int64_t) C.int64_t {
	if ops := currentTestViaOps(); ops != nil && ops.open != nil {
		return C.int64_t(ops.open(d != 0, C.GoStringN(a, C.int(l)), int64(t)))
	}
	return 0
}

//export cts_test_go_via_read
func cts_test_go_via_read(c C.int64_t, b *C.uint8_t, capLen C.size_t, f *C.char, fl *C.size_t) C.int64_t {
	ops := currentTestViaOps()
	if ops == nil || ops.read == nil {
		return C.CTS_IO_FAILED
	}
	var dst []byte
	if b != nil && capLen > 0 {
		dst = unsafe.Slice((*byte)(unsafe.Pointer(b)), int(capLen))
	}
	n, from := ops.read(int64(c), dst)
	if fl != nil {
		if f != nil && *fl > 0 && len(from) > 0 {
			out := unsafe.Slice((*byte)(unsafe.Pointer(f)), int(*fl))
			copied := copy(out, from)
			*fl = C.size_t(copied)
		} else {
			*fl = 0
		}
	}
	return C.int64_t(n)
}

//export cts_test_go_via_write
func cts_test_go_via_write(c C.int64_t, b *C.uint8_t, l C.size_t, t *C.char, tl C.size_t) C.int64_t {
	ops := currentTestViaOps()
	if ops == nil || ops.write == nil {
		return C.CTS_IO_FAILED
	}
	var data []byte
	if b != nil && l > 0 {
		data = unsafe.Slice((*byte)(unsafe.Pointer(b)), int(l))
	}
	return C.int64_t(ops.write(int64(c), data, C.GoStringN(t, C.int(tl))))
}

//export cts_test_go_via_close
func cts_test_go_via_close(c C.int64_t) {
	if ops := currentTestViaOps(); ops != nil && ops.close != nil {
		ops.close(int64(c))
	}
}
