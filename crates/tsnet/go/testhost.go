//go:build ctstest

package main

/*
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "cts.h"

static atomic_long cts_test_calls, cts_test_late, cts_test_failed, cts_test_packets, cts_test_batches;
static atomic_int cts_test_stopped;
static char cts_test_failure[256];

static void cts_test_note(void) {
    atomic_fetch_add(&cts_test_calls, 1);
    if (atomic_load(&cts_test_stopped)) atomic_fetch_add(&cts_test_late, 1);
}
static void t_deliver(void *u, const uint8_t *const *p, const size_t *l, size_t n) {
    cts_test_note();
    atomic_fetch_add(&cts_test_batches, 1);
    atomic_fetch_add(&cts_test_packets, (long)n);
}
static void t_writable(void *u) { cts_test_note(); }
static int32_t t_prepare(void *u, int64_t fd, int32_t f, int32_t d, const char *a, size_t l) {
    cts_test_note();
    return 0;
}
static void t_event(void *u, int32_t kind, const char *t, size_t l) {
    cts_test_note();
    if (kind == CTS_EVENT_FAILED) {
        size_t n = l < sizeof cts_test_failure - 1 ? l : sizeof cts_test_failure - 1;
        memcpy(cts_test_failure, t, n);
        cts_test_failure[n] = 0;
        atomic_fetch_add(&cts_test_failed, 1);
    }
}
static void t_dns(void *u, uint64_t id, const uint8_t *m, size_t l, const char *e, size_t el) {
    cts_test_note();
}
static int64_t t_lookup(void *u, const char *h, size_t hl, char *o, size_t oc) {
    cts_test_note();
    return -1;
}
static int32_t t_verbose(void *u) {
    cts_test_note();
    return 1;
}
static int64_t t_open(void *u, int32_t d, const char *a, size_t l, int64_t t) {
    cts_test_note();
    return 0;
}
static int64_t t_read(void *u, int64_t c, uint8_t *b, size_t cap, char *f, size_t *fl) {
    cts_test_note();
    return CTS_IO_FAILED;
}
static int64_t t_write(void *u, int64_t c, const uint8_t *b, size_t l, const char *t, size_t tl) {
    cts_test_note();
    return CTS_IO_FAILED;
}
static void t_deadline(void *u, int64_t c, int32_t d, int64_t t) { cts_test_note(); }
static void t_close(void *u, int64_t c) { cts_test_note(); }

static cts_callbacks cts_test_cb = {
    0, t_deliver, t_writable, t_prepare, t_event, t_dns, t_lookup, t_verbose,
    t_open, t_read, t_write, t_deadline, t_close,
};

static cts_callbacks *cts_test_callbacks(void) { return &cts_test_cb; }
static void cts_test_reset(void) {
    atomic_store(&cts_test_calls, 0);
    atomic_store(&cts_test_late, 0);
    atomic_store(&cts_test_failed, 0);
    atomic_store(&cts_test_packets, 0);
    atomic_store(&cts_test_batches, 0);
    atomic_store(&cts_test_stopped, 0);
}
static void cts_test_mark_stopped(void) { atomic_store(&cts_test_stopped, 1); }
static long cts_test_late_calls(void) { return atomic_load(&cts_test_late); }
static long cts_test_failed_events(void) { return atomic_load(&cts_test_failed); }
static const char *cts_test_last_failure(void) { return cts_test_failure; }
static long cts_test_delivered(void) { return atomic_load(&cts_test_packets); }
static long cts_test_deliveries(void) { return atomic_load(&cts_test_batches); }
*/
import "C"

import "unsafe"

// A host for the tests, which cannot use cgo themselves: callbacks that count, and count apart
// those that arrive after the test marked its node stopped.

func testReset()              { C.cts_test_reset() }
func testMarkStopped()        { C.cts_test_mark_stopped() }
func testLateCalls() int64    { return int64(C.cts_test_late_calls()) }
func testFailedEvents() int64 { return int64(C.cts_test_failed_events()) }
func testLastFailure() string { return C.GoString(C.cts_test_last_failure()) }
func testDelivered() (packets, batches int64) {
	return int64(C.cts_test_delivered()), int64(C.cts_test_deliveries())
}

func testStart(config string) (int64, string) {
	text := C.CString(config)
	defer C.free(unsafe.Pointer(text))
	why := (*C.char)(C.malloc(256))
	defer C.free(unsafe.Pointer(why))
	whyLen := C.size_t(256)
	h := cts_start(text, C.size_t(len(config)), C.cts_test_callbacks(), why, &whyLen)
	return int64(h), C.GoStringN(why, C.int(whyLen))
}

func testStop(h int64) { cts_stop(C.int64_t(h)) }

func testLinkChanged(h int64) { cts_link_changed(C.int64_t(h)) }

func testQuery(h int64, id uint64, msg []byte) int32 {
	raw := C.CBytes(msg)
	defer C.free(raw)
	return int32(cts_query_dns(C.int64_t(h), C.uint64_t(id), (*C.uint8_t)(raw), C.size_t(len(msg))))
}

func testTun() *packetTun { return newPacketTun(C.cts_test_callbacks(), newGate()) }

func testCallbacks() *C.cts_callbacks { return C.cts_test_callbacks() }
