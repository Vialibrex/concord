#ifndef CONCORD_TSNET_H
#define CONCORD_TSNET_H

#include <stddef.h>
#include <stdint.h>

#define CTS_ABI_VERSION 3

/* The most packets one cts_send or deliver carries: wireguard-go's conn.IdealBatchSize. */
#define CTS_BATCH 128

#define CTS_EVENT_STATE 1
#define CTS_EVENT_LOGIN_URL 2
#define CTS_EVENT_ADDRS 3
#define CTS_EVENT_LOG 4
#define CTS_EVENT_ERROR 5
#define CTS_EVENT_DEBUG 6
/* The node stopped for good: Start, EditPrefs or the IPN bus failed. */
#define CTS_EVENT_FAILED 7

/* conn_read and conn_write results below zero. */
#define CTS_IO_TIMEOUT -1
#define CTS_IO_FAILED -2
/* conn_deadline directions. */
#define CTS_IO_READ 1
#define CTS_IO_WRITE 2
#define CTS_IO_BOTH 3

typedef struct cts_callbacks {
    void *user;
    void (*deliver)(void *user, const uint8_t *const *packets, const size_t *lens, size_t count);
    void (*writable)(void *user);
    int32_t (*prepare_socket)(void *user, int64_t fd, int32_t family, int32_t datagram,
                              const char *addr, size_t addr_len);
    void (*event)(void *user, int32_t kind, const char *text, size_t len);
    /* An answer, or an error when err_len > 0. */
    void (*dns_answer)(void *user, uint64_t id, const uint8_t *msg, size_t len, const char *err,
                       size_t err_len);
    /* Resolves a control or DERP host the way Concord resolves a proxy server's: writes its
       addresses to out as text, one per line, and returns the length written, or -1. Blocks. */
    int64_t (*lookup)(void *user, const char *host, size_t host_len, char *out, size_t out_cap);
    /* Whether Concord logs at debug now, which is when tsnet's own log is worth sending. */
    int32_t (*verbose)(void *user);
    /* The node's own connections when it has a dialer-proxy; see via.go. conn_open opens a stream
       to addr (datagram 0) or a UDP session (datagram 1) and returns its id, or 0 when it failed
       or timeout_ms (< 0 for none) passed. Blocks. */
    int64_t (*conn_open)(void *user, int32_t datagram, const char *addr, size_t addr_len,
                         int64_t timeout_ms);
    /* Waits for data and returns how much it copied; 0 is the end of a stream. A session also
       writes the sender as "ip:port" to from, whose capacity *from_len gives, and sets *from_len. */
    int64_t (*conn_read)(void *user, int64_t conn, uint8_t *buf, size_t cap, char *from,
                         size_t *from_len);
    /* Waits for room and returns how much it took: part of a stream's bytes, or a whole packet
       for a session, sent to "ip:port" to. */
    int64_t (*conn_write)(void *user, int64_t conn, const uint8_t *buf, size_t len, const char *to,
                          size_t to_len);
    /* Waiting reads, writes or both give up timeout_ns from now; < 0 means never. */
    void (*conn_deadline)(void *user, int64_t conn, int32_t dir, int64_t timeout_ns);
    void (*conn_close)(void *user, int64_t conn);
} cts_callbacks;

/* Every pointer a callback gets is valid for that call only, and no callback runs once cts_stop
   returned; cts_stop waits for the callbacks in flight, so a callback must not call it. The
   exported calls are main.go's: cts_abi_version, cts_start (a refused node returns -1
   and its reason in the caller's buffer), cts_send, cts_query_dns (-1 when the node is gone),
   cts_link_changed and cts_stop. */

static inline void cts_call_deliver(const cts_callbacks *cb, const uint8_t *const *packets,
                                    const size_t *lens, size_t count) {
    cb->deliver(cb->user, packets, lens, count);
}

static inline void cts_call_writable(const cts_callbacks *cb) { cb->writable(cb->user); }

static inline int32_t cts_call_prepare_socket(const cts_callbacks *cb, int64_t fd, int32_t family,
                                              int32_t datagram, const char *addr,
                                              size_t addr_len) {
    return cb->prepare_socket(cb->user, fd, family, datagram, addr, addr_len);
}

static inline void cts_call_event(const cts_callbacks *cb, int32_t kind, const char *text,
                                  size_t len) {
    cb->event(cb->user, kind, text, len);
}

static inline int64_t cts_call_lookup(const cts_callbacks *cb, const char *host, size_t host_len,
                                      char *out, size_t out_cap) {
    return cb->lookup(cb->user, host, host_len, out, out_cap);
}

static inline int32_t cts_call_verbose(const cts_callbacks *cb) { return cb->verbose(cb->user); }

static inline void cts_call_dns_answer(const cts_callbacks *cb, uint64_t id, const uint8_t *msg,
                                       size_t len, const char *err, size_t err_len) {
    cb->dns_answer(cb->user, id, msg, len, err, err_len);
}

static inline int64_t cts_call_conn_open(const cts_callbacks *cb, int32_t datagram,
                                         const char *addr, size_t addr_len, int64_t timeout_ms) {
    return cb->conn_open(cb->user, datagram, addr, addr_len, timeout_ms);
}

static inline int64_t cts_call_conn_read(const cts_callbacks *cb, int64_t conn, uint8_t *buf,
                                         size_t cap, char *from, size_t *from_len) {
    return cb->conn_read(cb->user, conn, buf, cap, from, from_len);
}

static inline int64_t cts_call_conn_write(const cts_callbacks *cb, int64_t conn,
                                          const uint8_t *buf, size_t len, const char *to,
                                          size_t to_len) {
    return cb->conn_write(cb->user, conn, buf, len, to, to_len);
}

static inline void cts_call_conn_deadline(const cts_callbacks *cb, int64_t conn, int32_t dir,
                                          int64_t timeout_ns) {
    cb->conn_deadline(cb->user, conn, dir, timeout_ns);
}

static inline void cts_call_conn_close(const cts_callbacks *cb, int64_t conn) {
    cb->conn_close(cb->user, conn);
}

#endif
