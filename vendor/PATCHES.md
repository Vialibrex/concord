# Vendored crates

Each crate here is the crates.io release named below with the listed changes, wired in through `[patch.crates-io]` in
the workspace `Cargo.toml`. Every source change carries a `Concord:` comment. To upgrade, unpack the new release, replay
the changes below, and compare against the registry copy:

```sh
diff -r ~/.cargo/registry/src/index.crates.io-*/shadowsocks-1.25.0 vendor/shadowsocks
```

A change to a vendored crate adds its entry here in the same commit. Each bullet that opens with backticked paths
lists files that differ from the release, a path relative to the crate, a trailing part of the bullet's first path, or
a directory ending in `/`. `vendor/UPSTREAM.sha256` holds the SHA-256 of every file in each pinned package as cargo
unpacks it, and xtask's `vendor_patches` test (part of `cargo test --workspace`) fails when a file differs without a
bullet or a bullet names a file that does not differ. An upgrade regenerates the manifest from the new release:

```sh
cd ~/.cargo/registry/src/index.crates.io-*/shadowsocks-1.25.0 &&
  find . -type f ! -name .cargo-ok | LC_ALL=C sort | xargs shasum -a 256 | sed 's#  \./#  shadowsocks/#'
```

### Upstream route

Each change below should reach its upstream, so the vendored copy can go, unless its row says otherwise. A row's
status is what this file records; check the tracker before acting on it. When upstream releases the change: drop the
crate's directory, its `[patch.crates-io]` entry and its lines in `UPSTREAM.sha256`, and the section below.

| Crate | Change | Upstream | Route |
|---|---|---|---|
| boring | Read-only `SslRef` record-layer accessors | None | None planned: the change stays in the vendored copy |
| h3 | Bound frame and DATA read-ahead | hyperium/h3#344, `c916ed5a` (frame headers); #328 and #386 are related | Backport #344; propose the DATA-body extension to hyperium/h3 |
| h3 | Opt-in draft-00 datagram SETTINGS for WARP | None | Propose the default-off client builder switch to hyperium/h3 |
| h3 | Discard unknown frames as they arrive; bound HEADERS and SETTINGS before buffering | None; quic-go bounds both (`http3/frames.go:134`, `:182`) | Propose to hyperium/h3 with the decoder tests |
| h3 | Fix 0.0.8 rustc warnings under current toolchains | hyperium/h3#318, `18df8ceb` (on master, unreleased) | Backport #318; drop once upgrading past a release that includes it |
| h3-quinn | Public `SendStream::new` and `RecvStream::new` | None | Propose to hyperium/h3 |
| h3-quinn | `RecvStream` keeps its quinn stream while a read waits, so `stop_sending` and `recv_id` do not panic | None | Issue and PR to hyperium/h3 with the NaiveProxy stop-while-reading test |
| gotatun | Deliver already-ready encrypted IP packets to the bounded UDP queue together | None yet | Propose the batch handoff to mullvad/gotatun |
| h2 | Ignore DATA and HEADERS on forgotten client streams | None as of 0.4.20 | Issue and PR to hyperium/h2 with the delayed-DATA-after-reset transport test |
| h2 | Opt-in split-I/O client direct DATA writes | None as of 0.4.20 | Propose split-transport client API to hyperium/h2 once framing and multi-stream contracts settle |
| h2 | `SendStream::poll_drained` before a reset | None as of 0.4.20 | Propose to hyperium/h2 with the NaiveProxy tunnel-close transport test |
| h2 | Request priority through `ext::StreamPriority` | None | None planned: only the NaiveProxy outbound's fingerprint uses it |
| h2 | Huffman-code a string only when that is shorter | None as of 0.4.20 | PR to hyperium/h2 citing Go's hpack, Chromium's encoder and nghttp2, which all choose so |
| h2 | `client::Builder::index_pseudo_headers` | None | None planned: only the NaiveProxy outbound's fingerprint uses it |
| h2 | `SendStream::send_reset_padded` | None | None planned: only the NaiveProxy outbound's fingerprint uses it |
| mio | High-resolution timed waits on Windows | None | PR to tokio-rs/mio, citing Go's default poller path |
| mio | Nanosecond timed waits through `epoll_pwait2` on Linux | None | PR to tokio-rs/mio |
| quinn | `MAX_TRANSMIT_DATAGRAMS` 80 (`MAX_TRANSMIT_SEGMENTS` back to upstream's 10) | n0-computer/noq#636 (noq) | The segment cap is upstream's again; propose only the datagram limit to quinn-rs/quinn |
| quinn | Stamp each received batch with its own read time | None; quinn `main` `8fe66c3` passes one `now` | PR with `crates/proxy/tests/quinn_recv_time.rs` as the regression |
| quinn | Lease receive scratch for a socket poll instead of an endpoint lifetime | None | Propose to quinn-rs/quinn with the endpoint sharing regression and receive-buffer lease contracts |
| quinn | A connection whose driver has ended lets go of its socket | None | Propose to quinn-rs/quinn with the release contract of `crates/quic/src/release.rs` |
| quinn | Hold one UDP_GRO socket for the process so per-connection sockets do not flip the kernel's encapsulation static keys | None | Propose to quinn-rs/quinn, or to quinn-udp where `UdpSocketState::new` sets UDP_GRO |
| quinn | Public `RecvStream::poll_read_chunk` | None | Propose with the h3-quinn change; quinn's `read_chunk` future already wraps it |
| quinn-proto | `send_quantum`, `on_packet_lost`, `min_pacing_delay` and explicit-rate pacing | quinn-rs/quinn#2481; merged as noq#611 | Follow #2481. `min_pacing_delay` is Concord's own addition and needs its own proposal; the pacer changes cannot move into `quic/src/congestion.rs` while the controller API lacks these hooks |
| quinn-proto | Requeue unacknowledged STREAM data on a PTO; withdraw acknowledged copies | None; quinn `main` `765abecf` requeues only control frames | PR with the recovery contracts of `crates/proxy/tests/quinn_pto.rs` |
| quinn-proto | A DATAGRAM-only packet does not bundle a pending ACK | None | PR citing quic-go's default path and the `quinn_pto.rs` ACK contracts |
| rustls | Check that a buffered client can be exported to the record engine | None | PR adding the eligibility check next to rustls's kernel-TLS export |
| shadowsocks | Zero the AEAD-2022 request padding | None | Small bug-fix PR first: the padding was uninitialized memory |
| shadowsocks | Send the first write over as many chunks as it needs | None | Bug-fix PR |
| shadowsocks | AEAD-2022 padding of 1 to 900 bytes under 900-byte payloads | None | PR citing sing-shadowsocks |
| shadowsocks | `set_clock`; split halves; owned in-place writes | None | Last, as one design discussion: the largest and most Concord-specific |
| shadowsocks | Cache a UDP cipher by key bytes, and only after its packet opens | None | Bug-fix PR: unauthenticated datagrams fill the cache |
| tokio | Notify peer workers only after `transition_from_parked` removes self from `idle.sleepers` | None | Bug-fix PR |
| tokio | Check pending queues in `transition_worker_from_searching` before waking a parked worker | None | Bug-fix PR |
| tokio | Notify peer workers on `yield_now` only when `should_notify_others()` is true | None | Bug-fix PR |
| tokio | Fire traditional wheel timers at their nanosecond deadline instead of rounding up to the next millisecond | None | Propose to tokio-rs/tokio |
| tun-rs | `AsyncDevice::into_sync` keeps the owned device | None | PR to tun-rs |

## boring 5.4.0

The package archive checksum is `7227623e47342428b893b9401d85cae09c4656aecaae524206652e8f6a6246c4`.

- `src/ssl/mod.rs`: `SslRef` gains `has_pending`, `read_sequence`, `write_sequence`, `shutdown_state` and
  `key_block`, read-only wrappers over `SSL_has_pending`, `SSL_get_read_sequence`, `SSL_get_write_sequence`,
  `SSL_get_shutdown`, and `SSL_get_key_block_len` with `SSL_generate_key_block`. `concord-tls` reads them once per
  connection, when a finished BoringSSL handshake hands its keys and sequence numbers to the directional record layer
  (`crates/tls/src/boring_backend.rs` `record_state`). The release wraps none of them on `SslRef` (`get_shutdown` is
  on `SslStream` and takes `&mut self`), so tls otherwise needs `boring-sys` and `unsafe`. No upstream PR is planned.

## gotatun 0.10.2

The package archive checksum is `5e37c2134d46523ed5b3c4bbdb578225e2e7379d03aea65baef41584725b1991`.

- `src/device/mod.rs`, `src/udp/buffer.rs`: the outgoing task encrypts the group its IP device already returned and
  publishes each contiguous group of same-family packets to the existing UDP queue. Each group stops at the smaller of
  the transport batch limit and the channel capacity. Reserving one channel slot per packet keeps backpressure in packet
  units. The producer fills these slots without awaiting between sends. The UDP task can still drain concurrently.
  An isolated IP packet, a transport that sends one packet at a time, and packets from timers or the receive task use
  the usual single enqueue. This follows wireguard-go's batch handoff between the device reader, encryption and sender
  (`device/send.go` in metacubex/wireguard-go `a6cecdd7`). Upstream gotatun queues each packet as it encrypts it.
- `Cargo.toml`, `benches/`, `tests/`: the `[[test]]` and `[[bench]]` targets are removed with their sources.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

## h2 0.4.20

The package archive checksum is `7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118`.

- `src/proto/streams/streams.rs`: a client ignores HEADERS, and refunds and ignores DATA, on forgotten streams it
  initiated, matching the pinned Go HTTP/2 client's cancellation handling. The bounded reset history can discard a
  canceled stream before its in-flight response DATA arrives; turning that DATA into new protocol-error resets
  otherwise exhausts the connection's local-error budget. Future stream IDs and the server path retain their
  errors. Ignored non-final DATA retains the existing framing guard and releases its accounting immediately, since
  no payload is buffered. Reset limits, flow-control limits and empty non-final DATA limits are unchanged.
  Workspace transport tests cover delayed DATA after cancellation beyond the reset-history bound, connection
  flow-control refunds, connection reuse, unsolicited DATA and the empty-frame guard. Upstream h2 has no
  equivalent as of 0.4.20.
- `src/share.rs`, `src/proto/streams/streams.rs`, `src/proto/streams/prioritize.rs`: `SendStream::poll_drained` is
  ready once none of the stream's queued DATA waits for the connection (`buffered_send_data` is 0) or the stream is
  closed; `Prioritize::pop_frame` wakes the stream's send task when it takes the last queued bytes. Upstream's
  `send_reset` and the reset a dropped stream schedules both discard queued DATA, so a caller that ends a stream
  with RST_STREAM instead of END_STREAM has no way to send its last writes first. `h2io::H2Body::without_half_close`
  waits on it before its reset; on a split-I/O connection, which the NaiveProxy outbound now uses, direct writes
  queue no DATA and it is ready at once, so it only matters for such a tunnel on a plain connection, which no
  outbound opens today. `crates/transport` tests check that every byte written before the shutdown reaches the
  server ahead of the reset on both connections, and that a peer granting no window gets the reset after the drain
  limit. A direct write the peer grants no window waits in `poll_write_direct`, as a queued write waits for
  capacity: nothing bounds it short of the connection closing or failing `h2io`'s liveness check, which runs only
  ahead of a new stream and passes while the peer keeps sending.
- `src/client.rs`, `src/share.rs`, `src/codec/mod.rs`, `src/codec/framed_write.rs`, `src/proto/mod.rs`, `src/proto/direct_writer.rs`, `src/proto/connection.rs`, `src/proto/go_away.rs`, `src/proto/ping_pong.rs`, `src/proto/settings.rs`, `src/proto/streams/mod.rs`, `src/proto/streams/streams.rs`, `src/proto/streams/send.rs`, `src/proto/streams/prioritize.rs`, `src/proto/streams/recv.rs`: opt-in client split-I/O handshake (`client::Builder::handshake_split(read, write)`) and synchronous direct DATA write (`SendStream::poll_write_direct` / `poll_flush_direct`; 15 files, +1,643/-226 lines against `h2 0.4.20`, including the one-write handshake below). Existing `client::handshake`, `server`, and `SendStream::send_data` paths behave as before. `proto::Connection` and `SplitConnection` share `ConnectionInner` for what does not depend on I/O (its construction, the window and settings accessors, the closing error and the dispatch of a received frame; both deref to it), and `client::Builder` builds the `proto::Config` and applies the receive limits for both handshakes, so the two connections differ only in `poll` and their write paths. `SplitConnection` keeps `FramedRead<R>` exclusively on the connection task (so incoming WINDOW_UPDATE/DATA/control frames are never blocked by outbound backpressure), while `FramedWrite<W>` is shared through `DirectWriter` under a short mutex guarding only non-blocking polls. Each direct write checks RFC 9113 stream-open/HEADERS order (HPACK encoding runs inside the writer lock) and peer stream+connection flow control, sends at most one DATA frame bounded by `min(len, peer_max_frame_size, peer_window)` directly to `W`, flushes before returning `Ready`, yields FIFO to waiting streams and prioritizes connection control frames. On `Poll::Pending` the in-flight owner keeps the writer slot (releasing the mutex) until flushed; dropping a stream that owns the writer marks the owner `Abandoned` so `SplitConnection` finishes and reclaims the frame in flight, including a queued frame the stream flushed on the connection path, and releases it before sending `RST_STREAM`; fatal write I/O errors mark the writer broken, record the error and wake all waiters to close the connection, and later direct writes fail at once. Liveness depends on callers: the stream that owns the writer holds it until it is polled again or dropped, so a caller that abandons a pending `poll_write_direct`/`poll_flush_direct` but keeps its `SendStream` stalls the connection's own frames and every other stream; a slot reserved for the next waiting stream (FIFO) holds back only the other streams, until the connection next takes the writer for its own frames. Upstream `hyperium/h2` 0.4.20 couples `FramedRead` and `FramedWrite` over a single `T: AsyncRead + AsyncWrite` driven only by `Connection::poll` through an in-memory `pending_send` buffer (`DEFAULT_MAX_SEND_BUFFER_SIZE = 400 KiB`), with no split-I/O or caller-driven direct write API (unlike Go's `x/net/http2` / `metacubex/http` `ClientConn.wmu`). Workspace `h2io` tests verify partial-write/WouldBlock framing, interleaved control frames, HPACK/HEADERS ordering, mid-frame drop/cancel, I/O error teardown, multi-stream fairness, RST_STREAM/GOAWAY/SETTINGS and connection close arriving while a direct frame is being flushed, and WINDOW_UPDATE parity with the plain client on download.
- `src/client.rs`, `src/codec/mod.rs`, `src/codec/framed_write.rs`, `src/proto/streams/streams.rs`, `src/proto/streams/recv.rs`:
  the split-I/O handshake buffers the client preface, SETTINGS and the connection WINDOW_UPDATE and sends them in
  one write, as Go's HTTP/2 client does (`net/http/internal/http2/transport.go` in Go 1.27.3,
  one `Flush` after the three) and as naiveproxy `v154.0.8037.49-5` and sing-box `v1.15.0-alpha.13`'s cronet client
  were seen to (one TLS record, the first HEADERS in the next). Before, the preface went out on its own, SETTINGS in a second write and the
  WINDOW_UPDATE with the first request; `client::handshake` still works that way, as upstream does.
  `h2io::tests::split_handshake_writes_preface_settings_and_window_update_at_once` checks the one write.
- `src/ext.rs`, `src/client.rs`, `src/proto/streams/streams.rs`, `src/frame/headers.rs`, `src/frame/priority.rs`:
  a client request may carry an `ext::StreamPriority { dependency, weight, exclusive }` extension; its HEADERS frame
  then sets PRIORITY and carries the five priority octets (RFC 9113 §6.2), as Chromium's requests do. Upstream sends
  no priority on requests and `Streams::send_request` clears every extension, so the priority is taken out before the
  clear. A request without the extension is encoded as before. `h2io::tests::a_request_carries_its_priority_and_raw_values_where_huffman_is_longer`
  checks the octets; the NaiveProxy outbound chains the dependency as Chromium's `Http2PriorityDependencies` does.
- `src/hpack/encoder.rs`: a string literal is Huffman-coded only when that is shorter than the raw octets, as Go's
  hpack and Chromium's HPACK encoder decide; upstream always Huffman-codes. This changes every h2 outbound and the
  server's responses, but only the bytes of values whose Huffman form is not shorter (such as `CONNECT`, or values of
  characters the code spends 8 bits or more on), which now go out raw; a decoder reads both. `h2io` tests check a
  raw value; the transport's gun, xhttp and h2mux interop tests run against it.
- `src/hpack/encoder.rs`, `src/hpack/table.rs`, `src/codec/mod.rs`, `src/codec/framed_write.rs`, `src/client.rs`:
  `client::Builder::index_pseudo_headers(false)` keeps pseudo-headers other than `:authority` out of the HPACK
  dynamic table (sent from the static table or as literals without indexing), as Chromium's encoder does (quiche
  `HpackEncoder::DefaultPolicy`). The default, `true`, indexes them as upstream does.
  `h2io::tests::pseudo_headers_other_than_authority_can_stay_out_of_the_dynamic_table` checks both.
- `src/share.rs`, `src/proto/streams/streams.rs`, `src/proto/streams/send.rs`, `src/proto/streams/prioritize.rs`, `src/proto/streams/stream.rs`, `src/frame/reset.rs`:
  `SendStream::send_reset_padded(reason, padding)` resets a stream as `send_reset` does, first writing an empty DATA
  frame with END_STREAM and PADDED whose payload is `padding` octets (the pad-length octet included), when both
  flow-control windows hold it and the connection window holds at least 72 octets; the padding counts against both
  windows. This is how Chromium cancels a stream (`SpdySession::EnqueueResetStreamFrame`, naiveproxy
  `v154.0.8037.49-5`), except that Chromium checks and charges only the connection window; padding counts against
  the stream's window too (RFC 9113 §6.9.1), so a stream without room for it gets only the reset. The DATA rides in
  the queued `Reset` frame so the two go out together. `send_reset` is unchanged. `h2io` tests check the frame, the 72-octet floor and the reset that follows.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

## mio 1.2.4

- `src/sys/unix/selector/epoll.rs`: on Linux (excluding Android), a timed `select` invokes `epoll_pwait2` with a
  nanosecond `__kernel_timespec` (`{ i64, i64 }`), falling back permanently to `epoll_wait` after `ENOSYS` or `EPERM`.
  Android keeps `epoll_wait` because app seccomp policies can kill a process with `SIGSYS` on syscalls bionic does not
  expose; Linux environments whose seccomp filter kills with `SIGSYS` instead of returning `EPERM` (such as OHOS) are
  outside the supported scope. Regression contract: `crates/platform/tests/timer_deadline.rs`.
- `Cargo.lock`: registry lockfile omitted; the workspace uses its root lockfile.
- `src/sys/windows/hires_timer.rs`, `selector.rs`, `mod.rs`, `overlapped.rs`, `Cargo.toml`: a timed `select` arms a
  high-resolution waitable timer and associates it with the completion port through `NtAssociateWaitCompletionPacket`,
  so the wait ends at its deadline instead of on the system tick that `GetQueuedCompletionStatusEx`'s own timeout
  follows. This is the default path of Go 1.27.3's poller (`reference-choices.md`, Reference by area): `netpoll`
  queues the timer for any positive delay (`runtime/netpoll_windows.go:167-174`) and keeps its millisecond timeout
  on the call as the bound (`:182-197`); `netpollQueueTimer` cancels, sets and associates (`:251`, `:259`, `:264`);
  each M gets the timer and packet whenever `CREATE_WAITABLE_TIMER_HIGH_RESOLUTION` and
  `NtCreateWaitCompletionPacket` exist (`runtime/os_windows.go:871-878`), and `timeBeginPeriod` is only the
  fallback without them (`osRelax`, `:380-386`). One timer per selector suffices because one thread polls at a time.
  The packet carries an odd key and an `Overlapped` whose callback adds no event, so it only ends the wait and never
  reaches the caller as a token. Re-arming first cancels the previous association with
  `NtCancelWaitCompletionPacket(.., TRUE)`, which also drops a packet already queued for it; only when that cancel
  returns `STATUS_PENDING` (the packet is being delivered) can a late packet end a later wait early, with no event,
  and the caller then sees an early timeout and waits again for its own deadline. An untimed wait cancels the
  association, so an idle poller is not woken; Go leaves it armed. Go also re-arms on every timed wait
  (`netpoll_windows.go:174`); here a wait whose deadline lies less than 1 ms after the armed one keeps the armed
  timer, since tokio rounds deadlines to whole milliseconds and a request-response loop waits on the same timer
  again and again. Re-arming every time cost 15-22% more client CPU per `udp-rr` transaction on the Windows VM
  (`clw_hrt_c2b` direct and ss-aes128, `clw_hrt_c1` hysteria2-brutal). Without the high-resolution flag (before Windows
  10 1803) the selector waits as the release does. `windows-link` declares the three ntdll calls, which
  `windows-sys` does not; `Overlapped::new` is built without `os-ext`.

## quinn 0.11.12

- `src/endpoint.rs`, `src/endpoint/recv_buffer.rs`: receive scratch is leased from a thread-local cache only
  during `poll_socket`. Packets are already copied into owned `BytesMut`s before dispatch, so no scratch must
  survive the poll. Keeping the full batch/GRO scratch on each endpoint multiplies it by all live and closing
  endpoints, and the allocator can retain the freed pages after connection churn. One cached allocation per
  polling thread keeps the original payload, GRO and batch capacities without tying storage to endpoint count.
  The lease holds no cache borrow while a custom socket is called, supports reentrant polls, and frees normally
  if thread-local destruction has started. Contracts: `quic::receive_scratch_tests` and
  `crates/proxy/tests/quinn_recv_buffer.rs`.
- `src/connection.rs`: `MAX_TRANSMIT_DATAGRAMS` 20 → 80, the value proposed in n0-computer/noq#636. A bulk sender
  yields, and wakes another tokio worker, a quarter as often (`8452ddc`). `MAX_TRANSMIT_SEGMENTS` stays at upstream's
  10: `8452ddc` raised it to 40 with #645, and a 40-datagram GSO packet cost the receiving Go server 30% more CPU per
  GB on a WAN upload than ten (`clq_hy2_wan_burst_1`); quic-go never coalesces more than its ten-packet pacer burst.
- `src/endpoint.rs`: `RecvState::poll_socket` stamps each received batch with the time it was read, instead of the
  one `now` that `EndpointDriver::poll` took when the driver woke. A receive cycle runs until the socket is drained
  or the work limiter stops it, while connection tasks keep sending on other threads; an ACK for such a packet,
  read later in the same cycle, carried a time before the packet was sent, so the RTT sample saturated to zero,
  `min_rtt` stayed zero and BBR's delivery-rate samples grew without bound (Windows: every bulk connection of
  `clw_stats_1`). Upstream `main` (`8fe66c3`) still passes one `now` through `drive_recv` and `poll_socket`.
  quic-go stamps every packet as it reads it (sing-box quic-go `v0.61.0-sing-box-mod.12` `sys_conn.go:154`,
  `:194`, `sys_conn_oob.go:406`); a batch here comes from one `recvmmsg` or `WSARecvMsg` call, so stamping per
  batch is the same up to the call's own duration. Contract: `crates/proxy/tests/quinn_recv_time.rs`.
- `src/runtime/tokio.rs`: on Linux and Android, the first `wrap_udp_socket` opens one loopback UDP socket, connected
  to itself so nothing else reaches it, runs `UdpSocketState::new` on it and keeps it for the process. quinn-udp turns
  on UDP_GRO for every socket, and the kernel counts each such socket in the UDP encapsulation static keys
  (`udp_tunnel_encap_enable`; `udpv6_destroy_sock` releases them); a count moving between zero and one patches kernel
  text (`jump_label_update`) and synchronises every CPU. A client that opens a socket per QUIC connection, as XHTTP
  over HTTP/3 and the QUIC proxies do, paid that on open and close of every connection when no other GRO socket was
  open: 11.4% of the core's CPU samples in stream-one CRR on Linux arm64 (`clqrb_crr_profile_1`), with the IPIs
  landing on the peer's and origin's CPUs too. quic-go never sets UDP_GRO (metacubex quic-go
  `v0.61.1-0.20260727080200-2548683b76f4` `sys_conn_oob.go:80-143`), so its clients never touch the keys. While one
  GRO socket is open the count stays above zero and the per-connection change is an atomic increment. The keys gate
  a per-packet encapsulation check that any open QUIC socket already enables. Contract:
  `crates/proxy/tests/quinn_gro_key.rs`.
- `src/connection.rs`: when a connection's driver ends, however it ends, its state puts a socket that never
  sends or receives in place of the endpoint's. Upstream keeps the socket and its poller in the connection state
  until the last `Connection`, stream or datagram handle goes, and a server hands such handles to work that outlives
  the connection: a UDP session's reply sits in the tunnel's NAT for its idle time, and a TCP relay the client half
  closed runs until the destination closes. Until then a listener stopped by a reload could not free its port for
  the listener built in its place. The endpoint itself is released by `crates/quic/src/release.rs`; its contract
  `a_drained_connection_kept_by_a_handle_frees_the_port` holds a server handle past the drain.
- `src/recv_stream.rs`: `RecvStream::poll_read_chunk` is public, unchanged otherwise; the vendored h3-quinn reads
  through it so its `RecvStream` never gives up the stream while a read waits.
- `Cargo.toml`, `benches/`, `examples/`, `tests/`: the `[[example]]`, `[[test]]` and `[[bench]]` targets are removed
  with their sources.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

`quinn-udp` is not vendored; an upgrade moves all three crates together.

## quinn-proto 0.11.19

The package archive checksum is the original Cargo.lock checksum
`0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`.

- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

- `src/congestion.rs`: optional `send_quantum` and `on_packet_lost` follow the API proposed in
  [quinn#2481](https://github.com/quinn-rs/quinn/pull/2481) (head `01b8848d`) and merged in
  [noq#611](https://github.com/n0-computer/noq/pull/611) (`0ac6b462`). An additional optional
  `min_pacing_delay` preserves fixed-rate controllers' timer granularity. `pacing_rate` keeps Quinn's bits/s
  units; supplying a send quantum opts in, so existing diagnostic rates do not activate pacing.
- `src/connection/pacing.rs`, `src/connection/mod.rs`, `src/connection/packet_builder.rs`: an opted-in controller
  supplies the rate and burst separately from its window. Other controllers retain the original pacer. The
  rate budget charges actual packet lengths, including ACK-only packets, while the native budget still charges
  congestion-controlled bytes. Pacing inputs are sampled once per outgoing batch before ACK-only sends can
  bypass admission; the per-datagram congestion window remains current. Loss callbacks count ack-eliciting packets,
  excluding ECN and MTU probes.
- `src/connection/pacing.rs`, `src/connection/mod.rs`: on an explicit-rate deficit, schedule a refill using Quinn's
  existing 2ms burst interval, leaving the controller's minimum-delay worth of headroom for timer overshoot and
  reserving exact pending packet bytes. Existing credit still admits immediately; native pacing is unchanged.
- `src/congestion/cubic.rs`, `src/congestion/new_reno.rs`, `src/congestion/bbr/mod.rs`: default the optional pacing
  inputs to unset.
- Pacer unit tests run through `crates/proxy/tests/quinn_pacing.rs`, which includes the vendored source so the
  workspace gate executes the tests without a separate target or dependency graph. Late-wake tests check H2/SQ's
  rate headroom and H1's unchanged reference minimum-wait deadline, including its packet-remainder clipping.
- Admission and refill subtract the exact buffered packet reservation before applying the quantum bound;
  a one-MTU quantum test checks that the buffered packet cannot lend that credit to the next packet.
- A repeated budget-query regression test checks that unsent fractional credit is not lost between polls.
  Explicit pacing caches its current rate and computes budget from the last actual send, as the reference
  pacer's `Budget`/`SentPacket` pair does; polling cannot consume fractional elapsed credit. Native accounting
  and refill arithmetic remain unchanged.
  Explicit credit and its minimum-delay floor share one last-send timestamp, avoiding duplicate connection state.
  The H1 deadline comparison maintains an independent reference budget and last-send time.
- A buffered-packet regression test covers the minimum-delay anchor at cold start and on an early H1 poll.
  A reserved packet is finalized at the current transmit time before the connection returns, so it also
  anchors the next scheduled minimum delay. No timer value, capacity or native arithmetic changes.

- `src/connection/mod.rs`, `src/connection/spaces.rs`, `src/connection/streams/state.rs`: when a PTO has no new
  STREAM data, queue the oldest packet's still-unacknowledged STREAM ranges through the existing stream retransmit
  scheduler. Original STREAM/FIN metadata remains available for ACKs; PTO does not report congestion loss. New
  stream data and the existing control-only recovery path retain priority and behaviour.
- `src/connection/send_buffer.rs`, `src/connection/streams/send.rs`: an ACK withdraws queued copies of its bytes/FIN;
  later retransmit requests clip the discarded prefix and exclude selectively ACKed ranges. Empty/reset/closed
  scheduler entries cannot resurrect data or FIN after an original or probe copy was acknowledged.
- Recovery contracts in `crates/proxy/tests/quinn_pto.rs` run real QUIC endpoints on a virtual link, including
  delivery before any new ACK, both ACK orders, pending-probe cancellation, repeated probes, FIN/reset, exhausted
  flow credit, new-data priority and control-only probes.
- `src/connection/mod.rs`: a 1-RTT packet that carries DATAGRAM frames and nothing else no longer bundles a pending
  ACK at the end of `populate_packet`; it carries one only when an ACK is already due (`PendingAcks::can_send`, the
  ACK branch at the top of the packet), and otherwise the `MaxAckDelay` timer sends it alone. A datagram exchange
  then acknowledges every second ack-eliciting packet instead of every one. This is the default path of sing-box's
  quic-go `v0.61.0-sing-box-mod.12` (`reference-choices.md`, Reference by area): `packet_packer.go:724-729` asks
  for an ACK only if queued unless the packet has stream data, control frames or retransmissions; `framer.go:62-71`
  counts stream data, control frames and PATH_RESPONSE, not DATAGRAM; `received_packet_tracker.go:79`, `:187` and
  `:209-213` queue an ACK every second ack-eliciting packet or when the ACK alarm fires. Quinn's own immediate
  threshold is the same two packets (`spaces.rs` `ack_eliciting_threshold` 1). Only a packet whose payload is
  wholly DATAGRAM frames changes: PING, IMMEDIATE_ACK, PATH_CHALLENGE, PATH_RESPONSE, NEW_TOKEN, STREAM and every
  retransmitted frame keep the bundling, as quic-go's control frames and path responses do. Quinn bundled an ACK
  into the next packet after every ack-eliciting one, so a request-response over datagrams gave the peer one ACK
  per small packet; on the Windows VM mihomo's BBR server then sampled about 75 KB/s and paced `udp-rr` replies at
  1.5 ms after a bulk transfer (`clw_rrack_2`, Go 0.21 ms). Contracts in `crates/proxy/tests/quinn_pto.rs`: every
  second datagram reply carries the ACK, a lone one waits for the ACK delay, and a STREAM reply still carries it.

Upstream comparison: [quinn main `765abecf`](https://github.com/quinn-rs/quinn/blob/765abecf7b5e18e5eeb8aa46e30e2174c54547d7/quinn-proto/src/connection/spaces.rs)
still queues only control retransmits in `maybe_queue_probe`, with no equivalent STREAM requeue or ACK-copy
bookkeeping. The independent upstream DATAGRAM-ready guard is outside this patch.

Upgrade `quinn`, `quinn-proto` and `quinn-udp` together; replay these changes and the quinn changes above.

## rustls 0.23.46

- `src/conn.rs`, `src/client/client_conn.rs`, `src/common_state.rs`: a checked buffered-client handoff to the
  existing kernel connection export. It refuses retained ciphertext/plaintext, partial handshake messages, pending
  output, a queued KeyUpdate answer or a pending key refresh, errors and close state; successful export keeps
  traffic sequences and the KeyUpdate schedule. The caller can check eligibility without consuming the connection
  and retain upstream I/O when it is not quiescent.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

## shadowsocks 1.25.0

- `src/relay/tcprelay/crypto_io.rs`, `proxy_stream/client.rs`, `proxy_stream/mod.rs`: split cipher and client
  streams over independently owned transport halves. The reader preserves response authentication and the sent
  request nonce; the writer retains its handshake and cipher state. Mutable transport access lets ciphertext
  already accepted from a caller-owned buffer drain before a subsequent encrypted write after splitting.
- `src/relay/tcprelay/aead.rs`, `aead_2022.rs`, `crypto_io.rs`, `proxy_stream/client.rs`: an opt-in owned write.
  Once a writer's startup bytes have drained (the classic AEAD salt and address; the AEAD-2022 authenticated header
  and EIH), `EncryptedWriter::encrypt_in_place` seals one normal record in caller-owned length/payload/tag space.
  `crypto_io::seal_owned_record` frames the record for both families; each writer passes its own payload limit
  (`0x3FFF`, `0xFFFF`) and its cipher, which advances the record nonces. `CryptoStream` dispatches the hook to the
  active writer. Pending ciphertext remains the caller's responsibility; stream ciphers, request construction,
  padding and all readers keep their original paths.
- `src/relay/mod.rs`: an AEAD-2022 request header whose payload is under 900 bytes gets 1 to 900 bytes of padding, as
  sing-shadowsocks sends; upstream padded only an empty payload, by 0 to 900 (`f53191e`).
- `src/relay/tcprelay/proxy_stream/client.rs`:
  - the padding is zeroed instead of left as uninitialized memory (`f53191e`);
  - the first write, which carries the address, goes out over as many `poll_write_encrypted` calls as it needs, since
    each seals at most one chunk (`8f40a78`).
- `src/relay/tcprelay/aead_2022.rs`, `src/relay/tcprelay/mod.rs`: `set_clock` replaces the system clock for AEAD-2022
  timestamps; `concord-proxy` points it at the engine's NTP-corrected clock (`f53191e`).
- `src/relay/udprelay/aead_2022.rs`: the session ID is read with `u64::from_be_bytes` instead of through a `&[u64]`
  made from a byte pointer, which is undefined behaviour when the datagram does not start 8-byte aligned; a
  server's datagram, which follows its listener's headroom, does not.
- `src/relay/udprelay/aead_2022.rs`, `src/relay/udprelay/crypto_io.rs`: the per-thread UDP cipher cache is keyed by a
  hash of the key's bytes instead of its address, and a decrypted packet's cipher is cached only once the packet
  opens, so datagrams that do not authenticate leave nothing behind (sing-shadowsocks drops the session of a first
  packet that fails, `shadowaead_2022/service.go:429-445`). Upstream cached one cipher per random session id: 100,000
  random packets grew a thread's heap by 15.5 MiB, of which 2.3 MiB is the cache's index allocated up front.
  `crypto_io::cipher_cache_len` reads the cache's size for tests.
- `src/relay/udprelay/aead_2022.rs`, `src/relay/tcprelay/aead_2022.rs`, `src/relay/tcprelay/mod.rs`: UDP timestamps
  read the clock `set_clock` installs, as the TCP relay's do. The clock sits in an `ArcSwapOption`, which UDP reads
  for every packet without a lock; `Cargo.toml` makes `arc-swap` a plain dependency for it instead of one
  `hickory-dns` turns on.
- `Cargo.toml`, `tests/`: the `[[test]]` targets, their sources and the `env_logger` dev-dependency are removed.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

## tokio 1.54.1

The package archive checksum is `b52fd3255258d26fac7264ab5a76b53c13367136dc011d3d6ad4f8ed070396a3`.

- `src/runtime/scheduler/multi_thread/worker.rs`, `src/runtime/scheduler/multi_thread/idle.rs`:
  - Fix self-notification on driver wake: move `should_notify_others` -> `notify_parked_local` out of `park_internal`
    into `Context::park` after `transition_from_parked` (and into `Context::park_yield`). Previously, a worker waking
    from the I/O or timer driver with >=2 tasks was still in `idle.sleepers`, so `worker_to_notify` could pop and
    unpark the waking worker itself, leaving its parker `NOTIFIED` (forcing a noop park on the next turn) and causing
    `unpark_worker_by_id` to fail and mis-set `is_searching = true`.
  - Fix spurious wakeup on empty queues: `Handle::transition_worker_from_searching` now calls `notify_if_work_pending`
    (returning `bool`, reusing the same `SeqCst` RMW Dekker ordering as `transition_to_parked`) instead of
    unconditionally calling `notify_parked_local` when no stealable or injected tasks exist. `TimerFlavor::Alternative`
    retains the unconditional notify because `notify_if_work_pending` does not inspect `inject_timers`.
  - Fix spurious wakeup on single-task `yield_now`: `Handle::schedule_local` splits `is_yield` from
    `!core.lifo_enabled` and checks `core.should_notify_others()` (`!is_searching && lifo_slot.is_some() +
    run_queue.len() > 1`) instead of unconditionally waking a parked worker when the yielded task is the only
    runnable task on the worker. `Schedule::yield_now` is only called from `Harness::poll` after `poll_future`
    has already returned `Pending`, so the current worker immediately returns to `Context::run` to poll the
    task; waking a `PARKED_DRIVER` peer for a lone yielded task produced ~24 `eventfd` writes/MB on Linux TUN
    UDP. Unlike earlier reverted TUN workarounds—arming the queue `AsyncFd` wait at park (`6997a798`, which
    added `epoll_ctl` churn and park waits) and suppressing local driver wakes in `TxPool` (`6f4210f8`, which
    regressed Shadowsocks download and multi-flow throughput)—this fixes the scheduler wakeup directly with no
    extra `epoll_ctl` and still wakes a peer worker whenever >=2 local tasks are runnable.
  - Unit tests (`concord_tests` in `worker.rs`, with `Idle::is_searching_any` test helper in `idle.rs`, plus workspace
    stable-API regressions in `crates/platform/tests/tokio_scheduler.rs`) reproduce all three bugs before the fixes
    and assert zero self-notify noop parks, zero mis-set `is_searching`, single-worker wakeup on single remote task
    spawns and single-task self-yields, two-task LIFO+yield peer wakeups, and bounded I/O latency on a parked
    driver worker while a peer self-yields.
    Tokio's upstream `rt_metrics`, `rt_threaded`, `rt_unstable_metrics`, and `rt_unstable_eager_driver_handoff` suites
    were also verified against the full upstream package before trimming `tests/`.
- `src/runtime/driver.rs`, `src/runtime/mod.rs`, `src/runtime/time/entry.rs`, `src/runtime/time/mod.rs`, `src/runtime/time/source.rs`, `src/runtime/time/tests/mod.rs`, `src/runtime/time/wheel/level.rs`, `src/runtime/time/wheel/mod.rs`, `src/time/sleep.rs`, `src/util/linked_list.rs`:
  - Fire traditional wheel timers at their nanosecond deadline instead of rounding each deadline up to the next
    millisecond (`TimeSource::deadline_to_tick` added 999,999 ns and parked for whole milliseconds, adding ~1 ms of
    overshoot to every sleep). `TimerShared.state` now stores the deadline in nanoseconds while `registered_when`
    keeps the 1 ms wheel slot (`floor(deadline)`). Entries whose millisecond slot has been processed while their
    nanosecond deadline lies later in that millisecond wait on a per-wheel `held` list (marked by `REGISTERED_HELD`
    in `registered_when` for cancellation), because 1.54's `next_occupied_slot` skips the slot holding `elapsed`.
    `Wheel::next_wake_nanos` scans the `held` list and the next level-0 slot for the earliest nanosecond deadline
    so `Driver::park_internal` parks for the exact remaining duration. `Timer::new`/`init`/`reset` take `Instant`
    directly (`TimerFlavor::Alternative` keeps millisecond ticks). A timer fires only when `deadline <= clock.now()`,
    verified by `runtime::time::tests::concord_tests`, the upstream tokio 1.54.1 `time_*` and `rt_time_start_paused`
    suites, and `crates/platform/tests/timer_deadline.rs`.
- `Cargo.toml`, `tests/`: the `[[test]]` targets are removed with their sources.
- `.cargo_vcs_info.json`, `Cargo.lock`, `Cargo.toml.orig`: crates.io packaging metadata, omitted.

## tun-rs 2.8.16

- `Cargo.lock`: registry lockfile omitted; the workspace uses its root lockfile.

- `src/async_device/unix/mod.rs`: `AsyncDevice::into_sync` returns the existing owned device after reactor deregistration, preserving its FD, queued packets and VNET/offload state. TUN queue owners use it with `AsyncDevice::new` to register on their runtime; raw-fd adoption rejects VNET descriptors. It is compiled only on Linux and Android, where `crates/tun` has queue owners; macOS exports its own `AsyncDevice` wrapper instead.


## h3 0.0.8

The package archive checksum is `10872b55cfb02a821b69dc7cf8dc6a71d6af25eb9a79662bec4a9d016056b3be`.

- `src/frame.rs`: backport the decode-before-read ordering from upstream
  [PR #344](https://github.com/hyperium/h3/pull/344), commit
  [`c916ed5af1c6818c74fb86cc05a18e51ecc1fcb1`](https://github.com/hyperium/h3/commit/c916ed5af1c6818c74fb86cc05a18e51ecc1fcb1).
  Extend the same backpressure to DATA bodies: drain buffered bytes before polling QUIC again, preventing
  accumulating read-ahead and quadratic cursor walks. Upstream's changelog still ends at 0.0.8; master contains
  #344 but still polls QUIC first in `poll_data`. The broader [PR #328](https://github.com/hyperium/h3/pull/328)
  reworks buffering; [issue #386](https://github.com/hyperium/h3/issues/386) tracks truncated DATA. Propose the
  DATA-body extension upstream; it has not been submitted. Drop the frame-header backport when upgrading past
  #344, and recheck the DATA extension separately. Truncated finite DATA returns `H3_FRAME_ERROR` rather than
  clean EOF (RFC 9114 section 7.1); an explicit unframed marker preserves WebTransport EOF. Public-API regressions
  are in `crates/proxy/tests/h3_read_ahead.rs`; xhttp's lifecycle test checks error propagation without a panic.

- `src/config.rs`, `src/client/builder.rs`: a default-off legacy HTTP datagram switch advertises `0x276: 1`
  for MASQUE peers, alongside the standard setting. The default encoding is unchanged. The byte-level QUIC
  contracts are in `crates/proxy/tests/h3_settings.rs`; the off-switch golden was captured from unpatched 0.0.8.
- `src/ext.rs`: the fixed `CF_CONNECT_IP` protocol token sends and decodes Cloudflare WARP extended CONNECT
  requests. Existing protocol values and defaults are unchanged; there is no dynamic protocol API.
- `src/proto/headers.rs`: ordinary CONNECT omits `:scheme`/`:path` as RFC 9114 section 4.4 requires;
  extended CONNECT and other methods keep their original bytes. Consider reporting this fix upstream.
- `src/config.rs`, `src/client/builder.rs`: default-off omission of disabled extension settings, used only by
  MASQUE to match quic-go's IP and L4 SETTINGS profiles. Other H3 clients retain their original bytes.
- `src/config.rs`, `src/proto/frame.rs`: peer datagram support also recognizes and retains WARP's draft-00
  setting as a receive-side alias.
- `src/shared_state.rs`, `src/client/connection.rs`: a read-only poll for received peer datagram SETTINGS lets
  CONNECT-IP wait for and validate peer support without enabling h3's internal API feature.
- `src/proto/frame.rs`, `src/frame.rs`, `src/error/internal_error.rs`: the frame decoder discards an unknown
  frame's payload as it arrives instead of waiting to buffer it whole, and decides on the others from the frame
  header: a SETTINGS frame over 8 KiB is `Settings(Exceeded)`, a CANCEL_PUSH, GOAWAY or MAX_PUSH_ID longer than one
  varint is malformed, and a HEADERS or PUSH_PROMISE frame over the stream's limit is refused before its payload
  is read, as `H3_EXCESSIVE_LOAD` unless it is a request's first HEADERS frame. A stream that ends inside a
  discarded frame is an unexpected end, as one that ends inside any other frame is. quic-go does the same
  (`http3/frames.go:134`, `:182`, `server_conn.go:123-129`). Before this an unauthenticated peer could make a
  Hysteria 2 listener buffer a frame as long as a varint allows. The limit defaults to `u64::MAX`, so a client
  that sets no `max_field_section_size` decodes as before apart from the streamed discard and the SETTINGS cap.
  The decoder tests are `unknown_frame_is_discarded_as_it_arrives`,
  `a_long_headers_or_settings_frame_is_refused_from_its_header`, `a_long_push_promise_is_refused_by_its_type` and
  `poll_next_unknown_frame_cut_by_the_end`; `crates/proxy/src/server/hysteria2/tests.rs` holds the listener's.
- `src/server/connection.rs`, `src/connection.rs`: request streams and the peer's control stream take the
  connection's `max_field_section_size` as their HEADERS limit.
- `src/server/request.rs`, `src/tests/request.rs`: a request whose first HEADERS frame is refused that way gets
  upstream's 431 and `HeaderTooBig`, with its receive side stopped with `H3_EXCESSIVE_LOAD`, and the connection
  stays, as with quic-go. `header_too_big_response_from_server` now reports the encoded length the decoder saw,
  not the decoded size, so it no longer pins `actual_size`.
- `src/stream.rs`, `src/buf.rs`, `src/shared_state.rs`, `src/qpack/dynamic.rs`, `src/qpack/prefix_string/decode.rs`:
  backport upstream [PR #318](https://github.com/hyperium/h3/pull/318), commit
  [`18df8ceb`](https://github.com/hyperium/h3/commit/18df8ceb) (on master, unreleased; crates.io is still 0.0.8),
  fixing the 0.0.8 rustc warnings (unused `Decode` import, unused `err` without `tracing`, unread `StreamEnd::Reset`
  payload via `#[allow(dead_code)]`, and elided lifetime syntax) so `Cargo.toml` no longer needs
  `[lints.rust] warnings = "allow"`. Drop once upgrading past a release that includes #318.

## h3-quinn 0.0.10

- `src/lib.rs`: `SendStream::new` and `RecvStream::new` are public. The hysteria2 server reads the frame type a
  bidirectional stream opens with before h3 sees it, since sing-quic routes TCP requests (`0x401`) away from
  HTTP/3 that way (`hysteria2/service.go:337-355`), and hands h3 the other streams with those bytes in front.
  The clients build their streams as before.
- `src/lib.rs`: `RecvStream` holds its `quinn::RecvStream` and reads through `poll_read_chunk` instead of moving
  the stream into a boxed `read_chunk` future. Upstream leaves `stream` empty while a read waits, so
  `stop_sending` or `recv_id` on a stream whose read is pending unwraps `None` and panics; a NaiveProxy tunnel
  that ends while its reader waits stops its stream that way. `read_chunk` is cancel-safe and the poll keeps no
  state between calls, so a dropped read loses nothing; dropping `RecvStream` drops the quinn stream as before.
  Contract: `naive::tests::a_quic_tunnel_ended_while_its_reader_waits_stops_the_stream_cancelled`.
