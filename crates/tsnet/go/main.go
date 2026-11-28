package main

/*
#include <stdlib.h>
#include "cts.h"
*/
import "C"

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/metacubex/tailscale/envknob"
	"github.com/metacubex/tailscale/ipn"
	"github.com/metacubex/tailscale/ipn/store/mem"
	"github.com/metacubex/tailscale/tsnet"
	"golang.org/x/net/dns/dnsmessage"
)

type nodeConfig struct {
	Hostname               string `json:"hostname"`
	AuthKey                string `json:"auth_key"`
	ControlURL             string `json:"control_url"`
	StateDir               string `json:"state_dir"`
	Ephemeral              bool   `json:"ephemeral"`
	StateInMemory          bool   `json:"state_in_memory"`
	AcceptRoutes           *bool  `json:"accept_routes"`
	ExitNode               string `json:"exit_node"`
	ExitNodeAllowLANAccess *bool  `json:"exit_node_allow_lan_access"`
	// ExtraRootCAs are DER certificates Concord trusts beyond the system's, as mihomo passes
	// its custom certificates.
	ExtraRootCAs [][]byte `json:"extra_root_cas"`
	// Via sends the node's own traffic through Concord, which dials it through the node's
	// dialer-proxy.
	Via bool `json:"via"`
}

type node struct {
	cb     *C.cts_callbacks
	gate   *gate
	cfg    nodeConfig
	server *tsnet.Server
	tun    *packetTun
	via    *via
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	// startDone closes once Start returned, with started telling whether it succeeded: tsnet's
	// Close must not run before or during Start, nor after a Start that failed early.
	startDone chan struct{}
	started   bool
	// linkMu guards stopping against cts_link_changed adding to links.
	linkMu   sync.Mutex
	stopping bool
	links    sync.WaitGroup
}

var (
	nodesMu sync.Mutex
	nodes   = map[int64]*node{}
	nextID  atomic.Int64
)

func init() {
	envknob.SetNoLogsNoSupport()
	installPlatform()
}

// cstr passes Go memory for the duration of one callback: a C.malloc copy would run on a Go
// thread, and glibc gives each thread that allocates an arena of its own.
func cstr(s string) (*C.char, C.size_t) {
	return (*C.char)(unsafe.Pointer(unsafe.StringData(s))), C.size_t(len(s))
}

func (n *node) emit(kind C.int32_t, text string) {
	if !n.gate.enter() {
		return
	}
	defer n.gate.leave()
	p, l := cstr(text)
	C.cts_call_event(n.cb, kind, p, l)
}

func (n *node) verbose() bool {
	if !n.gate.enter() {
		return false
	}
	defer n.gate.leave()
	return C.cts_call_verbose(n.cb) != 0
}

// prepare asks Concord to protect and route a socket the library opened, false once the node
// stopped; address is empty for one tailscale opened through netns, which only needs protecting.
func (n *node) prepare(fd uintptr, family, datagram C.int32_t, address string) (bool, error) {
	if !n.gate.enter() {
		return false, net.ErrClosed
	}
	defer n.gate.leave()
	addr, addrLen := cstr(address)
	if rc := C.cts_call_prepare_socket(n.cb, C.int64_t(fd), family, datagram, addr, addrLen); rc != 0 {
		return true, fmt.Errorf("concord: preparing a socket for %q failed (%d)", address, rc)
	}
	return true, nil
}

// protectAny is the netns hook, which is process-wide: any running node's Concord protects.
func protectAny(fd int) error {
	nodesMu.Lock()
	running := make([]*node, 0, len(nodes))
	for _, n := range nodes {
		running = append(running, n)
	}
	nodesMu.Unlock()
	for _, n := range running {
		if live, err := n.prepare(uintptr(fd), 0, 0, ""); live {
			return err
		}
	}
	return nil
}

func (n *node) control(datagram bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		family := C.int32_t(4)
		if strings.HasSuffix(network, "6") {
			family = 6
		}
		dg := C.int32_t(0)
		if datagram {
			dg = 1
		}
		var prepared error
		err := c.Control(func(fd uintptr) {
			_, prepared = n.prepare(fd, family, dg, address)
		})
		if err != nil {
			return err
		}
		return prepared
	}
}

func (n *node) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d := net.Dialer{Control: n.control(false)}
	return d.DialContext(ctx, network, address)
}

func (n *node) listenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: n.control(true)}
	return lc.ListenPacket(ctx, network, address)
}

func (n *node) prefs() *ipn.MaskedPrefs {
	var mp ipn.MaskedPrefs
	changed := false
	if n.cfg.AcceptRoutes != nil {
		mp.RouteAll = *n.cfg.AcceptRoutes
		mp.RouteAllSet = true
		changed = true
	}
	if n.cfg.ExitNode != "" {
		if auto, ok := ipn.ParseAutoExitNodeString(n.cfg.ExitNode); ok {
			mp.AutoExitNode = auto
			mp.AutoExitNodeSet = true
			changed = true
		}
	}
	if n.cfg.ExitNodeAllowLANAccess != nil && !n.exitNodeByIP() {
		mp.ExitNodeAllowLANAccess = *n.cfg.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
		changed = true
	}
	if !changed {
		return nil
	}
	return &mp
}

func (n *node) exitNodeByIP() bool {
	if n.cfg.ExitNode == "" {
		return false
	}
	_, auto := ipn.ParseAutoExitNodeString(n.cfg.ExitNode)
	return !auto
}

func (n *node) applyExitNodeIP() error {
	ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
	defer cancel()
	lc, err := n.server.LocalClient()
	if err != nil {
		return err
	}
	status, err := lc.Status(ctx)
	if err != nil {
		return err
	}
	mp := &ipn.MaskedPrefs{ExitNodeIPSet: true}
	if n.cfg.ExitNodeAllowLANAccess != nil {
		mp.ExitNodeAllowLANAccess = *n.cfg.ExitNodeAllowLANAccess
		mp.ExitNodeAllowLANAccessSet = true
	}
	if err := mp.SetExitNodeIP(n.cfg.ExitNode, status); err != nil {
		return err
	}
	_, err = lc.EditPrefs(ctx, mp)
	return err
}

// lookupAddrs is mihomo's LookupHook: control and DERP hosts resolve as a proxy server's do.
func (n *node) lookupAddrs(ctx context.Context, host string) ([]netip.Addr, error) {
	var out [1024]byte
	if !n.gate.enter() {
		return nil, net.ErrClosed
	}
	p, l := cstr(host)
	got := C.cts_call_lookup(n.cb, p, l, (*C.char)(unsafe.Pointer(&out[0])), C.size_t(len(out)))
	n.gate.leave()
	if got < 0 {
		return nil, fmt.Errorf("concord could not resolve %s", host)
	}
	var addrs []netip.Addr
	for _, line := range strings.Split(string(out[:got]), "\n") {
		if addr, err := netip.ParseAddr(line); err == nil {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no address for %s", host)
	}
	return addrs, nil
}

func rootCAs(ders [][]byte) (*x509.CertPool, error) {
	if len(ders) == 0 {
		return nil, nil
	}
	pool := x509.NewCertPool()
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

// dnsTimeout is Concord's for a query through the node (proxy::tailscale::tunnel::DNS_TIMEOUT).
const dnsTimeout = 5 * time.Second

type addrsEvent struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

func (n *node) run() {
	defer n.wg.Done()
	if n.ctx.Err() != nil {
		close(n.startDone)
		return
	}
	err := n.server.Start()
	n.started = err == nil
	close(n.startDone)
	if err != nil {
		n.emit(C.CTS_EVENT_FAILED, "start: "+err.Error())
		return
	}
	if mp := n.prefs(); mp != nil {
		lc, err := n.server.LocalClient()
		if err == nil {
			ctx, cancel := context.WithTimeout(n.ctx, 30*time.Second)
			_, err = lc.EditPrefs(ctx, mp)
			cancel()
		}
		if err != nil {
			n.emit(C.CTS_EVENT_FAILED, "prefs: "+err.Error())
			return
		}
	}
	lc, err := n.server.LocalClient()
	if err != nil {
		n.emit(C.CTS_EVENT_FAILED, "local client: "+err.Error())
		return
	}
	watcher, err := lc.WatchIPNBus(n.ctx, ipn.NotifyInitialState)
	if err != nil {
		n.emit(C.CTS_EVENT_FAILED, "watch: "+err.Error())
		return
	}
	defer watcher.Close()
	exitPending := n.exitNodeByIP()
	var lastAddrs addrsEvent
	for {
		msg, err := watcher.Next()
		if err != nil {
			if n.ctx.Err() == nil {
				n.emit(C.CTS_EVENT_FAILED, "watch: "+err.Error())
			}
			return
		}
		if msg.BrowseToURL != nil && *msg.BrowseToURL != "" {
			n.emit(C.CTS_EVENT_LOGIN_URL, *msg.BrowseToURL)
		}
		if msg.ErrMessage != nil {
			n.emit(C.CTS_EVENT_ERROR, *msg.ErrMessage)
		}
		if msg.State == nil {
			continue
		}
		n.emit(C.CTS_EVENT_STATE, msg.State.String())
		if *msg.State != ipn.Running {
			continue
		}
		v4, v6 := n.server.TailscaleIPs()
		addrs := addrsEvent{}
		if v4.IsValid() {
			addrs.IPv4 = v4.String()
		}
		if v6.IsValid() {
			addrs.IPv6 = v6.String()
		}
		if addrs != lastAddrs {
			lastAddrs = addrs
			text, _ := json.Marshal(addrs)
			n.emit(C.CTS_EVENT_ADDRS, string(text))
		}
		if exitPending {
			exitPending = false
			if err := n.applyExitNodeIP(); err != nil {
				n.emit(C.CTS_EVENT_ERROR, "exit node: "+err.Error())
			}
		}
	}
}

func lookup(h C.int64_t) *node {
	nodesMu.Lock()
	defer nodesMu.Unlock()
	return nodes[int64(h)]
}

//export cts_abi_version
func cts_abi_version() C.int32_t { return C.CTS_ABI_VERSION }

func refuse(why string, out *C.char, outLen *C.size_t) C.int64_t {
	buf := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(*outLen))
	*outLen = C.size_t(copy(buf, why))
	return -1
}

// cts_start begins bringing a node up and returns at once; progress comes through `event`.
// `cb` must stay valid until cts_stop returns. A refused node returns -1 with the reason in
// err, whose capacity *err_len gives, and *err_len set to its length.
//
//export cts_start
func cts_start(config *C.char, length C.size_t, cb *C.cts_callbacks, why *C.char, whyLen *C.size_t) C.int64_t {
	var cfg nodeConfig
	if err := json.Unmarshal(C.GoBytes(unsafe.Pointer(config), C.int(length)), &cfg); err != nil {
		return refuse("node configuration: "+err.Error(), why, whyLen)
	}
	roots, err := rootCAs(cfg.ExtraRootCAs)
	if err != nil {
		return refuse(err.Error(), why, whyLen)
	}
	ctx, cancel := context.WithCancel(context.Background())
	g := newGate()
	n := &node{cb: cb, gate: g, cfg: cfg, ctx: ctx, cancel: cancel, tun: newPacketTun(cb, g),
		startDone: make(chan struct{})}
	dial, listenPacket := n.dial, n.listenPacket
	if cfg.Via {
		n.via = newVia(cb, g)
		dial, listenPacket = n.via.dial, n.via.listenPacket
	}
	n.server = &tsnet.Server{
		Dir:                  cfg.StateDir,
		Hostname:             cfg.Hostname,
		AuthKey:              cfg.AuthKey,
		ControlURL:           cfg.ControlURL,
		Ephemeral:            cfg.Ephemeral,
		Tun:                  n.tun,
		SystemDialer:         dial,
		SystemPacketListener: listenPacket,
		ExtraRootCAs:         roots,
		LookupHook:           n.lookupAddrs,
		UserLogf: func(format string, args ...any) {
			n.emit(C.CTS_EVENT_LOG, fmt.Sprintf(format, args...))
		},
		Logf: func(format string, args ...any) {
			if n.verbose() {
				n.emit(C.CTS_EVENT_DEBUG, fmt.Sprintf(format, args...))
			}
		},
	}
	if cfg.StateInMemory {
		n.server.Store = new(mem.Store)
	}
	id := nextID.Add(1)
	nodesMu.Lock()
	nodes[id] = n
	nodesMu.Unlock()
	n.wg.Add(1)
	go n.run()
	return C.int64_t(id)
}

// cts_send queues packets from Concord's stack for the tailnet and returns how many it took;
// after a short count it calls `writable` once there is room again.
//
//export cts_send
func cts_send(h C.int64_t, packets *unsafe.Pointer, lens *C.size_t, count C.size_t) C.size_t {
	n := lookup(h)
	if n == nil {
		return 0
	}
	return C.size_t(n.tun.send(unsafe.Slice(packets, int(count)), unsafe.Slice(lens, int(count))))
}

// cts_query_dns asks the node's resolver (MagicDNS, then the tailnet's upstreams) and answers
// through `dns_answer` with the same id; it returns -1, and never answers, when the node is gone.
//
//export cts_query_dns
func cts_query_dns(h C.int64_t, id C.uint64_t, query *C.uint8_t, length C.size_t) C.int32_t {
	n := lookup(h)
	if n == nil || !n.gate.enter() {
		return -1
	}
	msg := C.GoBytes(unsafe.Pointer(query), C.int(length))
	go func() {
		defer n.gate.leave()
		answer, err := n.queryDNS(msg)
		if err != nil {
			why, whyLen := cstr(err.Error())
			C.cts_call_dns_answer(n.cb, id, nil, 0, why, whyLen)
			return
		}
		C.cts_call_dns_answer(n.cb, id, (*C.uint8_t)(unsafe.Pointer(unsafe.SliceData(answer))), C.size_t(len(answer)), nil, 0)
	}()
	return 0
}

func (n *node) queryDNS(raw []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	if _, err := parser.Start(raw); err != nil {
		return nil, err
	}
	q, err := parser.Question()
	if err != nil {
		return nil, errors.New("should have one question at least")
	}
	qtype := strings.TrimPrefix(q.Type.String(), "Type")
	lc, err := n.server.LocalClient()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(n.ctx, dnsTimeout)
	defer cancel()
	answer, _, err := lc.QueryDNS(ctx, q.Name.String(), qtype)
	if err != nil {
		return nil, err
	}
	if len(answer) < 2 || len(raw) < 2 {
		return nil, errors.New("short DNS message")
	}
	copy(answer[:2], raw[:2])
	return answer, nil
}

// cts_link_changed tells a started node that the device's network changed under it, as the
// official Android client tells netmon: it rechecks the links, and magicsock opens its UDP
// sockets again (through `prepare_socket`, so they follow the new network) and finds its paths
// anew. A node still starting reads the network as it is.
//
//export cts_link_changed
func cts_link_changed(h C.int64_t) {
	n := lookup(h)
	if n == nil {
		return
	}
	select {
	case <-n.startDone:
	default:
		return
	}
	if !n.started {
		return
	}
	n.linkMu.Lock()
	defer n.linkMu.Unlock()
	if n.stopping {
		return
	}
	n.links.Add(1)
	go func() {
		defer n.links.Done()
		sys := n.server.Sys()
		if monitor, ok := sys.NetMon.GetOK(); ok {
			monitor.InjectEvent()
		}
		if conn, ok := sys.MagicSock.GetOK(); ok {
			conn.Rebind()
			conn.ReSTUN("concord-link-change")
		}
	}()
}

// cts_stop closes the node and waits for its goroutines; no callback runs after it returns.
//
//export cts_stop
func cts_stop(h C.int64_t) {
	nodesMu.Lock()
	n := nodes[int64(h)]
	delete(nodes, int64(h))
	nodesMu.Unlock()
	if n == nil {
		return
	}
	n.linkMu.Lock()
	n.stopping = true
	n.linkMu.Unlock()
	n.cancel()
	n.links.Wait()
	<-n.startDone
	if n.started {
		_ = n.server.Close()
	}
	n.tun.Close()
	n.wg.Wait()
	n.gate.close()
	n.tun.free()
	debug.FreeOSMemory()
}

func main() {}
