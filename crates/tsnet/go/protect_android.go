package main

/*
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "cts.h"
*/
import "C"

import (
	"net"
	"syscall"
	"unsafe"

	"github.com/metacubex/tailscale/net/netmon"
	"github.com/metacubex/tailscale/net/netns"
)

func installPlatform() {
	// tailscale opens some sockets through netns instead of the dialers it was given (port
	// mapping, netcheck); Android's VpnService needs every one protected.
	netns.SetAndroidProtectFunc(protectAny)
	netmon.RegisterInterfaceGetter(interfaces)
}

// interfaces lists the links with bionic's getifaddrs: from API 30 an app may not read the
// netlink tables net.Interfaces asks for, and bionic falls back to what it may read. mihomo uses
// a copy of anet for this; upstream anet writes into net's private zone cache, which Go links
// only with -checklinkname=0. MTU and hardware address stay unset, as tailscale only compares
// them between two listings.
func interfaces() ([]netmon.Interface, error) {
	var head *C.struct_ifaddrs
	if rc, err := C.getifaddrs(&head); rc != 0 {
		return nil, err
	}
	defer C.freeifaddrs(head)
	var out []netmon.Interface
	byName := map[string]int{}
	for ifa := head; ifa != nil; ifa = ifa.ifa_next {
		name := C.GoString(ifa.ifa_name)
		at, seen := byName[name]
		if !seen {
			at = len(out)
			byName[name] = at
			out = append(out, netmon.Interface{Interface: &net.Interface{
				Index: int(C.if_nametoindex(ifa.ifa_name)),
				Name:  name,
				Flags: linkFlags(uint32(ifa.ifa_flags)),
			}})
		}
		if ip := sockaddrIP(ifa.ifa_addr); ip != nil {
			mask := net.IPMask(sockaddrIP(ifa.ifa_netmask))
			out[at].AltAddrs = append(out[at].AltAddrs, &net.IPNet{IP: ip, Mask: mask})
		}
	}
	return out, nil
}

func linkFlags(raw uint32) net.Flags {
	var flags net.Flags
	for _, pair := range [...]struct {
		raw  uint32
		flag net.Flags
	}{
		{syscall.IFF_UP, net.FlagUp},
		{syscall.IFF_BROADCAST, net.FlagBroadcast},
		{syscall.IFF_LOOPBACK, net.FlagLoopback},
		{syscall.IFF_POINTOPOINT, net.FlagPointToPoint},
		{syscall.IFF_MULTICAST, net.FlagMulticast},
		{syscall.IFF_RUNNING, net.FlagRunning},
	} {
		if raw&pair.raw != 0 {
			flags |= pair.flag
		}
	}
	return flags
}

// sockaddrIP reads the address of a sockaddr_in or sockaddr_in6.
func sockaddrIP(sa *C.struct_sockaddr) net.IP {
	if sa == nil {
		return nil
	}
	switch sa.sa_family {
	case syscall.AF_INET:
		in := (*C.struct_sockaddr_in)(unsafe.Pointer(sa))
		raw := (*[4]byte)(unsafe.Pointer(&in.sin_addr))
		return net.IP(append([]byte(nil), raw[:]...))
	case syscall.AF_INET6:
		in6 := (*C.struct_sockaddr_in6)(unsafe.Pointer(sa))
		raw := (*[16]byte)(unsafe.Pointer(&in6.sin6_addr))
		return net.IP(append([]byte(nil), raw[:]...))
	}
	return nil
}
