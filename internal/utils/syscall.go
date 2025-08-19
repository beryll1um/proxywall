package utils

import (
	"encoding/binary"
	"net"
	"strconv"
	"syscall"
	"unsafe"
)

// include/uapi/linux/netfilter_ipv6/ip6_tables.h
const SO_ORIGINAL_DST = 80

type RawSockaddrAny struct {
	syscall.RawSockaddrAny
}

func (sa RawSockaddrAny) IP() net.IP {
	var host []byte
	ptr := unsafe.Pointer(&sa)
	switch sa.Addr.Family {
	case syscall.AF_INET:
		sa4 := (*syscall.RawSockaddrInet4)(ptr)
		host = sa4.Addr[:]
	case syscall.AF_INET6:
		sa6 := (*syscall.RawSockaddrInet6)(ptr)
		host = sa6.Addr[:]
	}
	return net.IP(host)
}

func be16(p *uint16) uint16 {
	b := *(*[2]byte)(unsafe.Pointer(p))
	return binary.BigEndian.Uint16(b[:])
}

func (sa RawSockaddrAny) Port() int {
	var port uint16
	ptr := unsafe.Pointer(&sa)
	switch sa.Addr.Family {
	case syscall.AF_INET:
		sa4 := (*syscall.RawSockaddrInet4)(ptr)
		port = sa4.Port
	case syscall.AF_INET6:
		sa6 := (*syscall.RawSockaddrInet6)(ptr)
		port = sa6.Port
	}
	return int(be16(&port))
}

func (sa RawSockaddrAny) String() string {
	return net.JoinHostPort(sa.IP().String(), strconv.Itoa(sa.Port()))
}

func GetOriginalDst4(fd uintptr, sa *RawSockaddrAny) error {
	sz := unsafe.Sizeof(*sa)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
		syscall.SOL_IP, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(sa)),
		uintptr(unsafe.Pointer(&sz)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func GetOriginalDst6(fd uintptr, sa *RawSockaddrAny) error {
	sz := unsafe.Sizeof(*sa)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd,
		syscall.SOL_IPV6, SO_ORIGINAL_DST, uintptr(unsafe.Pointer(sa)),
		uintptr(unsafe.Pointer(&sz)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// vim: set ts=4 sw=4 noexpandtab:
