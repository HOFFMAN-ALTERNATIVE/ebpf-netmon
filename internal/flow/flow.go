// Package flow defines the user-space mirror of the kernel flow_key / flow_val structs.
package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Direction of traffic relative to the monitored cgroup.
type Direction uint8

const (
	Ingress Direction = 0
	Egress  Direction = 1
)

func (d Direction) String() string {
	switch d {
	case Ingress:
		return "in"
	case Egress:
		return "out"
	default:
		return fmt.Sprintf("dir(%d)", uint8(d))
	}
}

// KeySize and ValueSize must match struct flow_key / flow_val in bpf/c/netmon.bpf.c.
const (
	KeySize   = 40
	ValueSize = 32
)

// Key is the binary-compatible layout of struct flow_key.
type Key struct {
	Saddr  [16]byte
	Daddr  [16]byte
	Sport  uint16
	Dport  uint16
	Proto  uint8
	Dir    Direction
	Family uint8
	Pad    uint8
}

// Stats is the binary-compatible layout of struct flow_val.
type Stats struct {
	Packets     uint64
	Bytes       uint64
	FirstSeenNs uint64
	LastSeenNs  uint64
}

var ErrShortBuffer = errors.New("flow: short buffer")

// DecodeKey parses a raw little-endian map key.
func DecodeKey(b []byte) (Key, error) {
	var k Key
	if len(b) < KeySize {
		return k, ErrShortBuffer
	}
	copy(k.Saddr[:], b[0:16])
	copy(k.Daddr[:], b[16:32])
	k.Sport = binary.LittleEndian.Uint16(b[32:34])
	k.Dport = binary.LittleEndian.Uint16(b[34:36])
	k.Proto = b[36]
	k.Dir = Direction(b[37])
	k.Family = b[38]
	return k, nil
}

// Encode serialises the key in kernel layout (used by tests and replay tooling).
func (k Key) Encode() []byte {
	b := make([]byte, KeySize)
	copy(b[0:16], k.Saddr[:])
	copy(b[16:32], k.Daddr[:])
	binary.LittleEndian.PutUint16(b[32:34], k.Sport)
	binary.LittleEndian.PutUint16(b[34:36], k.Dport)
	b[36] = k.Proto
	b[37] = uint8(k.Dir)
	b[38] = k.Family
	return b
}

// DecodeStats parses a raw little-endian map value.
func DecodeStats(b []byte) (Stats, error) {
	if len(b) < ValueSize {
		return Stats{}, ErrShortBuffer
	}
	return Stats{
		Packets:     binary.LittleEndian.Uint64(b[0:8]),
		Bytes:       binary.LittleEndian.Uint64(b[8:16]),
		FirstSeenNs: binary.LittleEndian.Uint64(b[16:24]),
		LastSeenNs:  binary.LittleEndian.Uint64(b[24:32]),
	}, nil
}

func addr(raw [16]byte, family uint8) netip.Addr {
	a := netip.AddrFrom16(raw)
	if family == 4 {
		return a.Unmap()
	}
	return a
}

// Src returns the source address (IPv4 unmapped).
func (k Key) Src() netip.Addr { return addr(k.Saddr, k.Family) }

// Dst returns the destination address (IPv4 unmapped).
func (k Key) Dst() netip.Addr { return addr(k.Daddr, k.Family) }

// ProtoName is a human name for the L4 protocol.
func (k Key) ProtoName() string {
	switch k.Proto {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return fmt.Sprintf("ip-%d", k.Proto)
	}
}

// HasPorts reports whether the protocol carries L4 ports.
func (k Key) HasPorts() bool { return k.Proto == 6 || k.Proto == 17 }

func (k Key) String() string {
	if k.HasPorts() {
		return fmt.Sprintf("%s %s %s -> %s",
			k.Dir, k.ProtoName(),
			netip.AddrPortFrom(k.Src(), k.Sport), netip.AddrPortFrom(k.Dst(), k.Dport))
	}
	return fmt.Sprintf("%s %s %s -> %s", k.Dir, k.ProtoName(), k.Src(), k.Dst())
}

// NewKey builds a Key from addresses (handy for tests and fixtures).
func NewKey(dir Direction, proto uint8, src, dst netip.AddrPort) Key {
	k := Key{Sport: src.Port(), Dport: dst.Port(), Proto: proto, Dir: dir, Family: 6}
	if src.Addr().Is4() || src.Addr().Is4In6() {
		k.Family = 4
	}
	k.Saddr = src.Addr().As16()
	k.Daddr = dst.Addr().As16()
	return k
}
