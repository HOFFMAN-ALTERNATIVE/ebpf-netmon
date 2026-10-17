package flow

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"
)

func TestLayoutMatchesKernel(t *testing.T) {
	if s := unsafe.Sizeof(Key{}); s != KeySize {
		t.Fatalf("Key is %d bytes, kernel expects %d", s, KeySize)
	}
	if s := unsafe.Sizeof(Stats{}); s != ValueSize {
		t.Fatalf("Stats is %d bytes, kernel expects %d", s, ValueSize)
	}
	// binary.Write must agree with our hand-rolled encoder (what cilium/ebpf uses for structs)
	k := NewKey(Egress, 6, netip.MustParseAddrPort("10.1.2.3:43210"), netip.MustParseAddrPort("192.0.2.10:443"))
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, k); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), k.Encode()) {
		t.Fatalf("encoding mismatch\n binary.Write=%x\n Encode     =%x", buf.Bytes(), k.Encode())
	}
}

func TestRoundTripIPv4(t *testing.T) {
	k := NewKey(Ingress, 17, netip.MustParseAddrPort("198.51.100.7:53"), netip.MustParseAddrPort("10.0.0.2:5353"))
	got, err := DecodeKey(k.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got != k {
		t.Fatalf("round trip: got %+v want %+v", got, k)
	}
	if got.Src().String() != "198.51.100.7" || !got.Src().Is4() {
		t.Errorf("src = %v, want unmapped IPv4", got.Src())
	}
	if want := "in udp 198.51.100.7:53 -> 10.0.0.2:5353"; got.String() != want {
		t.Errorf("String() = %q, want %q", got.String(), want)
	}
}

func TestRoundTripIPv6(t *testing.T) {
	k := NewKey(Egress, 6, netip.MustParseAddrPort("[2001:db8::1]:50000"), netip.MustParseAddrPort("[2001:db8::2]:443"))
	got, _ := DecodeKey(k.Encode())
	if got.Family != 6 || got.Dst().String() != "2001:db8::2" {
		t.Fatalf("unexpected decode %+v", got)
	}
	if want := "out tcp [2001:db8::1]:50000 -> [2001:db8::2]:443"; got.String() != want {
		t.Errorf("String() = %q, want %q", got.String(), want)
	}
}

func TestDecodeKernelBytes(t *testing.T) {
	// hand-built buffer exactly as the BPF program writes it: v4-mapped, host-order ports
	raw := make([]byte, KeySize)
	copy(raw[10:16], []byte{0xff, 0xff, 127, 0, 0, 1})
	copy(raw[26:32], []byte{0xff, 0xff, 127, 0, 0, 1})
	binary.LittleEndian.PutUint16(raw[32:], 40000)
	binary.LittleEndian.PutUint16(raw[34:], 8080)
	raw[36], raw[37], raw[38] = 6, 1, 4
	k, err := DecodeKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	if k.String() != "out tcp 127.0.0.1:40000 -> 127.0.0.1:8080" {
		t.Fatalf("got %q", k.String())
	}
}

func TestICMPHasNoPorts(t *testing.T) {
	k := NewKey(Ingress, 1, netip.MustParseAddrPort("192.0.2.1:0"), netip.MustParseAddrPort("192.0.2.2:0"))
	if k.HasPorts() {
		t.Fatal("icmp must not have ports")
	}
	if k.String() != "in icmp 192.0.2.1 -> 192.0.2.2" {
		t.Fatalf("got %q", k.String())
	}
	if (Key{Proto: 132}).ProtoName() != "ip-132" {
		t.Fatal("unknown proto naming")
	}
}

func TestStatsDecodeAndShortBuffers(t *testing.T) {
	raw := make([]byte, ValueSize)
	binary.LittleEndian.PutUint64(raw[0:], 3)
	binary.LittleEndian.PutUint64(raw[8:], 4500)
	s, err := DecodeStats(raw)
	if err != nil || s.Packets != 3 || s.Bytes != 4500 {
		t.Fatalf("got %+v, %v", s, err)
	}
	if _, err := DecodeStats(raw[:10]); err != ErrShortBuffer {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
	if _, err := DecodeKey(raw[:10]); err != ErrShortBuffer {
		t.Fatalf("want ErrShortBuffer, got %v", err)
	}
}
