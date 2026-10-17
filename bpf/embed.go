// Package bpf embeds the compiled eBPF object (built from netmon.bpf.c by `make bpf`).
package bpf

import (
	"bytes"
	_ "embed"

	"github.com/cilium/ebpf"
)

//go:embed netmon.bpf.o
var object []byte

// Object returns the raw ELF bytes of the compiled program.
func Object() []byte { return object }

// Spec parses the embedded ELF into a CollectionSpec without touching the kernel.
func Spec() (*ebpf.CollectionSpec, error) {
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
}
