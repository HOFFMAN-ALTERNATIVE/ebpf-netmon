//go:build !linux

package probe

import (
	"errors"

	"github.com/HOFFMAN-ALTERNATIVE/ebpf-netmon/internal/source"
)

// Load is only supported on Linux.
func Load(string) (source.Source, error) { return nil, errors.New("ebpf-netmon requires Linux") }
