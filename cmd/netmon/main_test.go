package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestParseFlagsValidates(t *testing.T) {
	if _, err := parseFlags([]string{"-interval", "10ms"}); err == nil {
		t.Error("tiny interval must be rejected")
	}
	if _, err := parseFlags([]string{"-top", "0"}); err == nil {
		t.Error("top=0 must be rejected")
	}
	c, err := parseFlags([]string{"-demo", "-top", "3"})
	if err != nil || !c.demo || c.top != 3 || c.cgroup != "/sys/fs/cgroup" {
		t.Fatalf("unexpected config %+v, %v", c, err)
	}
}

func TestDemoRunRendersTopTalkers(t *testing.T) {
	var out bytes.Buffer
	cfg := config{demo: true, interval: 120 * time.Millisecond, top: 3, ticks: 3}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run(ctx, cfg, &out, slog.New(slog.NewTextHandler(io.Discard, nil))); err != nil {
		t.Fatal(err)
	}
	s := out.String()
	if !strings.Contains(s, "DIR") || !strings.Contains(s, "flows tracked: 5") {
		t.Fatalf("missing header/flow count:\n%s", s)
	}
	if !strings.Contains(s, "198.51.100.20:443") {
		t.Fatalf("busiest demo flow not shown:\n%s", s)
	}
}

func TestHumanBytes(t *testing.T) {
	cases := map[float64]string{0: "0 B", 1023: "1023 B", 1536: "1.5 KiB", 5 * 1024 * 1024: "5.0 MiB"}
	for in, want := range cases {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%v) = %q, want %q", in, got, want)
		}
	}
}
