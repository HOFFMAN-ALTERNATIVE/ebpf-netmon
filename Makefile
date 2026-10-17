CLANG ?= clang
ARCH_INC ?= /usr/include/$(shell uname -m)-linux-gnu
BPF_CFLAGS := -target bpf -O2 -g -Wall -Werror -I$(ARCH_INC)

.PHONY: all bpf build test race integration lint demo
all: bpf build test

bpf: ## compile the eBPF object that gets embedded into the binary
	$(CLANG) $(BPF_CFLAGS) -c bpf/c/netmon.bpf.c -o bpf/netmon.bpf.o

build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/netmon ./cmd/netmon

test:
	go test -race -cover ./...

integration: ## needs root: loads into the kernel, attaches to the root cgroup
	sudo -E env "PATH=$$PATH" go test -tags integration -count=1 -v ./internal/probe/

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go vet -tags integration ./...

demo:
	go run ./cmd/netmon -demo -top 5
