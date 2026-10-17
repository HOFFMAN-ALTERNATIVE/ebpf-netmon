// SPDX-License-Identifier: (MIT OR GPL-2.0-only)
//
// netmon: per-flow L3/L4 accounting at the cgroup socket layer.
//
// Attached as cgroup_skb ingress + egress on a cgroup v2 hierarchy (the root
// cgroup by default) it sees every packet of every socket in that subtree —
// including loopback — with no packet copies to user space. User space only
// ever reads aggregated counters from an LRU hash map.
//
// Self-contained on purpose: depends only on <linux/bpf.h> (uapi), no libbpf
// headers and no vmlinux.h, so it builds with any clang that has a BPF target.

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) __typeof__(val) *name

/* helper IDs from the stable BPF ABI (include/uapi/linux/bpf.h) */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *)BPF_FUNC_skb_load_bytes;

#define ETH_P_IP_BE   0x0008 /* htons(0x0800) */
#define ETH_P_IPV6_BE 0xDD86 /* htons(0x86DD) */
#define IPPROTO_TCP_  6
#define IPPROTO_UDP_  17

#define DIR_INGRESS 0
#define DIR_EGRESS  1

/* keep in sync with internal/flow/flow.go */
struct flow_key {
	__u8  saddr[16]; /* IPv4 is stored v4-mapped (::ffff:a.b.c.d) */
	__u8  daddr[16];
	__u16 sport;     /* host byte order */
	__u16 dport;
	__u8  proto;
	__u8  dir;
	__u8  family;    /* 4 or 6 */
	__u8  pad;
};

struct flow_val {
	__u64 packets;
	__u64 bytes;
	__u64 first_seen_ns;
	__u64 last_seen_ns;
};

enum counter {
	CNT_PACKETS = 0,
	CNT_UNSUPPORTED = 1,
	CNT_PARSE_ERRORS = 2,
	CNT_UPDATE_ERRORS = 3,
	CNT_MAX = 4,
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, struct flow_key);
	__type(value, struct flow_val);
} flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CNT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &idx);
	if (v)
		*v += 1; /* per-CPU slot: no atomics needed */
}

static __always_inline __u16 bswap16(__u16 x) { return __builtin_bswap16(x); }

static __always_inline int load_ports(struct __sk_buff *skb, __u32 off, struct flow_key *k)
{
	__u16 ports[2];
	if (k->proto != IPPROTO_TCP_ && k->proto != IPPROTO_UDP_)
		return 0;
	if (bpf_skb_load_bytes(skb, off, ports, sizeof(ports)) < 0)
		return -1;
	k->sport = bswap16(ports[0]);
	k->dport = bswap16(ports[1]);
	return 0;
}

static __always_inline int parse(struct __sk_buff *skb, struct flow_key *k)
{
	if (skb->protocol == ETH_P_IP_BE) {
		__u8 hdr[20];
		if (bpf_skb_load_bytes(skb, 0, hdr, sizeof(hdr)) < 0)
			return -1;
		__u32 ihl = (hdr[0] & 0x0f) * 4;
		if (ihl < 20)
			return -1;
		k->family = 4;
		k->proto = hdr[9];
		k->saddr[10] = 0xff; k->saddr[11] = 0xff;
		k->daddr[10] = 0xff; k->daddr[11] = 0xff;
		__builtin_memcpy(&k->saddr[12], &hdr[12], 4);
		__builtin_memcpy(&k->daddr[12], &hdr[16], 4);
		return load_ports(skb, ihl, k);
	}
	if (skb->protocol == ETH_P_IPV6_BE) {
		__u8 hdr[40];
		if (bpf_skb_load_bytes(skb, 0, hdr, sizeof(hdr)) < 0)
			return -1;
		k->family = 6;
		k->proto = hdr[6]; /* next header; extension headers are reported as-is */
		__builtin_memcpy(k->saddr, &hdr[8], 16);
		__builtin_memcpy(k->daddr, &hdr[24], 16);
		return load_ports(skb, 40, k);
	}
	return 1;
}

static __always_inline int account(struct __sk_buff *skb, __u8 dir)
{
	struct flow_key k = {};
	int rc = parse(skb, &k);
	if (rc > 0) {
		bump(CNT_UNSUPPORTED);
		return 1;
	}
	if (rc < 0) {
		bump(CNT_PARSE_ERRORS);
		return 1;
	}
	k.dir = dir;
	bump(CNT_PACKETS);

	__u64 now = bpf_ktime_get_ns();
	struct flow_val *v = bpf_map_lookup_elem(&flows, &k);
	if (v) {
		__sync_fetch_and_add(&v->packets, 1);
		__sync_fetch_and_add(&v->bytes, skb->len);
		v->last_seen_ns = now;
		return 1;
	}
	struct flow_val init = {
		.packets = 1,
		.bytes = skb->len,
		.first_seen_ns = now,
		.last_seen_ns = now,
	};
	if (bpf_map_update_elem(&flows, &k, &init, BPF_NOEXIST) < 0) {
		/* lost a race with another CPU creating the same flow */
		v = bpf_map_lookup_elem(&flows, &k);
		if (v) {
			__sync_fetch_and_add(&v->packets, 1);
			__sync_fetch_and_add(&v->bytes, skb->len);
		} else {
			bump(CNT_UPDATE_ERRORS);
		}
	}
	return 1; /* observe only: never drop */
}

SEC("cgroup_skb/ingress")
int netmon_ingress(struct __sk_buff *skb) { return account(skb, DIR_INGRESS); }

SEC("cgroup_skb/egress")
int netmon_egress(struct __sk_buff *skb) { return account(skb, DIR_EGRESS); }

char LICENSE[] SEC("license") = "Dual MIT/GPL";
