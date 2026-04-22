#include "common.bpf.h"

#define AEGIS_TCP_ESTABLISHED 1

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} blocked_ipv4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct aegis_network_event_key);
    __type(value, struct aegis_network_event_value);
} observed_ipv4_connect_events SEC(".maps");

static __always_inline void
aegis_record_ipv4_connect(__u32 daddr, __u16 dport, __u16 family, __u8 blocked)
{
    struct aegis_network_event_key key = {};
    struct aegis_network_event_value value = {};

    if (!daddr) {
        return;
    }

    key.pid = aegis_current_pid();
    key.daddr = daddr;
    key.dport = dport;
    key.family = family;
    key.op = AEGIS_NET_OP_CONNECT;

    value.seen_ns = bpf_ktime_get_ns();
    value.pid = key.pid;
    value.daddr = daddr;
    value.dport = dport;
    value.family = family;
    value.blocked = blocked;
    aegis_capture_comm(value.comm);

    bpf_map_update_elem(&observed_ipv4_connect_events, &key, &value, BPF_ANY);
}

SEC("tracepoint/sock/inet_sock_set_state")
int aegis_inet_sock_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    __u32 daddr = 0;

    if (!ctx) {
        return 0;
    }

    if (ctx->family != AEGIS_AF_INET || ctx->newstate != AEGIS_TCP_ESTABLISHED) {
        return 0;
    }

    daddr = ((__u32)ctx->daddr[0]) |
        ((__u32)ctx->daddr[1] << 8) |
        ((__u32)ctx->daddr[2] << 16) |
        ((__u32)ctx->daddr[3] << 24);
    aegis_record_ipv4_connect(daddr, ctx->dport, ctx->family, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(aegis_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    struct sockaddr_in *addr4;
    __u16 family;
    __u32 daddr;
    __u16 dport;

    if (!sk || !uaddr) {
        return 0;
    }

    addr4 = (struct sockaddr_in *)uaddr;
    family = BPF_CORE_READ(addr4, sin_family);
    if (family != AEGIS_AF_INET) {
        return 0;
    }

    daddr = BPF_CORE_READ(addr4, sin_addr.s_addr);
    dport = BPF_CORE_READ(addr4, sin_port);
    aegis_record_ipv4_connect(daddr, dport, family, 0);
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(
    aegis_socket_connect,
    struct socket *sock,
    struct sockaddr *address,
    int addrlen,
    int ret
)
{
    struct sockaddr_in *addr4;
    __u16 family;
    __u32 daddr;
    __u16 dport;
    __u64 *enabled;
    __u8 blocked = 0;

    if (ret) {
        return ret;
    }

    if (!address) {
        return 0;
    }

    addr4 = (struct sockaddr_in *)address;
    family = BPF_CORE_READ(addr4, sin_family);
    if (family != AEGIS_AF_INET) {
        return 0;
    }

    daddr = BPF_CORE_READ(addr4, sin_addr.s_addr);
    dport = BPF_CORE_READ(addr4, sin_port);
    enabled = bpf_map_lookup_elem(&blocked_ipv4, &daddr);
    if (enabled) {
        blocked = 1;
    }
    aegis_record_ipv4_connect(daddr, dport, family, blocked);
    if (!enabled) {
        return 0;
    }

    return -AEGIS_EPERM;
}

char LICENSE[] SEC("license") = "GPL";
