#include "common.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} blocked_ipv4 SEC(".maps");

SEC("tracepoint/sock/inet_sock_set_state")
int aegis_inet_sock_state(void *ctx)
{
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(aegis_tcp_v4_connect, struct sock *sk)
{
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
    __u64 *enabled;

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
    enabled = bpf_map_lookup_elem(&blocked_ipv4, &daddr);
    if (!enabled) {
        return 0;
    }

    return -AEGIS_EPERM;
}

char LICENSE[] SEC("license") = "GPL";
