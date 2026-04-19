#include "common.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} blocked_exec_inodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u64);
} protected_inodes SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_bprm_check_security, struct linux_binprm *bprm, int ret)
{
    __u64 key;
    __u64 *enabled;

    if (ret) {
        return ret;
    }

    key = aegis_bprm_inode_key(bprm);
    if (!key) {
        return 0;
    }

    enabled = bpf_map_lookup_elem(&blocked_exec_inodes, &key);
    if (!enabled) {
        return 0;
    }

    return -AEGIS_EPERM;
}

SEC("lsm/file_open")
int BPF_PROG(aegis_file_open, struct file *file, int ret)
{
    __u64 key;
    __u64 *enabled;

    if (ret) {
        return ret;
    }

    key = aegis_file_inode_key(file);
    if (!key) {
        return 0;
    }

    enabled = bpf_map_lookup_elem(&protected_inodes, &key);
    if (!enabled) {
        return 0;
    }

    return -AEGIS_EPERM;
}

char LICENSE[] SEC("license") = "GPL";
