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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, struct aegis_file_event_key);
    __type(value, struct aegis_file_event_value);
} observed_file_events SEC(".maps");

static __always_inline void
aegis_record_file_event(__u64 inode, __u32 op, __u8 blocked, const char *path)
{
    struct aegis_file_event_key key = {};
    struct aegis_file_event_value value = {};
    long copied = 0;

    if (!inode && !path) {
        return;
    }

    key.pid = aegis_current_pid();
    key.op = op;

    value.seen_ns = bpf_ktime_get_ns();
    value.pid = key.pid;
    value.op = op;
    value.inode = inode;
    value.blocked = blocked;
    aegis_capture_comm(value.comm);
    __builtin_memset(value.path, 0, sizeof(value.path));

    if (path) {
        copied = bpf_probe_read_user_str(value.path, sizeof(value.path), path);
        if (copied > 1) {
            value.identity = aegis_hash_bytes(value.path, sizeof(value.path));
        }
    }
    if (!value.identity) {
        value.identity = inode;
    }
    if (!value.identity) {
        return;
    }

    key.identity = value.identity;
    value.identity = value.identity;
    bpf_map_update_elem(&observed_file_events, &key, &value, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int aegis_sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];

    aegis_record_file_event(0, AEGIS_FILE_OP_OPEN, 0, filename);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int aegis_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];

    aegis_record_file_event(0, AEGIS_FILE_OP_OPEN, 0, filename);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int aegis_sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[0];

    aegis_record_file_event(0, AEGIS_FILE_OP_EXEC, 0, filename);
    return 0;
}

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
    aegis_record_file_event(key, AEGIS_FILE_OP_EXEC, enabled ? 1 : 0, 0);
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
    aegis_record_file_event(key, AEGIS_FILE_OP_OPEN, enabled ? 1 : 0, 0);
    if (!enabled) {
        return 0;
    }

    return -AEGIS_EPERM;
}

char LICENSE[] SEC("license") = "GPL";
