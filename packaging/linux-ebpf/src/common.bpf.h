#ifndef AEGIS_COMMON_BPF_H
#define AEGIS_COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AEGIS_EPERM 1
#define AEGIS_AF_INET 2
#define AEGIS_TASK_COMM_LEN 16
#define AEGIS_FILE_PATH_LEN 256

#define AEGIS_FILE_OP_OPEN 1
#define AEGIS_FILE_OP_EXEC 2
#define AEGIS_NET_OP_CONNECT 1

struct aegis_file_event_key {
    __u32 pid;
    __u32 op;
    __u64 identity;
};

struct aegis_file_event_value {
    __u64 seen_ns;
    __u32 pid;
    __u32 op;
    __u64 identity;
    __u64 inode;
    __u8 blocked;
    char comm[AEGIS_TASK_COMM_LEN];
    char path[AEGIS_FILE_PATH_LEN];
};

struct aegis_network_event_key {
    __u32 pid;
    __u32 daddr;
    __u16 dport;
    __u16 family;
    __u32 op;
};

struct aegis_network_event_value {
    __u64 seen_ns;
    __u32 pid;
    __u32 daddr;
    __u16 dport;
    __u16 family;
    __u8 blocked;
    char comm[AEGIS_TASK_COMM_LEN];
};

static __always_inline __u64 aegis_inode_ino(struct inode *inode)
{
    if (!inode) {
        return 0;
    }

    return BPF_CORE_READ(inode, i_ino);
}

static __always_inline __u64 aegis_file_inode_key(struct file *file)
{
    struct inode *inode;

    if (!file) {
        return 0;
    }

    inode = BPF_CORE_READ(file, f_inode);
    return aegis_inode_ino(inode);
}

static __always_inline __u64 aegis_bprm_inode_key(struct linux_binprm *bprm)
{
    struct file *file;
    struct inode *inode;

    if (!bprm) {
        return 0;
    }

    file = BPF_CORE_READ(bprm, file);
    if (!file) {
        return 0;
    }

    inode = BPF_CORE_READ(file, f_inode);
    return aegis_inode_ino(inode);
}

static __always_inline __u32 aegis_current_pid(void)
{
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline void aegis_capture_comm(char comm[AEGIS_TASK_COMM_LEN])
{
    __builtin_memset(comm, 0, AEGIS_TASK_COMM_LEN);
    bpf_get_current_comm(comm, AEGIS_TASK_COMM_LEN);
}

static __always_inline __u64 aegis_hash_bytes(const char *value, __u32 limit)
{
    __u64 hash = 1469598103934665603ULL;
    __u32 index;

#pragma unroll
    for (index = 0; index < AEGIS_FILE_PATH_LEN; index++) {
        char ch;

        if (index >= limit) {
            break;
        }

        ch = value[index];
        if (!ch) {
            break;
        }

        hash ^= (__u8)ch;
        hash *= 1099511628211ULL;
    }

    return hash;
}

#endif
