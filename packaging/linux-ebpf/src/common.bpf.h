#ifndef AEGIS_COMMON_BPF_H
#define AEGIS_COMMON_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AEGIS_EPERM 1
#define AEGIS_AF_INET 2

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

#endif
