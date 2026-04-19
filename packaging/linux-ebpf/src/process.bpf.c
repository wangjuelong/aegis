#include "common.bpf.h"

SEC("tracepoint/sched/sched_process_exec")
int aegis_sched_exec(void *ctx)
{
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int aegis_sched_exit(void *ctx)
{
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int aegis_sched_fork(void *ctx)
{
    return 0;
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(aegis_commit_creds, struct cred *new)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
