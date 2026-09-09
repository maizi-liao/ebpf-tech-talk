#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("struct_ops/fifo_select_cpu")
s32 BPF_PROG(fifo_select_cpu, struct task_struct *task, s32 previous_cpu,
             u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu;

    cpu = scx_bpf_select_cpu_dfl(task, previous_cpu, wake_flags, &is_idle);
    if (is_idle)
        scx_bpf_dsq_insert(task, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);

    return cpu;
}

SEC("struct_ops/fifo_enqueue")
void BPF_PROG(fifo_enqueue, struct task_struct *task, u64 enqueue_flags)
{
    scx_bpf_dsq_insert(task, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enqueue_flags);
}

SEC(".struct_ops")
struct sched_ext_ops fifo_ops = {
    .select_cpu = (void *)fifo_select_cpu,
    .enqueue = (void *)fifo_enqueue,
    .name = "fifo",
};