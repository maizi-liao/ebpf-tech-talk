#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm-generic/errno.h>

#include "iomem.h"

static __always_inline void *lookup_or_init(void *map, const void *key,
                                             const void *initial_value)
{
    void *value = bpf_map_lookup_elem(map, key);
    long error;

    if (value)
        return value;

    error = bpf_map_update_elem(map, key, initial_value, BPF_NOEXIST);
    if (error && error != -EEXIST)
        return NULL;

    return bpf_map_lookup_elem(map, key);
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct request *);
    __type(value, struct who_t);
} whobyreq SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct who_t);
    __type(value, struct val_t);
} counts SEC(".maps");

SEC("tp_btf/block_rq_issue")
int BPF_PROG(handle_block_rq_issue, struct request *request)
{
    struct who_t process = {};

    if (bpf_get_current_comm(process.name, sizeof(process.name)))
        return 0;

    process.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&whobyreq, &request, &process, BPF_ANY);
    return 0;
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(handle_block_rq_complete, struct request *request,
             blk_status_t error, unsigned int bytes)
{
    const struct who_t *process;
    struct val_t initial_value = {};
    struct val_t *value;

    (void)error;
    process = bpf_map_lookup_elem(&whobyreq, &request);
    if (!process)
        return 0;

    value = lookup_or_init(&counts, process, &initial_value);
    if (value)
        __sync_fetch_and_add(&value->bytes, bytes);

    bpf_map_delete_elem(&whobyreq, &request);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
