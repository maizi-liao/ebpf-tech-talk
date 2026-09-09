#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "fifo.skel.h"

static volatile sig_atomic_t exiting;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    exiting = 1;
}

int main(void)
{
    struct fifo_bpf *skeleton;
    struct bpf_link *link;
    long error;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skeleton = fifo_bpf__open_and_load();
    if (!skeleton) {
        fprintf(stderr, "failed to open and load FIFO scheduler\n");
        return 1;
    }

    link = bpf_map__attach_struct_ops(skeleton->maps.fifo_ops);
    error = libbpf_get_error(link);
    if (error) {
        fprintf(stderr, "failed to attach FIFO scheduler: %ld\n", error);
        fifo_bpf__destroy(skeleton);
        return 1;
    }

    puts("FIFO scheduler enabled; press Ctrl-C to stop");
    while (!exiting)
        pause();

    bpf_link__destroy(link);
    fifo_bpf__destroy(skeleton);
    return 0;
}