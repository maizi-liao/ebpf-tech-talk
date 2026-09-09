#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "iomem.h"
#include "iomem.skel.h"

static volatile sig_atomic_t exiting;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    exiting = 1;
}

static int print_and_clear_counts(struct bpf_map *counts)
{
    struct who_t key;
    int map_fd = bpf_map__fd(counts);

    while (bpf_map_get_next_key(map_fd, NULL, &key) == 0) {
        struct val_t value;

        if (bpf_map_lookup_elem(map_fd, &key, &value) == 0)
            printf("%u:%s %llu\n", key.pid, key.name,
                   (unsigned long long)value.bytes);
        else
            fprintf(stderr, "failed to look up counter: %s\n", strerror(errno));

        if (bpf_map_delete_elem(map_fd, &key)) {
            fprintf(stderr, "failed to clear counter: %s\n", strerror(errno));
            return -errno;
        }
    }

    return 0;
}

int main(void)
{
    struct iomem_bpf *skeleton;
    int error;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skeleton = iomem_bpf__open_and_load();
    if (!skeleton) {
        fprintf(stderr, "failed to open and load BPF object\n");
        return 1;
    }

    error = iomem_bpf__attach(skeleton);
    if (error) {
        fprintf(stderr, "failed to attach tracepoints: %d\n", error);
        iomem_bpf__destroy(skeleton);
        return 1;
    }

    while (!exiting) {
        sleep(1);
        error = print_and_clear_counts(skeleton->maps.counts);
        if (error)
            break;
    }

    iomem_bpf__destroy(skeleton);
    return error != 0;
}
