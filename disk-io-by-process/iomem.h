#ifndef IOMEM_H
#define IOMEM_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define TASK_COMM_LEN 16

struct who_t {
    __u32 pid;
    char name[TASK_COMM_LEN];
};

struct val_t {
    __u64 bytes;
};

#endif
