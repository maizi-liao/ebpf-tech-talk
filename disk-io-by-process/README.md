# Disk I/O by process using request pointers

This demo uses BTF tracepoints `block_rq_issue` and `block_rq_complete`. It keys the outstanding-request map by `struct request *`, which identifies the same block request at issue and completion. Completed bytes are attributed to the task current when the request is issued.

## Prerequisites

Run this in an Ubuntu 26.04 VM with a kernel exposing BTF and BTF block request tracepoints:

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev bpftool \
  linux-headers-$(uname -r) linux-tools-common linux-tools-$(uname -r)
test -r /sys/kernel/btf/vmlinux && echo "BTF available"
```

The generated `vmlinux.h` must contain BTF declarations for `block_rq_issue` and `block_rq_complete`. The hook prototypes may differ between kernel versions.

## Build

```bash
make
```

For a non-x86 host, pass the BPF target architecture accepted by the kernel, for example `make ARCH=arm64`.

## Run

```bash
sudo ./iomem
```

The program prints completed data bytes every second as `PID:COMMAND BYTES`. Requests issued before the program attaches have no saved owner and are ignored at completion.

## Clean

```bash
make clean
```
