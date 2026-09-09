# sched-ext FIFO scheduler

This is the FIFO-only core of `scx_simple`. A waking task goes directly to an idle CPU's local dispatch queue when possible. Otherwise, it is appended to sched-ext's built-in global FIFO queue. No weighted virtual time, custom dispatch queue, or scheduler statistics are included.

## Prerequisites

Use an isolated Ubuntu 26.04 VM. Install the normal eBPF toolchain:

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libbpf-dev bpftool pahole \
  linux-headers-$(uname -r) linux-tools-common linux-tools-$(uname -r)
```

The booted kernel must expose sched-ext and BTF:

```bash
grep -E 'CONFIG_(BPF|BPF_SYSCALL|BPF_JIT|DEBUG_INFO_BTF|SCHED_CLASS_EXT)=' /boot/config-$(uname -r)
test -r /sys/kernel/btf/vmlinux && echo "BTF available"
test -e /sys/kernel/sched_ext/state && cat /sys/kernel/sched_ext/state
```

At minimum, the kernel needs `CONFIG_SCHED_CLASS_EXT=y`, `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_BPF_JIT=y`, and `CONFIG_DEBUG_INFO_BTF=y`. If `/sys/kernel/sched_ext/state` does not exist, boot a kernel that enables sched-ext; installing a userspace package cannot add it.

## Why this example generates `vmlinux.h`

This example generates `vmlinux.h` from the **running VM**, just like the disk-I/O example:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

This minimal FIFO example uses the BTF types and kfunc declarations from its generated `vmlinux.h`. For an arm64 VM, also pass `ARCH=arm64`.

## Build

```bash
make
```

This creates `vmlinux.h`, `fifo.bpf.o`, its libbpf skeleton, and the `fifo` loader.

## Run and inspect

```bash
sudo ./fifo

# In another terminal
cat /sys/kernel/sched_ext/state
cat /sys/kernel/sched_ext/root/ops
cat /sys/kernel/sched_ext/root/events
```

The scheduler is active only while the loader runs. Press `Ctrl-C` to detach; sched-ext returns affected tasks to the fair scheduler. A global FIFO scheduler is intentionally unfair, so do not use it for general workloads.

## Clean

```bash
make clean
```