CLANG ?= clang
CC ?= cc
ARCH ?= x86

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.
USER_CFLAGS := -g -O2 -Wall -Wextra

.PHONY: all clean

all: iomem

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

iomem.bpf.o: iomem.bpf.c iomem.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

iomem.skel.h: iomem.bpf.o
	bpftool gen skeleton $< > $@

iomem: iomem.c iomem.h iomem.skel.h
	$(CC) $(USER_CFLAGS) $< -lbpf -o $@

clean:
	rm -f iomem iomem.bpf.o iomem.skel.h vmlinux.h
