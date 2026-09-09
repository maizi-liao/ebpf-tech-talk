CLANG ?= clang
CC ?= cc
ARCH ?= x86

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -I.
USER_CFLAGS := -g -O2 -Wall -Wextra

.PHONY: all clean

all: fifo

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

fifo.bpf.o: fifo.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

fifo.skel.h: fifo.bpf.o
	bpftool gen skeleton $< > $@

fifo: fifo.c fifo.skel.h
	$(CC) $(USER_CFLAGS) $< -lbpf -o $@

clean:
	rm -f fifo fifo.bpf.o fifo.skel.h vmlinux.h