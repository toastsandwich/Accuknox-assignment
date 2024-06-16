TARGET = droper
ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

vmlinux.h:
	@sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@echo generated vmlinux.h

%.bpf.o: %.bpf.c
	@echo compiling...
	@clang -g -O2 --target=bpf -D __TARGET_ARCH_$(ARCH) -Wall -o $@ -c $<

clean:
	rm -f *.bpf.o
