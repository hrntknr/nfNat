LLC ?= llc
CLANG ?= clang
CC ?= gcc

LIBBPF_DIR = ./libbpf/src/

KERN_C = nfNat_dp.c
KERN_OBJ = ${KERN_C:.c=.o}

CFLAGS ?= -I$(LIBBPF_DIR) -I./lib
KERN_CFLAGS ?= $(CFLAGS)

all: llvm-check $(KERN_OBJ)

.PHONY: clean $(CLANG) $(LLC)
clean:
	cd $(LIBBPF_DIR) && $(MAKE) clean;
	rm -f $(KERN_OBJ)
	rm -f *.ll

.PHONY: llvm-check $(CLANG) $(LLC)
llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(KERN_OBJ): %.o: %.c Makefile
	$(CLANG) -S \
			-D __BPF_TRACING__ \
			$(KERN_CFLAGS) \
			-Wall \
			-Wno-unused-value -Wno-pointer-sign \
			-Wno-compare-distinct-pointer-types \
			-O2 -emit-llvm -c -g $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
	llvm-strip $@ --no-strip-all -R .BTF
