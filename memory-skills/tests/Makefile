CC      := aarch64-linux-gnu-gcc
CFLAGS  := -O0 -Wall -g
LDFLAGS :=

TARGETS := test_malloc_alloc test_mmap_alloc test_dmabuf_alloc test_shmem_alloc

all: $(TARGETS)

test_malloc_alloc: userspace/test_malloc_alloc.c
	$(CC) $(CFLAGS) -o $@ $<

test_mmap_alloc: userspace/test_mmap_alloc.c
	$(CC) $(CFLAGS) -o $@ $<

test_dmabuf_alloc: userspace/test_dmabuf_alloc.c
	$(CC) $(CFLAGS) -o $@ $<

test_shmem_alloc: userspace/test_shmem_alloc.c
	$(CC) $(CFLAGS) -o $@ $< -lrt

clean:
	rm -f $(TARGETS)
	$(MAKE) -C kernel clean 2>/dev/null || true

push: all
	adb push $(TARGETS) /data/local/tmp/
	adb shell chmod +x $(addsuffix ,$(addprefix /data/local/tmp/,$(TARGETS)))
	@echo "Binaries pushed to /data/local/tmp/"

# Build kernel module (requires kernel headers on device or cross-compile setup)
kernel_module:
	$(MAKE) -C kernel

.PHONY: all clean push kernel_module
