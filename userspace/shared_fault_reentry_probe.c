// ST-K2-P2(a) probe guest: map one MAP_SHARED|MAP_ANONYMOUS page, never touch
// it, and ask the kernel to fault it in while it holds the lock chosen at build
// time with -DST_K2_REENTRY_LOCK (0 PROCESS_TABLE, 1 PCB, 2 MmState).
//
// A repaired kernel stops in the page-fault handler with "same-CPU <lock>
// reentry during shared fault" and the probe image ends QEMU. prctl returns
// only on a kernel that let the fault resolve.
#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#ifndef ST_K2_REENTRY_LOCK
#error "build with -DST_K2_REENTRY_LOCK=0, 1 or 2"
#endif

#define PR_SHARED_FAULT_REENTRY_PROBE 0x5a534652

int main(void) {
    void *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        printf("ST-K2-REENTRY-PROBE GUEST-FAIL stage=mmap errno=%d\n", errno);
        return 1;
    }
    printf("ST-K2-REENTRY-PROBE GUEST lock=%d\n", ST_K2_REENTRY_LOCK);
    fflush(stdout);
    int rc = prctl(PR_SHARED_FAULT_REENTRY_PROBE, ST_K2_REENTRY_LOCK,
                   (unsigned long)page, 0UL, 0UL);
    printf("ST-K2-REENTRY-PROBE GUEST-RETURNED rc=%d errno=%d\n", rc, errno);
    return 2;
}
