#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

extern uint64_t __zero_os_usercopy_cmpxchg_u32(uint32_t *, uint32_t, uint32_t);
extern const unsigned char __zero_os_usercopy_cmpxchg_u32_access;
extern uint32_t __zero_os_usercopy_put_u32(uint32_t *, uint32_t);
extern size_t __zero_os_usercopy_copy_bytes(uint8_t *, const uint8_t *, size_t);
extern const unsigned char __zero_os_usercopy_copy_bytes_access;
extern const int32_t __ksa_ex_start[];
extern const int32_t __ksa_ex_end[];

static volatile sig_atomic_t recovered;
static _Atomic(uintptr_t) active_address;
static _Atomic(uintptr_t) active_instruction;

static void recover_fault(int signal_number, siginfo_t *info, void *raw_context) {
    ucontext_t *context = raw_context;
    uintptr_t fault_rip = (uintptr_t)context->uc_mcontext.gregs[REG_RIP];
    if (signal_number != SIGSEGV || (uintptr_t)info->si_addr != active_address) {
        _Exit(91);
    }
    for (uintptr_t cursor = (uintptr_t)__ksa_ex_start;
         cursor < (uintptr_t)__ksa_ex_end; cursor += 2 * sizeof(int32_t)) {
        const int32_t *entry = (const int32_t *)cursor;
        uintptr_t instruction = (uintptr_t)entry + (intptr_t)entry[0];
        if (instruction == fault_rip) {
            if (instruction != active_instruction) {
                _Exit(92);
            }
            context->uc_mcontext.gregs[REG_RIP] =
                (greg_t)((uintptr_t)(entry + 1) + (intptr_t)entry[1]);
            recovered++;
            return;
        }
    }
    _Exit(93);
}

int main(void) {
    struct sigaction action = {0};
    action.sa_sigaction = recover_fault;
    action.sa_flags = SA_SIGINFO;
    assert(sigemptyset(&action.sa_mask) == 0);
    assert(sigaction(SIGSEGV, &action, NULL) == 0);
    long page_size = sysconf(_SC_PAGESIZE);
    assert(page_size > 0);
    uint32_t *word = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(word != MAP_FAILED);
    *word = UINT32_MAX;
    assert(__zero_os_usercopy_cmpxchg_u32(word, UINT32_MAX, 17) == UINT32_MAX);
    assert(*word == 17);
    assert(__zero_os_usercopy_cmpxchg_u32(word, 18, 23) == 17);
    assert(*word == 17);
    active_address = (uintptr_t)word;
    assert(mprotect(word, (size_t)page_size, PROT_READ) == 0);
    active_instruction = (uintptr_t)__zero_os_usercopy_put_u32;
    assert(__zero_os_usercopy_put_u32(word, 0) == 1);
    assert(*word == 17);
    assert(recovered == 1);
    active_instruction = (uintptr_t)&__zero_os_usercopy_cmpxchg_u32_access;
    assert(__zero_os_usercopy_cmpxchg_u32(word, 17, 23) == UINT64_C(0x100000000));
    assert(*word == 17);
    assert(recovered == 2);
    assert(mprotect(word, (size_t)page_size, PROT_NONE) == 0);
    assert(__zero_os_usercopy_cmpxchg_u32(word, 17, 23) == UINT64_C(0x100000000));
    assert(recovered == 3);
    assert(munmap(word, (size_t)page_size) == 0);
    assert(__zero_os_usercopy_cmpxchg_u32((uint32_t *)active_address, 17, 23) ==
           UINT64_C(0x100000000));
    assert(recovered == 4);

    /* Issue #109 §4.2: Hardware rep movsb bulk copy + exact mid-copy SIGSEGV recovery. */
    size_t ps = (size_t)page_size;
    uint8_t *two_pages = mmap(NULL, 2 * ps, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    assert(two_pages != MAP_FAILED);
    uint8_t *kbuf = malloc(ps + 64);
    assert(kbuf != NULL);
    for (size_t i = 0; i < ps; i++) {
        two_pages[i] = (uint8_t)((i * 31u + 7u) & 0xffu);
        kbuf[i] = 0xCCu;
    }
    /* Zero-length copy must never touch unmapped memory. */
    assert(__zero_os_usercopy_copy_bytes(kbuf, (const uint8_t *)0x1000, 0) == 0);
    /* Complete mapped copy across unaligned offset returns 0. */
    assert(__zero_os_usercopy_copy_bytes(kbuf + 3, two_pages + 5, ps - 5) == 0);
    for (size_t i = 0; i < ps - 5; i++) {
        assert(kbuf[3 + i] == two_pages[5 + i]);
    }
    /* Read fault crossing from mapped page 0 into PROT_NONE page 1. */
    assert(mprotect(two_pages + ps, ps, PROT_NONE) == 0);
    active_address = (uintptr_t)(two_pages + ps);
    active_instruction = (uintptr_t)&__zero_os_usercopy_copy_bytes_access;
    size_t rem_read = __zero_os_usercopy_copy_bytes(kbuf, two_pages + ps - 19, 64);
    assert(rem_read == 64 - 19);
    assert(recovered == 5);
    for (size_t i = 0; i < 19; i++) {
        assert(kbuf[i] == two_pages[ps - 19 + i]);
    }
    /* Write fault crossing from writable page 0 into PROT_READ page 1. */
    assert(mprotect(two_pages + ps, ps, PROT_READ | PROT_WRITE) == 0);
    two_pages[ps] = 0x5Au;
    assert(mprotect(two_pages + ps, ps, PROT_READ) == 0);
    for (size_t i = 0; i < 64; i++) {
        kbuf[i] = (uint8_t)(0xA0u + i);
    }
    size_t rem_write = __zero_os_usercopy_copy_bytes(two_pages + ps - 13, kbuf, 64);
    assert(rem_write == 64 - 13);
    assert(recovered == 6);
    assert(two_pages[ps] == 0x5Au);
    for (size_t i = 0; i < 13; i++) {
        assert(two_pages[ps - 13 + i] == kbuf[i]);
    }
    free(kbuf);
    assert(munmap(two_pages, 2 * ps) == 0);

    puts("KSA-002 + Issue #109 §4.2: mapped match/mismatch and 6 exact-RIP fault recoveries passed");
    return 0;
}
