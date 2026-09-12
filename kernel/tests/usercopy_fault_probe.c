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
extern const int32_t __ksa_ex_start[];
extern const int32_t __ksa_ex_end[];

static volatile sig_atomic_t recovered;
static _Atomic(uintptr_t) active_address;

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
            const unsigned char *opcode = (const unsigned char *)instruction;
            if (opcode[0] != 0xf0 || opcode[1] != 0x0f || opcode[2] != 0xb1) {
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
    assert(__zero_os_usercopy_cmpxchg_u32(word, 17, 23) == UINT64_C(0x100000000));
    assert(*word == 17);
    assert(recovered == 1);
    assert(mprotect(word, (size_t)page_size, PROT_NONE) == 0);
    assert(__zero_os_usercopy_cmpxchg_u32(word, 17, 23) == UINT64_C(0x100000000));
    assert(recovered == 2);
    assert(munmap(word, (size_t)page_size) == 0);
    assert(__zero_os_usercopy_cmpxchg_u32((uint32_t *)active_address, 17, 23) ==
           UINT64_C(0x100000000));
    assert(recovered == 3);
    puts("KSA-002: mapped match/mismatch and 3 exact-RIP fault recoveries passed");
    return 0;
}
