# AFL++ Status for Nilix Kernel

**Date:** 2026-07-04  
**Status:** ⚠️ Infrastructure complete but incompatible with bare-metal kernel target

---

## Summary

AFL++ has been fully built and configured, but **cannot run on the bare-metal Nilix kernel** because:

- Nilix kernel is `x86_64-unknown-none` (UEFI bare-metal)
- AFL++ QEMU mode fuzzes `x86_64-linux-gnu` userspace binaries
- The kernel has no `main()`, no `fork()`, no Linux syscalls
- Error: "Unable to request new process from fork server"

**This is expected and documented.** AFL++ is preserved for potential future use.

---

## What's Ready (But Inactive)

### ✅ Built Components

- AFL++ core: `afl-fuzz++4.00c`
- QEMU mode: `afl-qemu-trace` (built and tested)
- Seed generator: `scripts/generate_afl_seeds.py` (10 binary syscall traces)
- Scripts: `afl_fuzz.sh`, `afl_parallel.sh`, `afl_triage.sh`
- CI workflow: `.github/workflows/afl_fuzz.yml`
- Makefile targets: `make afl-fuzz`, `make afl-fuzz-parallel`
- Documentation: `fuzz/afl/README.md`, `docs/fuzz/IMPLEMENTATION.md`

### ⚠️ Known Limitation

Running `make afl-fuzz` will fail with:
```
Unable to request new process from fork server (OOM?)
```

This is **expected** — the kernel is not a Linux userspace binary.

---

## Alternative: Use libFuzzer (Recommended)

LibFuzzer works and is actively maintained:

**Working targets:**
- ✅ `fuzz_elf_loader` — 961 corpus, 406k exec/s
- ✅ `fuzz_network_packet` — 703 corpus, 176k exec/s
- ✅ `fuzz_vfs_path` — 1,115 corpus, 105k exec/s
- ✅ `fuzz_syscall` — 350 paths, 52k exec/s (using mock kernel context)

**See:** `docs/fuzz/MOCK_KERNEL.md` for the working approach.

---

## Future Use Cases for AFL++

AFL++ infrastructure is preserved for these scenarios:

### 1. Userspace Test Programs

Extract kernel components into Linux userspace wrappers:

```rust
// fuzz_targets/afl_elf_parser.rs (compile with x86_64-linux-gnu)
use std::fs;

fn main() {
    let input = std::env::args().nth(1).unwrap();
    let data = fs::read(input).unwrap();
    
    // Call REAL kernel ELF parser
    kernel::elf_loader::parse_elf(&data);
}
```

**Build:**
```bash
cargo build --target x86_64-unknown-linux-gnu --bin afl_elf_parser
```

**Fuzz:**
```bash
make afl-fuzz --kernel=target/x86_64-unknown-linux-gnu/release/afl_elf_parser
```

### 2. QEMU System Mode (Future)

Boot the full kernel in QEMU system emulation:
- Feed input via virtio/serial
- Detect crashes via QEMU monitor
- **Note:** 100-1000x slower than userspace fuzzing

---

## Recommendation

**Do not remove AFL++ infrastructure.** It's complete, documented, and may be useful for:
- Userspace test programs (parsers)
- Full-kernel QEMU system mode (if needed)
- Reference implementation

**Current focus:** libFuzzer with mock kernel context (see `docs/fuzz/MOCK_KERNEL.md`)

---

## Makefile Targets

The AFL++ targets remain in the Makefile but will fail with a clear error:

```makefile
# AFL++ Fuzzing Targets (NOTE: Incompatible with bare-metal kernel)
afl-seeds:
	@echo "=== 生成AFL++种子语料库 ==="
	python3 scripts/generate_afl_seeds.py

afl-fuzz: build afl-seeds
	@echo "=== 运行AFL++单实例模糊测试 ==="
	@echo "WARNING: AFL++ cannot fuzz bare-metal kernel directly."
	@echo "See docs/fuzz/AFL_STATUS.md for alternatives."
	chmod +x scripts/afl_fuzz.sh
	./scripts/afl_fuzz.sh --kernel kernel-target/x86_64-unknown-none/release/kernel
```

Users who run these will see the error and be directed to documentation.

---

## Files to Keep

**Do not delete:**
- `fuzz/afl/` directory
- `scripts/afl_*.sh` scripts
- `scripts/generate_afl_seeds.py`
- `.github/workflows/afl_fuzz.yml`
- `docs/fuzz/IMPLEMENTATION.md`
- Makefile AFL++ targets

**Reason:** Complete infrastructure for future userspace test programs or QEMU system mode.

---

## Files to Update

### Makefile: Add warning to AFL++ targets

```makefile
afl-fuzz: build afl-seeds
	@echo "=== 运行AFL++单实例模糊测试 ==="
	@echo "⚠️  WARNING: AFL++ QEMU mode cannot fuzz bare-metal x86_64-unknown-none kernel."
	@echo "    See docs/fuzz/AFL_STATUS.md for alternatives (userspace wrappers or libFuzzer)."
	@echo ""
	chmod +x scripts/afl_fuzz.sh
	./scripts/afl_fuzz.sh --kernel kernel-target/x86_64-unknown-none/release/kernel
```

### CI Workflow: Disable AFL++ job

In `.github/workflows/afl_fuzz.yml`, add a comment at the top:

```yaml
# NOTE: This workflow is preserved but disabled because AFL++ QEMU mode
# cannot fuzz the bare-metal Nilix kernel (x86_64-unknown-none).
# See docs/fuzz/AFL_STATUS.md for alternatives.
#
# To enable for userspace test programs, remove the 'if: false' condition below.

jobs:
  afl-fuzz:
    if: false  # Disabled: incompatible with bare-metal kernel target
    runs-on: ubuntu-latest
```

---

## Summary

- ✅ AFL++ infrastructure is **complete and documented**
- ⚠️ AFL++ is **incompatible with bare-metal kernel** (expected)
- ✅ libFuzzer with mock kernel is **working and recommended**
- 📦 AFL++ is **preserved for future use** (userspace wrappers, QEMU system mode)
- 🎯 **Action:** Add warnings to Makefile + disable CI workflow
