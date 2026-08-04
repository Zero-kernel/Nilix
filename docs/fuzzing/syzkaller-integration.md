# Syzkaller-Style Host-Driven Fuzzing Architecture for Nilix

**Status:** 🚧 Architecture specification — host-driven mutation loop not yet implemented  
**Current CI:** Deterministic KCOV guest E2E + cargo-fuzz targets (see [README.md](README.md))

---

## Overview

This document specifies a syzkaller-inspired fuzzing architecture for Nilix that completes Phase 7 of the fuzzing infrastructure. Unlike the current deterministic KCOV guest E2E which executes two fixed syscall programs, this design implements a full coverage-guided feedback loop:

1. **Host mutator** generates syscall sequences from grammar
2. **Guest executor** runs sequences in isolated QEMU instance
3. **KCOV collector** extracts coverage bitmap from guest
4. **Corpus manager** saves inputs that discover new edges
5. **Crash triager** deduplicates and classifies findings

The design prioritizes **Security > Correctness > Efficiency > Performance** and maintains the private disclosure boundary established in the current CI integration.

---

## Architecture Components

### 1. Host-Side Fuzzer (`nilix-syz-fuzzer`)

The host fuzzer runs as a persistent process that orchestrates the feedback loop:

```rust
// userspace/nilix-syz-fuzzer/src/main.rs

struct SyzFuzzer {
    corpus: Corpus,
    mutator: SyscallMutator,
    executor: QemuExecutor,
    coverage: CoverageTracker,
    triager: CrashTriager,
}

impl SyzFuzzer {
    fn run(&mut self, config: FuzzConfig) -> Result<()> {
        let mut stats = FuzzStats::new();
        
        loop {
            // 1. Select input from corpus (energy-based scheduling)
            let seed = self.corpus.select_seed(&stats)?;
            
            // 2. Mutate to generate new program
            let program = self.mutator.mutate(&seed)?;
            
            // 3. Execute in QEMU guest
            let result = self.executor.execute(&program, config.timeout)?;
            
            // 4. Process result
            match result.outcome {
                Outcome::Success(coverage) => {
                    if self.coverage.is_new(&coverage) {
                        // New coverage discovered
                        self.corpus.add(program, coverage)?;
                        stats.new_coverage += 1;
                    }
                }
                Outcome::Crash(crash_info) => {
                    self.triager.handle_crash(program, crash_info)?;
                    stats.crashes += 1;
                }
                Outcome::Timeout => {
                    stats.timeouts += 1;
                }
                Outcome::Hang => {
                    self.triager.handle_hang(program)?;
                    stats.hangs += 1;
                }
            }
            
            stats.iterations += 1;
            
            if stats.should_report() {
                self.report_progress(&stats)?;
            }
        }
    }
}
```

**Key Features:**
- **Energy scheduling:** Prioritize seeds that recently discovered coverage
- **Mutation strategies:** Grammar-aware mutations that respect resource dependencies
- **Parallel execution:** Multiple QEMU instances for throughput
- **Corpus minimization:** Periodically reduce corpus to minimal covering set
- **Crash deduplication:** HMAC-based opaque IDs (existing CI infrastructure)

---

### 2. Syscall Program Representation

Programs are sequences of syscalls with resource tracking:

```rust
#[derive(Clone, Debug)]
struct SyscallProgram {
    syscalls: Vec<Syscall>,
    resources: ResourceMap,
}

#[derive(Clone, Debug)]
struct Syscall {
    number: u64,
    args: Vec<Argument>,
    resource_deps: Vec<ResourceId>,
    result: Option<ResultResource>,
}

#[derive(Clone, Debug)]
enum Argument {
    Immediate(u64),
    Resource(ResourceId),
    Buffer(Vec<u8>),
    Pointer(Box<Argument>),
    Array(Vec<Argument>),
}

#[derive(Clone, Debug)]
struct ResourceMap {
    fds: HashMap<ResourceId, FdResource>,
    pids: HashMap<ResourceId, PidResource>,
    addrs: HashMap<ResourceId, AddrResource>,
}
```

**Example program:**
```
r0 = open("/test.tmp", O_RDWR|O_CREAT, 0600)  # Creates fd resource r0
write(r0, "data", 4)                          # Uses r0
close(r0)                                      # Consumes r0
```

---

### 3. QEMU Guest Executor

The executor boots a fresh QEMU instance per program:

```rust
struct QemuExecutor {
    qemu_path: PathBuf,
    kernel_path: PathBuf,
    ovmf_path: PathBuf,
    timeout: Duration,
}

impl QemuExecutor {
    fn execute(&self, program: &SyscallProgram, timeout: Duration) 
        -> Result<ExecutionResult> {
        // 1. Serialize program to guest-readable format
        let program_blob = self.serialize_program(program)?;
        
        // 2. Write to temporary input file
        let input_file = self.create_temp_input(&program_blob)?;
        
        // 3. Launch QEMU with virtio-serial transport
        let mut qemu = Command::new(&self.qemu_path)
            .arg("-bios").arg(&self.ovmf_path)
            .arg("-drive").arg(format!("format=raw,file=fat:rw:{}", self.kernel_path.parent().unwrap().display()))
            .arg("-device").arg(format!("virtio-serial-pci"))
            .arg("-chardev").arg(format!("file,id=input,path={}", input_file.display()))
            .arg("-device").arg("virtserialport,chardev=input,name=fuzz.input")
            .arg("-chardev").arg("pipe,id=output,path=/tmp/fuzz-output")
            .arg("-device").arg("virtserialport,chardev=output,name=fuzz.output")
            .arg("-serial").arg("file:/tmp/serial.log")
            .arg("-display").arg("none")
            .arg("-no-reboot").arg("-no-shutdown")
            .arg("-m").arg("512M")
            .arg("-smp").arg("1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        
        // 4. Monitor execution with timeout
        let result = self.wait_with_timeout(&mut qemu, timeout)?;
        
        // 5. Extract coverage and crash info
        let coverage = self.read_coverage_bitmap()?;
        let serial = self.read_serial_log()?;
        
        // 6. Classify outcome
        let outcome = self.classify_outcome(&result, &coverage, &serial)?;
        
        Ok(ExecutionResult { outcome, coverage, serial })
    }
    
    fn serialize_program(&self, program: &SyscallProgram) -> Result<Vec<u8>> {
        // Binary format:
        // Header: magic=0x4E494C58 ("NILX"), version=1, count=N
        // For each syscall:
        //   u64 syscall_number
        //   u64 arg_count
        //   For each arg: u64 type, u64 length, [data]
        let mut buf = Vec::new();
        buf.write_u32::<LittleEndian>(0x4E494C58)?; // Magic
        buf.write_u32::<LittleEndian>(1)?; // Version
        buf.write_u64::<LittleEndian>(program.syscalls.len() as u64)?;
        
        for syscall in &program.syscalls {
            buf.write_u64::<LittleEndian>(syscall.number)?;
            buf.write_u64::<LittleEndian>(syscall.args.len() as u64)?;
            
            for arg in &syscall.args {
                self.serialize_argument(arg, &mut buf)?;
            }
        }
        
        Ok(buf)
    }
}
```

**Guest executor binary** (`userspace/nilix_syz_executor.c`):

```c
/*
 * Guest-side executor that receives serialized programs via virtio-serial
 * and executes them under KCOV coverage collection.
 */

#define NILIX_SYS_KCOV_INIT 520
#define NILIX_SYS_KCOV_ENABLE 521
#define NILIX_SYS_KCOV_DISABLE 522
#define NILIX_SYS_KCOV_DUMP 523
#define NILIX_SYS_KCOV_RESET 524

#define KCOV_BUFFER_SIZE 32768

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint64_t syscall_count;
} ProgramHeader;

typedef struct {
    uint64_t syscall_number;
    uint64_t arg_count;
} SyscallHeader;

int execute_program(const uint8_t *program_data, size_t length) {
    uint8_t coverage_bitmap[KCOV_BUFFER_SIZE];
    
    // Initialize KCOV
    if (syscall(NILIX_SYS_KCOV_INIT, KCOV_BUFFER_SIZE) != 0) {
        return -1;
    }
    
    // Enable coverage collection
    if (syscall(NILIX_SYS_KCOV_ENABLE) != 0) {
        return -1;
    }
    
    // Parse and execute program
    const uint8_t *ptr = program_data;
    ProgramHeader *header = (ProgramHeader *)ptr;
    ptr += sizeof(ProgramHeader);
    
    for (uint64_t i = 0; i < header->syscall_count; ++i) {
        SyscallHeader *syscall_hdr = (SyscallHeader *)ptr;
        ptr += sizeof(SyscallHeader);
        
        // Parse arguments
        uint64_t args[6] = {0};
        for (uint64_t j = 0; j < syscall_hdr->arg_count && j < 6; ++j) {
            args[j] = parse_argument(&ptr);
        }
        
        // Execute syscall (ignore errors to continue program)
        syscall(syscall_hdr->syscall_number, 
                args[0], args[1], args[2], args[3], args[4], args[5]);
    }
    
    // Disable and dump coverage
    if (syscall(NILIX_SYS_KCOV_DISABLE) != 0) {
        return -1;
    }
    
    long edge_count = syscall(NILIX_SYS_KCOV_DUMP, coverage_bitmap, KCOV_BUFFER_SIZE);
    if (edge_count < 0) {
        return -1;
    }
    
    // Write coverage to virtio-serial output
    write_coverage_to_host(coverage_bitmap, edge_count);
    
    return 0;
}

int main(void) {
    // Read program from virtio-serial input
    uint8_t program_buffer[65536];
    ssize_t program_length = read_program_from_host(program_buffer, sizeof(program_buffer));
    
    if (program_length <= 0) {
        printf("NILIX_SYZ_EXECUTOR_FAIL stage=read_program\n");
        return 1;
    }
    
    // Execute under KCOV
    if (execute_program(program_buffer, program_length) != 0) {
        printf("NILIX_SYZ_EXECUTOR_FAIL stage=execute\n");
        return 1;
    }
    
    printf("NILIX_SYZ_EXECUTOR_PASS\n");
    return 0;
}
```

---

### 4. Coverage-Guided Mutation

The mutator uses grammar-aware strategies that preserve resource dependencies:

```rust
struct SyscallMutator {
    grammar: SyscallGrammar,
    interesting_values: InterestingValues,
}

impl SyscallMutator {
    fn mutate(&mut self, seed: &SyscallProgram) -> Result<SyscallProgram> {
        let mut program = seed.clone();
        let strategy = self.select_strategy();
        
        match strategy {
            MutationStrategy::InsertSyscall => {
                // Insert a new syscall that respects resource dependencies
                let position = rand::random::<usize>() % (program.syscalls.len() + 1);
                let available_resources = program.resources_at(position);
                let new_syscall = self.grammar.generate_syscall(&available_resources)?;
                program.insert_syscall(position, new_syscall)?;
            }
            MutationStrategy::DeleteSyscall => {
                if program.syscalls.len() > 1 {
                    let position = rand::random::<usize>() % program.syscalls.len();
                    program.delete_syscall(position)?;
                }
            }
            MutationStrategy::MutateArgument => {
                let syscall_idx = rand::random::<usize>() % program.syscalls.len();
                let arg_idx = rand::random::<usize>() % program.syscalls[syscall_idx].args.len();
                self.mutate_argument(&mut program.syscalls[syscall_idx].args[arg_idx])?;
            }
            MutationStrategy::SplicePrograms => {
                // Take a slice from another corpus entry
                let other = self.corpus.random_entry()?;
                let splice_point = rand::random::<usize>() % program.syscalls.len();
                let splice_length = 1 + rand::random::<usize>() % 5;
                program.splice(splice_point, &other, splice_length)?;
            }
            MutationStrategy::SquashSyscalls => {
                // Merge adjacent syscalls operating on same resource
                if program.syscalls.len() >= 2 {
                    let position = rand::random::<usize>() % (program.syscalls.len() - 1);
                    program.squash_syscalls(position)?;
                }
            }
        }
        
        // Fix up resource references after mutation
        program.fixup_resources()?;
        
        Ok(program)
    }
    
    fn mutate_argument(&mut self, arg: &mut Argument) -> Result<()> {
        match arg {
            Argument::Immediate(val) => {
                let strategy = rand::random::<u8>() % 4;
                match strategy {
                    0 => *val = self.interesting_values.random_int(),
                    1 => *val = val.wrapping_add(1 + rand::random::<u64>() % 100),
                    2 => *val = val.wrapping_sub(1 + rand::random::<u64>() % 100),
                    3 => *val ^= 1u64 << (rand::random::<u64>() % 64),
                    _ => unreachable!(),
                }
            }
            Argument::Buffer(buf) => {
                let strategy = rand::random::<u8>() % 3;
                match strategy {
                    0 => {
                        // Flip random bit
                        if !buf.is_empty() {
                            let idx = rand::random::<usize>() % buf.len();
                            buf[idx] ^= 1u8 << (rand::random::<u8>() % 8);
                        }
                    }
                    1 => {
                        // Insert interesting byte
                        if buf.len() < 65536 {
                            let idx = rand::random::<usize>() % (buf.len() + 1);
                            buf.insert(idx, self.interesting_values.random_byte());
                        }
                    }
                    2 => {
                        // Delete byte
                        if !buf.is_empty() {
                            let idx = rand::random::<usize>() % buf.len();
                            buf.remove(idx);
                        }
                    }
                    _ => unreachable!(),
                }
            }
            Argument::Resource(_) => {
                // Resource arguments are fixed up separately
            }
            _ => {}
        }
        Ok(())
    }
}
```

---

### 5. CI Integration

Extend `.github/workflows/fuzz.yml` with the syzkaller-style fuzzer:

```yaml
  nilix-syz-fuzzer:
    name: Syzkaller-Style Host-Driven Fuzzing
    needs: fuzz-tools-test
    runs-on: ubuntu-latest
    timeout-minutes: 120
    permissions:
      contents: read
    if: |
      github.event_name == 'schedule' && github.event.schedule == '0 2 * * 0' ||
      github.event_name == 'workflow_dispatch' && github.event.inputs.mode == 'syz'
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v7
      
      - name: Setup Rust nightly
        uses: dtolnay/rust-toolchain@nightly
        with:
          toolchain: nightly-2025-12-08
          components: rust-src
      
      - name: Install dependencies
        run: |
          sudo apt-get update
          sudo apt-get install -y qemu-system-x86 ovmf build-essential musl-tools
      
      - name: Build KCOV kernel
        run: make build-kcov
      
      - name: Build guest executor
        run: |
          musl-gcc -std=c11 -static -O2 -Wall -Wextra \
            -o userspace/nilix_syz_executor.elf \
            userspace/nilix_syz_executor.c
          cp userspace/nilix_syz_executor.elf kernel/src/nilix_syz_executor.elf
      
      - name: Rebuild KCOV kernel with executor
        run: make build-kcov
      
      - name: Build host fuzzer
        run: |
          cargo build --locked --release \
            --manifest-path userspace/nilix-syz-fuzzer/Cargo.toml \
            --target x86_64-unknown-linux-gnu
      
      - name: Restore corpus
        uses: actions/cache/restore@v6
        with:
          path: syz-corpus/
          key: syz-corpus-${{ github.run_id }}
          restore-keys: syz-corpus-
      
      - name: Run syzkaller-style fuzzer
        id: run_syz
        env:
          SYZ_TIMEOUT: 3600
          NILIX_FUZZ_FINGERPRINT_KEY: ${{ secrets.FUZZ_FINGERPRINT_KEY }}
        run: |
          mkdir -p syz-corpus syz-crashes syz-candidates
          
          private_log="$RUNNER_TEMP/syz-fuzzer.log"
          set +e
          userspace/nilix-syz-fuzzer/target/x86_64-unknown-linux-gnu/release/nilix-syz-fuzzer \
            --corpus-dir syz-corpus \
            --crash-dir syz-crashes \
            --kernel esp-kcov/kernel.elf \
            --timeout "$SYZ_TIMEOUT" \
            --workers 4 \
            > "$private_log" 2>&1
          exit_code=$?
          set -e
          echo "exit_code=${exit_code}" >> "$GITHUB_OUTPUT"
      
      - name: Count findings
        id: count_syz_findings
        run: |
          findings=$(find syz-crashes -type f -name 'crash-*' 2>/dev/null | wc -l)
          echo "findings=${findings}" >> "$GITHUB_OUTPUT"
      
      - name: Create opaque candidate metadata
        if: steps.count_syz_findings.outputs.findings > 0
        # ... (similar to cargo-fuzz candidate handling)
      
      - name: Save clean corpus
        if: steps.count_syz_findings.outputs.findings == '0'
        uses: actions/cache/save@v6
        with:
          path: syz-corpus/
          key: syz-corpus-${{ github.run_id }}-${{ github.run_attempt }}
```

---

## Differences from Linux Syzkaller

| Feature | Linux Syzkaller | Nilix Syz | Status |
|---------|-----------------|-----------|--------|
| **Executor** | Shared memory transport | virtio-serial transport | Specified |
| **Coverage** | Compiler instrumentation | Manual `record_edge!` + KCOV syscalls | Implemented |
| **Grammar** | .txt description files | `.syz` descriptions (compatible syntax) | Specified |
| **Crash reporting** | Direct kernel logs | Serial + QEMU interrupt log | Implemented |
| **Corpus sync** | Git repository | GitHub Actions cache | Specified |
| **Parallel fuzzing** | SSH workers | QEMU instances on single runner | Specified |
| **Syscall filtering** | Enable/disable lists | All syscalls fuzzed | Specified |

---

## Security Considerations

1. **Private disclosure boundary:** Maintained via existing HMAC-based opaque candidate IDs
2. **Input validation:** Guest executor validates program format before execution
3. **Sandbox isolation:** Each QEMU instance is isolated; crashes contained
4. **Resource limits:** Programs bounded to max 100 syscalls, 64KB buffers
5. **Timeout enforcement:** Hard 30s timeout per program execution

---

## Performance Targets

- **Throughput:** 50-100 programs/second on 4-core runner
- **Coverage growth:** Discover 5-10 new edges per 1000 executions (early phase)
- **Corpus size:** Maintain < 10,000 programs via periodic minimization
- **Crash deduplication:** < 100ms per crash via HMAC fingerprinting

---

## Implementation Roadmap

### Phase 7.1: Basic Host-Driven Loop (2-3 weeks)
- [ ] Implement `QemuExecutor` with virtio-serial transport
- [ ] Build guest executor binary (`nilix_syz_executor.c`)
- [ ] Wire up coverage extraction from KCOV
- [ ] Verify single-program execution end-to-end

### Phase 7.2: Mutation and Corpus (2-3 weeks)
- [ ] Implement `SyscallMutator` with grammar-aware strategies
- [ ] Build `Corpus` manager with energy scheduling
- [ ] Integrate with existing syscall descriptions (`.syz`)
- [ ] Test mutation quality with manual corpus inspection

### Phase 7.3: Parallel Execution (1-2 weeks)
- [ ] Implement multi-worker QEMU pool
- [ ] Add corpus synchronization between workers
- [ ] Optimize throughput via persistent QEMU instances

### Phase 7.4: CI Integration (1 week)
- [ ] Add `nilix-syz-fuzzer` job to workflow
- [ ] Wire up existing crash triager
- [ ] Test end-to-end on GitHub Actions runner
- [ ] Document corpus cache and finding disclosure flow

### Phase 7.5: Monitoring and Tuning (ongoing)
- [ ] Add real-time dashboard with kernel execution metrics
- [ ] Tune mutation weights based on coverage growth
- [ ] Implement corpus minimization pass
- [ ] Benchmark against syzkaller on comparable workload

---

## Testing Strategy

### Unit Tests
- Syscall serialization/deserialization round-trip
- Mutation preserves resource dependencies
- Coverage bitmap comparison logic
- Crash fingerprinting determinism

### Integration Tests
- Single-program execution with known coverage
- Multi-program corpus evolution
- Crash detection and triaging
- Timeout handling and cleanup

### End-to-End Test
```bash
# Build everything
make build-kcov
make build-syz-executor
cargo build --release --bin nilix-syz-fuzzer

# Run for 60 seconds
./target/release/nilix-syz-fuzzer \
  --corpus-dir test-corpus \
  --crash-dir test-crashes \
  --kernel esp-kcov/kernel.elf \
  --timeout 60 \
  --workers 2

# Verify corpus growth and no false-positive crashes
ls -lh test-corpus/
ls -lh test-crashes/
```

---

## Future Enhancements

1. **Persistent QEMU instances:** Reuse VM across programs via snapshot/restore
2. **Distributed fuzzing:** Coordinate across multiple GitHub Actions runners
3. **Smart program generation:** Use ML to predict high-coverage mutations
4. **Differential fuzzing:** Compare Nilix behavior against Linux on same programs
5. **Compiler instrumentation:** Replace manual `record_edge!` with LLVM `-fsanitize=fuzzer`

---

**Last Updated:** 2026-08-04  
**Status:** Architecture specification complete; implementation Phase 7.1 not started  
**Current CI:** Deterministic KCOV E2E + cargo-fuzz (see [README.md](README.md))
