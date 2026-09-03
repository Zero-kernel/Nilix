.PHONY: all build build-shell run run-shell run-shell-gui run-blk run-blk-serial run-smp run-smp-debug ensure-ext3-image clean lint-release lint-smap lint-fetch-add lint-repr-c-copy lint-fallible lint-fallible-selftest abi-check lint test test-hosted-subcrates test-ext3 boot-check musl-check test-smp test-smp-4core test-smp-extended stress-test-selftest stress-test stress-test-extended build-stress-runner build-stress run-stress test-perf test-security-mitigations test-melting test-comprehensive test-quick fmt fmt-check clippy hooks afl-seeds afl-fuzz afl-fuzz-parallel afl-triage build-fuzz-runner run-fuzz-runner build-kcov-runner build-kcov run-kcov test-kcov build-syz-fuzzer build-syz-executor run-syz-fuzz test-syz

OVMF_PATH = $(shell \
	if [ -f /usr/share/qemu/OVMF.fd ]; then \
		echo /usr/share/qemu/OVMF.fd; \
	elif [ -f /usr/share/ovmf/OVMF.fd ]; then \
		echo /usr/share/ovmf/OVMF.fd; \
	elif [ -f /usr/share/OVMF/OVMF_CODE.fd ]; then \
		echo /usr/share/OVMF/OVMF_CODE.fd; \
	else \
		find /usr/share/OVMF/ -type f -name "OVMF_CODE*.fd" 2>/dev/null | head -n 1; \
	fi)
QEMU = qemu-system-x86_64
QEMU_ESP ?= esp
ESP_DIR = $(shell pwd)/esp/EFI/BOOT
KERNEL_LD = $(shell pwd)/kernel/kernel.ld
MUSL_TARGET_DIR := kernel-target/musl
MUSL_KERNEL := $(MUSL_TARGET_DIR)/x86_64-unknown-none/release/kernel
# RF180-59 FIX: the feature artifact's final package/boot input is isolated too.
MUSL_ESP := $(MUSL_TARGET_DIR)/esp
MUSL_ESP_DIR := $(CURDIR)/$(MUSL_ESP)/EFI/BOOT
STRESS_TARGET_DIR := kernel-target/stress
STRESS_KERNEL := $(STRESS_TARGET_DIR)/x86_64-unknown-none/release/kernel
STRESS_ESP := esp-stress
STRESS_ESP_DIR := $(CURDIR)/$(STRESS_ESP)/EFI/BOOT
STRESS_RUNNER_USER := userspace/stress_runner.elf
STRESS_RUNNER_EMBEDDED := kernel/src/stress_runner.elf
KCOV_TARGET_DIR := kernel-target/kcov
KCOV_KERNEL := $(KCOV_TARGET_DIR)/x86_64-unknown-none/release/kernel
KCOV_ESP := esp-kcov
KCOV_ESP_DIR := $(CURDIR)/$(KCOV_ESP)/EFI/BOOT
KCOV_RUNNER_USER := userspace/fuzz_runner.elf
KCOV_RUNNER_EMBEDDED := kernel/src/fuzz_runner.elf

# Syzkaller-style executor kernel. Unlike build-kcov (which embeds the
# deterministic fuzz_runner.elf test program for make test-kcov), build-syz-kcov
# embeds nilix_syz_executor.elf — the Ring-3 program the host syz-fuzzer drives.
# The executor reads a fuzz program from the mounted ext3 disk and emits
# NILIX_SYZ_V2_* markers. Isolated target dir + ESP so a reused artifact can
# never boot the wrong guest program (same discipline as KCOV/stress/musl).
SYZ_TARGET_DIR := kernel-target/syz
SYZ_KERNEL := $(SYZ_TARGET_DIR)/x86_64-unknown-none/release/kernel
SYZ_ESP := esp-syz
SYZ_ESP_DIR := $(CURDIR)/$(SYZ_ESP)/EFI/BOOT
SYZ_EXEC_USER := userspace/nilix_syz_executor.elf
SYZ_EXEC_EMBEDDED := kernel/src/nilix_syz_executor.elf

all: build

build:
	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi --features kaslr

	@echo "=== 构建 Kernel (Bare Metal) ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-pie -C relocation-model=pie -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== 构建完成 ==="

# Build with interactive shell instead of hello test
build-shell:
	@echo "=== 构建 Shell 用户程序 ==="
	cd userspace && \
	cargo build --release --bin shell --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
	cp userspace/target/x86_64-unknown-none/release/shell kernel/src/shell.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi --features kaslr

	@echo "=== 构建 Kernel (Bare Metal) with Shell ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-pie -C relocation-model=pie -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features shell

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Shell模式）==="

# Build with syscall test program
build-syscall-test:
	@echo "=== 构建 Syscall Test 用户程序 ==="
	cd userspace && \
	cargo build --release --bin syscall_test --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
	cp userspace/target/x86_64-unknown-none/release/syscall_test kernel/src/syscall_test.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi --features kaslr

	@echo "=== 构建 Kernel (Bare Metal) with Syscall Test ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-pie -C relocation-model=pie -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features syscall_test

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Syscall Test模式）==="

# Run syscall test (serial output)
run-syscall-test: build-syscall-test
	@echo "=== 启动内核（Syscall Test模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Build with musl test program
build-musl-test:
	@echo "=== 编译 musl 测试程序 ==="
	cd userspace && musl-gcc -static -o hello_musl.elf hello_musl.c
	cp userspace/hello_musl.elf kernel/src/musl_test.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi --features kaslr

	@echo "=== 构建 Kernel (Bare Metal) with Musl Test ==="
	# RF180-55 FIX: isolate the feature build from the default kernel's top-level
	# output hardlink. Cargo may reuse a fresh feature artifact without replacing
	# a top-level binary most recently written by a different feature set.
	cd kernel && \
	CARGO_TARGET_DIR=../$(MUSL_TARGET_DIR) RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-pie -C relocation-model=pie -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features musl_test

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p "$(MUSL_ESP_DIR)"

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi "$(MUSL_ESP_DIR)/BOOTX64.EFI"

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp "$(MUSL_KERNEL)" "$(MUSL_ESP)/kernel.elf"
	# RF180-59 FIX: prove the exact Cargo artifact reaches the isolated boot ESP.
	@set -eu; \
	src_hash=$$(sha256sum "$(MUSL_KERNEL)" | awk '{print $$1}'); \
	dst_hash=$$(sha256sum "$(MUSL_ESP)/kernel.elf" | awk '{print $$1}'); \
	cmp -s "$(MUSL_KERNEL)" "$(MUSL_ESP)/kernel.elf" || { \
		echo "RF180-59 FAIL: packaged musl kernel differs from Cargo artifact" >&2; exit 1; \
	}; \
	test "$$src_hash" = "$$dst_hash" || { \
		echo "RF180-59 FAIL: packaged musl kernel SHA-256 mismatch" >&2; exit 1; \
	}; \
	echo "RF180-59: musl packaged kernel SHA-256 $$dst_hash"

	@echo "=== 内核信息 ==="
	@readelf -h "$(MUSL_ESP)/kernel.elf" | grep "Entry\|Type"
	@echo "=== musl ELF 信息 ==="
	@readelf -h kernel/src/musl_test.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Musl Test模式）==="

# Run musl test (serial output)
# RF180-59: interactive and automated musl consumers boot the same isolated ESP.
run-musl-test: QEMU_ESP := $(MUSL_ESP)
run-musl-test: build-musl-test
	@echo "=== 启动内核（Musl Test模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Build with clone test program
build-clone-test:
	@echo "=== 编译 clone 测试程序 ==="
	cd userspace && musl-gcc -static -o clone_test.elf clone_test.c
	cp userspace/clone_test.elf kernel/src/clone_test.elf

	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi --features kaslr

	@echo "=== 构建 Kernel (Bare Metal) with Clone Test ==="
	cd kernel && \
	CARGO_TARGET_DIR=../kernel-target RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-pie -C relocation-model=pie -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features clone_test

	@echo "=== 准备 EFI ESP 目录 ==="
	mkdir -p $(ESP_DIR)

	@echo "复制 Bootloader 到 ESP/BOOTX64.EFI"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi $(ESP_DIR)/BOOTX64.EFI

	@echo "复制 Kernel 到 ESP/kernel.elf"
	cp kernel-target/x86_64-unknown-none/release/kernel esp/kernel.elf

	@echo "=== 内核信息 ==="
	@readelf -h esp/kernel.elf | grep "Entry\|Type"
	@echo "=== clone ELF 信息 ==="
	@readelf -h kernel/src/clone_test.elf | grep "Entry\|Type"
	@echo "=== 构建完成（Clone Test模式）==="

# Run clone test (serial output)
run-clone-test: build-clone-test
	@echo "=== 启动内核（Clone Test模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Build the bounded static-musl workload embedded by the monthly stress kernel.
build-stress-runner:
	@echo "=== Building bounded Ring-3 stress workload ==="
	musl-gcc -std=c11 -static -O2 -Wall -Wextra -Werror \
		-o "$(STRESS_RUNNER_USER)" userspace/stress_runner.c
	cp "$(STRESS_RUNNER_USER)" "$(STRESS_RUNNER_EMBEDDED)"
	@cmp -s "$(STRESS_RUNNER_USER)" "$(STRESS_RUNNER_EMBEDDED)"
	@echo "Stress guest SHA-256: $$(sha256sum "$(STRESS_RUNNER_EMBEDDED)" | awk '{print $$1}')"
	@readelf -h "$(STRESS_RUNNER_EMBEDDED)" | grep "Entry\|Type"

# Keep feature-specific Cargo output and the packaged ESP isolated from normal
# and KCOV builds, so a reused artifact can never boot the wrong guest program.
build-stress: build-stress-runner
	@echo "=== Building bootloader for Ring-3 stress workload ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi --features kaslr

	@echo "=== Building isolated Ring-3 stress kernel ==="
	cd kernel && \
	CARGO_TARGET_DIR=../$(STRESS_TARGET_DIR) \
	RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-pie -C relocation-model=pie -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features stress_runner

	@echo "=== Preparing isolated stress ESP ==="
	mkdir -p "$(STRESS_ESP_DIR)"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi "$(STRESS_ESP_DIR)/BOOTX64.EFI"
	cp "$(STRESS_KERNEL)" "$(STRESS_ESP)/kernel.elf"
	@cmp -s "$(STRESS_KERNEL)" "$(STRESS_ESP)/kernel.elf"
	@echo "Stress kernel SHA-256: $$(sha256sum "$(STRESS_ESP)/kernel.elf" | awk '{print $$1}')"
	@readelf -h "$(STRESS_ESP)/kernel.elf" | grep "Entry\|Type"

run-stress: QEMU_ESP := $(STRESS_ESP)
run-stress: build-stress ensure-ext3-image
	@echo "=== Starting configured combined Ring-3 stress profile ==="
	@STRESS_PROFILES=combined STRESS_PROFILE_LIMIT=1 bash scripts/stress_test.sh "$(STRESS_ESP)"

# Compatibility alias for the deterministic KCOV guest executor build.
build-fuzz-runner: build-kcov

# Run the deterministic KCOV guest executor interactively.
run-fuzz-runner: QEMU_ESP := $(KCOV_ESP)
run-fuzz-runner: build-fuzz-runner
	@echo "=== 启动内核（KCOV Fuzz Runner模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# === Phase 7: Syzkaller-Style Coverage-Guided Fuzzing ===

# Build the host-side syzkaller-style fuzzer (runs on Linux, not bare-metal)
build-syz-fuzzer:
	@echo "=== Building Syzkaller-Style Host Fuzzer ==="
	cd userspace/nilix-syz-fuzzer && \
	chmod +x build-isolated.sh && \
	./build-isolated.sh
	@echo "=== Host Fuzzer Built: userspace/nilix-syz-fuzzer/target/x86_64-unknown-linux-gnu/release/nilix-syz-fuzzer ==="

# Build the guest executor for syzkaller fuzzing
build-syz-executor:
	@echo "=== Building Syzkaller Guest Executor ==="
	cd userspace && \
	musl-gcc -std=c11 -static -O2 -Wall -Wextra -Werror \
		-o nilix_syz_executor.elf nilix_syz_executor.c
	@echo "=== Guest Executor Built: userspace/nilix_syz_executor.elf ==="

# Run syzkaller-style fuzzing campaign (requires KCOV kernel)
# Usage: make run-syz-fuzz [DURATION=3600] [WORKERS=4]
DURATION ?= 3600
WORKERS ?= 4
run-syz-fuzz: build-kcov build-syz-executor build-syz-fuzzer
	@echo "=== Starting Syzkaller-Style Fuzzing Campaign ==="
	@echo "Duration: $(DURATION)s | Workers: $(WORKERS)"
	@echo "Kernel: $(KCOV_ESP)/kernel.elf"
	cd userspace/nilix-syz-fuzzer && \
	./target/x86_64-unknown-linux-gnu/release/nilix-syz-fuzzer \
		--kernel ../../$(KCOV_ESP)/kernel.elf \
		--corpus-dir ./syz-corpus \
		--crash-dir ./syz-crashes \
		--timeout $(DURATION) \
		--workers $(WORKERS) \
		--program-timeout 30 \
		--ovmf $(OVMF_PATH)

# Quick smoke test for syzkaller infrastructure
test-syz: build-kcov build-syz-executor build-syz-fuzzer
	@echo "=== Running Syzkaller Infrastructure Smoke Test ==="
	cd userspace/nilix-syz-fuzzer && \
	timeout 60 ./target/x86_64-unknown-linux-gnu/release/nilix-syz-fuzzer \
		--kernel ../../$(KCOV_ESP)/kernel.elf \
		--corpus-dir ./test-corpus \
		--crash-dir ./test-crashes \
		--timeout 60 \
		--workers 1 \
		--program-timeout 10 \
		--ovmf $(OVMF_PATH) \
		|| true
	@echo "=== Smoke Test Complete ==="
	@if [ -d userspace/nilix-syz-fuzzer/test-corpus ]; then \
		echo "Corpus entries: $$(find userspace/nilix-syz-fuzzer/test-corpus -name 'prog-*.bin' | wc -l)"; \
	fi
	@if [ -d userspace/nilix-syz-fuzzer/test-crashes ]; then \
		echo "Crashes found: $$(find userspace/nilix-syz-fuzzer/test-crashes -name 'crash-*.bin' | wc -l)"; \
	fi


# 通用QEMU参数
# -vga std: 强制使用标准VGA模式，确保0xB8000文本缓冲区可用
# 使用默认的i440FX机器类型，其PCI内存布局将BAR放在4GB以下
# (q35会将某些BAR放在高于4GB的地址，超出bootloader的identity mapping范围)
# R39-8 FIX: Add CPU model with SMEP/SMAP/UMIP/RDRAND support
QEMU_COMMON = -bios $(OVMF_PATH) \
	-drive "format=raw,file=fat:rw:$$(sh scripts/esp_run_copy.sh $(QEMU_ESP))" \
	-m 256M \
	-vga std \
	-no-reboot -no-shutdown \
	-cpu qemu64,+smep,+smap,+umip,+rdrand

# virtio-blk 块设备配置 (Phase C: Storage Foundation)
# 默认使用PCI transport（x86 QEMU更可靠），可切换为MMIO
# 使用环境变量 VIRTIO_BLK_TRANSPORT=mmio 切换到MMIO transport
VIRTIO_BLK_TRANSPORT ?= pci
VIRTIO_MMIO_ADDR = 0x10001000

# PCI transport: 标准x86 QEMU配置
QEMU_BLK_PCI = -drive if=none,file=disk-ext2.img,format=raw,id=vdisk0,cache=writeback,discard=unmap \
	-device virtio-blk-pci,drive=vdisk0

# MMIO transport: 用于非PCI平台或特殊配置
QEMU_BLK_MMIO = -drive if=none,file=disk-ext2.img,format=raw,id=vdisk0,cache=writeback,discard=unmap \
	-device virtio-blk-device,drive=vdisk0

ifeq ($(VIRTIO_BLK_TRANSPORT),mmio)
QEMU_BLK = $(QEMU_BLK_MMIO)
else
QEMU_BLK = $(QEMU_BLK_PCI)
endif

# virtio-net 网络设备配置 (Phase D: Network Foundation)
# 使用user-mode网络和virtio-net-pci设备
# romfile= 禁用UEFI网络驱动，让内核处理设备初始化
QEMU_NET = -netdev user,id=net0 \
	-device virtio-net-pci,netdev=net0,romfile=

# Create the production Ext3 image with a standard internal JBD2 journal.
# The historical filename is retained so existing run scripts keep working.
disk-ext2.img:
	@echo "=== Creating 64MB Ext3/JBD2 filesystem image ==="
	dd if=/dev/zero of=$@ bs=1M count=64 2>/dev/null
	mkfs.ext3 -F -b 4096 -I 256 -J size=4 -L zeroos $@
	@echo "=== 写入测试文件 ==="
	@if command -v debugfs >/dev/null 2>&1; then \
		tmpfile=$$(mktemp); \
		emptyfile=$$(mktemp); \
		echo "Zero-OS virtio-blk test file" > $$tmpfile; \
		debugfs -w -R "mkdir /test" $@ 2>/dev/null || true; \
		debugfs -w -R "write $$tmpfile /test/hello.txt" $@ 2>/dev/null || true; \
		debugfs -w -R "write $$emptyfile /test/alloc.bin" $@ 2>/dev/null || true; \
		rm -f $$tmpfile $$emptyfile; \
		echo "测试文件已写入: /test/hello.txt, /test/alloc.bin"; \
	else \
		echo "警告: debugfs不可用，跳过测试文件创建"; \
	fi

# Existing developer images are upgraded offline before QEMU attachment. The
# kernel never performs an implicit on-disk format conversion during mount.
ensure-ext3-image: disk-ext2.img
	@for tool in tune2fs e2fsck debugfs; do \
		command -v $$tool >/dev/null 2>&1 || { echo "$$tool is required"; exit 1; }; \
	done
	@if ! LC_ALL=C tune2fs -l disk-ext2.img 2>/dev/null | grep -q 'has_journal'; then \
		echo "=== Upgrading existing disk-ext2.img with an internal journal ==="; \
		tune2fs -j -J size=4 disk-ext2.img; \
	fi
	@e2fsck -pf disk-ext2.img >/dev/null || status=$$?; \
		if [ "$${status:-0}" -gt 1 ]; then exit "$${status}"; fi
	@# RF180-48 FIX: debugfs returns success after leaking an orphan inode when
	@# mkdir targets an existing directory, and its command exit status does not
	@# distinguish lookup failure. Accept only an existing directory or the exact
	@# C-locale missing-path diagnostic; always fsck after any attempted mutation.
	@emptyfile=; status=0; \
		cleanup() { \
			trap - 0 1 2 3 15; \
			[ -z "$$emptyfile" ] || rm -f "$$emptyfile"; \
			fsck_status=0; e2fsck -pf disk-ext2.img >/dev/null || fsck_status=$$?; \
			if [ "$$fsck_status" -gt 1 ]; then exit "$$fsck_status"; fi; \
			exit "$$status"; \
		}; \
		trap 'status=$$?; cleanup' 0; \
		trap 'exit 129' 1; trap 'exit 130' 2; trap 'exit 131' 3; trap 'exit 143' 15; \
		test_stat=$$(LC_ALL=C debugfs -R "stat /test" disk-ext2.img 2>&1); \
		case "$$test_stat" in \
			*'Type: directory'*) ;; \
			*'/test: File not found by ext2_lookup'*) \
				debugfs -w -R "mkdir /test" disk-ext2.img >/dev/null 2>&1 || exit 1; \
				test_stat=$$(LC_ALL=C debugfs -R "stat /test" disk-ext2.img 2>&1); \
				printf '%s\n' "$$test_stat" | grep -q 'Type: directory' || exit 1 ;; \
			*) printf '%s\n' "$$test_stat" >&2; echo "failed to validate /test" >&2; exit 1 ;; \
		esac; \
		alloc_stat=$$(LC_ALL=C debugfs -R "stat /test/alloc.bin" disk-ext2.img 2>&1); \
		case "$$alloc_stat" in \
			*'Type: regular'*'Size: 0'*) ;; \
			*'/test/alloc.bin: File not found by ext2_lookup'*) \
				emptyfile=$$(mktemp) || exit 1; \
				debugfs -w -R "write $$emptyfile /test/alloc.bin" disk-ext2.img >/dev/null 2>&1 \
					|| exit 1; \
				alloc_stat=$$(LC_ALL=C debugfs -R "stat /test/alloc.bin" disk-ext2.img 2>&1); \
				printf '%s\n' "$$alloc_stat" | grep -q 'Type: regular' \
					&& printf '%s\n' "$$alloc_stat" | grep -q 'Size: 0' || exit 1 ;; \
			*) printf '%s\n' "$$alloc_stat" >&2; \
				echo "/test/alloc.bin is not an empty regular file" >&2; exit 1 ;; \
		esac

# 默认运行 - 图形窗口模式（可看到VGA输出）
run: build
	@echo "=== 启动内核（图形窗口模式）==="
	@echo "提示：使用Ctrl+Alt+G释放鼠标，Ctrl+Alt+2切换到QEMU监视器"
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET)

# 串口输出模式 - 通过串口查看内核输出
run-serial: build
	@echo "=== 启动内核（串口输出模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) $(QEMU_NET) \
		-nographic

# virtio-blk 图形模式 - 附加ext2磁盘镜像
run-blk: build ensure-ext3-image
	@echo "=== 启动内核（virtio-blk 图形模式）==="
	@echo "磁盘: disk-ext2.img (64MB Ext3/JBD2)"
	@echo "提示：使用Ctrl+Alt+G释放鼠标，Ctrl+Alt+2切换到QEMU监视器"
	$(QEMU) $(QEMU_COMMON) $(QEMU_BLK) $(QEMU_NET)

# virtio-blk 串口模式 - 便于查看挂载日志
run-blk-serial: build ensure-ext3-image
	@echo "=== 启动内核（virtio-blk 串口模式）==="
	@echo "磁盘: disk-ext2.img (64MB Ext3/JBD2)"
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) $(QEMU_BLK) $(QEMU_NET) \
		-nographic

# Shell模式 - 运行交互式Shell（串口输出）
run-shell: build-shell
	@echo "=== 启动内核（Shell串口模式）==="
	@echo "提示：这是一个交互式Shell，输入 help 查看可用命令"
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Shell图形模式 - 运行交互式Shell（VGA窗口 + PS/2键盘）
run-shell-gui: build-shell
	@echo "=== 启动内核（Shell图形模式）==="
	@echo "提示：这是一个交互式Shell，输入 help 查看可用命令"
	@echo "提示：使用Ctrl+Alt+G释放鼠标，Ctrl+Alt+2切换到QEMU监视器"
	$(QEMU) $(QEMU_COMMON)

# 调试模式 - 显示详细的CPU状态和中断信息
run-debug: build
	@echo "=== 启动内核（调试模式）==="
	@echo "提示：查看详细的CPU状态、中断和内存访问信息"
	$(QEMU) $(QEMU_COMMON) \
		-nographic \
		-serial mon:stdio \
		-d int,cpu_reset \
		-D qemu-debug.log

# 详细调试模式 - 记录更多信息到文件
run-verbose: build
	@echo "=== 启动内核（详细调试模式）==="
	@echo "提示：所有调试信息将记录到qemu-verbose.log"
	$(QEMU) $(QEMU_COMMON) \
		-nographic \
		-d int,cpu,mmu,guest_errors \
		-D qemu-verbose.log

# GDB调试模式 - 等待GDB连接
debug: build
	@echo "=== 启动内核（GDB调试模式）==="
	@echo "在另一个终端运行: gdb esp/kernel.elf"
	@echo "然后在GDB中执行: target remote :1234"
	$(QEMU) $(QEMU_COMMON) \
		-nographic \
		-s -S

# 组合模式 - 图形窗口 + 串口输出
run-both: build
	@echo "=== 启动内核（图形+串口模式）==="
	@echo "提示：VGA输出在图形窗口，串口输出在终端"
	$(QEMU) $(QEMU_COMMON) \
		-serial stdio

# Runtime suite gate (P1-C VT-2 / Gate #4) — exit code reflects REAL suite health.
# Historical form was `timeout 10 qemu ... || true` (always green + too short
# for the full runtime suite). Verdict is now serial Test Summary + panic/NX
# via scripts/kernel_test.sh (exit 0 PASS / 1 FAILED / 2 NOT-RUN).
test: build
	@echo "=== 启动内核（运行时测试套件门禁）==="
	@OVMF_PATH="$(OVMF_PATH)" bash scripts/kernel_test.sh esp

# R180-6 production filesystem gate: attach the reproducibly journaled image
# so the mounted-image probe exercises real JBD2 transactions.
test-ext3: build ensure-ext3-image
	@echo "=== Running Ext3/JBD2 production-image gate ==="
	@# RF180-50 FIX: the kernel intentionally upgrades its mounted journal with
	@# a private incompat bit that host e2fsprogs must reject. Boot a disposable
	@# copy so the canonical fixture stays host-checkable and the gate is repeatable.
	@test_image=$$(mktemp "$(CURDIR)/.r180-ext3-test.XXXXXX") || exit 1; \
		trap 'rm -f "$$test_image"' 0; \
		trap 'exit 129' 1; trap 'exit 130' 2; trap 'exit 131' 3; trap 'exit 143' 15; \
		cp disk-ext2.img "$$test_image" || exit 1; \
		OVMF_PATH="$(OVMF_PATH)" KERNEL_TEST_DISK="$$test_image" bash scripts/kernel_test.sh esp

# CI boot-health gate — exit code reflects REAL boot health. Boots under QEMU
# and asserts the kernel reaches userspace with zero NX-violation #PF. See
# scripts/boot_check.sh and the D1-BOOT-NX-KASLR-LAYOUT process lesson.
boot-check: build
	@OVMF_PATH="$(OVMF_PATH)" bash scripts/boot_check.sh esp

# M0 conformance gate (item 3): prove a REAL static-musl binary runs end-to-end
# (crt+auxv -> musl stdio printf/writev -> clean exit). Exit code reflects real
# libc-conformance health (sibling of make test / boot-check). Builds with
# --features musl_test so the embedded userspace/hello_musl.elf is the Ring-3
# init program. See scripts/musl_check.sh.
musl-check: build-musl-test
	@OVMF_PATH="$(OVMF_PATH)" bash scripts/musl_check.sh "$(MUSL_ESP)"

# SMP stress test gates - validate R175 D0 fixes under multi-core operation
# Exit code reflects real SMP stability (0 = pass, non-zero = fail).
# 2-core test validates basic SMP operation, 4-core validates scaling.
test-smp: build
	@echo "=== Running 2-Core SMP Stress Test ==="
	@OVMF_PATH="$(OVMF_PATH)" bash scripts/smp_test.sh esp

test-smp-4core: build
	@echo "=== Running 4-Core SMP Stress Test ==="
	@OVMF_PATH="$(OVMF_PATH)" bash scripts/smp_test_4core.sh esp

# SMP测试模式 - 启用多核支持
# 使用 -smp 指定CPU数量（默认2个）
# ACPI MADT表会自动生成，使内核能够发现多核
SMP_CPUS ?= 2
run-smp: build ensure-ext3-image
	@echo "=== 启动内核（SMP模式 - $(SMP_CPUS)核）==="
	@echo "磁盘: disk-ext2.img (64MB Ext3/JBD2)"
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) $(QEMU_BLK) $(QEMU_NET) \
		-smp cpus=$(SMP_CPUS) \
		-nographic

# SMP调试模式 - 详细的APIC/IPI日志
run-smp-debug: build ensure-ext3-image
	@echo "=== 启动内核（SMP调试模式 - $(SMP_CPUS)核）==="
	@echo "磁盘: disk-ext2.img (64MB Ext3/JBD2)"
	@echo "提示：中断日志记录到 qemu-smp.log"
	$(QEMU) $(QEMU_COMMON) $(QEMU_BLK) $(QEMU_NET) \
		-smp cpus=$(SMP_CPUS) \
		-nographic \
		-d int,cpu_reset \
		-D qemu-smp.log

# H.2.2 CI gate: Reject ungated println! in kernel code.
# Allowed locations: kernel/drivers/ (macro definition), kernel/klog/ (implementation),
# build.rs (cargo build-script protocol REQUIRES println!("cargo:...")), and
# kernel/tests/ (host-side tests, not kernel runtime code).
# All other crates must use kprintln!, klog!, or klog_always!.
# Comments and doc strings containing println! are excluded.
lint-release:
	@echo "=== Lint: checking for ungated println! ==="
	@HITS=$$(grep -rn '\bprintln!' kernel/ \
		--include='*.rs' \
		--exclude-dir=drivers \
		--exclude-dir=klog \
		--exclude-dir=tests \
		--exclude=build.rs \
		| grep -v '^\s*//' \
		| grep -v '//.*println!' \
		| grep -v '///.*println!' \
		| grep -v '//!.*println!' \
		| grep -v '#\[cfg(feature' \
		| grep -v 'macro_rules!' \
		| grep '^\S*\.rs:[0-9]*:\s*println!' \
	) ; \
	if [ -n "$$HITS" ]; then \
		echo "ERROR: Ungated println! found in kernel code:"; \
		echo "$$HITS"; \
		echo ""; \
		echo "Use kprintln!, klog!(Level, ...), or klog_always! instead."; \
		exit 1; \
	else \
		echo "OK: No ungated println! found outside drivers/klog."; \
	fi

# P1-6: SMAP Window Minimization Policy lint.
# Only copy_from_user_safe / copy_to_user_safe (and their helpers inside
# usercopy.rs) may instantiate UserAccessGuard.  Any ad-hoc UserAccessGuard::new()
# in other files widens the SMAP window and bypasses the chunked-copy design.
lint-smap:
	@echo "=== Lint: checking for ad-hoc UserAccessGuard usage ==="
	@HITS=$$(grep -rn 'UserAccessGuard::new()' kernel/ \
		--include='*.rs' \
		| grep -v 'usercopy\.rs' \
		| grep -v '^\s*//' \
		| grep -v '//.*UserAccessGuard' \
	) ; \
	if [ -n "$$HITS" ]; then \
		echo "ERROR: Ad-hoc UserAccessGuard::new() found outside usercopy.rs:"; \
		echo "$$HITS"; \
		echo ""; \
		echo "SMAP policy: only copy_from_user_safe/copy_to_user_safe may lift SMAP."; \
		echo "Use copy_from_user_safe() or copy_to_user_safe() instead."; \
		exit 1; \
	else \
		echo "OK: No ad-hoc UserAccessGuard usage outside usercopy.rs."; \
	fi

# R112-2 / P3-5: Catch bare fetch_add(1 in kernel core / VFS / namespace code.
# ID counters and refcounts MUST use fetch_update + checked_add (R105-5 pattern).
# Legitimate counter-style uses (statistics, events, ticks) annotate with:
#   // lint-fetch-add: allow
# Scoped to high-risk paths; bulk statistics dirs (net/, arch/, sched/, etc.) excluded.
lint-fetch-add:
	@echo "=== Lint: checking for bare fetch_add(1) in core/VFS/namespace paths ==="
	@OUT=$$(for F in $$(grep -rl 'fetch_add(1' kernel/kernel_core kernel/vfs kernel/mm/page_cache.rs --include='*.rs'); do awk '{a[NR]=$$0} END{for(i=1;i<=NR;i++){l=a[i]; if(l~/fetch_add\(1/ && l!~/^[[:space:]]*\/\// && l!~/\/\/.*fetch_add/){ if(l~/lint-fetch-add: allow/||a[i-1]~/lint-fetch-add: allow/) continue; printf "%s:%d:%s\n",FILENAME,i,l}}}' "$$F"; done) ; \
	if [ -n "$$OUT" ]; then \
		echo "ERROR: Bare fetch_add(1) found in core/VFS/namespace code:"; \
		echo "$$OUT"; \
		echo ""; \
		echo "ID counters and refcounts MUST use fetch_update + checked_add (R105-5)."; \
		echo "If a legitimate counter, add '// lint-fetch-add: allow' on the fetch_add line OR the line directly above"; \
		echo "(the marker survives rustfmt either way)."; \
		exit 1; \
	else \
		echo "OK: No unguarded fetch_add(1 in core/VFS/namespace paths."; \
	fi

# R113-1 / P3-6 / H.0.1-3: Catch unannotated struct-to-bytes copies at the
# kernel-userspace boundary.
# Any from_raw_parts, copy_nonoverlapping, or transmute on #[repr(C)] structs
# MUST carry a lint-repr-c-copy annotation documenting why the copy is
# padding-safe (or be replaced with a zeroed-buffer copy).
# H.0.1-3: Expanded scan scope from syscall.rs-only to all boundary files.
lint-repr-c-copy:
	@echo "=== Lint: checking for unannotated repr(C) struct copies ==="
	@FILES="kernel/kernel_core/syscall.rs kernel/kernel_core/usercopy.rs kernel/audit/lib.rs"; \
	FAIL=""; \
	for FILE in $$FILES; do \
		HITS=$$(grep -n 'from_raw_parts\|copy_nonoverlapping\|mem::transmute' $$FILE \
			| grep -v '^\s*//' \
			| grep -v '//.*from_raw_parts\|//.*copy_nonoverlapping\|//.*transmute' \
			| grep -v 'as_mut_ptr() as \*mut u8, total' \
		) ; \
		for line in $$HITS; do \
			LINENO_PART=$$(echo "$$line" | cut -d: -f1); \
			if [ -n "$$LINENO_PART" ] && [ "$$LINENO_PART" -eq "$$LINENO_PART" ] 2>/dev/null; then \
				PREV=$$(sed -n "$$((LINENO_PART-3)),$$((LINENO_PART-1))p" $$FILE); \
				if ! echo "$$PREV" | grep -q 'lint-repr-c-copy: allow'; then \
					echo "  $$FILE:$$LINENO_PART"; \
					FAIL="1"; \
				fi; \
			fi; \
		done; \
	done; \
	if [ -n "$$FAIL" ]; then \
		echo ""; \
		echo "ERROR: Unannotated struct-to-bytes copy found."; \
		echo "Add '// lint-repr-c-copy: allow (<reason>)' within 2 lines above each site."; \
		echo "Or use a zeroed-buffer copy pattern (see copy_vfs_stat_to_user)."; \
		exit 1; \
	else \
		echo "OK: All repr(C) struct copies in audited files are annotated."; \
	fi

# D2-ERR-VFS-FALLIBILITY: mechanized VFS fallibility lint.
# Flags INFALLIBLE heap-growth on recoverable VFS paths (an OOM there panics the
# kernel instead of returning ENOMEM). Pure POSIX grep/awk (no ripgrep — the CI
# lint job provisions nothing). Suppression = comment / fn-scope try_reserve guard /
# DELIBERATE test exclusion (boot self-tests are boot-fatal-by-policy on OOM) /
# bounded string literal / annotation. See docs/design/PO-VFS-01 section 4.2.
lint-fallible: lint-fallible-selftest
	@echo "=== Lint: VFS fallibility (infallible alloc on recoverable paths) ==="
	@HITS=$$(bash scripts/lint_fallible.sh kernel/vfs) ; \
	if [ -n "$$HITS" ]; then \
		echo "ERROR: unguarded infallible-allocation candidates in kernel/vfs:"; \
		echo "$$HITS"; \
		echo ""; \
		echo "Fix: reserve fallibly (try_reserve / FallibleOrderedMap) before growth,"; \
		echo "or annotate on the line or <=3 lines above:"; \
		echo "  // lint-fallible: PREALLOCATED(<evidence>) | BOUNDED(<bound>) | INFALLIBLE-OK(<reason>)"; \
		echo "  // lint-fallible-fn: <token>(<reason>)   (above a fn; blesses its body)"; \
		echo "Grammar: docs/design/PO-VFS-01-vfs-fallibility-contract.md section 4.2."; \
		exit 1; \
	else \
		echo "OK: kernel/vfs infallible-allocation candidates are all guarded/annotated."; \
	fi

# Both-directions self-test (PE-04): proves the lint still CATCHES (violation.rs, exactly
# 21 planted hits) and does not over-flag (annotated_pass.rs, 0 hits) BEFORE it gates the
# tree. A count drift means a regex alternation regressed or the fixture changed unpinned.
lint-fallible-selftest:
	@echo "=== Lint: VFS fallibility self-test (fixtures) ==="
	@N=$$(bash scripts/lint_fallible.sh scripts/lint_fallible_fixtures/violation.rs | grep -c .) ; \
	if [ "$$N" -ne 22 ]; then \
		echo "ERROR: violation fixture caught $$N lines, expected 22."; \
		echo "  (scanner regressed, OR the fixture changed without updating this count)"; \
		exit 1; \
	fi ; \
	P=$$(bash scripts/lint_fallible.sh scripts/lint_fallible_fixtures/annotated_pass.rs | grep -c .) ; \
	if [ "$$P" -ne 0 ]; then \
		echo "ERROR: annotated_pass fixture produced $$P false positive(s), expected 0."; \
		bash scripts/lint_fallible.sh scripts/lint_fallible_fixtures/annotated_pass.rs; \
		exit 1; \
	fi ; \
	echo "OK: lint-fallible self-test (22 caught / 0 false positives)."

# D2-TST-ABI-BYTES: cross-language ABI layout gate.
# Leg A parses the kernel Rust sources (repr(C) layout engine + demand-driven const
# eval); Leg B is an explicit Linux x86-64 KERNEL-ABI reference table (uapi citations,
# NOT glibc variants); Leg C re-checks the reference table against gcc-native structs
# via offsetof/sizeof. Layout only — byte order/overflow/errno are behavioral and are
# covered by `make musl-check`. Exit 0=match, 1=layout mismatch, 2=source-drift/parse/
# toolchain failure (fail closed — no --skip-cc here, so a missing gcc fails the gate).
abi-check:
	@echo "=== ABI layout oracle: kernel Rust source vs Linux x86-64 reference ==="
	python3 scripts/abi_layout_oracle.py --self-test
	python3 scripts/abi_layout_oracle.py --check --work-dir target/abi-oracle

# Unified lint target: runs all CI lint checks.
lint: lint-release lint-smap lint-fetch-add lint-repr-c-copy lint-fallible abi-check

# ============================================================================
# Extended Test Suite - Stress, Performance, Security, SMP
# ============================================================================

# Stress protocol self-tests reject malformed configs/logs and fake recovery
# before an expensive QEMU run is allowed to start.
stress-test-selftest:
	@echo "=== Running Stress-v2 Host Protocol Self-Tests ==="
	@bash scripts/stress_test_test.sh

# Stress test suite - catches resource leaks and stability issues
stress-test: build-stress ensure-ext3-image
	@echo "=== Running Stress Test Suite ==="
	@bash scripts/stress_test_test.sh
	@STRESS_DURATION=60 STRESS_CPUS=4 bash scripts/stress_test.sh "$(STRESS_ESP)"

stress-test-extended: build-stress ensure-ext3-image
	@echo "=== Running Extended Stress Test Suite ==="
	@bash scripts/stress_test_test.sh
	@STRESS_DURATION=300 STRESS_CPUS=4 bash scripts/stress_test.sh "$(STRESS_ESP)"

# Performance regression gate - prevents accidental slowdowns
test-perf: build
	@echo "=== Running Performance Regression Gate ==="
	@bash scripts/perf_regression_test.sh esp

# Security mitigation tests - hardware/compiler-dependent validation
test-security-mitigations: build
	@echo "=== Running Security Mitigation Tests ==="
	@echo "Security tests are integrated into runtime_tests.rs"
	@echo "Run 'make test' to execute the full test suite including security tests"

# Melting test - sustained maximum load (real hardware only)
test-melting:
	@echo "=== Running Melting Test Suite ==="
	@echo "WARNING: Melting tests should be run on real hardware"
	@MELT_DURATION=600 bash scripts/melting_test.sh

# Extended SMP validation - 8-core and 16-core stress
test-smp-extended: build
	@echo "=== Running Extended SMP Test Suite ==="
	@bash scripts/extended_smp_test.sh esp

# Comprehensive test suite - all test categories
test-comprehensive: build build-stress ensure-ext3-image
	@echo "=== Running Comprehensive Test Suite ==="
	@echo ""
	@echo "1. Boot health check..."
	@bash scripts/boot_check.sh esp || exit 1
	@echo ""
	@echo "2. Runtime test suite..."
	@bash scripts/kernel_test.sh esp || exit 1
	@echo ""
	@echo "3. Musl conformance..."
	@bash scripts/musl_check.sh "$(MUSL_ESP)" || exit 1
	@echo ""
	@echo "4. SMP 2-core validation..."
	@bash scripts/smp_test.sh esp || exit 1
	@echo ""
	@echo "5. SMP 4-core validation..."
	@bash scripts/smp_test_4core.sh esp || exit 1
	@echo ""
	@echo "6. Extended SMP validation..."
	@bash scripts/extended_smp_test.sh esp || exit 1
	@echo ""
	@echo "7. Ext3/JBD2 production gate..."
	@bash scripts/kernel_test.sh esp || exit 1
	@echo ""
	@echo "8. Stress test suite..."
	@bash scripts/stress_test_test.sh || exit 1
	@STRESS_DURATION=60 bash scripts/stress_test.sh "$(STRESS_ESP)" || exit 1
	@echo ""
	@echo "9. Performance regression gate..."
	@bash scripts/perf_regression_test.sh esp || exit 1
	@echo ""
	@echo "=== ✅ Comprehensive Test Suite PASSED ==="

# Quick smoke test - essential gates only
test-quick: build
	@echo "=== Running Quick Smoke Test ==="
	@bash scripts/boot_check.sh esp || exit 1
	@bash scripts/kernel_test.sh esp || exit 1
	@echo "=== ✅ Quick Smoke Test PASSED ==="

# ──────────────────────────────────────────────────────────────────────────
# Code-style + clippy gates — plain local cargo, exactly what CI runs.
# `make fmt-check` / `make clippy` need a local Rust toolchain (see
# CONTRIBUTING.md). The .githooks/pre-push hook runs them automatically before
# each push: locally when a toolchain is present, or offloaded over SSH for a
# toolchain-less mirror. Enable it with `make hooks` (or the pre-commit
# framework via .pre-commit-config.yaml — pick ONE, see CONTRIBUTING.md).
# rustfmt.toml pins newline_style=Windows (the repo is CRLF) so fmt is stable.
# ──────────────────────────────────────────────────────────────────────────

# Hosted unit tests for the explicit kernel sub-crate allowlist. The runner
# preserves Rust's default-parallel scheduler, isolates Cargo target dirs, and
# count-pins every suite so a missing registration/filter cannot pass as 0 tests.
test-hosted-subcrates:
	@bash scripts/hosted_subcrate_tests.sh

# Enable the repo's pre-push hook (runs fmt-check + clippy before each push).
hooks:
	git config --local core.hooksPath .githooks
	@echo "OK: pre-push hook enabled (core.hooksPath=.githooks). Bypass once with: SKIP_PREPUSH=1 git push"

# Auto-format every crate: the workspace (bootloader + kernel and its path-dep
# sub-crates) plus the workspace-excluded userspace crate.
fmt:
	cargo fmt --all
	cd userspace && cargo fmt --all

# Verify formatting without writing. Fails (exit 1) if anything is unformatted.
fmt-check:
	@echo "=== cargo fmt --check (workspace) ==="
	cargo fmt --all -- --check
	@echo "=== cargo fmt --check (userspace) ==="
	cd userspace && cargo fmt --all -- --check
	@echo "OK: all crates are rustfmt-clean."

# Clippy across all three build units (separate target dirs so they don't clash
# with `make build`). Fails on clippy ERRORS (deny-by-default correctness lints);
# warnings are reported but non-blocking.
clippy:
	@echo "=== clippy: bootloader (UEFI) ==="
	cd bootloader && CARGO_TARGET_DIR=../clippy-bootloader-target \
		cargo clippy --release --target x86_64-unknown-uefi --features kaslr
	@echo "=== clippy: kernel (bare-metal, build-std) ==="
	cd kernel && CARGO_TARGET_DIR=../clippy-kernel-target \
		cargo clippy --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
	@echo "=== clippy: userspace (build-std) ==="
	cd userspace && CARGO_TARGET_DIR=clippy-userspace-target \
		cargo clippy --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins
	@echo "OK: clippy reports no errors."

clean:
	cargo clean
	rm -rf kernel-target
	rm -rf bootloader-target
	rm -rf hosted-subcrate-target
	rm -rf esp
	rm -rf esp-stress
	rm -f userspace/stress_runner.elf kernel/src/stress_runner.elf
	rm -f qemu-debug.log qemu-verbose.log qemu-smp.log disk-ext2.img

# AFL++ Fuzzing Targets
# NOTE: AFL++ QEMU mode cannot fuzz bare-metal x86_64-unknown-none kernel.
#       See docs/fuzz/AFL_STATUS.md for alternatives (userspace wrappers or libFuzzer).
afl-seeds:
	@echo "=== 生成AFL++种子语料库 ==="
	python3 scripts/generate_afl_seeds.py

afl-fuzz: build afl-seeds
	@echo "=== 运行AFL++单实例模糊测试 ==="
	@echo "⚠️  WARNING: AFL++ QEMU mode cannot fuzz bare-metal x86_64-unknown-none kernel."
	@echo "    This will fail with 'Unable to request new process from fork server'."
	@echo "    See docs/fuzz/AFL_STATUS.md for alternatives (userspace wrappers or libFuzzer)."
	@echo ""
	chmod +x scripts/afl_fuzz.sh
	./scripts/afl_fuzz.sh --kernel kernel-target/x86_64-unknown-none/release/kernel

afl-fuzz-parallel: build afl-seeds
	@echo "=== 运行AFL++并行模糊测试 ==="
	@echo "⚠️  WARNING: AFL++ QEMU mode cannot fuzz bare-metal x86_64-unknown-none kernel."
	@echo "    See docs/fuzz/AFL_STATUS.md for alternatives."
	@echo ""
	chmod +x scripts/afl_parallel.sh
	./scripts/afl_parallel.sh \
		--kernel kernel-target/x86_64-unknown-none/release/kernel \
		--instances $(INSTANCES)

afl-triage:
	@echo "=== 分类AFL++崩溃发现 ==="
	chmod +x scripts/afl_triage.sh
	@if [ -d fuzz/afl_findings ]; then \
		for fuzzer in fuzz/afl_findings/fuzzer*/crashes; do \
			if [ -d "$$fuzzer" ]; then \
				./scripts/afl_triage.sh "$$fuzzer"; \
			fi; \
		done; \
	else \
		echo "错误: 未找到AFL++结果目录 fuzz/afl_findings"; \
		echo "请先运行 'make afl-fuzz' 或 'make afl-fuzz-parallel'"; \
	fi

# 用于连接到QEMU监视器
monitor:
	telnet localhost 45454

# 显示帮助信息
help:
	@echo "Zero-OS Makefile 使用说明"
	@echo "================================"
	@echo "构建命令:"
	@echo "  make build        - 编译bootloader和kernel（默认hello程序）"
	@echo "  make build-shell  - 编译bootloader和kernel（交互式shell）"
	@echo ""
	@echo "运行模式:"
	@echo "  make run          - 图形窗口模式（推荐，可看到VGA输出）"
	@echo "  make run-serial   - 串口输出模式（终端显示）"
	@echo "  make run-blk      - virtio-blk磁盘模式（图形）"
	@echo "  make run-blk-serial - virtio-blk磁盘模式（串口）"
	@echo "  make run-shell    - 串口模式运行交互式Shell（终端输入输出）"
	@echo "  make run-shell-gui - 图形模式运行交互式Shell（VGA+键盘）"
	@echo "  make run-debug    - 调试模式（显示中断和CPU状态）"
	@echo "  make run-verbose  - 详细调试（记录到文件）"
	@echo "  make run-both     - 图形+串口组合模式"
	@echo "  make debug        - GDB调试模式（等待GDB连接）"
	@echo "  make test         - 运行时套件门禁（Test Summary + panic/NX；exit 0/1/2）"
	@echo "  make test-hosted-subcrates - 主机侧内核子 crate 测试（169 tests + 3 compile checks，默认并行，精确计数门禁）"
	@echo ""
	@echo "SMP多核模式:"
	@echo "  make run-smp      - 启用SMP多核模式（默认2核）"
	@echo "  make run-smp SMP_CPUS=4 - 指定4核"
	@echo "  make run-smp-debug - SMP调试模式（记录中断到qemu-smp.log）"
	@echo ""
	@echo "Fuzzing (AFL++) [⚠️  Disabled - incompatible with bare-metal kernel]:"
	@echo "  make afl-seeds    - 生成AFL++种子语料库"
	@echo "  make afl-fuzz     - 运行单实例AFL++模糊测试（会失败，见AFL_STATUS.md）"
	@echo "  make afl-fuzz-parallel INSTANCES=4 - 并行运行多个AFL++实例（会失败）"
	@echo "  make afl-triage   - 分类AFL++崩溃发现"
	@echo "  NOTE: AFL++ cannot fuzz bare-metal kernel. Use libFuzzer instead (see docs/fuzz/)."
	@echo ""
	@echo "清理命令:"
	@echo "  make clean        - 清理所有构建文件"
	@echo ""
	@echo "提示:"
	@echo "  - 图形模式可以看到完整的VGA输出和集成测试结果"
	@echo "  - 串口模式适合通过脚本自动化测试"
	@echo "  - Shell串口模式：使用终端输入输出，按Ctrl+A X退出"
	@echo "  - Shell图形模式：使用PS/2键盘和VGA显示，Ctrl+Alt+G释放鼠标"
	@echo "  - 调试模式会在qemu-debug.log中记录详细信息"
	@echo "  - SMP模式会启动多个CPU核心，可用SMP_CPUS环境变量指定数量"
	@echo "  - AFL++模糊测试需要先安装AFL++工具链"
	@echo "  - 按Ctrl+C可以随时停止QEMU或AFL++"

# ============================================================================
# KCOV: Kernel Code Coverage for Fuzzing
# ============================================================================

# Rebuild the deterministic guest executor from source on every KCOV build.
build-kcov-runner:
	@echo "=== Building deterministic KCOV guest executor ==="
	musl-gcc -std=c11 -static -O2 -Wall -Wextra -Werror \
		-o "$(KCOV_RUNNER_USER)" userspace/fuzz_runner.c
	cp "$(KCOV_RUNNER_USER)" "$(KCOV_RUNNER_EMBEDDED)"
	@cmp -s "$(KCOV_RUNNER_USER)" "$(KCOV_RUNNER_EMBEDDED)"
	@echo "KCOV guest SHA-256: $$(sha256sum "$(KCOV_RUNNER_EMBEDDED)" | awk '{print $$1}')"
	@readelf -h "$(KCOV_RUNNER_EMBEDDED)" | grep "Entry\|Type"

# Build the isolated kernel artifact containing the freshly built guest.
build-kcov: build-kcov-runner
	@echo "=== 构建 Bootloader (UEFI) ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi --features kaslr

	@echo "=== 构建 Kernel (Bare Metal) with KCOV ==="
	cd kernel && \
	CARGO_TARGET_DIR=../$(KCOV_TARGET_DIR) \
	RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-pie -C relocation-model=pie -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features kcov,fuzz_runner

	@echo "=== Preparing isolated KCOV ESP ==="
	mkdir -p "$(KCOV_ESP_DIR)"

	@echo "Copying bootloader to the KCOV ESP"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi "$(KCOV_ESP_DIR)/BOOTX64.EFI"

	@echo "Copying the isolated KCOV kernel to the KCOV ESP"
	cp "$(KCOV_KERNEL)" "$(KCOV_ESP)/kernel.elf"
	@cmp -s "$(KCOV_KERNEL)" "$(KCOV_ESP)/kernel.elf"
	@echo "KCOV kernel SHA-256: $$(sha256sum "$(KCOV_ESP)/kernel.elf" | awk '{print $$1}')"

	@echo "=== 内核信息 ==="
	@readelf -h "$(KCOV_ESP)/kernel.elf" | grep "Entry\|Type"
	@echo "=== 构建完成（KCOV模式）==="

# Run the KCOV kernel interactively from its single isolated ESP.
run-kcov: QEMU_ESP := $(KCOV_ESP)
run-kcov: build-kcov
	@echo "=== 启动内核（KCOV模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic

# Boot QEMU and validate the deterministic guest executor markers.
test-kcov: build-kcov
	bash scripts/fuzz_runner_test.sh "$(KCOV_ESP)"


# === Syzkaller-Style Executor Kernel (embeds nilix_syz_executor.elf) ===

# Build the syz guest executor and copy it into the kernel source tree so the
# syz_executor feature can include_bytes! it. Mirrors build-kcov-runner.
build-syz-executor-embedded:
	@echo "=== Building syzkaller guest executor (embedded) ==="
	musl-gcc -std=c11 -static -O2 -Wall -Wextra -Werror \
		-o "$(SYZ_EXEC_USER)" userspace/nilix_syz_executor.c
	cp "$(SYZ_EXEC_USER)" "$(SYZ_EXEC_EMBEDDED)"
	@cmp -s "$(SYZ_EXEC_USER)" "$(SYZ_EXEC_EMBEDDED)"
	@echo "syz executor SHA-256: $$(sha256sum "$(SYZ_EXEC_EMBEDDED)" | awk '{print $$1}')"
	@readelf -h "$(SYZ_EXEC_EMBEDDED)" | grep "Entry\|Type"

# Build the isolated kernel that boots the syz guest executor (reads a fuzz
# program from the mounted ext3 disk, emits NILIX_SYZ_V2_* markers). Mirrors
# build-kcov but with --features kcov,syz_executor and its own ESP. build-kcov
# (esp-kcov, fuzz_runner.elf) stays the deterministic test-kcov path — untouched.
build-syz-kcov: build-syz-executor-embedded
	@echo "=== Building bootloader for syz executor kernel ==="
	cd bootloader && \
	CARGO_TARGET_DIR=../bootloader-target cargo build --release --target x86_64-unknown-uefi --features kaslr

	@echo "=== Building isolated syz-executor kernel ==="
	cd kernel && \
	CARGO_TARGET_DIR=../$(SYZ_TARGET_DIR) \
	RUSTFLAGS="-C link-arg=-T$(KERNEL_LD) -C link-arg=-nostdlib -C link-arg=-static -C link-arg=-pie -C relocation-model=pie -C code-model=kernel -C panic=abort" \
	cargo build --release --target x86_64-unknown-none -Z build-std=core,alloc,compiler_builtins --features kcov,syz_executor

	@echo "=== Preparing isolated syz-executor ESP ==="
	mkdir -p "$(SYZ_ESP_DIR)"
	cp bootloader-target/x86_64-unknown-uefi/release/bootloader.efi "$(SYZ_ESP_DIR)/BOOTX64.EFI"
	cp "$(SYZ_KERNEL)" "$(SYZ_ESP)/kernel.elf"
	@cmp -s "$(SYZ_KERNEL)" "$(SYZ_ESP)/kernel.elf"
	@echo "syz-executor kernel SHA-256: $$(sha256sum "$(SYZ_ESP)/kernel.elf" | awk '{print $$1}')"
	@readelf -h "$(SYZ_ESP)/kernel.elf" | grep "Entry\|Type"
	@echo "=== 构建完成（syz executor 模式）==="

# Run the syz-executor kernel interactively from its single isolated ESP.
run-syz-kcov: QEMU_ESP := $(SYZ_ESP)
run-syz-kcov: build-syz-kcov
	@echo "=== 启动内核（syz executor 模式）==="
	@echo "提示：按Ctrl+A然后按X退出QEMU"
	$(QEMU) $(QEMU_COMMON) \
		-nographic


# === Phase 8: Cargo-Fuzz Integration with QEMU Executor ===

# Build prerequisites for QEMU-based cargo-fuzz
build-fuzz-qemu-deps: build-kcov build-syz-fuzzer
	@echo "=== QEMU Fuzzing Prerequisites Ready ==="

# Run cargo-fuzz with QEMU executor (5-minute smoke test)
fuzz-qemu-smoke: build-fuzz-qemu-deps
	@echo "=== Running QEMU-Based Cargo-Fuzz Smoke Test ==="
	cd fuzz && \
	cargo +nightly fuzz run fuzz_syscall_qemu --features qemu-executor -- \
		-max_total_time=300 \
		-timeout=15 \
		-rss_limit_mb=4096 \
		-print_final_stats=1
	@echo "=== Smoke Test Complete ==="
	@if [ -d fuzz/artifacts/fuzz_syscall_qemu ]; then \
		CRASHES=$$(find fuzz/artifacts/fuzz_syscall_qemu -name 'crash-*' | wc -l); \
		echo "Crashes found: $$CRASHES"; \
		if [ $$CRASHES -gt 0 ]; then \
			echo "ERROR: Crashes detected!"; \
			exit 1; \
		fi; \
	fi

# Run extended QEMU fuzzing campaign (1 hour)
fuzz-qemu-campaign: build-fuzz-qemu-deps
	@echo "=== Running 1-Hour QEMU Fuzzing Campaign ==="
	cd fuzz && \
	cargo +nightly fuzz run fuzz_syscall_qemu --features qemu-executor -- \
		-max_total_time=3600 \
		-timeout=12 \
		-rss_limit_mb=4096 \
		-print_final_stats=1

# Run overnight QEMU fuzzing (8 hours)
fuzz-qemu-overnight: build-fuzz-qemu-deps
	@echo "=== Running Overnight QEMU Fuzzing (8 hours) ==="
	cd fuzz && \
	cargo +nightly fuzz run fuzz_syscall_qemu --features qemu-executor -- \
		-max_total_time=28800 \
		-timeout=10 \
		-rss_limit_mb=8192 \
		-print_final_stats=1

# Parallel QEMU fuzzing with 4 workers (requires 4x memory)
fuzz-qemu-parallel: build-fuzz-qemu-deps
	@echo "=== Running Parallel QEMU Fuzzing (4 workers) ==="
	cd fuzz && \
	cargo +nightly fuzz run fuzz_syscall_qemu --features qemu-executor --jobs=4 -- \
		-max_total_time=3600 \
		-timeout=15 \
		-rss_limit_mb=4096 \
		-print_final_stats=1

# List all available cargo-fuzz targets
fuzz-list:
	@echo "=== Available Cargo-Fuzz Targets ==="
	@cd fuzz && cargo +nightly fuzz list

# Clean cargo-fuzz artifacts and corpus
fuzz-clean:
	@echo "=== Cleaning Cargo-Fuzz Artifacts ==="
	rm -rf fuzz/corpus/* fuzz/artifacts/* fuzz/coverage/*
	rm -rf fuzz/target/
	@echo "=== Cleaned ==="

