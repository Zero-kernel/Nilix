use anyhow::{bail, Context, Result};
#[cfg(unix)]
use nix::sys::signal::{kill, Signal};
#[cfg(unix)]
use nix::unistd::Pid;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::disk::{ensure_qemu_safe_path, Ext3Tools, Ext3Transport};
use crate::program::SyscallProgram;
use crate::protocol::{
    constant_time_eq, decode_result, encode_program, ExecutionIdentity, ProgramBinding,
};

const MAX_SERIAL_LOG: u64 = 4 * 1024 * 1024;
const MAX_DIAGNOSTIC_LOG: usize = 256 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const PASS_SETTLE_TIME: Duration = Duration::from_millis(75);
const TERM_GRACE: Duration = Duration::from_secs(2);
static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
pub enum ExecutionResult {
    Success(Vec<u8>),
    Crash(CrashInfo),
    Timeout,
    Hang,
}

#[derive(Debug)]
pub struct CrashInfo {
    pub classification: String,
    pub serial_log: String,
    pub qemu_stderr: String,
}

#[derive(Clone, Debug)]
pub struct QemuExecutor {
    qemu_path: PathBuf,
    kernel_path: PathBuf,
    ovmf_path: PathBuf,
    timeout: Duration,
    transport: Ext3Transport,
    artifact_dir: Option<PathBuf>,
}

impl QemuExecutor {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        qemu_path: &Path,
        kernel_path: &Path,
        ovmf_path: Option<&Path>,
        timeout_secs: u64,
        disk_mib: u64,
        tools: Ext3Tools,
    ) -> Result<Self> {
        if timeout_secs == 0 {
            bail!("per-program timeout must be positive");
        }
        if !kernel_path.is_file() {
            bail!("kernel not found: {}", kernel_path.display());
        }
        if kernel_path.file_name().and_then(|name| name.to_str()) != Some("kernel.elf") {
            bail!(
                "kernel must be named kernel.elf for the Zero-OS UEFI bootloader: {}",
                kernel_path.display()
            );
        }
        let ovmf_path = match ovmf_path {
            Some(path) => {
                if !path.is_file() {
                    bail!("OVMF firmware not found: {}", path.display());
                }
                path.to_path_buf()
            }
            None => find_ovmf()?,
        };

        Ok(Self {
            qemu_path: qemu_path.to_path_buf(),
            kernel_path: kernel_path.to_path_buf(),
            ovmf_path,
            timeout: Duration::from_secs(timeout_secs),
            transport: Ext3Transport::new(tools, disk_mib)?,
            artifact_dir: None,
        })
    }

    /// Retain each execution's inputs, private ESP, disk and logs for a finite
    /// validation run. Normal campaigns keep the default temporary cleanup.
    pub fn with_artifact_dir(mut self, directory: PathBuf) -> Self {
        self.artifact_dir = Some(directory);
        self
    }

    pub fn execute(&self, program: &SyscallProgram) -> Result<ExecutionResult> {
        let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        if sequence == u64::MAX {
            bail!("execution sequence space exhausted");
        }
        let encoded = encode_program(program, &ExecutionIdentity::random(sequence))?;

        let mut builder = tempfile::Builder::new();
        builder.prefix("nilix-syz-v2-");
        let temp_dir = match &self.artifact_dir {
            Some(root) => {
                std::fs::create_dir_all(root).context("failed to create artifact root")?;
                builder.tempdir_in(root)
            }
            None => builder.tempdir(),
        }
        .context("failed to create per-execution temporary directory")?;
        let work_dir = temp_dir.path().to_path_buf();
        let _auto_cleanup = if self.artifact_dir.is_some() {
            let _ = temp_dir.keep();
            eprintln!("NILIX_SYZ_ARTIFACTS {}", work_dir.display());
            None
        } else {
            Some(temp_dir)
        };
        let serial_path = work_dir.join("serial.log");
        let stderr_path = work_dir.join("qemu.stderr");
        File::create(&serial_path).context("failed to create serial log")?;
        let stderr_file = File::create(&stderr_path).context("failed to create QEMU stderr log")?;
        let disk_path = self
            .transport
            .prepare(&work_dir, &encoded.bytes)
            .context("failed to prepare fresh syz Ext3 transport")?;

        let source_esp = self
            .kernel_path
            .parent()
            .context("kernel path has no parent directory")?;
        // QEMU's writable FAT backend/OVMF modifies NvVars. Never share the
        // source ESP between programs or workers, and never reuse stale state.
        let esp_dir = work_dir.join("esp");
        std::fs::create_dir_all(esp_dir.join("EFI/BOOT"))?;
        std::fs::copy(&self.kernel_path, esp_dir.join("kernel.elf"))
            .context("failed to copy the guest kernel")?;
        std::fs::copy(
            source_esp.join("EFI/BOOT/BOOTX64.EFI"),
            esp_dir.join("EFI/BOOT/BOOTX64.EFI"),
        )
        .context("missing UEFI bootloader; run make build-syz-kcov")?;
        ensure_qemu_safe_path(&esp_dir)?;
        ensure_qemu_safe_path(&disk_path)?;
        ensure_qemu_safe_path(&serial_path)?;

        let args = qemu_args(&self.ovmf_path, &esp_dir, &disk_path, &serial_path)?;
        if self.artifact_dir.is_some() {
            std::fs::write(
                work_dir.join("qemu-command.json"),
                serde_json::to_vec(&args)?,
            )?;
        }
        let mut child = Command::new(&self.qemu_path)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .with_context(|| format!("failed to spawn {}", self.qemu_path.display()))?;
        if self.artifact_dir.is_some() {
            eprintln!(
                "NILIX_SYZ_QEMU_STARTED pid={} artifacts={}",
                child.id(),
                work_dir.display()
            );
        }

        let observation =
            observe_execution(&mut child, &serial_path, &encoded.binding, self.timeout)?;

        let serial_log = read_bounded_text(&serial_path, MAX_SERIAL_LOG as usize);
        let qemu_stderr = read_bounded_text(&stderr_path, MAX_DIAGNOSTIC_LOG);

        match observation {
            Observation::Pass(marker) => {
                let result_bytes = match self.transport.extract_result(&disk_path, &work_dir) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        return Ok(ExecutionResult::Crash(CrashInfo {
                            classification: format!("missing_or_invalid_result: {error:#}"),
                            serial_log,
                            qemu_stderr,
                        }));
                    }
                };
                let decoded = match decode_result(&result_bytes, &encoded.binding) {
                    Ok(result) => result,
                    Err(error) => {
                        return Ok(ExecutionResult::Crash(CrashInfo {
                            classification: format!("result_protocol_violation: {error:#}"),
                            serial_log,
                            qemu_stderr,
                        }));
                    }
                };
                if marker.occupied_slot_count != decoded.occupied_slot_count
                    || !constant_time_eq(&marker.tag, &decoded.tag)
                {
                    return Ok(ExecutionResult::Crash(CrashInfo {
                        classification: "serial_result_mismatch".to_string(),
                        serial_log,
                        qemu_stderr,
                    }));
                }
                Ok(ExecutionResult::Success(decoded.coverage))
            }
            Observation::GuestFailure { stage, code } => Ok(ExecutionResult::Crash(CrashInfo {
                classification: format!("executor_failure:{stage}:{code}"),
                serial_log,
                qemu_stderr,
            })),
            Observation::Crash(classification) => Ok(ExecutionResult::Crash(CrashInfo {
                classification,
                serial_log,
                qemu_stderr,
            })),
            Observation::Timeout { began: false } => Ok(ExecutionResult::Timeout),
            Observation::Timeout { began: true } => Ok(ExecutionResult::Hang),
        }
    }
}

#[derive(Debug)]
enum Observation {
    Pass(PassMarker),
    GuestFailure { stage: String, code: i64 },
    Crash(String),
    Timeout { began: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PassMarker {
    occupied_slot_count: u32,
    tag: [u8; 32],
}

#[derive(Debug)]
struct FailureMarker {
    stage: String,
    code: i64,
}

#[derive(Debug)]
struct MarkerTracker<'a> {
    binding: &'a ProgramBinding,
    began: bool,
    pass: Option<PassMarker>,
    failure: Option<FailureMarker>,
}

impl<'a> MarkerTracker<'a> {
    fn new(binding: &'a ProgramBinding) -> Self {
        Self {
            binding,
            began: false,
            pass: None,
            failure: None,
        }
    }

    fn process_line(&mut self, line: &[u8]) -> Result<()> {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if !line.starts_with(b"NILIX_SYZ_V2_") {
            return Ok(());
        }
        let line = std::str::from_utf8(line).context("syz marker is not valid UTF-8")?;
        if line.starts_with("NILIX_SYZ_V2_BEGIN ") {
            self.process_begin(line)
        } else if line.starts_with("NILIX_SYZ_V2_PASS ") {
            self.process_pass(line)
        } else if line.starts_with("NILIX_SYZ_V2_FAIL ") {
            self.process_failure(line)
        } else {
            bail!("unknown syz marker type");
        }
    }

    fn process_begin(&mut self, line: &str) -> Result<()> {
        if self.began || self.pass.is_some() || self.failure.is_some() {
            bail!("duplicate or out-of-order BEGIN marker");
        }
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() != 4 || fields[0] != "NILIX_SYZ_V2_BEGIN" {
            bail!("malformed BEGIN marker");
        }
        require_identity(fields[1], fields[2], fields[3], self.binding)?;
        self.began = true;
        Ok(())
    }

    fn process_pass(&mut self, line: &str) -> Result<()> {
        if !self.began || self.pass.is_some() || self.failure.is_some() {
            bail!("duplicate or out-of-order PASS marker");
        }
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() != 6 || fields[0] != "NILIX_SYZ_V2_PASS" {
            bail!("malformed PASS marker");
        }
        require_identity(fields[1], fields[2], fields[3], self.binding)?;
        let slots_text = field_value(fields[4], "slots")?;
        let occupied_slot_count: u32 = slots_text
            .parse()
            .context("invalid PASS occupied-slot count")?;
        if occupied_slot_count == 0 || occupied_slot_count.to_string() != slots_text {
            bail!("PASS occupied-slot count is zero or non-canonical");
        }
        let tag = parse_hex_array::<32>(field_value(fields[5], "tag")?, "PASS tag")?;
        self.pass = Some(PassMarker {
            occupied_slot_count,
            tag,
        });
        Ok(())
    }

    fn process_failure(&mut self, line: &str) -> Result<()> {
        if self.pass.is_some() || self.failure.is_some() {
            bail!("duplicate or out-of-order FAIL marker");
        }
        let fields: Vec<&str> = line.split_ascii_whitespace().collect();
        if fields.len() != 6 || fields[0] != "NILIX_SYZ_V2_FAIL" {
            bail!("malformed FAIL marker");
        }
        if self.began {
            require_identity(fields[1], fields[2], fields[3], self.binding)?;
        } else if fields[1] != "seq=none" || fields[2] != "run=none" || fields[3] != "program=none"
        {
            bail!("pre-BEGIN FAIL marker must not claim an execution identity");
        }
        let stage = field_value(fields[4], "stage")?;
        if stage.is_empty()
            || stage.len() > 48
            || !stage
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            bail!("FAIL stage token is non-canonical");
        }
        let code_text = field_value(fields[5], "code")?;
        let code: i64 = code_text.parse().context("invalid FAIL code")?;
        if code.to_string() != code_text {
            bail!("FAIL code is non-canonical");
        }
        self.failure = Some(FailureMarker {
            stage: stage.to_string(),
            code,
        });
        Ok(())
    }
}

struct SerialMonitor<'a> {
    file: File,
    offset: u64,
    partial: Vec<u8>,
    recent: Vec<u8>,
    fatal: Option<String>,
    tracker: MarkerTracker<'a>,
}

impl<'a> SerialMonitor<'a> {
    fn open(path: &Path, binding: &'a ProgramBinding) -> Result<Self> {
        Ok(Self {
            file: OpenOptions::new()
                .read(true)
                .open(path)
                .with_context(|| format!("failed to open {}", path.display()))?,
            offset: 0,
            partial: Vec::new(),
            recent: Vec::new(),
            fatal: None,
            tracker: MarkerTracker::new(binding),
        })
    }

    fn poll(&mut self) -> Result<()> {
        let length = self.file.metadata()?.len();
        if length < self.offset {
            bail!("serial log was truncated while QEMU was running");
        }
        if length > MAX_SERIAL_LOG {
            bail!("serial log exceeded the {MAX_SERIAL_LOG}-byte limit");
        }
        if length == self.offset {
            return Ok(());
        }

        self.file.seek(SeekFrom::Start(self.offset))?;
        let mut new_bytes = Vec::with_capacity((length - self.offset) as usize);
        // QEMU may append after metadata(). Only consume this snapshot, and
        // advance by bytes actually read so a later poll cannot replay markers.
        (&mut self.file)
            .take(length - self.offset)
            .read_to_end(&mut new_bytes)?;
        self.offset += new_bytes.len() as u64;
        self.recent.extend_from_slice(&new_bytes);
        if self.fatal.is_none() {
            self.fatal = classify_fatal(&self.recent);
        }
        if self.recent.len() > MAX_DIAGNOSTIC_LOG {
            let excess = self.recent.len() - MAX_DIAGNOSTIC_LOG;
            self.recent.drain(..excess);
        }
        self.partial.extend_from_slice(&new_bytes);

        if let Some(newline) = self.partial.iter().rposition(|byte| *byte == b'\n') {
            for line in self.partial[..newline].split(|byte| *byte == b'\n') {
                self.tracker.process_line(line)?;
            }
            self.partial.drain(..=newline);
        }
        Ok(())
    }

    fn crash_classification(&self) -> Option<String> {
        self.fatal.clone()
    }
}

fn classify_fatal(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    if text.contains("KERNEL PANIC") || text.contains("kernel panicked") {
        Some("kernel_panic".to_string())
    } else if text.contains("triple fault") {
        Some("triple_fault".to_string())
    } else if text.contains("page fault") {
        Some("page_fault".to_string())
    } else {
        None
    }
}

/// Reap first, then validate the complete immutable serial log and exit status.
/// A provisional PASS never overrides a failure during emulator shutdown.
fn observe_execution(
    child: &mut Child,
    serial_path: &Path,
    binding: &ProgramBinding,
    timeout: Duration,
) -> Result<Observation> {
    let provisional = monitor_execution(child, serial_path, binding, timeout);
    let termination = terminate_qemu(child).context("failed to stop QEMU cleanly")?;
    let provisional = provisional?;
    let mut final_serial = SerialMonitor::open(serial_path, binding)?;
    final_serial
        .poll()
        .context("invalid serial protocol after QEMU exit")?;
    if !final_serial.partial.is_empty()
        && (final_serial.partial.starts_with(b"NILIX_SYZ_V2_")
            || b"NILIX_SYZ_V2_".starts_with(&final_serial.partial))
    {
        bail!("unterminated protocol marker after QEMU exit");
    }
    if let Some(reason) = final_serial.crash_classification() {
        return Ok(Observation::Crash(reason));
    }
    if !termination.expected() {
        return Ok(Observation::Crash(classify_early_exit(
            termination.status,
            final_serial.tracker.began,
        )));
    }
    if let Some(failure) = final_serial.tracker.failure {
        return Ok(Observation::GuestFailure {
            stage: failure.stage,
            code: failure.code,
        });
    }
    if let Observation::Pass(ref pass) = provisional {
        if final_serial.tracker.pass.as_ref() != Some(pass) {
            bail!("final serial completion differs from the observed PASS");
        }
    }
    Ok(provisional)
}

fn monitor_execution(
    child: &mut Child,
    serial_path: &Path,
    binding: &ProgramBinding,
    timeout: Duration,
) -> Result<Observation> {
    let start = Instant::now();
    let mut serial = SerialMonitor::open(serial_path, binding)?;
    loop {
        serial.poll().context("invalid serial protocol")?;

        if let Some(failure) = serial.tracker.failure.take() {
            return Ok(Observation::GuestFailure {
                stage: failure.stage,
                code: failure.code,
            });
        }
        if let Some(classification) = serial.crash_classification() {
            return Ok(Observation::Crash(classification));
        }
        if let Some(pass) = serial.tracker.pass.clone() {
            std::thread::sleep(PASS_SETTLE_TIME);
            serial
                .poll()
                .context("invalid serial protocol after PASS")?;
            if serial.tracker.failure.is_some() {
                bail!("FAIL marker followed PASS");
            }
            if let Some(classification) = serial.crash_classification() {
                return Ok(Observation::Crash(classification));
            }
            if let Some(status) = child.try_wait().context("failed to poll QEMU after PASS")? {
                if !status.success() {
                    return Ok(Observation::Crash(classify_early_exit(status, true)));
                }
            }
            return Ok(Observation::Pass(pass));
        }
        if let Some(status) = child.try_wait().context("failed to poll QEMU")? {
            serial.poll().context("invalid final serial protocol")?;
            if let Some(classification) = serial.crash_classification() {
                return Ok(Observation::Crash(classification));
            }
            if !status.success() {
                return Ok(Observation::Crash(classify_early_exit(
                    status,
                    serial.tracker.began,
                )));
            }
            if let Some(failure) = serial.tracker.failure.take() {
                return Ok(Observation::GuestFailure {
                    stage: failure.stage,
                    code: failure.code,
                });
            }
            if let Some(pass) = serial.tracker.pass.clone() {
                return Ok(Observation::Pass(pass));
            }
            return Ok(Observation::Crash(classify_early_exit(
                status,
                serial.tracker.began,
            )));
        }
        if start.elapsed() >= timeout {
            return Ok(Observation::Timeout {
                began: serial.tracker.began,
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

struct Termination {
    status: ExitStatus,
    term_sent: bool,
    kill_sent: bool,
}

impl Termination {
    fn expected(&self) -> bool {
        if self.status.success() {
            return true;
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            (self.term_sent && self.status.signal() == Some(Signal::SIGTERM as i32))
                || (self.kill_sent && self.status.signal() == Some(Signal::SIGKILL as i32))
        }
        #[cfg(not(unix))]
        {
            self.kill_sent
        }
    }
}

fn terminate_qemu(child: &mut Child) -> Result<Termination> {
    if let Some(status) = child.try_wait()? {
        return Ok(Termination {
            status,
            term_sent: false,
            kill_sent: false,
        });
    }
    #[cfg(not(unix))]
    {
        child.kill().context("failed to terminate QEMU")?;
        let status = child.wait().context("failed to reap QEMU")?;
        Ok(Termination {
            status,
            term_sent: false,
            kill_sent: true,
        })
    }

    #[cfg(unix)]
    {
        let pid = Pid::from_raw(i32::try_from(child.id()).context("QEMU PID exceeds i32")?);
        let term_sent = kill(pid, Signal::SIGTERM).is_ok();
        let deadline = Instant::now() + TERM_GRACE;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait()? {
                return Ok(Termination {
                    status,
                    term_sent,
                    kill_sent: false,
                });
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        let kill_sent = kill(pid, Signal::SIGKILL).is_ok();
        let status = child.wait().context("failed to reap QEMU after SIGKILL")?;
        Ok(Termination {
            status,
            term_sent,
            kill_sent,
        })
    }
}

fn qemu_args(ovmf: &Path, esp_dir: &Path, disk: &Path, serial: &Path) -> Result<Vec<String>> {
    for path in [ovmf, esp_dir, disk, serial] {
        ensure_qemu_safe_path(path)?;
    }
    let ovmf = utf8_path(ovmf)?;
    let esp_dir = utf8_path(esp_dir)?;
    let disk = utf8_path(disk)?;
    let serial = utf8_path(serial)?;
    Ok(vec![
        "-bios".into(),
        ovmf.into(),
        "-drive".into(),
        // OVMF can write to the ESP. Keep those writes in this drive's overlay;
        // the separate result disk must remain persistent for extraction.
        format!("format=raw,file=fat:{esp_dir},snapshot=on"),
        "-drive".into(),
        // Writeback matches the block path used by the kernel runtime gates
        // and avoids QEMU 8.x direct-I/O alignment differences on Ext3.
        format!("if=none,file={disk},format=raw,id=syzdisk,cache=writeback"),
        "-device".into(),
        "virtio-blk-pci,drive=syzdisk".into(),
        "-m".into(),
        "512M".into(),
        "-smp".into(),
        "1".into(),
        "-cpu".into(),
        "qemu64,+smep,+smap,+umip,+rdrand".into(),
        "-nic".into(),
        "none".into(),
        "-serial".into(),
        format!("file:{serial}"),
        "-monitor".into(),
        "none".into(),
        "-display".into(),
        "none".into(),
        "-no-reboot".into(),
        "-no-shutdown".into(),
    ])
}

fn require_identity(
    sequence_field: &str,
    run_field: &str,
    program_field: &str,
    binding: &ProgramBinding,
) -> Result<()> {
    if field_value(sequence_field, "seq")? != binding.sequence_hex()
        || field_value(run_field, "run")? != binding.run_hex()
        || field_value(program_field, "program")? != binding.program_hex()
    {
        bail!("serial marker identity does not match the submitted program");
    }
    Ok(())
}

fn field_value<'a>(field: &'a str, name: &str) -> Result<&'a str> {
    field
        .strip_prefix(name)
        .and_then(|rest| rest.strip_prefix('='))
        .filter(|value| !value.is_empty())
        .with_context(|| format!("missing or malformed {name} field"))
}

fn parse_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} is not canonical lowercase hexadecimal");
    }
    let decoded = hex::decode(value).with_context(|| format!("invalid {label}"))?;
    Ok(decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid {label} length"))?)
}

fn classify_early_exit(status: ExitStatus, began: bool) -> String {
    if began {
        format!("qemu_exit_after_begin:{status}")
    } else {
        format!("boot_failure:{status}")
    }
}

fn find_ovmf() -> Result<PathBuf> {
    let candidates = [
        "/usr/share/qemu/OVMF.fd",
        "/usr/share/ovmf/OVMF.fd",
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
    ];
    candidates
        .into_iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .context("OVMF firmware not found; pass --ovmf explicitly")
}

fn utf8_path(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn read_bounded_text(path: &Path, maximum: usize) -> String {
    if maximum == 0 {
        return String::new();
    }

    // Do not read an untrusted QEMU log in full just to retain its tail.  Seek
    // from the end and cap the allocation/read itself at `maximum` (U58-6).
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let Ok(length) = file.metadata().map(|metadata| metadata.len()) else {
        return String::new();
    };
    let start = length.saturating_sub(maximum as u64);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }

    let mut data = Vec::with_capacity(length.saturating_sub(start).min(maximum as u64) as usize);
    if file.take(maximum as u64).read_to_end(&mut data).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&data).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{Syscall, SyscallProgram, SYS_GETPID};
    use crate::protocol::{encode_program, ExecutionIdentity};

    fn binding() -> ProgramBinding {
        encode_program(
            &SyscallProgram {
                syscalls: vec![Syscall {
                    number: SYS_GETPID,
                    args: vec![],
                }],
            },
            &ExecutionIdentity::random(0x42),
        )
        .unwrap()
        .binding
    }

    #[test]
    fn marker_state_machine_accepts_one_matching_begin_and_pass() {
        let binding = binding();
        let mut tracker = MarkerTracker::new(&binding);
        tracker
            .process_line(
                format!(
                    "NILIX_SYZ_V2_BEGIN seq={} run={} program={}",
                    binding.sequence_hex(),
                    binding.run_hex(),
                    binding.program_hex()
                )
                .as_bytes(),
            )
            .unwrap();
        tracker
            .process_line(
                format!(
                    "NILIX_SYZ_V2_PASS seq={} run={} program={} slots=3 tag={}",
                    binding.sequence_hex(),
                    binding.run_hex(),
                    binding.program_hex(),
                    "11".repeat(32)
                )
                .as_bytes(),
            )
            .unwrap();
        assert_eq!(tracker.pass.unwrap().occupied_slot_count, 3);
    }

    #[test]
    fn marker_state_machine_rejects_spoofing_duplicates_and_bad_order() {
        let binding = binding();
        let pass = format!(
            "NILIX_SYZ_V2_PASS seq={} run={} program={} slots=1 tag={}",
            binding.sequence_hex(),
            binding.run_hex(),
            binding.program_hex(),
            "00".repeat(32)
        );
        let mut tracker = MarkerTracker::new(&binding);
        assert!(tracker.process_line(pass.as_bytes()).is_err());

        let begin = format!(
            "NILIX_SYZ_V2_BEGIN seq={} run={} program={}",
            binding.sequence_hex(),
            binding.run_hex(),
            binding.program_hex()
        );
        tracker.process_line(begin.as_bytes()).unwrap();
        assert!(tracker.process_line(begin.as_bytes()).is_err());

        let mut mismatch = MarkerTracker::new(&binding);
        let bad = begin.replace("seq=0000000000000042", "seq=0000000000000043");
        assert!(mismatch.process_line(bad.as_bytes()).is_err());
    }

    #[test]
    fn marker_state_machine_rejects_legacy_edge_field() {
        let binding = binding();
        let mut tracker = MarkerTracker::new(&binding);
        let begin = format!(
            "NILIX_SYZ_V2_BEGIN seq={} run={} program={}",
            binding.sequence_hex(),
            binding.run_hex(),
            binding.program_hex()
        );
        tracker.process_line(begin.as_bytes()).unwrap();
        let legacy = format!(
            "NILIX_SYZ_V2_PASS seq={} run={} program={} edges=1 tag={}",
            binding.sequence_hex(),
            binding.run_hex(),
            binding.program_hex(),
            "11".repeat(32)
        );
        assert!(tracker.process_line(legacy.as_bytes()).is_err());
    }

    #[test]
    fn pre_begin_failure_must_be_identity_free() {
        let binding = binding();
        let mut tracker = MarkerTracker::new(&binding);
        tracker
            .process_line(
                b"NILIX_SYZ_V2_FAIL seq=none run=none program=none stage=read_input code=-5",
            )
            .unwrap();
        assert_eq!(tracker.failure.unwrap().stage, "read_input");
    }

    #[cfg(unix)]
    fn markers(binding: &ProgramBinding, pass: bool) -> String {
        let mut text = format!(
            "NILIX_SYZ_V2_BEGIN seq={} run={} program={}\n",
            binding.sequence_hex(),
            binding.run_hex(),
            binding.program_hex()
        );
        if pass {
            text.push_str(&format!(
                "NILIX_SYZ_V2_PASS seq={} run={} program={} slots=1 tag={}\n",
                binding.sequence_hex(),
                binding.run_hex(),
                binding.program_hex(),
                "11".repeat(32)
            ));
        }
        text
    }

    // These tests run the production monitor against real host child processes.
    // Their synthetic serial logs exercise classification, not guest execution.
    #[cfg(unix)]
    fn observe_fixture(log: &str, binding: &ProgramBinding, exit: bool) -> Result<Observation> {
        let directory = tempfile::tempdir()?;
        let serial = directory.path().join("serial.log");
        std::fs::write(&serial, log)?;
        let mut child = Command::new("sh")
            .args(["-c", if exit { "exit 7" } else { "exec sleep 10" }])
            .spawn()?;
        if exit {
            child.wait()?;
        }
        let result = observe_execution(&mut child, &serial, binding, Duration::from_millis(100));
        assert!(child.try_wait()?.is_some(), "fixture child must be reaped");
        result
    }

    #[test]
    #[cfg(unix)]
    fn real_child_timeout_distinguishes_boot_from_guest_hang() {
        let binding = binding();
        assert!(matches!(
            observe_fixture("", &binding, false).unwrap(),
            Observation::Timeout { began: false }
        ));
        assert!(matches!(
            observe_fixture(&markers(&binding, false), &binding, false).unwrap(),
            Observation::Timeout { began: true }
        ));
    }

    #[test]
    #[cfg(unix)]
    fn abnormal_process_exit_never_passes_even_with_a_valid_pass_marker() {
        let binding = binding();
        for log in [
            String::new(),
            markers(&binding, false),
            markers(&binding, true),
        ] {
            let Observation::Crash(classification) = observe_fixture(&log, &binding, true).unwrap()
            else {
                panic!("nonzero process exit must be a crash");
            };
            assert!(classification.contains("exit status: 7"));
        }
    }

    #[test]
    #[cfg(unix)]
    fn panic_after_pass_overrides_success_and_live_pass_is_observed() {
        let binding = binding();
        let pass = markers(&binding, true);
        assert!(matches!(
            observe_fixture(&pass, &binding, false).unwrap(),
            Observation::Pass(_)
        ));
        let log = format!("{pass}KERNEL PANIC\n");
        assert!(
            matches!(observe_fixture(&log, &binding, false).unwrap(), Observation::Crash(reason) if reason == "kernel_panic")
        );
    }

    #[test]
    #[cfg(unix)]
    fn malformed_serial_is_an_error_and_the_process_is_stopped() {
        let binding = binding();
        assert!(observe_fixture("NILIX_SYZ_V2_BAD\n", &binding, false).is_err());
    }

    #[test]
    #[cfg(unix)]
    fn shutdown_panic_and_nonzero_status_override_provisional_pass() {
        let binding = binding();
        for (trap, expected) in [
            ("printf 'KERNEL PANIC\\n' >> \"$1\"; exit 0", "kernel_panic"),
            ("exit 7", "qemu_exit_after_begin:"),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let serial = directory.path().join("serial.log");
            std::fs::write(&serial, markers(&binding, true)).unwrap();
            // Pass the trap body separately so nested quotes remain shell data.
            let mut child = Command::new("sh")
                .args([
                    "-c",
                    "trap \"$2\" TERM; printf 'READY\\n' >> \"$1\"; while :; do sleep 0.01; done",
                    "fixture",
                ])
                .arg(&serial)
                .arg(trap)
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while !std::fs::read_to_string(&serial).unwrap().contains("READY") {
                if Instant::now() >= deadline {
                    let _ = terminate_qemu(&mut child);
                    panic!("fixture failed to install TERM trap");
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            let result =
                observe_execution(&mut child, &serial, &binding, Duration::from_secs(1)).unwrap();
            assert!(child.try_wait().unwrap().is_some());
            assert!(
                matches!(result, Observation::Crash(reason) if reason.starts_with(expected)),
                "shutdown failure was accepted"
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn incomplete_final_protocol_tail_cannot_satisfy_success() {
        let binding = binding();
        let pass = markers(&binding, true);
        for partial in [
            "NILIX_SYZ_V2_FAIL seq=",
            "NILIX_SYZ_V2_UNKNOWN",
            "NILIX_SYZ_",
        ] {
            assert!(observe_fixture(&format!("{pass}{partial}"), &binding, false).is_err());
        }
        assert!(matches!(
            observe_fixture(&format!("{pass}ordinary diagnostic tail"), &binding, false).unwrap(),
            Observation::Pass(_)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn serial_offsets_are_exact_and_fatal_evidence_survives_tail_eviction() {
        use std::io::Write;
        let binding = binding();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("serial.log");
        std::fs::write(&path, markers(&binding, false)).unwrap();
        let mut serial = SerialMonitor::open(&path, &binding).unwrap();
        serial.poll().unwrap();
        serial.poll().unwrap();
        assert!(serial.tracker.began);
        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(b"KERNEL PAN").unwrap();
        serial.poll().unwrap();
        writer.write_all(b"IC\n").unwrap();
        writer
            .write_all(&vec![b'x'; MAX_DIAGNOSTIC_LOG + 1])
            .unwrap();
        serial.poll().unwrap();
        assert_eq!(serial.offset, writer.metadata().unwrap().len());
        assert_eq!(serial.recent.len(), MAX_DIAGNOSTIC_LOG);
        assert_eq!(
            serial.crash_classification().as_deref(),
            Some("kernel_panic")
        );
        serial.poll().unwrap();
        assert_eq!(
            serial.crash_classification().as_deref(),
            Some("kernel_panic")
        );
    }

    #[test]
    fn qemu_arguments_attach_fresh_ext3_and_disable_networking() {
        let args = qemu_args(
            Path::new("/usr/share/OVMF/OVMF.fd"),
            Path::new("/tmp/esp"),
            Path::new("/tmp/run/disk.img"),
            Path::new("/tmp/run/serial.log"),
        )
        .unwrap();
        assert!(args
            .iter()
            .any(|arg| arg.contains("id=syzdisk,cache=writeback")));
        assert!(args.windows(2).any(|pair| pair == ["-nic", "none"]));
        assert!(args.iter().any(|arg| arg == "virtio-blk-pci,drive=syzdisk"));
        assert!(!args.iter().any(|arg| arg.contains("virtio-serial")));
        assert!(args
            .iter()
            .any(|arg| arg == "format=raw,file=fat:/tmp/esp,snapshot=on"));
        assert!(!args.iter().any(|arg| arg == "-snapshot"));
        assert!(!args
            .iter()
            .any(|arg| arg.contains("id=syzdisk") && arg.contains("snapshot")));
    }

    #[test]
    fn bounded_diagnostic_reader_only_retains_the_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("stderr.log");
        std::fs::write(&path, b"0123456789abcdef").unwrap();
        assert_eq!(read_bounded_text(&path, 5), "bcdef");
        assert_eq!(read_bounded_text(&path, 0), "");
    }
}
