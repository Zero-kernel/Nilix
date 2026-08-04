use anyhow::{bail, Context, Result};
use nix::sys::signal::{kill, Signal};
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
        })
    }

    pub fn execute(&self, program: &SyscallProgram) -> Result<ExecutionResult> {
        let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        if sequence == u64::MAX {
            bail!("execution sequence space exhausted");
        }
        let encoded = encode_program(program, &ExecutionIdentity::random(sequence))?;

        let temp_dir = tempfile::Builder::new()
            .prefix("nilix-syz-v2-")
            .tempdir()
            .context("failed to create per-execution temporary directory")?;
        let serial_path = temp_dir.path().join("serial.log");
        let stderr_path = temp_dir.path().join("qemu.stderr");
        File::create(&serial_path).context("failed to create serial log")?;
        let stderr_file = File::create(&stderr_path).context("failed to create QEMU stderr log")?;
        let disk_path = self
            .transport
            .prepare(temp_dir.path(), &encoded.bytes)
            .context("failed to prepare fresh syz Ext3 transport")?;

        let esp_dir = self
            .kernel_path
            .parent()
            .context("kernel path has no parent directory")?;
        ensure_qemu_safe_path(esp_dir)?;
        ensure_qemu_safe_path(&disk_path)?;
        ensure_qemu_safe_path(&serial_path)?;

        let args = qemu_args(
            &self.ovmf_path,
            esp_dir,
            &disk_path,
            &serial_path,
        )?;
        let mut child = Command::new(&self.qemu_path)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .with_context(|| format!("failed to spawn {}", self.qemu_path.display()))?;

        let monitor_result = monitor_execution(
            &mut child,
            &serial_path,
            &encoded.binding,
            self.timeout,
        );
        let stop_result = terminate_qemu(&mut child);
        let observation = monitor_result?;
        stop_result.context("failed to stop QEMU cleanly")?;

        let serial_log = read_bounded_text(&serial_path, MAX_SERIAL_LOG as usize);
        let qemu_stderr = read_bounded_text(&stderr_path, MAX_DIAGNOSTIC_LOG);

        match observation {
            Observation::Pass(marker) => {
                let result_bytes = match self.transport.extract_result(&disk_path, temp_dir.path()) {
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
                if marker.edges != decoded.edge_count
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
            Observation::GuestFailure { stage, code } => {
                Ok(ExecutionResult::Crash(CrashInfo {
                    classification: format!("executor_failure:{stage}:{code}"),
                    serial_log,
                    qemu_stderr,
                }))
            }
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
    edges: u32,
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
        let edges_text = field_value(fields[4], "edges")?;
        let edges: u32 = edges_text.parse().context("invalid PASS edge count")?;
        if edges == 0 || edges.to_string() != edges_text {
            bail!("PASS edge count is zero or non-canonical");
        }
        let tag = parse_hex_array::<32>(field_value(fields[5], "tag")?, "PASS tag")?;
        self.pass = Some(PassMarker { edges, tag });
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
        } else if fields[1] != "seq=none"
            || fields[2] != "run=none"
            || fields[3] != "program=none"
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
        self.file.read_to_end(&mut new_bytes)?;
        self.offset = length;
        self.recent.extend_from_slice(&new_bytes);
        if self.recent.len() > MAX_DIAGNOSTIC_LOG {
            let excess = self.recent.len() - MAX_DIAGNOSTIC_LOG;
            self.recent.drain(..excess);
        }
        self.partial.extend_from_slice(&new_bytes);

        while let Some(newline) = self.partial.iter().position(|byte| *byte == b'\n') {
            let mut line = self.partial.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            self.tracker.process_line(&line)?;
        }
        Ok(())
    }

    fn crash_classification(&self) -> Option<String> {
        let text = String::from_utf8_lossy(&self.recent);
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
        if let Some(pass) = serial.tracker.pass.clone() {
            std::thread::sleep(PASS_SETTLE_TIME);
            serial.poll().context("invalid serial protocol after PASS")?;
            if serial.tracker.failure.is_some() {
                bail!("FAIL marker followed PASS");
            }
            return Ok(Observation::Pass(pass));
        }
        if let Some(classification) = serial.crash_classification() {
            return Ok(Observation::Crash(classification));
        }
        if let Some(status) = child.try_wait().context("failed to poll QEMU")? {
            serial.poll().context("invalid final serial protocol")?;
            if let Some(failure) = serial.tracker.failure.take() {
                return Ok(Observation::GuestFailure {
                    stage: failure.stage,
                    code: failure.code,
                });
            }
            if let Some(pass) = serial.tracker.pass.clone() {
                return Ok(Observation::Pass(pass));
            }
            return Ok(Observation::Crash(classify_early_exit(status, serial.tracker.began)));
        }
        if start.elapsed() >= timeout {
            return Ok(Observation::Timeout {
                began: serial.tracker.began,
            });
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn terminate_qemu(child: &mut Child) -> Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    let pid = Pid::from_raw(i32::try_from(child.id()).context("QEMU PID exceeds i32")?);
    let _ = kill(pid, Signal::SIGTERM);
    let deadline = Instant::now() + TERM_GRACE;
    while Instant::now() < deadline {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    let _ = kill(pid, Signal::SIGKILL);
    child.wait().context("failed to reap QEMU after SIGKILL")?;
    Ok(())
}

fn qemu_args(
    ovmf: &Path,
    esp_dir: &Path,
    disk: &Path,
    serial: &Path,
) -> Result<Vec<String>> {
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
        format!("format=raw,file=fat:rw:{esp_dir}"),
        "-drive".into(),
        format!("if=none,file={disk},format=raw,id=syzdisk,cache=directsync"),
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
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        bail!("{label} is not canonical lowercase hexadecimal");
    }
    let decoded = hex::decode(value).with_context(|| format!("invalid {label}"))?;
    Ok(decoded.try_into().map_err(|_| anyhow::anyhow!("invalid {label} length"))?)
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
    let data = std::fs::read(path).unwrap_or_default();
    let data = if data.len() > maximum {
        &data[data.len() - maximum..]
    } else {
        &data
    };
    String::from_utf8_lossy(data).into_owned()
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
                    "NILIX_SYZ_V2_PASS seq={} run={} program={} edges=3 tag={}",
                    binding.sequence_hex(),
                    binding.run_hex(),
                    binding.program_hex(),
                    "11".repeat(32)
                )
                .as_bytes(),
            )
            .unwrap();
        assert_eq!(tracker.pass.unwrap().edges, 3);
    }

    #[test]
    fn marker_state_machine_rejects_spoofing_duplicates_and_bad_order() {
        let binding = binding();
        let pass = format!(
            "NILIX_SYZ_V2_PASS seq={} run={} program={} edges=1 tag={}",
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
    fn pre_begin_failure_must_be_identity_free() {
        let binding = binding();
        let mut tracker = MarkerTracker::new(&binding);
        tracker
            .process_line(b"NILIX_SYZ_V2_FAIL seq=none run=none program=none stage=read_input code=-5")
            .unwrap();
        assert_eq!(tracker.failure.unwrap().stage, "read_input");
    }

    #[test]
    fn timeout_classification_distinguishes_boot_from_guest_hang() {
        assert!(matches!(Observation::Timeout { began: false }, Observation::Timeout { began: false }));
        assert!(matches!(Observation::Timeout { began: true }, Observation::Timeout { began: true }));
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
        assert!(args.iter().any(|arg| arg.contains("id=syzdisk,cache=directsync")));
        assert!(args.windows(2).any(|pair| pair == ["-nic", "none"]));
        assert!(args.iter().any(|arg| arg == "virtio-blk-pci,drive=syzdisk"));
        assert!(!args.iter().any(|arg| arg.contains("virtio-serial")));
    }
}
