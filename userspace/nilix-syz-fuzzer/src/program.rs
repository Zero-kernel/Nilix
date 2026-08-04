use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub const MAX_SYSCALLS: usize = 100;
pub const MAX_ARGS: usize = 6;
pub const MAX_BUFFER_CAPACITY: usize = 4096;
pub const MAX_ARENA_CAPACITY: usize = 128 * 1024;

pub const SYS_STAT: u32 = 4;
pub const SYS_LSTAT: u32 = 6;
pub const SYS_BRK: u32 = 12;
pub const SYS_ACCESS: u32 = 21;
pub const SYS_SCHED_YIELD: u32 = 24;
pub const SYS_GETPID: u32 = 39;
pub const SYS_UNAME: u32 = 63;
pub const SYS_GETCWD: u32 = 79;
pub const SYS_GETTIMEOFDAY: u32 = 96;
pub const SYS_GETRLIMIT: u32 = 97;
pub const SYS_GETUID: u32 = 102;
pub const SYS_GETGID: u32 = 104;
pub const SYS_GETEUID: u32 = 107;
pub const SYS_GETEGID: u32 = 108;
pub const SYS_GETPPID: u32 = 110;
pub const SYS_GETTID: u32 = 186;
pub const SYS_SCHED_GETAFFINITY: u32 = 204;
pub const SYS_CLOCK_GETTIME: u32 = 228;
pub const SYS_GETRANDOM: u32 = 318;

const PURE_NOARG_SYSCALLS: &[u32] = &[
    SYS_SCHED_YIELD,
    SYS_GETPID,
    SYS_GETUID,
    SYS_GETGID,
    SYS_GETEUID,
    SYS_GETEGID,
    SYS_GETPPID,
    SYS_GETTID,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyscallProgram {
    pub syscalls: Vec<Syscall>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Syscall {
    pub number: u32,
    pub args: Vec<Argument>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Argument {
    Immediate(u64),
    /// Read-only bytes copied into the guest executor's isolated argument arena.
    Buffer(Vec<u8>),
    /// A zero-filled writable buffer.
    Output { capacity: u32 },
    /// Initial bytes followed by a zero-filled writable tail.
    InOut { data: Vec<u8>, capacity: u32 },
    Null,
}

impl SyscallProgram {
    pub fn new() -> Self {
        Self { syscalls: Vec::new() }
    }

    pub fn add_syscall(&mut self, syscall: Syscall) -> Result<()> {
        if self.syscalls.len() >= MAX_SYSCALLS {
            bail!("program exceeds the {MAX_SYSCALLS}-syscall limit");
        }
        validate_syscall(&syscall)?;
        self.syscalls.push(syscall);
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.syscalls.is_empty() {
            bail!("program must contain at least one syscall");
        }
        if self.syscalls.len() > MAX_SYSCALLS {
            bail!("program exceeds the {MAX_SYSCALLS}-syscall limit");
        }

        let mut arena_capacity = 0usize;
        for syscall in &self.syscalls {
            validate_syscall(syscall)?;
            for arg in &syscall.args {
                arena_capacity = arena_capacity
                    .checked_add(arg.capacity())
                    .context("argument arena capacity overflow")?;
            }
        }
        if arena_capacity > MAX_ARENA_CAPACITY {
            bail!(
                "program argument arena exceeds {MAX_ARENA_CAPACITY} bytes: {arena_capacity}"
            );
        }
        Ok(())
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).context("failed to serialize program JSON")
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let data = self.canonical_json()?;
        let parent = path.parent().context("program path has no parent")?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)
            .context("failed to create temporary program file")?;
        temp.write_all(&data)
            .context("failed to write temporary program file")?;
        temp.as_file()
            .sync_all()
            .context("failed to sync temporary program file")?;
        temp.persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("failed to publish {}", path.display()))?;
        sync_directory(parent)?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let program: Self = serde_json::from_slice(&data)
            .with_context(|| format!("invalid program JSON in {}", path.display()))?;
        program.validate()?;
        Ok(program)
    }

    pub fn to_json(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).context("failed to serialize program JSON")
    }
}

impl Argument {
    pub fn capacity(&self) -> usize {
        match self {
            Self::Immediate(_) | Self::Null => 0,
            Self::Buffer(data) => data.len(),
            Self::Output { capacity } | Self::InOut { capacity, .. } => *capacity as usize,
        }
    }

    pub fn writable_capacity(&self) -> Option<usize> {
        match self {
            Self::Output { capacity } | Self::InOut { capacity, .. } => {
                Some(*capacity as usize)
            }
            _ => None,
        }
    }
}

pub fn validate_syscall(syscall: &Syscall) -> Result<()> {
    if syscall.args.len() > MAX_ARGS {
        bail!("syscall {} has more than {MAX_ARGS} arguments", syscall.number);
    }
    for arg in &syscall.args {
        validate_argument(arg)?;
    }

    if PURE_NOARG_SYSCALLS.contains(&syscall.number) {
        expect_arg_count(syscall, 0)?;
        return Ok(());
    }

    match syscall.number {
        SYS_BRK => {
            expect_arg_count(syscall, 1)?;
            expect_immediate(&syscall.args[0], 0, 0, "brk address")?;
        }
        SYS_ACCESS => {
            expect_arg_count(syscall, 2)?;
            expect_path(&syscall.args[0])?;
            expect_immediate(&syscall.args[1], 0, 7, "access mode")?;
        }
        SYS_STAT | SYS_LSTAT => {
            expect_arg_count(syscall, 2)?;
            expect_path(&syscall.args[0])?;
            expect_writable(&syscall.args[1], 144, "stat output")?;
        }
        SYS_UNAME => {
            expect_arg_count(syscall, 1)?;
            expect_writable(&syscall.args[0], 390, "uname output")?;
        }
        SYS_GETTIMEOFDAY => {
            expect_arg_count(syscall, 2)?;
            expect_writable(&syscall.args[0], 16, "gettimeofday output")?;
            expect_null(&syscall.args[1], "gettimeofday timezone")?;
        }
        SYS_GETRLIMIT => {
            expect_arg_count(syscall, 2)?;
            expect_immediate(&syscall.args[0], 0, 15, "resource limit selector")?;
            expect_writable(&syscall.args[1], 16, "getrlimit output")?;
        }
        SYS_GETCWD => {
            expect_arg_count(syscall, 2)?;
            let capacity = expect_output(&syscall.args[0], 1, "getcwd output")?;
            expect_length(&syscall.args[1], capacity, "getcwd length")?;
        }
        SYS_READLINK => {
            expect_arg_count(syscall, 3)?;
            expect_path(&syscall.args[0])?;
            let capacity = expect_output(&syscall.args[1], 1, "readlink output")?;
            expect_length(&syscall.args[2], capacity, "readlink length")?;
        }
        SYS_SCHED_GETAFFINITY => {
            expect_arg_count(syscall, 3)?;
            expect_immediate(&syscall.args[0], 0, 0, "sched_getaffinity pid")?;
            let capacity = expect_output(&syscall.args[2], 1, "affinity output")?;
            expect_length(&syscall.args[1], capacity, "affinity length")?;
        }
        SYS_CLOCK_GETTIME => {
            expect_arg_count(syscall, 2)?;
            let clock = immediate_value(&syscall.args[0], "clock id")?;
            if !matches!(clock, 0 | 1 | 4 | 5 | 6 | 7) {
                bail!("clock_gettime clock id {clock} is not allowlisted");
            }
            expect_writable(&syscall.args[1], 16, "clock_gettime output")?;
        }
        SYS_GETRANDOM => {
            expect_arg_count(syscall, 3)?;
            let capacity = match &syscall.args[0] {
                Argument::Output { capacity } => *capacity as usize,
                _ => bail!("getrandom requires a zero-filled output buffer"),
            };
            if capacity == 0 || capacity > MAX_BUFFER_CAPACITY {
                bail!("invalid getrandom buffer capacity {capacity}");
            }
            expect_length(&syscall.args[1], capacity, "getrandom length")?;
            expect_immediate(&syscall.args[2], 1, 1, "getrandom flags")?;
        }
        number => bail!("syscall {number} is not in the non-destructive allowlist"),
    }
    Ok(())
}

fn validate_argument(arg: &Argument) -> Result<()> {
    match arg {
        Argument::Immediate(_) | Argument::Null => Ok(()),
        Argument::Buffer(data) => {
            if data.is_empty() || data.len() > MAX_BUFFER_CAPACITY {
                bail!("input buffer length must be 1..={MAX_BUFFER_CAPACITY}");
            }
            Ok(())
        }
        Argument::Output { capacity } => validate_capacity(*capacity, 0),
        Argument::InOut { data, capacity } => {
            validate_capacity(*capacity, data.len())?;
            if data.is_empty() {
                bail!("in/out buffers must contain at least one initialized byte");
            }
            Ok(())
        }
    }
}

fn validate_capacity(capacity: u32, data_len: usize) -> Result<()> {
    let capacity = capacity as usize;
    if capacity == 0 || capacity > MAX_BUFFER_CAPACITY {
        bail!("buffer capacity must be 1..={MAX_BUFFER_CAPACITY}");
    }
    if data_len > capacity {
        bail!("initialized buffer length {data_len} exceeds capacity {capacity}");
    }
    Ok(())
}

fn expect_arg_count(syscall: &Syscall, expected: usize) -> Result<()> {
    if syscall.args.len() != expected {
        bail!(
            "syscall {} requires {expected} arguments, got {}",
            syscall.number,
            syscall.args.len()
        );
    }
    Ok(())
}

fn immediate_value(arg: &Argument, label: &str) -> Result<u64> {
    match arg {
        Argument::Immediate(value) => Ok(*value),
        _ => bail!("{label} must be an immediate value"),
    }
}

fn expect_immediate(arg: &Argument, min: u64, max: u64, label: &str) -> Result<u64> {
    let value = immediate_value(arg, label)?;
    if !(min..=max).contains(&value) {
        bail!("{label} {value} is outside {min}..={max}");
    }
    Ok(value)
}

fn expect_length(arg: &Argument, capacity: usize, label: &str) -> Result<usize> {
    let value = immediate_value(arg, label)?;
    let length = usize::try_from(value).context("length does not fit usize")?;
    if length == 0 || length > capacity {
        bail!("{label} {length} is outside 1..={capacity}");
    }
    Ok(length)
}

fn expect_null(arg: &Argument, label: &str) -> Result<()> {
    if !matches!(arg, Argument::Null) {
        bail!("{label} must be null");
    }
    Ok(())
}

fn expect_output(arg: &Argument, minimum: usize, label: &str) -> Result<usize> {
    let capacity = match arg {
        Argument::Output { capacity } => *capacity as usize,
        _ => bail!("{label} must be a zero-filled output buffer"),
    };
    if capacity < minimum {
        bail!("{label} capacity {capacity} is smaller than {minimum}");
    }
    Ok(capacity)
}

fn expect_writable(arg: &Argument, minimum: usize, label: &str) -> Result<usize> {
    let capacity = arg
        .writable_capacity()
        .with_context(|| format!("{label} must be writable"))?;
    if capacity < minimum {
        bail!("{label} capacity {capacity} is smaller than {minimum}");
    }
    Ok(capacity)
}

fn expect_path(arg: &Argument) -> Result<()> {
    let bytes = match arg {
        Argument::Buffer(bytes) => bytes,
        _ => bail!("path argument must be an input buffer"),
    };
    if bytes.len() < 2 || bytes.last() != Some(&0) {
        bail!("path must contain bytes followed by exactly one NUL terminator");
    }
    if bytes[..bytes.len() - 1].contains(&0) {
        bail!("path contains an embedded NUL byte");
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open directory {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))
}

impl Default for SyscallProgram {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_destructive_or_executor_control_syscalls() {
        for number in [1, 2, 3, 56, 57, 59, 60, 62, 520, 521, 522, 523, 524] {
            let syscall = Syscall { number, args: vec![] };
            assert!(validate_syscall(&syscall).is_err(), "syscall {number}");
        }
    }

    #[test]
    fn validates_getrandom_bounds_and_nonblocking_flag() {
        let valid = Syscall {
            number: SYS_GETRANDOM,
            args: vec![
                Argument::Output { capacity: 32 },
                Argument::Immediate(32),
                Argument::Immediate(1),
            ],
        };
        assert!(validate_syscall(&valid).is_ok());

        let mut invalid = valid.clone();
        invalid.args[1] = Argument::Immediate(33);
        assert!(validate_syscall(&invalid).is_err());
        invalid.args[1] = Argument::Immediate(32);
        invalid.args[2] = Argument::Immediate(0);
        assert!(validate_syscall(&invalid).is_err());
    }

    #[test]
    fn path_must_be_canonical_c_string() {
        let valid = Argument::Buffer(b"/mnt/test\0".to_vec());
        assert!(expect_path(&valid).is_ok());
        assert!(expect_path(&Argument::Buffer(b"/mnt/test".to_vec())).is_err());
        assert!(expect_path(&Argument::Buffer(b"/mnt\0/test\0".to_vec())).is_err());
    }
}
