use anyhow::{bail, Context, Result};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::protocol::{
    KCOV_BITMAP_SIZE, MAX_PROGRAM_SIZE, RESULT_HEADER_SIZE, RESULT_TAG_SIZE,
};
use crate::program::MAX_SYSCALLS;

const PROGRAM_GUEST_PATH: &str = "/test/syz-program.bin";
const RESULT_GUEST_PATH: &str = "/test/syz-result.bin";
/// Empty probe file the kernel's optional R180-6 JBD2 write self-test opens at
/// `/mnt/test/alloc.bin` (see kernel/src/integration_test.rs). The production
/// `ensure-ext3-image` Makefile fixture creates it; inject an empty copy here so
/// the fuzz disk satisfies the probe and the self-test exercises the real JBD2
/// allocation/commit path instead of skipping it.
const ALLOC_PROBE_GUEST_PATH: &str = "/test/alloc.bin";
const MIN_DISK_MIB: u64 = 16;
const MAX_DISK_MIB: u64 = 1024;
const MAX_RESULT_SIZE: usize =
    RESULT_HEADER_SIZE + MAX_SYSCALLS * 8 + KCOV_BITMAP_SIZE + RESULT_TAG_SIZE;

#[derive(Clone, Debug)]
pub struct Ext3Tools {
    pub mke2fs: PathBuf,
    pub debugfs: PathBuf,
    pub e2fsck: PathBuf,
}

impl Default for Ext3Tools {
    fn default() -> Self {
        Self {
            mke2fs: PathBuf::from("mke2fs"),
            debugfs: PathBuf::from("debugfs"),
            e2fsck: PathBuf::from("e2fsck"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Ext3Transport {
    tools: Ext3Tools,
    disk_mib: u64,
}

impl Ext3Transport {
    pub fn new(tools: Ext3Tools, disk_mib: u64) -> Result<Self> {
        if !(MIN_DISK_MIB..=MAX_DISK_MIB).contains(&disk_mib) {
            bail!("disk size must be {MIN_DISK_MIB}..={MAX_DISK_MIB} MiB");
        }
        Ok(Self { tools, disk_mib })
    }

    pub fn prepare(&self, work_dir: &Path, program: &[u8]) -> Result<PathBuf> {
        if program.is_empty() || program.len() > MAX_PROGRAM_SIZE {
            bail!("program file size is outside the strict transport bound");
        }
        ensure_debugfs_safe_path(work_dir)?;

        let disk_path = work_dir.join("syz-disk.img");
        let program_path = work_dir.join("syz-program.host.bin");
        let verify_path = work_dir.join("syz-program.verify.bin");
        let alloc_path = work_dir.join("syz-alloc-probe.host.bin");
        ensure_debugfs_safe_path(&disk_path)?;
        ensure_debugfs_safe_path(&program_path)?;
        ensure_debugfs_safe_path(&verify_path)?;
        ensure_debugfs_safe_path(&alloc_path)?;

        let disk = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&disk_path)
            .with_context(|| format!("failed to create {}", disk_path.display()))?;
        disk.set_len(self.disk_mib * 1024 * 1024)
            .context("failed to size fresh Ext3 image")?;
        disk.sync_all().context("failed to sync fresh image file")?;

        write_new_file(&program_path, program)?;
        // Empty probe file for the kernel's R180-6 JBD2 write self-test.
        write_new_file(&alloc_path, &[])?;

        run_checked(
            &self.tools.mke2fs,
            &mke2fs_args(&disk_path),
            "create fresh Ext3 image",
        )?;
        run_checked(
            &self.tools.debugfs,
            &debugfs_args(&disk_path, true, "mkdir /test"),
            "create /test in Ext3 image",
        )?;
        let inject = format!(
            "write {} {PROGRAM_GUEST_PATH}",
            utf8_path(&program_path)?
        );
        run_checked(
            &self.tools.debugfs,
            &debugfs_args(&disk_path, true, &inject),
            "inject syz program into Ext3 image",
        )?;
        let inject_alloc = format!(
            "write {} {ALLOC_PROBE_GUEST_PATH}",
            utf8_path(&alloc_path)?
        );
        run_checked(
            &self.tools.debugfs,
            &debugfs_args(&disk_path, true, &inject_alloc),
            "inject R180-6 alloc probe into Ext3 image",
        )?;
        self.repair_image(&disk_path)?;

        let dump = format!(
            "dump -p {PROGRAM_GUEST_PATH} {}",
            utf8_path(&verify_path)?
        );
        run_checked(
            &self.tools.debugfs,
            &debugfs_args(&disk_path, false, &dump),
            "verify injected syz program",
        )?;
        let verified = std::fs::read(&verify_path).context("failed to read program verification dump")?;
        if verified != program {
            bail!("Ext3 program verification mismatch");
        }

        Ok(disk_path)
    }

    pub fn extract_result(&self, disk_path: &Path, work_dir: &Path) -> Result<Vec<u8>> {
        ensure_debugfs_safe_path(disk_path)?;
        ensure_debugfs_safe_path(work_dir)?;
        self.repair_image(disk_path)?;

        let output_path = work_dir.join("syz-result.host.bin");
        ensure_debugfs_safe_path(&output_path)?;
        let dump = format!(
            "dump -p {RESULT_GUEST_PATH} {}",
            utf8_path(&output_path)?
        );
        run_checked(
            &self.tools.debugfs,
            &debugfs_args(disk_path, false, &dump),
            "extract authenticated syz result",
        )?;

        let metadata = std::fs::metadata(&output_path)
            .context("debugfs did not create a result extraction file")?;
        if metadata.len() == 0 || metadata.len() > MAX_RESULT_SIZE as u64 {
            bail!(
                "result file length {} is outside 1..={MAX_RESULT_SIZE}",
                metadata.len()
            );
        }
        std::fs::read(&output_path).context("failed to read extracted syz result")
    }

    fn repair_image(&self, disk_path: &Path) -> Result<()> {
        let output = run(&self.tools.e2fsck, &e2fsck_args(disk_path), "check Ext3 image")?;
        match output.status.code() {
            Some(0 | 1) => Ok(()),
            code => bail!(
                "e2fsck failed with status {code:?}: {}",
                bounded_stderr(&output)
            ),
        }
    }
}

pub fn ensure_qemu_safe_path(path: &Path) -> Result<()> {
    let value = utf8_path(path)?;
    if value.contains(',') || value.chars().any(char::is_control) {
        bail!("QEMU drive path contains a comma or control character: {value:?}");
    }
    Ok(())
}

fn ensure_debugfs_safe_path(path: &Path) -> Result<()> {
    let value = utf8_path(path)?;
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')))
    {
        bail!("path is unsafe for debugfs command syntax: {value:?}");
    }
    Ok(())
}

fn utf8_path(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn write_new_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(data)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync {}", path.display()))
}

fn mke2fs_args(image: &Path) -> Vec<OsString> {
    ["-q", "-F", "-t", "ext3", "-b", "4096"]
        .into_iter()
        .map(OsString::from)
        .chain(std::iter::once(image.as_os_str().to_owned()))
        .collect()
}

fn debugfs_args(image: &Path, writable: bool, request: &str) -> Vec<OsString> {
    let mut args = Vec::with_capacity(4);
    if writable {
        args.push(OsString::from("-w"));
    }
    args.push(OsString::from("-R"));
    args.push(OsString::from(request));
    args.push(image.as_os_str().to_owned());
    args
}

fn e2fsck_args(image: &Path) -> Vec<OsString> {
    vec![OsString::from("-pf"), image.as_os_str().to_owned()]
}

fn run_checked(command: &Path, args: &[OsString], action: &str) -> Result<Output> {
    let output = run(command, args, action)?;
    if !output.status.success() {
        bail!(
            "failed to {action}; {} exited with {:?}: {}",
            command.display(),
            output.status.code(),
            bounded_stderr(&output)
        );
    }
    Ok(output)
}

fn run(command: &Path, args: &[OsString], action: &str) -> Result<Output> {
    Command::new(command)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {} to {action}", command.display()))
}

fn bounded_stderr(output: &Output) -> String {
    const MAX: usize = 4096;
    let slice = if output.stderr.len() > MAX {
        &output.stderr[output.stderr.len() - MAX..]
    } else {
        &output.stderr
    };
    String::from_utf8_lossy(slice).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_tool_arguments_are_explicit_and_scoped() {
        let image = Path::new("/tmp/nilix-syz/image.img");
        assert_eq!(
            mke2fs_args(image),
            vec!["-q", "-F", "-t", "ext3", "-b", "4096", image.to_str().unwrap()]
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            debugfs_args(image, true, "mkdir /test"),
            vec!["-w", "-R", "mkdir /test", image.to_str().unwrap()]
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            e2fsck_args(image),
            vec![OsString::from("-pf"), image.as_os_str().to_owned()]
        );
    }

    #[test]
    fn unsafe_tool_and_qemu_paths_are_rejected() {
        assert!(ensure_debugfs_safe_path(Path::new("/tmp/has space/image.img")).is_err());
        assert!(ensure_debugfs_safe_path(Path::new("/tmp/quote\"/image.img")).is_err());
        assert!(ensure_qemu_safe_path(Path::new("/tmp/comma,image.img")).is_err());
        assert!(ensure_qemu_safe_path(Path::new("/tmp/safe-image.img")).is_ok());
    }

    #[test]
    fn disk_size_is_strictly_bounded() {
        let tools = Ext3Tools::default();
        assert!(Ext3Transport::new(tools.clone(), MIN_DISK_MIB - 1).is_err());
        assert!(Ext3Transport::new(tools.clone(), MIN_DISK_MIB).is_ok());
        assert!(Ext3Transport::new(tools, MAX_DISK_MIB + 1).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_ext3_round_trip_when_e2fsprogs_is_available() {
        if !tool_available("mke2fs") || !tool_available("debugfs") || !tool_available("e2fsck") {
            return;
        }
        let temp = tempfile::Builder::new()
            .prefix("nilix-syz-test-")
            .tempdir_in("/tmp")
            .unwrap();
        let transport = Ext3Transport::new(Ext3Tools::default(), MIN_DISK_MIB).unwrap();
        let program = b"strict-test-program";
        let image = transport.prepare(temp.path(), program).unwrap();
        assert!(image.exists());
    }

    #[cfg(target_os = "linux")]
    fn tool_available(tool: &str) -> bool {
        Command::new(tool)
            .arg("-V")
            .output()
            .map(|output| output.status.success() || !output.stderr.is_empty())
            .unwrap_or(false)
    }
}
