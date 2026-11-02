//! Offline EXT2-MUT oracle for disposable mke2fs images. Run on the validation
//! machine with --features host_harness, then independently inspect output with
//! e2fsck. The input is never modified; only the explicit output path is written.
use block::{Bio, BlockDevice, BlockError, DurabilityGuarantee};
use std::sync::{Arc, Mutex};
use vfs::{Ext2Fs, FileMode, FileSystem, FsError, Inode};

struct State {
    live: Vec<u8>,
    durable: Vec<u8>,
    operations: u64,
    fail_at: u64,
    failed: bool,
    persist: bool,
}
struct Device(Mutex<State>);
impl Device {
    fn new(image: Vec<u8>, fail_at: u64, persist: bool) -> Self {
        Self(Mutex::new(State {
            live: image.clone(),
            durable: image,
            operations: 0,
            fail_at,
            failed: false,
            persist,
        }))
    }
    fn begin(state: &mut State) -> Result<(), BlockError> {
        if state.failed {
            return Err(BlockError::Io);
        }
        state.operations += 1;
        if state.operations == state.fail_at {
            if state.persist {
                state.durable.copy_from_slice(&state.live);
            }
            state.failed = true;
            return Err(BlockError::Io);
        }
        Ok(())
    }
}
impl BlockDevice for Device {
    fn name(&self) -> &str {
        "ext2-mut-offline"
    }
    fn capacity_sectors(&self) -> u64 {
        self.0.lock().unwrap().live.len() as u64 / 512
    }
    fn submit_bio(&self, _: Bio) -> Result<(), BlockError> {
        Err(BlockError::NotSupported)
    }
    fn read_sync(&self, sector: u64, bytes: &mut [u8]) -> Result<usize, BlockError> {
        let start = usize::try_from(sector)
            .ok()
            .and_then(|v| v.checked_mul(512))
            .ok_or(BlockError::Invalid)?;
        let state = self.0.lock().unwrap();
        bytes.copy_from_slice(
            state
                .live
                .get(start..start.checked_add(bytes.len()).ok_or(BlockError::Invalid)?)
                .ok_or(BlockError::Invalid)?,
        );
        Ok(bytes.len())
    }
    fn write_sync(&self, sector: u64, bytes: &[u8]) -> Result<usize, BlockError> {
        let start = usize::try_from(sector)
            .ok()
            .and_then(|v| v.checked_mul(512))
            .ok_or(BlockError::Invalid)?;
        let mut state = self.0.lock().unwrap();
        Self::begin(&mut state)?;
        state
            .live
            .get_mut(start..start.checked_add(bytes.len()).ok_or(BlockError::Invalid)?)
            .ok_or(BlockError::Invalid)?
            .copy_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&self) -> Result<(), BlockError> {
        let mut state = self.0.lock().unwrap();
        Self::begin(&mut state)?;
        let State { live, durable, .. } = &mut *state;
        durable.copy_from_slice(live);
        Ok(())
    }
    fn durability(&self) -> DurabilityGuarantee {
        DurabilityGuarantee::FlushBarrier
    }
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert!(
        args.len() >= 4,
        "INPUT OUTPUT exercise|mkdir|symlink|unlink|indirect|recover [FAIL_AT] [PERSIST]"
    );
    mm::publish_heap_budgets();
    let prepare = args[3].starts_with("prepare-");
    let scenario = args[3]
        .strip_prefix("prepare-")
        .unwrap_or(&args[3])
        .to_string();
    let prepared = args.get(6).is_some_and(|s| s == "prepared");
    let fail_at: u64 = args.get(4).map_or(0, |s| s.parse().unwrap());
    let persist = args.get(5).is_some_and(|s| s == "1");
    let device = Arc::new(Device::new(
        std::fs::read(&args[1]).unwrap(),
        if scenario == "recover" { fail_at } else { 0 },
        persist,
    ));
    let fs = match Ext2Fs::mount(device.clone()) {
        Ok(fs) => fs,
        Err(error) if scenario == "reject" => {
            let state = device.0.lock().unwrap();
            assert_eq!(state.operations, 0, "invalid log performed recovery I/O");
            std::fs::write(&args[2], &state.durable).unwrap();
            println!("REJECTED={error:?} OPERATIONS=0");
            return;
        }
        Err(error) if scenario == "recover" && fail_at != 0 => {
            std::fs::write(&args[2], &device.0.lock().unwrap().durable).unwrap();
            println!("RECOVERY_INTERRUPTED {error:?}");
            return;
        }
        Err(error) => panic!("mount: {error:?}"),
    };
    assert_ne!(scenario, "reject", "invalid log was accepted");
    let manager = vfs::manager::Vfs::new();
    manager
        .mount_in_namespace(&kernel_core::ROOT_MNT_NAMESPACE, "/", fs.clone())
        .unwrap();
    let setup_file: Option<Arc<dyn Inode>> = if matches!(
        scenario.as_str(),
        "unlink"
            | "indirect"
            | "truncate"
            | "double"
            | "triple"
            | "triple-carry"
            | "size-bounds"
            | "deep-truncate"
            | "deep-unlink"
    ) {
        let file = if prepared {
            fs.lookup(&fs.root_inode(), "mutation").unwrap()
        } else {
            manager
                .create_trusted("/mutation", FileMode::regular(0o600))
                .unwrap()
        };
        if scenario == "unlink" && !prepared {
            file.write_at(0, &[0x69; 8192]).unwrap();
        }
        if scenario == "truncate" && !prepared {
            file.write_at(12 * u64::from(file.stat().unwrap().blksize), b"indirect")
                .unwrap();
        }
        if !prepared && matches!(scenario.as_str(), "deep-truncate" | "deep-unlink") {
            let b = u64::from(file.stat().unwrap().blksize);
            let p = b / 4;
            for logical in [11, 12, 12 + p, 12 + p + p * p, 12 + p + p * p + p + 1] {
                file.write_at(logical * b + 17, b"deep payload").unwrap();
            }
        }
        Some(file)
    } else {
        None
    };
    let last_path = format!("/mutation/ffff{}", "n".repeat(251));
    if !prepared
        && matches!(
            scenario.as_str(),
            "directory" | "directory-rename" | "directory-unlink" | "directory-rmdir"
        )
    {
        let dir = manager
            .create_trusted("/mutation", FileMode::directory(0o700))
            .unwrap();
        let b = dir.stat().unwrap().blksize as usize;
        for index in 0..12 * (b / 264) {
            manager
                .create_trusted(
                    &format!("/mutation/{index:04}{}", "n".repeat(251)),
                    FileMode::regular(0o600),
                )
                .unwrap();
        }
        assert_eq!(dir.stat().unwrap().size, 12 * b as u64);
        if scenario != "directory" {
            manager
                .create_trusted(&last_path, FileMode::regular(0o600))
                .unwrap();
        }
        if scenario == "directory-rmdir" {
            for index in 0..12 * (b / 264) {
                manager
                    .unlink_trusted(
                        &format!("/mutation/{index:04}{}", "n".repeat(251)),
                        Some(false),
                    )
                    .unwrap();
            }
            manager.unlink_trusted(&last_path, Some(false)).unwrap();
        }
    }
    if prepare {
        std::fs::write(&args[2], &device.0.lock().unwrap().durable).unwrap();
        println!("PREPARED={scenario}");
        return;
    }
    if scenario != "recover" {
        let mut state = device.0.lock().unwrap();
        state.fail_at = if fail_at == 0 {
            0
        } else {
            state.operations + fail_at
        };
    }
    let mutation_start = device.0.lock().unwrap().operations;
    let long_target =
        "./".repeat(((fs.root_inode().stat().unwrap().blksize as usize - 1) / 2).min(700));
    let operation = match scenario.as_str() {
        "create" => manager
            .create_trusted("/mutation", FileMode::regular(0o600))
            .map(|_| ()),
        "mkdir" => manager
            .create_trusted("/mutation", FileMode::directory(0o750))
            .map(|_| ()),
        "symlink" => manager.symlink_trusted("/mutation", &long_target),
        "unlink" => {
            let result = manager.unlink_trusted("/mutation", Some(false));
            drop(setup_file);
            result
        }
        "indirect" => {
            let file = setup_file.unwrap();
            let block_size = file.stat().unwrap().blksize;
            file.write_at(12 * u64::from(block_size), b"indirect")
                .map(|_| ())
        }
        "double" | "triple" | "triple-carry" => {
            let file = setup_file.unwrap();
            let b = u64::from(file.stat().unwrap().blksize);
            let p = b / 4;
            let logical = 12
                + p
                + match scenario.as_str() {
                    "triple" => p * p,
                    "triple-carry" => 2 * p * p + p + 1,
                    _ => 0,
                };
            file.write_at(logical * b + 17, b"deep payload").map(|_| ())
        }
        "size-bounds" => {
            let file = setup_file.unwrap();
            let b = u64::from(file.stat().unwrap().blksize);
            let p = b / 4;
            let maximum = (12 + p + p * p + p * p * p).min(u64::from(u32::MAX) + 1) * b;
            let before = device.0.lock().unwrap().operations;
            assert!(file.write_at(maximum, b"x").is_err());
            assert!(file.write_at(u64::MAX, b"x").is_err());
            assert!(file.truncate(maximum + 1).is_err());
            assert_eq!(device.0.lock().unwrap().operations, before);
            assert_eq!(file.stat().unwrap().size, 0);
            Ok(())
        }
        "deep-truncate" => setup_file.unwrap().truncate(0),
        "deep-unlink" => {
            let result = manager.unlink_trusted("/mutation", Some(false));
            drop(setup_file);
            result
        }
        "directory" => manager
            .create_trusted(&last_path, FileMode::regular(0o600))
            .map(|_| ()),
        "directory-rename" => manager.rename_trusted(
            &last_path,
            &format!("/mutation/eeee{}", "n".repeat(251)),
            true,
        ),
        "directory-unlink" => manager.unlink_trusted(&last_path, Some(false)),
        "directory-rmdir" => manager.unlink_trusted("/mutation", Some(true)),
        "symlink-bounds" => {
            let maximum = fs.root_inode().stat().unwrap().blksize as usize - 1;
            for length in [59, 60, 61, maximum] {
                manager
                    .symlink_trusted(&format!("/link-{length}"), &"x".repeat(length))
                    .unwrap();
            }
            assert_eq!(
                manager.symlink_trusted("/too-long", &"x".repeat(maximum + 1)),
                Err(FsError::NameTooLong)
            );
            Ok(())
        }
        "truncate" => setup_file.unwrap().truncate(0),
        "recover" => Ok(()),
        "exercise" => {
            if manager.stat_trusted("/fixture.bin").is_ok() {
                manager.unlink_trusted("/fixture.bin", Some(false)).unwrap();
            }
            for _ in 0..32 {
                let directory = manager
                    .create_trusted("/mutation", FileMode::directory(0o750))
                    .unwrap();
                let file = manager
                    .create_trusted("/mutation/file", FileMode::regular(0o600))
                    .unwrap();
                file.write_at(12 * 4096, b"indirect").unwrap();
                file.truncate(5000).unwrap();
                file.truncate(65536).unwrap();
                manager.symlink_trusted("/mutation/short", "file").unwrap();
                manager
                    .symlink_trusted("/mutation/long", &long_target)
                    .unwrap();
                assert_eq!(
                    manager.unlink_trusted("/mutation", Some(true)),
                    Err(FsError::NotEmpty)
                );
                manager
                    .unlink_trusted("/mutation/file", Some(false))
                    .unwrap();
                assert_eq!(file.stat().unwrap().nlink, 0);
                file.write_at(0, b"open orphan").unwrap();
                drop(file);
                manager
                    .unlink_trusted("/mutation/short", Some(false))
                    .unwrap();
                manager
                    .unlink_trusted("/mutation/long", Some(false))
                    .unwrap();
                manager.unlink_trusted("/mutation", Some(true)).unwrap();
                drop(directory);
            }
            // Keep normal files and links for independent debugfs inspection.
            manager
                .create_trusted("/verified", FileMode::directory(0o755))
                .unwrap();
            manager
                .symlink_trusted("/verified/short", "target")
                .unwrap();
            manager
                .symlink_trusted("/verified/long", &long_target)
                .unwrap();
            Ok(())
        }
        _ => panic!("unknown scenario"),
    };
    if fail_at == 0 {
        operation.unwrap();
        fs.sync().unwrap();
    }
    if !device.0.lock().unwrap().failed {
        if let Ok(stat) = manager.stat_trusted("/mutation") {
            println!(
                "VISIBLE size={} blocks={} nlink={}",
                stat.size, stat.blocks, stat.nlink
            );
        }
    }
    let state = device.0.lock().unwrap();
    std::fs::write(&args[2], &state.durable).unwrap();
    println!(
        "SCENARIO={scenario} OPERATIONS={} MUTATION_OPERATIONS={} FAILED={}",
        state.operations,
        state.operations - mutation_start,
        state.failed
    );
}
