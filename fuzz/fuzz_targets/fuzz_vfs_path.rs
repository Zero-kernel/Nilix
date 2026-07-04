#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Fuzz input for the VFS path helpers.
#[derive(Arbitrary, Debug)]
struct VfsPathFuzzInput {
    /// Primary path string fed to the real normalizer/splitter.
    path: String,
    /// A second path (e.g. a rename destination) for extra coverage.
    second: String,
}

// Drives the REAL kernel VFS path helpers in `kernel/vfs` — `normalize_path`
// (the R32-VFS-1 `..`-escape guard used before every open/stat/mount) and
// `split_path` (parent/basename). These run on user-supplied path strings BEFORE
// any mount-table or inode state is touched, so they are pure and host-safe. The
// goal is to prove no path string can panic them (index-out-of-range on multibyte
// UTF-8 boundaries, empty components, all-slashes, etc.). A crash is a real
// finding; a returned Err (PermDenied/Invalid) is correct behaviour.
fuzz_target!(|input: VfsPathFuzzInput| {
    let _ = vfs::normalize_path(&input.path);
    let _ = vfs::split_path(&input.path);
    let _ = vfs::normalize_path(&input.second);
    let _ = vfs::split_path(&input.second);
});
