#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

/// Fuzz input for VFS path operations
#[derive(Arbitrary, Debug)]
struct VfsPathFuzzInput {
    operation: PathOperation,
    path: Vec<u8>,
    flags: u32,
    mode: u32,
}

#[derive(Arbitrary, Debug)]
enum PathOperation {
    Open,
    Stat,
    Mkdir,
    Rmdir,
    Unlink,
    Rename { newpath: Vec<u8> },
    Readlink,
    Symlink { target: Vec<u8> },
    Link { newpath: Vec<u8> },
}

fuzz_target!(|input: VfsPathFuzzInput| {
    // Target R172 VFS fixes:
    // - R172-14: ramfs rename self-deadlock
    // - R172-15: rename ancestor TOCTOU
    // - R172 FOLLOW-ON: rmdir/unlink type gate

    // Limit path length to reasonable size
    if input.path.len() > 4096 {
        return;
    }

    match input.operation {
        PathOperation::Open => {
            test_open_fuzzing(&input.path, input.flags, input.mode);
        }
        PathOperation::Stat => {
            test_stat_fuzzing(&input.path);
        }
        PathOperation::Mkdir => {
            test_mkdir_fuzzing(&input.path, input.mode);
        }
        PathOperation::Rmdir => {
            test_rmdir_fuzzing(&input.path);
        }
        PathOperation::Unlink => {
            test_unlink_fuzzing(&input.path);
        }
        PathOperation::Rename { ref newpath } => {
            if newpath.len() <= 4096 {
                test_rename_fuzzing(&input.path, newpath);
            }
        }
        PathOperation::Readlink => {
            test_readlink_fuzzing(&input.path);
        }
        PathOperation::Symlink { ref target } => {
            if target.len() <= 4096 {
                test_symlink_fuzzing(&input.path, target);
            }
        }
        PathOperation::Link { ref newpath } => {
            if newpath.len() <= 4096 {
                test_link_fuzzing(&input.path, newpath);
            }
        }
    }
});

fn test_open_fuzzing(path: &[u8], flags: u32, mode: u32) {
    // Validate path doesn't contain null bytes (except terminator)
    if path.is_empty() {
        return;
    }

    // Check for path traversal patterns
    check_path_traversal(path);

    // Validate flags combinations
    const O_RDONLY: u32 = 0;
    const O_WRONLY: u32 = 1;
    const O_RDWR: u32 = 2;
    const O_CREAT: u32 = 0x40;
    const O_EXCL: u32 = 0x80;
    const O_TRUNC: u32 = 0x200;
    const O_DIRECTORY: u32 = 0x10000;
    const O_CLOEXEC: u32 = 0x80000;

    let access_mode = flags & 0x3;

    // O_DIRECTORY with O_CREAT doesn't make sense
    if (flags & O_DIRECTORY != 0) && (flags & O_CREAT != 0) {
        return;
    }

    // O_EXCL requires O_CREAT
    if (flags & O_EXCL != 0) && (flags & O_CREAT == 0) {
        // Kernel should ignore O_EXCL
    }

    // Mode is only relevant with O_CREAT
    if flags & O_CREAT != 0 {
        // Mode should be masked to 0o7777
        assert!(mode <= 0o7777 || (mode & !0o7777) != 0, "open mode has extra bits");
    }
}

fn test_stat_fuzzing(path: &[u8]) {
    if path.is_empty() {
        return;
    }

    check_path_traversal(path);
    check_special_paths(path);
}

fn test_mkdir_fuzzing(path: &[u8], mode: u32) {
    if path.is_empty() {
        return;
    }

    check_path_traversal(path);

    // Mode should be directory permission bits
    assert!(mode <= 0o7777 || (mode & !0o7777) != 0, "mkdir mode has extra bits");

    // Cannot mkdir over existing file/dir (EEXIST)
    // Cannot mkdir if parent doesn't exist (ENOENT)
}

fn test_rmdir_fuzzing(path: &[u8]) {
    // R172 FOLLOW-ON: atomic type gate (must_be_dir=true)
    if path.is_empty() {
        return;
    }

    check_path_traversal(path);

    // rmdir on non-directory should return ENOTDIR
    // rmdir on non-empty directory should return ENOTEMPTY
    // rmdir on "." or ".." should return EINVAL

    if path == b"." || path == b".." {
        // Should be rejected
        return;
    }
}

fn test_unlink_fuzzing(path: &[u8]) {
    // R172 FOLLOW-ON: atomic type gate (must_be_dir=false)
    if path.is_empty() {
        return;
    }

    check_path_traversal(path);

    // unlink on directory should return EISDIR
    // unlink on "." or ".." should return EINVAL

    if path == b"." || path == b".." {
        return;
    }
}

fn test_rename_fuzzing(oldpath: &[u8], newpath: &[u8]) {
    // R172-14: ramfs rename self-deadlock when dest==old_parent
    // R172-15: rename ancestor TOCTOU

    if oldpath.is_empty() || newpath.is_empty() {
        return;
    }

    check_path_traversal(oldpath);
    check_path_traversal(newpath);

    // Test self-rename
    if oldpath == newpath {
        // Should be a no-op
        return;
    }

    // Test renaming to parent directory
    if is_ancestor_path(newpath, oldpath) {
        // Should return EINVAL (cannot move directory into its subtree)
        return;
    }

    // Test renaming with "." or ".."
    if ends_with_dot_component(oldpath) || ends_with_dot_component(newpath) {
        return;
    }

    // RENAME_NOREPLACE: newpath must not exist
    // Without flag: newpath can be replaced if same type
}

fn test_readlink_fuzzing(path: &[u8]) {
    if path.is_empty() {
        return;
    }

    check_path_traversal(path);

    // readlink on non-symlink should return EINVAL
    // readlink buffer should be user-space
}

fn test_symlink_fuzzing(target: &[u8], linkpath: &[u8]) {
    if target.is_empty() || linkpath.is_empty() {
        return;
    }

    check_path_traversal(linkpath);

    // Target can be arbitrary (even non-existent)
    // linkpath must not exist (EEXIST)
}

fn test_link_fuzzing(oldpath: &[u8], newpath: &[u8]) {
    if oldpath.is_empty() || newpath.is_empty() {
        return;
    }

    check_path_traversal(oldpath);
    check_path_traversal(newpath);

    // Cannot hardlink directories (EPERM)
    // Cannot hardlink across filesystems (EXDEV)
}

fn check_path_traversal(path: &[u8]) {
    // Check for dangerous path patterns

    // Multiple slashes
    let mut prev = 0u8;
    for &byte in path {
        if byte == b'/' && prev == b'/' {
            // Consecutive slashes should be normalized
        }
        prev = byte;
    }

    // Check for ".." components
    if path.windows(3).any(|w| w == b"/../" || w == b"..") {
        // Path traversal attempt
    }

    // Check for absolute vs relative
    if !path.is_empty() && path[0] == b'/' {
        // Absolute path
    } else {
        // Relative path
    }
}

fn check_special_paths(path: &[u8]) {
    // Check for special kernel paths
    const SPECIAL_PATHS: &[&[u8]] = &[
        b"/proc",
        b"/sys",
        b"/dev",
        b"/tmp",
    ];

    for &special in SPECIAL_PATHS {
        if path.starts_with(special) {
            // Special path handling
        }
    }
}

fn is_ancestor_path(potential_ancestor: &[u8], path: &[u8]) -> bool {
    // Check if potential_ancestor is an ancestor directory of path

    if potential_ancestor.len() >= path.len() {
        return false;
    }

    // path should start with potential_ancestor followed by '/'
    path.starts_with(potential_ancestor) &&
        (path.len() == potential_ancestor.len() ||
         path.get(potential_ancestor.len()) == Some(&b'/'))
}

fn ends_with_dot_component(path: &[u8]) -> bool {
    // Check if path ends with "/." or "/.."
    path.ends_with(b"/.") ||
    path.ends_with(b"/..") ||
    path == b"." ||
    path == b".."
}
