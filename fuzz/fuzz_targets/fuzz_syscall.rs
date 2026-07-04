#![no_main]

use libfuzzer_sys::fuzz_target;
use nilix_fuzz::MockKernelContext;

fuzz_target!(|data: &[u8]| {
    // Need at least one syscall (56 bytes: nr + 6 args)
    if data.len() < 56 {
        return;
    }

    // Create stateful kernel context
    let mut ctx = MockKernelContext::new();

    // Parse syscall(s) from input
    let mut offset = 0;
    while offset + 56 <= data.len() {
        // Parse syscall number + 6 arguments (each u64, little-endian)
        let nr = u64::from_le_bytes(data[offset..offset+8].try_into().unwrap());
        let args = [
            u64::from_le_bytes(data[offset+8..offset+16].try_into().unwrap()),
            u64::from_le_bytes(data[offset+16..offset+24].try_into().unwrap()),
            u64::from_le_bytes(data[offset+24..offset+32].try_into().unwrap()),
            u64::from_le_bytes(data[offset+32..offset+40].try_into().unwrap()),
            u64::from_le_bytes(data[offset+40..offset+48].try_into().unwrap()),
            u64::from_le_bytes(data[offset+48..offset+56].try_into().unwrap()),
        ];

        // Execute syscall with mock kernel
        let _ = ctx.syscall(nr, args);

        // Provide coverage feedback based on state changes
        let _ = ctx.process_count();
        let _ = ctx.fd_count();

        offset += 56;

        // Stop after processing max 10 syscalls (avoid timeout)
        if offset >= 560 {
            break;
        }
    }
});
