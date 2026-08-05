#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug, Clone)]
enum BuddyOperation {
    Allocate { count: u16 },
    Free { handle_index: u8 },
    AllocateMultiple { count: u8 },
    QueryFree,
}

#[derive(Arbitrary, Debug)]
struct BuddyFuzzInput {
    operations: Vec<BuddyOperation>,
}

fuzz_target!(|input: BuddyFuzzInput| {
    // Host harness simulating buddy allocator operations
    let mut allocator = mm::test_harness::BuddyAllocatorHarness::new();
    let mut handles = Vec::new();

    // Limit to 1000 operations to prevent timeout
    for op in input.operations.iter().take(1000) {
        match op {
            BuddyOperation::Allocate { count } => {
                // Limit count to reasonable range (1-256 pages = 4KB to 1MB)
                let count = (*count as usize % 256).max(1);
                if let Ok(frames) = allocator.allocate_frames(count) {
                    if !frames.is_empty() {
                        handles.push(frames[0]); // Store first frame as handle
                    }
                }
            }
            BuddyOperation::Free { handle_index } => {
                if !handles.is_empty() {
                    let idx = (*handle_index as usize) % handles.len();
                    let frame = handles.swap_remove(idx);
                    let _ = allocator.free_frames(frame);
                }
            }
            BuddyOperation::AllocateMultiple { count } => {
                // Allocate multiple small blocks
                let count = (*count as usize % 16).max(1);
                for _ in 0..count {
                    if let Ok(frames) = allocator.allocate_frames(1) {
                        if !frames.is_empty() {
                            handles.push(frames[0]);
                        }
                    }
                }
            }
            BuddyOperation::QueryFree => {
                let _ = allocator.query_free_memory();
            }
        }
    }

    // Cleanup: free all remaining allocations
    for frame in handles {
        let _ = allocator.free_frames(frame);
    }

    // Verify: no leaked frames, no corruption
    allocator.verify_integrity();
});
