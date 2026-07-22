// Crash triage system - deduplication and minimization
// Phase 7: CI Integration & Continuous Fuzzing

use crate::minimizer::{Minimizer, FailCondition};
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::hash::{Hash, Hasher};

/// Crash triage system
pub struct CrashTriageSystem {
    seen_crashes: BTreeMap<CrashSignature, CrashInfo>,
    minimizer: Minimizer,
}

/// Crash signature for deduplication
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CrashSignature {
    pub crash_type: CrashType,
    pub panic_message: Option<String>,
    pub stack_trace_hash: u64,
}

/// Type of crash
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CrashType {
    Panic,
    PageFault,
    TripleFault,
    GeneralProtectionFault,
    DivideByZero,
    DoubleFault,
    Unknown,
}

impl CrashType {
    fn from_output(output: &str) -> Self {
        if output.contains("PANIC") || output.contains("panicked") {
            CrashType::Panic
        } else if output.contains("Page Fault") || output.contains("PAGE FAULT") {
            CrashType::PageFault
        } else if output.contains("Triple Fault") || output.contains("TRIPLE FAULT") {
            CrashType::TripleFault
        } else if output.contains("General Protection") || output.contains("#GP") {
            CrashType::GeneralProtectionFault
        } else if output.contains("Divide") || output.contains("#DE") {
            CrashType::DivideByZero
        } else if output.contains("Double Fault") || output.contains("#DF") {
            CrashType::DoubleFault
        } else {
            CrashType::Unknown
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            CrashType::Panic => "Panic",
            CrashType::PageFault => "PageFault",
            CrashType::TripleFault => "TripleFault",
            CrashType::GeneralProtectionFault => "GeneralProtectionFault",
            CrashType::DivideByZero => "DivideByZero",
            CrashType::DoubleFault => "DoubleFault",
            CrashType::Unknown => "Unknown",
        }
    }
}

/// Information about a crash
pub struct CrashInfo {
    pub signature: CrashSignature,
    pub first_seen: u64, // Timestamp
    pub last_seen: u64,
    pub count: usize,
    pub reproducer: Vec<u8>,
    pub reproducer_minimized: bool,
    pub original_size: usize,
}

/// Triage result
pub enum TriageResult {
    /// This is a new, unique crash
    NewCrash {
        signature: CrashSignature,
        reproducer: Vec<u8>,
        original_size: usize,
        minimized_size: usize,
    },

    /// This crash has been seen before
    Duplicate {
        signature: CrashSignature,
        first_seen: u64,
        count: usize,
    },
}

/// Input for crash analysis
pub struct CrashInput {
    pub input: Vec<u8>,
    pub output: String,
    pub exit_code: i32,
}

impl CrashTriageSystem {
    /// Create new triage system
    pub fn new() -> Self {
        Self {
            seen_crashes: BTreeMap::new(),
            minimizer: Minimizer::new(Vec::new(), FailCondition::Crash),
        }
    }

    /// Process a crash and determine if it's new or duplicate
    pub fn process_crash(&mut self, crash: CrashInput) -> TriageResult {
        // 1. Extract signature
        let signature = self.extract_signature(&crash.output);

        klog!("[Triage] Processing crash: {:?}", signature.crash_type);

        // 2. Check if duplicate
        if let Some(existing) = self.seen_crashes.get_mut(&signature) {
            existing.count += 1;
            existing.last_seen = current_timestamp();

            klog!("[Triage] Duplicate crash (seen {} times)", existing.count);

            return TriageResult::Duplicate {
                signature: signature.clone(),
                first_seen: existing.first_seen,
                count: existing.count,
            };
        }

        // 3. New crash - minimize reproducer
        klog!("[Triage] New crash! Minimizing reproducer...");

        let original_size = crash.input.len();

        // Create fail condition that matches this crash signature
        let fail_condition = FailCondition::CrashSignature(signature.clone());

        // Minimize
        self.minimizer = Minimizer::new(crash.input.clone(), fail_condition);
        let minimized = self.minimizer.minimize(|input| {
            // Execute input and check if it produces same crash
            self.test_reproducer(input, &signature)
        });

        let minimized_size = minimized.len();
        let reduction = 100.0 * (1.0 - minimized_size as f64 / original_size as f64);

        klog!("[Triage] Minimization complete: {} -> {} bytes ({:.1}% reduction)",
            original_size, minimized_size, reduction);

        // 4. Store crash info
        let info = CrashInfo {
            signature: signature.clone(),
            first_seen: current_timestamp(),
            last_seen: current_timestamp(),
            count: 1,
            reproducer: minimized.clone(),
            reproducer_minimized: true,
            original_size,
        };

        self.seen_crashes.insert(signature.clone(), info);

        // 5. Return new crash result
        TriageResult::NewCrash {
            signature,
            reproducer: minimized,
            original_size,
            minimized_size,
        }
    }

    /// Extract crash signature from output
    fn extract_signature(&self, output: &str) -> CrashSignature {
        // Extract crash type
        let crash_type = CrashType::from_output(output);

        // Extract panic message (if present)
        let panic_message = self.extract_panic_message(output);

        // Hash stack trace
        let stack_trace_hash = self.hash_stack_trace(output);

        CrashSignature {
            crash_type,
            panic_message,
            stack_trace_hash,
        }
    }

    /// Extract panic message from output
    fn extract_panic_message(&self, output: &str) -> Option<String> {
        // Look for panic patterns
        for line in output.lines() {
            if line.contains("panicked at") {
                // Extract message after "panicked at"
                if let Some(idx) = line.find("panicked at") {
                    let msg = &line[idx + 11..];
                    // Take up to first comma or newline
                    let end = msg.find(',').unwrap_or(msg.len());
                    return Some(msg[..end].trim().to_string());
                }
            } else if line.contains("PANIC:") {
                // Extract message after "PANIC:"
                if let Some(idx) = line.find("PANIC:") {
                    let msg = &line[idx + 6..].trim();
                    return Some(msg.to_string());
                }
            }
        }

        None
    }

    /// Hash stack trace for signature
    fn hash_stack_trace(&self, output: &str) -> u64 {
        // Extract first 5 stack frames and hash them
        let mut frames = Vec::new();
        let mut in_stack = false;

        for line in output.lines() {
            // Detect start of stack trace
            if line.contains("Stack trace:") || line.contains("Backtrace:") {
                in_stack = true;
                continue;
            }

            // Extract frame if in stack trace
            if in_stack {
                // Look for patterns like:
                //   0: function_name
                //   #0 0x12345678 in function_name
                if line.trim().is_empty() {
                    break; // End of stack trace
                }

                // Extract function name (after colon or "in")
                let frame = if let Some(idx) = line.find(':') {
                    line[idx + 1..].trim()
                } else if let Some(idx) = line.find(" in ") {
                    line[idx + 4..].trim()
                } else {
                    line.trim()
                };

                frames.push(frame.to_string());

                if frames.len() >= 5 {
                    break;
                }
            }
        }

        // Hash the frames
        let mut hash = 0u64;
        for frame in frames {
            for byte in frame.as_bytes() {
                hash = hash.wrapping_mul(31).wrapping_add(*byte as u64);
            }
        }

        hash
    }

    /// Test if input reproduces the same crash
    fn test_reproducer(&self, input: &[u8], expected_sig: &CrashSignature) -> bool {
        // Execute input and check if signature matches
        // In real implementation, would run executor
        // For now, placeholder that always returns true
        true
    }

    /// Get statistics
    pub fn stats(&self) -> TriageStats {
        TriageStats {
            total_crashes: self.seen_crashes.values().map(|c| c.count).sum(),
            unique_crashes: self.seen_crashes.len(),
        }
    }

    /// Export all crashes as JSON
    pub fn export_crashes(&self) -> Vec<CrashReport> {
        let mut reports = Vec::new();

        for (sig, info) in &self.seen_crashes {
            reports.push(CrashReport {
                crash_type: sig.crash_type.as_str().to_string(),
                panic_message: sig.panic_message.clone(),
                stack_trace_hash: sig.stack_trace_hash,
                first_seen: info.first_seen,
                last_seen: info.last_seen,
                count: info.count,
                reproducer_size: info.reproducer.len(),
                original_size: info.original_size,
                reduction_percent: 100.0 * (1.0 - info.reproducer.len() as f64 / info.original_size as f64),
            });
        }

        reports
    }
}

/// Triage statistics
pub struct TriageStats {
    pub total_crashes: usize,
    pub unique_crashes: usize,
}

/// Crash report for export
pub struct CrashReport {
    pub crash_type: String,
    pub panic_message: Option<String>,
    pub stack_trace_hash: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub count: usize,
    pub reproducer_size: usize,
    pub original_size: usize,
    pub reduction_percent: f64,
}

// Helper functions

fn current_timestamp() -> u64 {
    // Placeholder - in real implementation would get system time
    0
}

fn klog(msg: &str) {
    // Placeholder - in real implementation would use actual logging
}

macro_rules! klog {
    ($fmt:expr) => { klog($fmt) };
    ($fmt:expr, $($arg:tt)*) => { klog(&alloc::format!($fmt, $($arg)*)) };
}
