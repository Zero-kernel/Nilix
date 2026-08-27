// Crash triage system - deduplication and minimization
// Phase 7: CI Integration & Continuous Fuzzing

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

macro_rules! klog {
    ($fmt:expr) => { klog($fmt) };
    ($fmt:expr, $($arg:tt)*) => { klog(&alloc::format!($fmt, $($arg)*)) };
}

/// Crash triage system
pub struct CrashTriageSystem {
    seen_crashes: BTreeMap<CrashSignature, CrashInfo>,
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
        }
    }

    /// Process a crash and determine if it's new or duplicate
    pub fn process_crash(&mut self, crash: CrashInput) -> TriageResult {
        // The legacy API has no executor callback, so it must not claim that
        // arbitrary byte deletions still reproduce a crash.  Preserve the
        // original input; callers with an executor can opt into verified
        // minimization through `process_crash_with_tester`.
        self.process_crash_with_tester(crash, |_candidate, _signature| false)
    }

    /// Process a crash while using a caller-provided reproducer oracle.
    ///
    /// The old Phase-7 scaffold attempted to feed raw `Vec<u8>` inputs into
    /// the syscall-oriented Phase-6 `Minimizer` and referenced a
    /// non-existent `CrashSignature` condition.  This byte-oriented API keeps
    /// the phases type-safe and only minimizes when the real executor confirms
    /// that a candidate still reproduces the same signature (U57-4).
    pub fn process_crash_with_tester<F>(
        &mut self,
        crash: CrashInput,
        mut tester: F,
    ) -> TriageResult
    where
        F: FnMut(&[u8], &CrashSignature) -> bool,
    {
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

        // 3. New crash - minimize reproducer only under a verified oracle.
        klog!("[Triage] New crash! Minimizing reproducer...");

        let original_size = crash.input.len();
        let minimized = minimize_bytes(&crash.input, &signature, &mut tester);

        let minimized_size = minimized.len();
        let reduction = if original_size == 0 {
            0.0
        } else {
            100.0 * (1.0 - minimized_size as f64 / original_size as f64)
        };

        klog!("[Triage] Minimization complete: {} -> {} bytes ({:.1}% reduction)",
            original_size, minimized_size, reduction);

        // 4. Store crash info
        let info = CrashInfo {
            signature: signature.clone(),
            first_seen: current_timestamp(),
            last_seen: current_timestamp(),
            count: 1,
            reproducer: minimized.clone(),
            reproducer_minimized: minimized_size < original_size,
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
        let mut frames: Vec<String> = Vec::new();
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
                reduction_percent: if info.original_size == 0 {
                    0.0
                } else {
                    100.0
                        * (1.0 - info.reproducer.len() as f64 / info.original_size as f64)
                },
            });
        }

        reports
    }
}

/// Delta-debug a byte input while preserving a positive oracle result.
fn minimize_bytes<F>(input: &[u8], signature: &CrashSignature, tester: &mut F) -> Vec<u8>
where
    F: FnMut(&[u8], &CrashSignature) -> bool,
{
    if input.is_empty() || !tester(input, signature) {
        return input.to_vec();
    }

    let mut best = input.to_vec();
    let mut granularity = 2usize;
    let mut iterations = 0usize;
    const MAX_ITERATIONS: usize = 1_000;

    while best.len() > 1 && iterations < MAX_ITERATIONS {
        let chunk = (best.len() + granularity - 1) / granularity;
        let mut reduced = false;
        let mut start = 0usize;

        while start < best.len() && iterations < MAX_ITERATIONS {
            let end = (start + chunk).min(best.len());
            let mut candidate = Vec::with_capacity(best.len() - (end - start));
            candidate.extend_from_slice(&best[..start]);
            candidate.extend_from_slice(&best[end..]);
            iterations += 1;
            if tester(&candidate, signature) {
                best = candidate;
                granularity = 2;
                reduced = true;
                break;
            }
            start = end;
        }

        if !reduced {
            if granularity >= best.len() {
                break;
            }
            granularity = (granularity * 2).min(best.len());
        }
    }

    best
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

fn klog(_msg: &str) {
    // Placeholder - in real implementation would use actual logging
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_minimization_requires_a_positive_reproducer_oracle() {
        let mut triage = CrashTriageSystem::new();
        let result = triage.process_crash(CrashInput {
            input: alloc::vec![1, 2, 3, 4],
            output: "PANIC: stable".to_string(),
            exit_code: 1,
        });
        let TriageResult::NewCrash { reproducer, .. } = result else {
            panic!("first crash must be new");
        };
        assert_eq!(reproducer, alloc::vec![1, 2, 3, 4]);
    }

    #[test]
    fn verified_minimization_reduces_only_when_the_oracle_accepts() {
        let mut triage = CrashTriageSystem::new();
        let result = triage.process_crash_with_tester(
            CrashInput {
                input: alloc::vec![9, 8, 7, 6, 5, 4],
                output: "PANIC: stable".to_string(),
                exit_code: 1,
            },
            |candidate, _| candidate.len() >= 2,
        );
        let TriageResult::NewCrash { reproducer, .. } = result else {
            panic!("first crash must be new");
        };
        assert_eq!(reproducer.len(), 2);
    }
}
