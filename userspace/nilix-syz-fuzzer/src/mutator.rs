use anyhow::Result;
use rand::Rng;

use crate::program::{Argument, Syscall, SyscallProgram};

pub struct SyscallMutator {
    rng: rand::rngs::ThreadRng,
}

impl SyscallMutator {
    pub fn new() -> Self {
        Self {
            rng: rand::thread_rng(),
        }
    }

    pub fn generate_seed(&mut self) -> Result<SyscallProgram> {
        let mut program = SyscallProgram::new();

        // Generate a simple program: getpid, getppid
        program.add_syscall(Syscall {
            number: 39,  // getpid
            args: vec![],
        });

        program.add_syscall(Syscall {
            number: 110,  // getppid
            args: vec![],
        });

        Ok(program)
    }

    pub fn mutate(&mut self, seed: &SyscallProgram) -> Result<SyscallProgram> {
        let mut program = seed.clone();

        if program.syscalls.is_empty() {
            return self.generate_seed();
        }

        let strategy = self.rng.gen_range(0..5);

        match strategy {
            0 => self.mutate_insert_syscall(&mut program)?,
            1 => self.mutate_delete_syscall(&mut program)?,
            2 => self.mutate_modify_argument(&mut program)?,
            3 => self.mutate_duplicate_syscall(&mut program)?,
            4 => self.mutate_reorder_syscalls(&mut program)?,
            _ => {}
        }

        Ok(program)
    }

    fn mutate_insert_syscall(&mut self, program: &mut SyscallProgram) -> Result<()> {
        if program.syscalls.len() >= 100 {
            return Ok(());
        }

        let syscall = self.generate_random_syscall();
        let position = if program.syscalls.is_empty() {
            0
        } else {
            self.rng.gen_range(0..=program.syscalls.len())
        };

        program.syscalls.insert(position, syscall);
        Ok(())
    }

    fn mutate_delete_syscall(&mut self, program: &mut SyscallProgram) -> Result<()> {
        if program.syscalls.len() <= 1 {
            return Ok(());
        }

        let position = self.rng.gen_range(0..program.syscalls.len());
        program.syscalls.remove(position);
        Ok(())
    }

    fn mutate_modify_argument(&mut self, program: &mut SyscallProgram) -> Result<()> {
        if program.syscalls.is_empty() {
            return Ok(());
        }

        let syscall_idx = self.rng.gen_range(0..program.syscalls.len());
        if program.syscalls[syscall_idx].args.is_empty() {
            return Ok(());
        }

        let arg_idx = self.rng.gen_range(0..program.syscalls[syscall_idx].args.len());

        match &mut program.syscalls[syscall_idx].args[arg_idx] {
            Argument::Immediate(val) => {
                *val = self.mutate_integer(*val);
            }
            Argument::Buffer(buf) => {
                self.mutate_buffer(buf);
            }
            Argument::Null => {
                // Replace with random value
                program.syscalls[syscall_idx].args[arg_idx] =
                    Argument::Immediate(self.rng.gen());
            }
        }

        Ok(())
    }

    fn mutate_duplicate_syscall(&mut self, program: &mut SyscallProgram) -> Result<()> {
        if program.syscalls.is_empty() || program.syscalls.len() >= 100 {
            return Ok(());
        }

        let source_idx = self.rng.gen_range(0..program.syscalls.len());
        let syscall = program.syscalls[source_idx].clone();

        let insert_pos = self.rng.gen_range(0..=program.syscalls.len());
        program.syscalls.insert(insert_pos, syscall);

        Ok(())
    }

    fn mutate_reorder_syscalls(&mut self, program: &mut SyscallProgram) -> Result<()> {
        if program.syscalls.len() < 2 {
            return Ok(());
        }

        let idx1 = self.rng.gen_range(0..program.syscalls.len());
        let idx2 = self.rng.gen_range(0..program.syscalls.len());

        program.syscalls.swap(idx1, idx2);
        Ok(())
    }

    fn generate_random_syscall(&mut self) -> Syscall {
        // Common syscalls with their numbers
        let syscalls = [
            (1, 3),    // read: fd, buf, count
            (2, 3),    // write: fd, buf, count
            (3, 3),    // open: path, flags, mode
            (4, 1),    // close: fd
            (12, 1),   // brk: addr
            (39, 0),   // getpid
            (110, 0),  // getppid
            (200, 2),  // mmap: length, prot (simplified)
            (201, 2),  // munmap: addr, length
        ];

        let &(syscall_num, arg_count) =
            syscalls.get(self.rng.gen_range(0..syscalls.len()))
                .unwrap();

        let mut args = Vec::new();
        for _ in 0..arg_count {
            args.push(self.generate_random_argument());
        }

        Syscall {
            number: syscall_num,
            args,
        }
    }

    fn generate_random_argument(&mut self) -> Argument {
        match self.rng.gen_range(0..3) {
            0 => Argument::Immediate(self.generate_interesting_integer()),
            1 => Argument::Buffer(self.generate_random_buffer()),
            2 => Argument::Null,
            _ => Argument::Immediate(0),
        }
    }

    fn generate_interesting_integer(&mut self) -> u64 {
        let interesting_values = [
            0, 1, u64::MAX, u64::MAX - 1,
            0x7fffffff, 0x80000000,
            0xffffffff, 0x100000000,
            4096, 8192, 16384,
        ];

        if self.rng.gen_bool(0.3) {
            *interesting_values.get(self.rng.gen_range(0..interesting_values.len()))
                .unwrap()
        } else {
            self.rng.gen()
        }
    }

    fn generate_random_buffer(&mut self) -> Vec<u8> {
        let len = self.rng.gen_range(0..256);
        (0..len).map(|_| self.rng.gen()).collect()
    }

    fn mutate_integer(&mut self, val: u64) -> u64 {
        match self.rng.gen_range(0..4) {
            0 => self.generate_interesting_integer(),
            1 => val.wrapping_add(1 + self.rng.gen_range(0..100)),
            2 => val.wrapping_sub(1 + self.rng.gen_range(0..100)),
            3 => val ^ (1 << self.rng.gen_range(0..64)),
            _ => val,
        }
    }

    fn mutate_buffer(&mut self, buf: &mut Vec<u8>) {
        if buf.is_empty() {
            buf.push(self.rng.gen());
            return;
        }

        match self.rng.gen_range(0..4) {
            0 => {
                // Flip random bit
                let idx = self.rng.gen_range(0..buf.len());
                buf[idx] ^= 1 << self.rng.gen_range(0..8);
            }
            1 => {
                // Insert byte
                if buf.len() < 65536 {
                    let idx = self.rng.gen_range(0..=buf.len());
                    buf.insert(idx, self.rng.gen());
                }
            }
            2 => {
                // Delete byte
                let idx = self.rng.gen_range(0..buf.len());
                buf.remove(idx);
            }
            3 => {
                // Replace byte
                let idx = self.rng.gen_range(0..buf.len());
                buf[idx] = self.rng.gen();
            }
            _ => {}
        }
    }
}

impl Default for SyscallMutator {
    fn default() -> Self {
        Self::new()
    }
}
