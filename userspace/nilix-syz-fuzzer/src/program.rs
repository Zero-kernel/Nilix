use anyhow::{Context, Result};
use byteorder::{LittleEndian, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyscallProgram {
    pub syscalls: Vec<Syscall>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Syscall {
    pub number: u64,
    pub args: Vec<Argument>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Argument {
    Immediate(u64),
    Buffer(Vec<u8>),
    Null,
}

impl SyscallProgram {
    pub fn new() -> Self {
        Self {
            syscalls: Vec::new(),
        }
    }

    pub fn add_syscall(&mut self, syscall: Syscall) {
        if self.syscalls.len() < 100 {
            self.syscalls.push(syscall);
        }
    }

    /// Serialize program to binary format for guest executor
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        // Header: magic=0x4E494C58 ("NILX"), version=1, count=N
        buf.write_u32::<LittleEndian>(0x4E494C58)?;
        buf.write_u32::<LittleEndian>(1)?;
        buf.write_u64::<LittleEndian>(self.syscalls.len() as u64)?;

        for syscall in &self.syscalls {
            buf.write_u64::<LittleEndian>(syscall.number)?;
            buf.write_u64::<LittleEndian>(syscall.args.len() as u64)?;

            for arg in &syscall.args {
                match arg {
                    Argument::Immediate(val) => {
                        buf.write_u8(0)?; // Type: immediate
                        buf.write_u64::<LittleEndian>(8)?; // Length
                        buf.write_u64::<LittleEndian>(*val)?;
                    }
                    Argument::Buffer(data) => {
                        buf.write_u8(1)?; // Type: buffer
                        let len = data.len().min(65536); // Cap at 64KB
                        buf.write_u64::<LittleEndian>(len as u64)?;
                        buf.write_all(&data[..len])?;
                    }
                    Argument::Null => {
                        buf.write_u8(2)?; // Type: null
                        buf.write_u64::<LittleEndian>(0)?;
                    }
                }
            }
        }

        Ok(buf)
    }

    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let data = self.serialize()?;
        let mut file = File::create(path)
            .context("Failed to create program file")?;
        file.write_all(&data)?;
        Ok(())
    }

    pub fn load_from_file(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        // For now, just deserialize from JSON if available
        let json_path = path.with_extension("json");
        if json_path.exists() {
            let json_data = std::fs::read_to_string(json_path)?;
            let program: SyscallProgram = serde_json::from_str(&json_data)?;
            Ok(program)
        } else {
            // Create minimal program
            Ok(Self::new())
        }
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

impl Default for SyscallProgram {
    fn default() -> Self {
        Self::new()
    }
}
