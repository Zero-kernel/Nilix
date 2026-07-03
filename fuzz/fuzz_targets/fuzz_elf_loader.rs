#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct ElfFuzzInput {
    elf_data: Vec<u8>,
}

fuzz_target!(|input: ElfFuzzInput| {
    // Target ELF loading vulnerabilities
    // - R172-02: crafted-ELF program-header OOB-slice panic DoS
    // - Invalid headers
    // - Overlapping segments
    // - Out-of-bounds offsets

    if input.elf_data.len() < 64 {
        return; // Too small for ELF header
    }

    test_elf_header(&input.elf_data);
    test_program_headers(&input.elf_data);
});

fn test_elf_header(data: &[u8]) {
    // Check ELF magic
    if data.len() < 4 {
        return;
    }

    if &data[0..4] != b"\x7fELF" {
        return; // Not an ELF file
    }

    // Check class (32-bit or 64-bit)
    let class = data[4];
    if class != 1 && class != 2 {
        return; // Invalid class
    }

    // Check endianness
    let endian = data[5];
    if endian != 1 && endian != 2 {
        return; // Invalid endianness
    }

    // Check version
    let version = data[6];
    if version != 1 {
        return; // Invalid version
    }
}

fn test_program_headers(data: &[u8]) {
    // R172-02: Validate e_phoff + e_phnum * e_phentsize bounds

    if data.len() < 64 {
        return;
    }

    // For 64-bit ELF
    let e_phoff = u64::from_le_bytes([
        data[32], data[33], data[34], data[35],
        data[36], data[37], data[38], data[39],
    ]);

    let e_phentsize = u16::from_le_bytes([data[54], data[55]]) as u64;
    let e_phnum = u16::from_le_bytes([data[56], data[57]]) as u64;

    // Check for overflow in phdr table calculation
    if let Some(phdr_end) = e_phoff.checked_add(e_phnum.checked_mul(e_phentsize).unwrap_or(u64::MAX)) {
        if phdr_end > data.len() as u64 {
            // Program header table extends beyond file
            return;
        }
    } else {
        // Overflow in calculation
        return;
    }

    // Validate individual program headers
    for i in 0..e_phnum {
        let phdr_offset = e_phoff + i * e_phentsize;
        if phdr_offset + e_phentsize > data.len() as u64 {
            return;
        }

        validate_program_header(&data[phdr_offset as usize..], data.len() as u64);
    }
}

fn validate_program_header(phdr_data: &[u8], file_size: u64) {
    if phdr_data.len() < 56 {
        return;
    }

    // p_type
    let p_type = u32::from_le_bytes([phdr_data[0], phdr_data[1], phdr_data[2], phdr_data[3]]);

    // p_offset
    let p_offset = u64::from_le_bytes([
        phdr_data[8], phdr_data[9], phdr_data[10], phdr_data[11],
        phdr_data[12], phdr_data[13], phdr_data[14], phdr_data[15],
    ]);

    // p_filesz
    let p_filesz = u64::from_le_bytes([
        phdr_data[32], phdr_data[33], phdr_data[34], phdr_data[35],
        phdr_data[36], phdr_data[37], phdr_data[38], phdr_data[39],
    ]);

    // p_memsz
    let p_memsz = u64::from_le_bytes([
        phdr_data[40], phdr_data[41], phdr_data[42], phdr_data[43],
        phdr_data[44], phdr_data[45], phdr_data[46], phdr_data[47],
    ]);

    // Validate PT_LOAD segment
    const PT_LOAD: u32 = 1;
    if p_type == PT_LOAD {
        // Check file bounds
        if let Some(end) = p_offset.checked_add(p_filesz) {
            if end > file_size {
                // Segment extends beyond file
                return;
            }
        }

        // p_memsz >= p_filesz (BSS padding)
        if p_memsz < p_filesz {
            return;
        }

        // Reasonable size limits
        const MAX_SEGMENT_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
        if p_memsz > MAX_SEGMENT_SIZE {
            return;
        }
    }
}
