use anyhow::{bail, Context, Result};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::program::{
    Argument, Syscall, SyscallProgram, MAX_ARGS, MAX_BUFFER_CAPACITY, MAX_SYSCALLS,
};

pub const PROGRAM_MAGIC: &[u8; 8] = b"NLSYZPG\0";
pub const RESULT_MAGIC: &[u8; 8] = b"NLSYZRS\0";
pub const PROTOCOL_VERSION: u16 = 2;
pub const PROGRAM_HEADER_SIZE: usize = 128;
pub const RESULT_HEADER_SIZE: usize = 128;
pub const CALL_HEADER_SIZE: usize = 16;
pub const ARG_HEADER_SIZE: usize = 24;
pub const MAX_PROGRAM_SIZE: usize = 256 * 1024;
pub const KCOV_BITMAP_SIZE: usize = 4096;
pub const RESULT_TAG_SIZE: usize = 32;

const PROGRAM_DIGEST_OFFSET: usize = 88;
const PROGRAM_DIGEST_END: usize = PROGRAM_DIGEST_OFFSET + 32;
const PROGRAM_DOMAIN: &[u8] = b"NILIX-SYZ-PROGRAM-V2";
const RESULT_DOMAIN: &[u8] = b"NILIX-SYZ-RESULT-V2";

const ARG_IMMEDIATE: u8 = 0;
const ARG_NULL: u8 = 1;
const ARG_INPUT: u8 = 2;
const ARG_OUTPUT: u8 = 3;
const ARG_INOUT: u8 = 4;

#[derive(Clone)]
pub struct ExecutionIdentity {
    pub sequence: u64,
    pub run_id: [u8; 16],
    auth_key: [u8; 32],
}

impl ExecutionIdentity {
    pub fn random(sequence: u64) -> Self {
        let mut run_id = [0u8; 16];
        let mut auth_key = [0u8; 32];
        OsRng.fill_bytes(&mut run_id);
        OsRng.fill_bytes(&mut auth_key);
        Self {
            sequence,
            run_id,
            auth_key,
        }
    }

    #[cfg(test)]
    fn fixed(sequence: u64) -> Self {
        Self {
            sequence,
            run_id: [0x31; 16],
            auth_key: [0xa7; 32],
        }
    }
}

impl fmt::Debug for ExecutionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecutionIdentity")
            .field("sequence", &self.sequence)
            .field("run_id", &hex::encode(self.run_id))
            .field("auth_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone)]
pub struct ProgramBinding {
    pub sequence: u64,
    pub run_id: [u8; 16],
    pub program_digest: [u8; 32],
    pub syscall_count: u32,
    auth_key: [u8; 32],
}

impl ProgramBinding {
    pub fn run_hex(&self) -> String {
        hex::encode(self.run_id)
    }

    pub fn program_hex(&self) -> String {
        hex::encode(self.program_digest)
    }

    pub fn sequence_hex(&self) -> String {
        format!("{:016x}", self.sequence)
    }
}

impl fmt::Debug for ProgramBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProgramBinding")
            .field("sequence", &self.sequence)
            .field("run_id", &self.run_hex())
            .field("program_digest", &self.program_hex())
            .field("syscall_count", &self.syscall_count)
            .field("auth_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct EncodedProgram {
    pub bytes: Vec<u8>,
    pub binding: ProgramBinding,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedResult {
    pub coverage: Vec<u8>,
    pub returns: Vec<i64>,
    pub edge_count: u32,
    pub tag: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct DecodedProgram {
    pub program: SyscallProgram,
    pub binding: ProgramBinding,
}

pub fn encode_program(program: &SyscallProgram, identity: &ExecutionIdentity) -> Result<EncodedProgram> {
    program.validate()?;

    let mut bytes = vec![0u8; PROGRAM_HEADER_SIZE];
    for syscall in &program.syscalls {
        encode_syscall(&mut bytes, syscall)?;
    }
    if bytes.len() > MAX_PROGRAM_SIZE {
        bail!(
            "encoded program is {} bytes, exceeding the {MAX_PROGRAM_SIZE}-byte limit",
            bytes.len()
        );
    }

    bytes[..8].copy_from_slice(PROGRAM_MAGIC);
    put_u16(&mut bytes, 8, PROTOCOL_VERSION)?;
    put_u16(&mut bytes, 10, PROGRAM_HEADER_SIZE as u16)?;
    put_u32(&mut bytes, 12, u32::try_from(bytes.len())?)?;
    put_u32(&mut bytes, 16, 0)?;
    put_u32(&mut bytes, 20, u32::try_from(program.syscalls.len())?)?;
    put_u32(&mut bytes, 24, KCOV_BITMAP_SIZE as u32)?;
    put_u32(&mut bytes, 28, 0)?;
    put_u64(&mut bytes, 32, identity.sequence)?;
    bytes[40..56].copy_from_slice(&identity.run_id);
    bytes[56..88].copy_from_slice(&identity.auth_key);
    bytes[PROGRAM_DIGEST_OFFSET..PROGRAM_DIGEST_END].fill(0);
    bytes[120..128].fill(0);

    let digest = program_digest(&bytes)?;
    bytes[PROGRAM_DIGEST_OFFSET..PROGRAM_DIGEST_END].copy_from_slice(&digest);

    Ok(EncodedProgram {
        bytes,
        binding: ProgramBinding {
            sequence: identity.sequence,
            run_id: identity.run_id,
            program_digest: digest,
            syscall_count: program.syscalls.len() as u32,
            auth_key: identity.auth_key,
        },
    })
}

pub fn decode_program(bytes: &[u8]) -> Result<DecodedProgram> {
    if bytes.len() < PROGRAM_HEADER_SIZE {
        bail!("program is shorter than the fixed header");
    }
    if bytes.len() > MAX_PROGRAM_SIZE {
        bail!("program exceeds the maximum size");
    }
    if &bytes[..8] != PROGRAM_MAGIC {
        bail!("invalid program magic");
    }
    if read_u16(bytes, 8)? != PROTOCOL_VERSION {
        bail!("unsupported program version");
    }
    if read_u16(bytes, 10)? as usize != PROGRAM_HEADER_SIZE {
        bail!("non-canonical program header length");
    }
    if read_u32(bytes, 12)? as usize != bytes.len() {
        bail!("program total length does not match the file length");
    }
    if read_u32(bytes, 16)? != 0 || read_u32(bytes, 28)? != 0 {
        bail!("program flags or reserved field is non-zero");
    }
    if bytes[120..128].iter().any(|byte| *byte != 0) {
        bail!("program reserved bytes are non-zero");
    }
    if read_u32(bytes, 24)? as usize != KCOV_BITMAP_SIZE {
        bail!("program requests an unsupported KCOV bitmap size");
    }

    let syscall_count = read_u32(bytes, 20)? as usize;
    if syscall_count == 0 || syscall_count > MAX_SYSCALLS {
        bail!("program syscall count is outside the accepted range");
    }

    let expected_digest = program_digest(bytes)?;
    if !constant_time_eq(
        &bytes[PROGRAM_DIGEST_OFFSET..PROGRAM_DIGEST_END],
        &expected_digest,
    ) {
        bail!("program digest mismatch");
    }

    let sequence = read_u64(bytes, 32)?;
    let mut run_id = [0u8; 16];
    run_id.copy_from_slice(&bytes[40..56]);
    let mut auth_key = [0u8; 32];
    auth_key.copy_from_slice(&bytes[56..88]);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[PROGRAM_DIGEST_OFFSET..PROGRAM_DIGEST_END]);

    let mut cursor = PROGRAM_HEADER_SIZE;
    let mut syscalls = Vec::with_capacity(syscall_count);
    for _ in 0..syscall_count {
        syscalls.push(decode_syscall(bytes, &mut cursor)?);
    }
    if cursor != bytes.len() {
        bail!("program contains trailing bytes");
    }

    let program = SyscallProgram { syscalls };
    program.validate()?;
    Ok(DecodedProgram {
        program,
        binding: ProgramBinding {
            sequence,
            run_id,
            program_digest: digest,
            syscall_count: syscall_count as u32,
            auth_key,
        },
    })
}

pub fn decode_result(bytes: &[u8], binding: &ProgramBinding) -> Result<DecodedResult> {
    if bytes.len() < RESULT_HEADER_SIZE + RESULT_TAG_SIZE {
        bail!("result is shorter than its fixed framing");
    }
    if &bytes[..8] != RESULT_MAGIC {
        bail!("invalid result magic");
    }
    if read_u16(bytes, 8)? != PROTOCOL_VERSION {
        bail!("unsupported result version");
    }
    if read_u16(bytes, 10)? as usize != RESULT_HEADER_SIZE {
        bail!("non-canonical result header length");
    }
    if read_u32(bytes, 12)? as usize != bytes.len() {
        bail!("result total length does not match the file length");
    }
    if read_u32(bytes, 16)? != 0 || read_u32(bytes, 20)? != 0 {
        bail!("result flags or status is non-zero");
    }
    if read_u32(bytes, 52)? != 0 || bytes[112..128].iter().any(|byte| *byte != 0) {
        bail!("result reserved fields are non-zero");
    }

    let syscall_count = read_u32(bytes, 24)?;
    let executed_count = read_u32(bytes, 28)?;
    let kcov_len = read_u32(bytes, 32)? as usize;
    let edge_count = read_u32(bytes, 36)?;
    let returns_offset = read_u32(bytes, 40)? as usize;
    let bitmap_offset = read_u32(bytes, 44)? as usize;
    let tag_offset = read_u32(bytes, 48)? as usize;

    if syscall_count != binding.syscall_count || executed_count != syscall_count {
        bail!("result syscall counts do not match the submitted program");
    }
    if kcov_len != KCOV_BITMAP_SIZE {
        bail!("result KCOV length is not exactly {KCOV_BITMAP_SIZE}");
    }
    let return_bytes = (syscall_count as usize)
        .checked_mul(8)
        .context("result return vector length overflow")?;
    let expected_bitmap_offset = RESULT_HEADER_SIZE
        .checked_add(return_bytes)
        .context("result bitmap offset overflow")?;
    let expected_tag_offset = expected_bitmap_offset
        .checked_add(KCOV_BITMAP_SIZE)
        .context("result tag offset overflow")?;
    let expected_total = expected_tag_offset
        .checked_add(RESULT_TAG_SIZE)
        .context("result total length overflow")?;
    if returns_offset != RESULT_HEADER_SIZE
        || bitmap_offset != expected_bitmap_offset
        || tag_offset != expected_tag_offset
        || bytes.len() != expected_total
    {
        bail!("result offsets or lengths are non-canonical");
    }

    if read_u64(bytes, 56)? != binding.sequence {
        bail!("result sequence does not match this execution");
    }
    if !constant_time_eq(&bytes[64..80], &binding.run_id) {
        bail!("result run id does not match this execution");
    }
    if !constant_time_eq(&bytes[80..112], &binding.program_digest) {
        bail!("result program digest does not match this execution");
    }

    let expected_tag = hmac_sha256(&binding.auth_key, RESULT_DOMAIN, &bytes[..tag_offset]);
    if !constant_time_eq(&bytes[tag_offset..], &expected_tag) {
        bail!("result authentication tag mismatch");
    }

    let coverage = bytes[bitmap_offset..tag_offset].to_vec();
    let popcount: u32 = coverage.iter().map(|byte| byte.count_ones()).sum();
    if edge_count == 0 || popcount == 0 {
        bail!("result contains zero coverage");
    }
    if edge_count != popcount {
        bail!("KCOV edge count {edge_count} does not match bitmap popcount {popcount}");
    }

    let mut returns = Vec::with_capacity(syscall_count as usize);
    for chunk in bytes[returns_offset..bitmap_offset].chunks_exact(8) {
        returns.push(i64::from_le_bytes(chunk.try_into().expect("eight-byte chunk")));
    }
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&bytes[tag_offset..]);

    Ok(DecodedResult {
        coverage,
        returns,
        edge_count,
        tag,
    })
}

fn encode_syscall(bytes: &mut Vec<u8>, syscall: &Syscall) -> Result<()> {
    let start = bytes.len();
    bytes.resize(start + CALL_HEADER_SIZE, 0);
    for arg in &syscall.args {
        encode_argument(bytes, arg)?;
        pad_to_eight(bytes);
    }
    let record_len = bytes
        .len()
        .checked_sub(start)
        .context("syscall record length underflow")?;
    if record_len % 8 != 0 {
        bail!("internal error: syscall record is not eight-byte aligned");
    }
    put_u32(bytes, start, syscall.number)?;
    put_u32(bytes, start + 4, u32::try_from(record_len)?)?;
    put_u16(bytes, start + 8, u16::try_from(syscall.args.len())?)?;
    put_u16(bytes, start + 10, 0)?;
    put_u32(bytes, start + 12, 0)?;
    Ok(())
}

fn encode_argument(bytes: &mut Vec<u8>, arg: &Argument) -> Result<()> {
    let start = bytes.len();
    bytes.resize(start + ARG_HEADER_SIZE, 0);
    let (kind, data, capacity, value) = match arg {
        Argument::Immediate(value) => (ARG_IMMEDIATE, &[][..], 0usize, *value),
        Argument::Null => (ARG_NULL, &[][..], 0usize, 0),
        Argument::Buffer(data) => (ARG_INPUT, data.as_slice(), data.len(), 0),
        Argument::Output { capacity } => (ARG_OUTPUT, &[][..], *capacity as usize, 0),
        Argument::InOut { data, capacity } => {
            (ARG_INOUT, data.as_slice(), *capacity as usize, 0)
        }
    };
    bytes[start] = kind;
    bytes[start + 1] = 0;
    put_u16(bytes, start + 2, 0)?;
    put_u32(bytes, start + 4, u32::try_from(data.len())?)?;
    put_u32(bytes, start + 8, u32::try_from(capacity)?)?;
    put_u32(bytes, start + 12, 0)?;
    put_u64(bytes, start + 16, value)?;
    bytes.extend_from_slice(data);
    Ok(())
}

fn decode_syscall(bytes: &[u8], cursor: &mut usize) -> Result<Syscall> {
    let start = *cursor;
    require(bytes, start, CALL_HEADER_SIZE)?;
    let number = read_u32(bytes, start)?;
    let record_len = read_u32(bytes, start + 4)? as usize;
    let arg_count = read_u16(bytes, start + 8)? as usize;
    if record_len < CALL_HEADER_SIZE || record_len % 8 != 0 {
        bail!("invalid syscall record length");
    }
    if arg_count > MAX_ARGS {
        bail!("syscall record exceeds the argument limit");
    }
    if read_u16(bytes, start + 10)? != 0 || read_u32(bytes, start + 12)? != 0 {
        bail!("syscall flags or reserved field is non-zero");
    }
    let end = start
        .checked_add(record_len)
        .context("syscall record end overflow")?;
    if end > bytes.len() {
        bail!("truncated syscall record");
    }

    let mut local = start + CALL_HEADER_SIZE;
    let mut args = Vec::with_capacity(arg_count);
    for _ in 0..arg_count {
        args.push(decode_argument(bytes, &mut local, end)?);
    }
    if local != end {
        bail!("syscall record contains trailing bytes");
    }
    *cursor = end;
    Ok(Syscall { number, args })
}

fn decode_argument(bytes: &[u8], cursor: &mut usize, record_end: usize) -> Result<Argument> {
    let start = *cursor;
    let header_end = start
        .checked_add(ARG_HEADER_SIZE)
        .context("argument header overflow")?;
    if header_end > record_end {
        bail!("truncated argument header");
    }
    let kind = bytes[start];
    if bytes[start + 1] != 0
        || read_u16(bytes, start + 2)? != 0
        || read_u32(bytes, start + 12)? != 0
    {
        bail!("argument flags or reserved field is non-zero");
    }
    let data_len = read_u32(bytes, start + 4)? as usize;
    let capacity = read_u32(bytes, start + 8)? as usize;
    let value = read_u64(bytes, start + 16)?;
    if capacity > MAX_BUFFER_CAPACITY {
        bail!("argument capacity exceeds the maximum");
    }
    let data_end = header_end
        .checked_add(data_len)
        .context("argument data length overflow")?;
    if data_end > record_end {
        bail!("truncated argument data");
    }
    let data = &bytes[header_end..data_end];

    let arg = match kind {
        ARG_IMMEDIATE if data_len == 0 && capacity == 0 => Argument::Immediate(value),
        ARG_NULL if data_len == 0 && capacity == 0 && value == 0 => Argument::Null,
        ARG_INPUT if data_len > 0 && data_len == capacity && value == 0 => {
            Argument::Buffer(data.to_vec())
        }
        ARG_OUTPUT if data_len == 0 && capacity > 0 && value == 0 => Argument::Output {
            capacity: capacity as u32,
        },
        ARG_INOUT if data_len > 0 && data_len <= capacity && value == 0 => Argument::InOut {
            data: data.to_vec(),
            capacity: capacity as u32,
        },
        _ => bail!("argument encoding is non-canonical"),
    };

    let aligned_end = align_eight(data_end).context("argument alignment overflow")?;
    if aligned_end > record_end {
        bail!("truncated argument padding");
    }
    if bytes[data_end..aligned_end].iter().any(|byte| *byte != 0) {
        bail!("argument padding is non-zero");
    }
    *cursor = aligned_end;
    Ok(arg)
}

fn program_digest(bytes: &[u8]) -> Result<[u8; 32]> {
    if bytes.len() < PROGRAM_DIGEST_END {
        bail!("program is too short to contain its digest field");
    }
    let mut hasher = Sha256::new();
    hasher.update(PROGRAM_DOMAIN);
    hasher.update(&bytes[..PROGRAM_DIGEST_OFFSET]);
    hasher.update([0u8; 32]);
    hasher.update(&bytes[PROGRAM_DIGEST_END..]);
    Ok(hasher.finalize().into())
}

fn hmac_sha256(key: &[u8; 32], domain: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut inner_key = [0x36u8; BLOCK_SIZE];
    let mut outer_key = [0x5cu8; BLOCK_SIZE];
    for (index, byte) in key.iter().enumerate() {
        inner_key[index] ^= byte;
        outer_key[index] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(domain);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner_digest);
    outer.finalize().into()
}

pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn pad_to_eight(bytes: &mut Vec<u8>) {
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
}

fn align_eight(value: usize) -> Option<usize> {
    value.checked_add(7).map(|rounded| rounded & !7)
}

fn require(bytes: &[u8], offset: usize, length: usize) -> Result<()> {
    let end = offset.checked_add(length).context("range overflow")?;
    if end > bytes.len() {
        bail!("truncated binary field");
    }
    Ok(())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    require(bytes, offset, 2)?;
    Ok(u16::from_le_bytes(bytes[offset..offset + 2].try_into()?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    require(bytes, offset, 4)?;
    Ok(u32::from_le_bytes(bytes[offset..offset + 4].try_into()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    require(bytes, offset, 8)?;
    Ok(u64::from_le_bytes(bytes[offset..offset + 8].try_into()?))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) -> Result<()> {
    require(bytes, offset, 2)?;
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) -> Result<()> {
    require(bytes, offset, 4)?;
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    require(bytes, offset, 8)?;
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
fn encode_result_for_test(
    binding: &ProgramBinding,
    returns: &[i64],
    coverage: &[u8],
) -> Result<Vec<u8>> {
    if returns.len() != binding.syscall_count as usize || coverage.len() != KCOV_BITMAP_SIZE {
        bail!("invalid test result fixture dimensions");
    }
    let bitmap_offset = RESULT_HEADER_SIZE + returns.len() * 8;
    let tag_offset = bitmap_offset + KCOV_BITMAP_SIZE;
    let total = tag_offset + RESULT_TAG_SIZE;
    let mut bytes = vec![0u8; total];
    bytes[..8].copy_from_slice(RESULT_MAGIC);
    put_u16(&mut bytes, 8, PROTOCOL_VERSION)?;
    put_u16(&mut bytes, 10, RESULT_HEADER_SIZE as u16)?;
    put_u32(&mut bytes, 12, total as u32)?;
    put_u32(&mut bytes, 16, 0)?;
    put_u32(&mut bytes, 20, 0)?;
    put_u32(&mut bytes, 24, binding.syscall_count)?;
    put_u32(&mut bytes, 28, binding.syscall_count)?;
    put_u32(&mut bytes, 32, KCOV_BITMAP_SIZE as u32)?;
    put_u32(
        &mut bytes,
        36,
        coverage.iter().map(|byte| byte.count_ones()).sum(),
    )?;
    put_u32(&mut bytes, 40, RESULT_HEADER_SIZE as u32)?;
    put_u32(&mut bytes, 44, bitmap_offset as u32)?;
    put_u32(&mut bytes, 48, tag_offset as u32)?;
    put_u32(&mut bytes, 52, 0)?;
    put_u64(&mut bytes, 56, binding.sequence)?;
    bytes[64..80].copy_from_slice(&binding.run_id);
    bytes[80..112].copy_from_slice(&binding.program_digest);
    for (index, value) in returns.iter().enumerate() {
        let start = RESULT_HEADER_SIZE + index * 8;
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[bitmap_offset..tag_offset].copy_from_slice(coverage);
    reseal_result_tag(&mut bytes, binding)?;
    Ok(bytes)
}

#[cfg(test)]
fn reseal_result_tag(bytes: &mut [u8], binding: &ProgramBinding) -> Result<()> {
    let tag_offset = read_u32(bytes, 48)? as usize;
    require(bytes, tag_offset, RESULT_TAG_SIZE)?;
    let tag = hmac_sha256(&binding.auth_key, RESULT_DOMAIN, &bytes[..tag_offset]);
    bytes[tag_offset..tag_offset + RESULT_TAG_SIZE].copy_from_slice(&tag);
    Ok(())
}

#[cfg(test)]
fn reseal_program_digest(bytes: &mut [u8]) -> Result<()> {
    bytes[PROGRAM_DIGEST_OFFSET..PROGRAM_DIGEST_END].fill(0);
    let digest = program_digest(bytes)?;
    bytes[PROGRAM_DIGEST_OFFSET..PROGRAM_DIGEST_END].copy_from_slice(&digest);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::{Argument, Syscall, SYS_GETPID, SYS_GETRANDOM};

    fn sample_program() -> SyscallProgram {
        SyscallProgram {
            syscalls: vec![
                Syscall {
                    number: SYS_GETPID,
                    args: vec![],
                },
                Syscall {
                    number: SYS_GETRANDOM,
                    args: vec![
                        Argument::Output { capacity: 32 },
                        Argument::Immediate(17),
                        Argument::Immediate(1),
                    ],
                },
            ],
        }
    }

    #[test]
    fn program_round_trip_is_canonical() {
        let encoded = encode_program(&sample_program(), &ExecutionIdentity::fixed(7)).unwrap();
        let decoded = decode_program(&encoded.bytes).unwrap();
        assert_eq!(decoded.program, sample_program());
        assert_eq!(decoded.binding.sequence, 7);
        assert_eq!(decoded.binding.program_digest, encoded.binding.program_digest);
    }

    #[test]
    fn rejects_truncated_trailing_reserved_and_bad_digest_programs() {
        let encoded = encode_program(&sample_program(), &ExecutionIdentity::fixed(7)).unwrap();

        assert!(decode_program(&encoded.bytes[..encoded.bytes.len() - 1]).is_err());

        let mut trailing = encoded.bytes.clone();
        trailing.push(0);
        assert!(decode_program(&trailing).is_err());

        let mut reserved = encoded.bytes.clone();
        reserved[120] = 1;
        assert!(decode_program(&reserved).is_err());

        let mut digest = encoded.bytes.clone();
        let last = digest.len() - 1;
        digest[last] ^= 1;
        assert!(decode_program(&digest).is_err());
    }

    #[test]
    fn rejects_noncanonical_record_and_padding_after_valid_digest() {
        let encoded = encode_program(&sample_program(), &ExecutionIdentity::fixed(7)).unwrap();

        let mut bad_length = encoded.bytes.clone();
        put_u32(&mut bad_length, PROGRAM_HEADER_SIZE + 4, 15).unwrap();
        reseal_program_digest(&mut bad_length).unwrap();
        assert!(decode_program(&bad_length).is_err());

        let mut bad_padding = encoded.bytes.clone();
        let second_call = PROGRAM_HEADER_SIZE + CALL_HEADER_SIZE;
        let output_arg_end = second_call + CALL_HEADER_SIZE + ARG_HEADER_SIZE;
        bad_padding[output_arg_end] = 1;
        reseal_program_digest(&mut bad_padding).unwrap();
        assert!(decode_program(&bad_padding).is_err());
    }

    #[test]
    fn authenticated_result_round_trip_rejects_tampering_and_zero_dummy() {
        let encoded = encode_program(&sample_program(), &ExecutionIdentity::fixed(9)).unwrap();
        let mut coverage = vec![0u8; KCOV_BITMAP_SIZE];
        coverage[3] = 0b1010_0001;
        coverage[100] = 1;
        let result = encode_result_for_test(&encoded.binding, &[123, -22], &coverage).unwrap();
        let decoded = decode_result(&result, &encoded.binding).unwrap();
        assert_eq!(decoded.coverage, coverage);
        assert_eq!(decoded.returns, vec![123, -22]);
        assert_eq!(decoded.edge_count, 4);

        let mut tampered = result.clone();
        tampered[RESULT_HEADER_SIZE] ^= 1;
        assert!(decode_result(&tampered, &encoded.binding).is_err());

        let zero = vec![0u8; KCOV_BITMAP_SIZE];
        let zero_result = encode_result_for_test(&encoded.binding, &[0, 0], &zero).unwrap();
        assert!(decode_result(&zero_result, &encoded.binding).is_err());
    }

    #[test]
    fn result_rejects_coverage_count_mismatch_even_with_valid_hmac() {
        let encoded = encode_program(&sample_program(), &ExecutionIdentity::fixed(11)).unwrap();
        let mut coverage = vec![0u8; KCOV_BITMAP_SIZE];
        coverage[0] = 3;
        let mut result = encode_result_for_test(&encoded.binding, &[1, 2], &coverage).unwrap();
        put_u32(&mut result, 36, 1).unwrap();
        reseal_result_tag(&mut result, &encoded.binding).unwrap();
        assert!(decode_result(&result, &encoded.binding).is_err());
    }

    #[test]
    fn result_rejects_cross_run_identity() {
        let first = encode_program(&sample_program(), &ExecutionIdentity::fixed(1)).unwrap();
        let second = encode_program(&sample_program(), &ExecutionIdentity::fixed(2)).unwrap();
        let mut coverage = vec![0u8; KCOV_BITMAP_SIZE];
        coverage[0] = 1;
        let result = encode_result_for_test(&first.binding, &[0, 0], &coverage).unwrap();
        assert!(decode_result(&result, &second.binding).is_err());
    }
}
