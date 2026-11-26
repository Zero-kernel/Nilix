//! Shared cryptographic primitives for Zero-OS kernel.
//!
//! R148-I9 FIX: Consolidates duplicate SHA-256 implementations from the audit
//! and livepatch subsystems into a single canonical FIPS 180-4 implementation.
//! This eliminates maintenance drift risk and ensures both subsystems use the
//! same KAT-validated code path.

#![no_std]

/// SHA-256 (FIPS 180-4) implementation for no_std kernel environment.
pub mod sha256 {
    /// SHA-256 round constants (FIPS 180-4, Section 4.2.2)
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    /// SHA-256 initial hash values (FIPS 180-4, Section 5.3.3)
    const INIT_STATE: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// SHA-256 block size in bytes.
    pub const BLOCK_SIZE: usize = 64;

    /// SHA-256 digest size in bytes.
    pub const DIGEST_SIZE: usize = 32;

    #[inline(always)]
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (!x & z)
    }

    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }

    #[inline(always)]
    fn big_sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }

    #[inline(always)]
    fn big_sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }

    #[inline(always)]
    fn small_sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }

    #[inline(always)]
    fn small_sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    /// Streaming SHA-256 hasher.
    ///
    /// Implements [`Drop`] with volatile zeroization so key-derived HMAC
    /// chaining state and partial message blocks are scrubbed on every exit
    /// path without relying on callers to consume the hasher by value.
    pub struct Sha256 {
        state: [u32; 8],
        buffer: [u8; 64],
        buffer_len: usize,
        total_len: u64,
    }

    impl Drop for Sha256 {
        fn drop(&mut self) {
            for word in &mut self.state {
                unsafe { core::ptr::write_volatile(word, 0) };
            }
            for byte in &mut self.buffer {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
            unsafe {
                core::ptr::write_volatile(&mut self.buffer_len, 0);
                core::ptr::write_volatile(&mut self.total_len, 0);
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Default for Sha256 {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Sha256 {
        /// Create a new SHA-256 hasher.
        pub const fn new() -> Self {
            Self {
                state: INIT_STATE,
                buffer: [0u8; 64],
                buffer_len: 0,
                total_len: 0,
            }
        }

        /// Compute the SHA-256 chaining midstate after compressing one 64-byte
        /// block directly into `out`, leaving no temporary state copies on the
        /// caller's stack.
        #[inline]
        pub fn compute_block_midstate(block: &[u8; 64], out: &mut [u32; 8]) {
            *out = INIT_STATE;
            Self::compress_state(out, block);
            scrub_crypto_stack();
        }

        /// Construct a hasher resumed from a block-aligned chaining state
        /// after `prefix_bytes` bytes (must be a multiple of `BLOCK_SIZE`).
        ///
        /// Takes `state` by reference to avoid creating an unzeroized by-value
        /// parameter copy on the caller's stack.
        #[inline]
        pub fn from_midstate(state: &[u32; 8], prefix_bytes: u64) -> Self {
            let mut hasher = Self {
                state: [0u32; 8],
                buffer: [0u8; 64],
                buffer_len: 0,
                total_len: prefix_bytes,
            };
            hasher.state.copy_from_slice(state);
            hasher
        }

        /// Compute SHA-256 digest of `data` starting from a precomputed
        /// block-aligned `state` (`prefix_bytes` already compressed).
        ///
        /// Finalizes in place and relies on [`Drop`] + [`scrub_crypto_stack`]
        /// to scrub both the hasher and any compiler-spilled compressor frame.
        #[inline]
        pub fn digest_from_midstate(state: &[u32; 8], prefix_bytes: u64, data: &[u8]) -> [u8; 32] {
            // Use a lexical scope so `Drop::drop(&mut hasher)` scrubs the
            // single stack slot in place without `core::mem::drop`'s by-value
            // move copying the state to a second slot.
            let digest = {
                let mut hasher = Self {
                    state: [0u32; 8],
                    buffer: [0u8; 64],
                    buffer_len: 0,
                    total_len: prefix_bytes,
                };
                hasher.state.copy_from_slice(state);
                hasher.update(data);
                hasher.finalize_in_place()
            };
            scrub_crypto_stack();
            digest
        }

        /// Fast single-block finalization from a block-aligned `state` for a
        /// 32-byte payload (used by HMAC-SHA256 outer hash).
        #[inline]
        pub fn digest_single_block_from_midstate(
            state: &[u32; 8],
            prefix_bytes: u64,
            data: &[u8; 32],
        ) -> [u8; 32] {
            let mut local_state = [0u32; 8];
            local_state.copy_from_slice(state);
            let total_bits = prefix_bytes.wrapping_add(32).wrapping_mul(8);
            let mut block = [0u8; 64];
            block[..32].copy_from_slice(data);
            block[32] = 0x80;
            block[56..64].copy_from_slice(&total_bits.to_be_bytes());
            Self::compress_state(&mut local_state, &block);

            let mut out = [0u8; 32];
            for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
                chunk.copy_from_slice(&local_state[i].to_be_bytes());
            }

            // Scrub key-derived chaining state, intermediate block, and any
            // compiler-spilled slots left below RSP by `compress_state`.
            for word in &mut local_state {
                unsafe { core::ptr::write_volatile(word, 0) };
            }
            for byte in &mut block {
                unsafe { core::ptr::write_volatile(byte, 0) };
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            scrub_crypto_stack();
            out
        }

        /// Compute SHA-256 digest of a single message.
        pub fn digest(data: &[u8]) -> [u8; 32] {
            let mut hasher = Self::new();
            hasher.update(data);
            hasher.finalize_in_place()
        }

        /// Feed more data into the hasher.
        pub fn update(&mut self, data: &[u8]) {
            let mut input = data;
            self.total_len = self.total_len.wrapping_add(input.len() as u64);

            // Fill an existing partial block first.
            if self.buffer_len != 0 {
                let take = core::cmp::min(64 - self.buffer_len, input.len());
                self.buffer[self.buffer_len..self.buffer_len + take]
                    .copy_from_slice(&input[..take]);
                self.buffer_len += take;
                input = &input[take..];

                if self.buffer_len == 64 {
                    Self::compress_state(&mut self.state, &self.buffer);
                    self.buffer_len = 0;
                }
            }

            // Compress full 64-byte blocks directly from the caller's slice.
            while input.len() >= 64 {
                let (head, tail) = input.split_at(64);
                let block: &[u8; 64] = head.try_into().expect("64-byte SHA-256 block");
                Self::compress_state(&mut self.state, block);
                input = tail;
            }

            // Buffer any remaining tail bytes (< 64).
            if !input.is_empty() {
                self.buffer[..input.len()].copy_from_slice(input);
                self.buffer_len = input.len();
            }
        }

        /// Finalize in place without moving `self` by value, avoiding extra
        /// stack copies of key-derived chaining state. [`Drop`] scrubs `self`.
        fn finalize_in_place(&mut self) -> [u8; 32] {
            let total_bits = self.total_len.wrapping_mul(8);

            // Pad with 0x80
            self.buffer[self.buffer_len] = 0x80;
            self.buffer_len += 1;

            // If not enough room for the 8-byte length, pad and compress
            if self.buffer_len > 56 {
                self.buffer[self.buffer_len..64].fill(0);
                Self::compress_state(&mut self.state, &self.buffer);
                self.buffer_len = 0;
            }

            // Pad with zeros until length field position
            self.buffer[self.buffer_len..56].fill(0);

            // Append bit length in big-endian
            self.buffer[56..64].copy_from_slice(&total_bits.to_be_bytes());
            Self::compress_state(&mut self.state, &self.buffer);

            // Output state in big-endian
            let mut out = [0u8; 32];
            for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
                chunk.copy_from_slice(&self.state[i].to_be_bytes());
            }
            out
        }

        /// Finalize and return the 32-byte digest. Consumes the hasher, whose
        /// [`Drop`] implementation scrubs all internal state and buffers.
        pub fn finalize(mut self) -> [u8; 32] {
            self.finalize_in_place()
        }

        /// Compress a single 512-bit block into `state`.
        ///
        /// Marked `#[inline(never)]` so `update()`/`finalize()` stay small on
        /// 32 KiB kernel stacks; debug builds use a compact 1-round loop while
        /// release builds unroll 8 rounds. Callers operating on key-derived
        /// midstates follow up with [`scrub_crypto_stack`] to erase any
        /// compiler-spilled frame slots left below RSP.
        #[inline(never)]
        fn compress_state(state: &mut [u32; 8], block: &[u8; 64]) {
            let mut w = [0u32; 16];
            for i in 0..16 {
                let off = i * 4;
                w[i] = u32::from_be_bytes([
                    block[off],
                    block[off + 1],
                    block[off + 2],
                    block[off + 3],
                ]);
            }

            #[cfg(debug_assertions)]
            {
                let mut v = *state;
                for round in 0..64 {
                    let word = if round < 16 {
                        w[round]
                    } else {
                        let i = round & 15;
                        w[i] = w[i]
                            .wrapping_add(small_sigma0(w[(i + 1) & 15]))
                            .wrapping_add(w[(i + 9) & 15])
                            .wrapping_add(small_sigma1(w[(i + 14) & 15]));
                        w[i]
                    };
                    let t1 = v[7]
                        .wrapping_add(big_sigma1(v[4]))
                        .wrapping_add(ch(v[4], v[5], v[6]))
                        .wrapping_add(K[round])
                        .wrapping_add(word);
                    let t2 = big_sigma0(v[0]).wrapping_add(maj(v[0], v[1], v[2]));
                    v[7] = v[6];
                    v[6] = v[5];
                    v[5] = v[4];
                    v[4] = v[3].wrapping_add(t1);
                    v[3] = v[2];
                    v[2] = v[1];
                    v[1] = v[0];
                    v[0] = t1.wrapping_add(t2);
                }
                for i in 0..8 {
                    state[i] = state[i].wrapping_add(v[i]);
                }
                // Scrub working variables and schedule words so key-derived
                // pad blocks and chaining states do not linger on the stack.
                for word in &mut v {
                    unsafe { core::ptr::write_volatile(word, 0) };
                }
            }

            #[cfg(not(debug_assertions))]
            {
                let mut a = state[0];
                let mut b = state[1];
                let mut c = state[2];
                let mut d = state[3];
                let mut e = state[4];
                let mut f = state[5];
                let mut g = state[6];
                let mut h = state[7];

                macro_rules! sha256_round {
                    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $k:expr, $w:expr) => {{
                        let t1 = $h
                            .wrapping_add(big_sigma1($e))
                            .wrapping_add(ch($e, $f, $g))
                            .wrapping_add($k)
                            .wrapping_add($w);
                        let t2 = big_sigma0($a).wrapping_add(maj($a, $b, $c));
                        $d = $d.wrapping_add(t1);
                        $h = t1.wrapping_add(t2);
                    }};
                }

                macro_rules! expand_word {
                    ($idx:expr) => {{
                        let i = $idx & 15;
                        let s0 = small_sigma0(w[(i + 1) & 15]);
                        let s1 = small_sigma1(w[(i + 14) & 15]);
                        w[i] = w[i]
                            .wrapping_add(s0)
                            .wrapping_add(w[(i + 9) & 15])
                            .wrapping_add(s1);
                        w[i]
                    }};
                }

                // Rounds 0..16: consume initial message schedule words directly.
                let mut base = 0usize;
                while base < 16 {
                    sha256_round!(a, b, c, d, e, f, g, h, K[base], w[base]);
                    sha256_round!(h, a, b, c, d, e, f, g, K[base + 1], w[base + 1]);
                    sha256_round!(g, h, a, b, c, d, e, f, K[base + 2], w[base + 2]);
                    sha256_round!(f, g, h, a, b, c, d, e, K[base + 3], w[base + 3]);
                    sha256_round!(e, f, g, h, a, b, c, d, K[base + 4], w[base + 4]);
                    sha256_round!(d, e, f, g, h, a, b, c, K[base + 5], w[base + 5]);
                    sha256_round!(c, d, e, f, g, h, a, b, K[base + 6], w[base + 6]);
                    sha256_round!(b, c, d, e, f, g, h, a, K[base + 7], w[base + 7]);
                    base += 8;
                }

                // Rounds 16..64: expand message schedule in place over the 16-word ring.
                while base < 64 {
                    let w0 = expand_word!(base);
                    sha256_round!(a, b, c, d, e, f, g, h, K[base], w0);
                    let w1 = expand_word!(base + 1);
                    sha256_round!(h, a, b, c, d, e, f, g, K[base + 1], w1);
                    let w2 = expand_word!(base + 2);
                    sha256_round!(g, h, a, b, c, d, e, f, K[base + 2], w2);
                    let w3 = expand_word!(base + 3);
                    sha256_round!(f, g, h, a, b, c, d, e, K[base + 3], w3);
                    let w4 = expand_word!(base + 4);
                    sha256_round!(e, f, g, h, a, b, c, d, K[base + 4], w4);
                    let w5 = expand_word!(base + 5);
                    sha256_round!(d, e, f, g, h, a, b, c, K[base + 5], w5);
                    let w6 = expand_word!(base + 6);
                    sha256_round!(c, d, e, f, g, h, a, b, K[base + 6], w6);
                    let w7 = expand_word!(base + 7);
                    sha256_round!(b, c, d, e, f, g, h, a, K[base + 7], w7);
                    base += 8;
                }

                // Update state
                state[0] = state[0].wrapping_add(a);
                state[1] = state[1].wrapping_add(b);
                state[2] = state[2].wrapping_add(c);
                state[3] = state[3].wrapping_add(d);
                state[4] = state[4].wrapping_add(e);
                state[5] = state[5].wrapping_add(f);
                state[6] = state[6].wrapping_add(g);
                state[7] = state[7].wrapping_add(h);
            }

            // Scrub rolling schedule words so key-derived pad blocks do not linger.
            for word in &mut w {
                unsafe { core::ptr::write_volatile(word, 0) };
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Overwrite the stack region immediately below the caller's frame so any
    /// compiler-generated spill slots left behind by `Sha256::compress_state`
    /// (saved input state words or working variables) are erased in both debug
    /// and release builds.
    ///
    /// Sized strictly larger than `compress_state`'s frame (and its transitive
    /// `update`/`finalize_in_place` frames in `digest_from_midstate`):
    /// - release: `compress_state` ~200 B, `update`/`finalize_in_place` ~128 B
    ///   -> 512 B (64 u64 words) covers the full callee stack footprint;
    /// - debug: `update`/`finalize_in_place` ~424 B + `compress_state` ~1048 B
    ///   -> 2048 B (256 u64 words) covers the full nested debug call footprint.
    #[inline(never)]
    fn scrub_crypto_stack() {
        #[cfg(debug_assertions)]
        const SCRUB_WORDS: usize = 256;
        #[cfg(not(debug_assertions))]
        const SCRUB_WORDS: usize = 64;

        let mut wipe = [0u64; SCRUB_WORDS];
        for word in &mut wipe {
            unsafe { core::ptr::write_volatile(word, 0) };
        }
        core::hint::black_box(&wipe);
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Constant-time byte-slice equality for MACs, digests and other authenticators.
///
/// R190-8 FIX: one shared helper instead of per-crate copies. The loop always
/// visits every byte and folds differences with OR, so the running time
/// depends only on the lengths, never on where the first mismatch is.
/// `black_box` keeps the optimizer from turning the fold into an early exit.
/// Lengths are not secret here (fixed-size digests), so a length mismatch
/// returns immediately.
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= core::hint::black_box(x ^ y);
    }
    core::hint::black_box(diff) == 0
}
