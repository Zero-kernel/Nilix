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
        z ^ (x & (y ^ z))
    }

    #[inline(always)]
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) | (z & (x | y))
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

        /// Fast fused HMAC-SHA256 from precomputed RFC 2104 `ipad`/`opad`
        /// midstates (each representing 64 bytes already compressed).
        ///
        /// Compresses full 64-byte blocks directly from `data`, folds the
        /// 32-byte inner digest into the single outer block, and performs ONE
        /// scrub of all working buffers + ONE `scrub_crypto_stack()` before
        /// returning (preserving R94-10 zeroization).
        #[inline]
        pub fn hmac_from_midstates(
            ipad_state: &[u32; 8],
            opad_state: &[u32; 8],
            data: &[u8],
        ) -> [u8; 32] {
            #[repr(align(8))]
            struct AlignedState([u32; 8]);
            #[repr(align(8))]
            struct AlignedSchedule([u32; 64]);
            #[repr(align(8))]
            struct AlignedBlock([u8; 64]);

            let mut inner_state = AlignedState([0u32; 8]);
            inner_state.0.copy_from_slice(ipad_state);
            let mut w = AlignedSchedule([0u32; 64]);
            let mut block_buf = AlignedBlock([0u8; 64]);
            let block = &mut block_buf.0;

            let mut input = data;
            while input.len() >= 64 {
                let (head, tail) = input.split_at(64);
                let blk: &[u8; 64] = head.try_into().expect("64-byte SHA-256 block");
                Self::load_block_words(blk, &mut w.0);
                Self::compress_words(&mut inner_state.0, &mut w.0);
                input = tail;
            }

            let rem = input.len();
            block[..rem].copy_from_slice(input);
            block[rem] = 0x80;
            let inner_bits = (64u64).wrapping_add(data.len() as u64).wrapping_mul(8);
            if rem >= 56 {
                block[rem + 1..64].fill(0);
                Self::load_block_words(block, &mut w.0);
                Self::compress_words(&mut inner_state.0, &mut w.0);
                block[..56].fill(0);
            } else {
                block[rem + 1..56].fill(0);
            }
            block[56..64].copy_from_slice(&inner_bits.to_be_bytes());
            Self::load_block_words(block, &mut w.0);
            Self::compress_words(&mut inner_state.0, &mut w.0);

            let out = Self::finish_hmac_outer(opad_state, &mut inner_state.0, &mut w.0);

            let block_u64 = block.as_mut_ptr().cast::<u64>();
            for i in 0..8 {
                unsafe { core::ptr::write_volatile(block_u64.add(i), 0) };
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            scrub_crypto_stack();
            out
        }

        /// Fast fused HMAC-SHA256 over caller-padded 64-byte blocks.
        ///
        /// Scrubs all working state AND invokes [`scrub_crypto_stack`] before
        /// returning so compressor spill frames directly below this frame are
        /// always within `scrub_crypto_stack`'s exact coverage window in both
        /// debug and release builds (R94-10).
        ///
        /// `padded_blocks` MUST be a non-empty multiple of 64 bytes already
        /// terminated with `0x80`, zero padding, and the big-endian total bit
        /// length `(64 + payload_len) * 8`.
        #[inline]
        pub fn hmac_from_midstates_padded(
            ipad_state: &[u32; 8],
            opad_state: &[u32; 8],
            padded_blocks: &[u8],
        ) -> [u8; 32] {
            #[repr(align(8))]
            struct AlignedState([u32; 8]);
            #[repr(align(8))]
            struct AlignedSchedule([u32; 64]);

            debug_assert!(!padded_blocks.is_empty() && padded_blocks.len() % 64 == 0);
            let mut inner_state = AlignedState([0u32; 8]);
            inner_state.0.copy_from_slice(ipad_state);
            let mut w = AlignedSchedule([0u32; 64]);

            for chunk in padded_blocks.chunks_exact(64) {
                let blk: &[u8; 64] = chunk.try_into().expect("64-byte SHA-256 block");
                Self::load_block_words(blk, &mut w.0);
                Self::compress_words(&mut inner_state.0, &mut w.0);
            }

            let out = Self::finish_hmac_outer(opad_state, &mut inner_state.0, &mut w.0);
            scrub_crypto_stack();
            out
        }

        /// Compute outer HMAC-SHA256 compression directly from `inner_state`
        /// words and volatile-scrub `inner_state`, `outer_state`, and `w`.
        #[inline(always)]
        fn finish_hmac_outer(
            opad_state: &[u32; 8],
            inner_state: &mut [u32; 8],
            w: &mut [u32; 64],
        ) -> [u8; 32] {
            #[repr(align(8))]
            struct AlignedState([u32; 8]);

            w[0] = inner_state[0];
            w[1] = inner_state[1];
            w[2] = inner_state[2];
            w[3] = inner_state[3];
            w[4] = inner_state[4];
            w[5] = inner_state[5];
            w[6] = inner_state[6];
            w[7] = inner_state[7];
            w[8] = 0x8000_0000;
            w[9] = 0;
            w[10] = 0;
            w[11] = 0;
            w[12] = 0;
            w[13] = 0;
            w[14] = 0;
            w[15] = (64 + 32) * 8;

            let mut outer_state = AlignedState([0u32; 8]);
            outer_state.0.copy_from_slice(opad_state);
            Self::compress_words(&mut outer_state.0, w);

            let mut out = [0u8; 32];
            for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
                chunk.copy_from_slice(&outer_state.0[i].to_be_bytes());
            }

            // R94-10: scrub every key-derived chaining state and message schedule
            // using aligned 64-bit volatile stores where guaranteed.
            let inner_ptr = inner_state.as_mut_ptr();
            let w_ptr = w.as_mut_ptr();
            if inner_ptr as usize % 8 == 0 {
                let p = inner_ptr.cast::<u64>();
                for i in 0..4 {
                    unsafe { core::ptr::write_volatile(p.add(i), 0) };
                }
            } else {
                for word in inner_state.iter_mut() {
                    unsafe { core::ptr::write_volatile(word, 0) };
                }
            }
            let outer_p = outer_state.0.as_mut_ptr().cast::<u64>();
            for i in 0..4 {
                unsafe { core::ptr::write_volatile(outer_p.add(i), 0) };
            }
            if w_ptr as usize % 8 == 0 {
                let p = w_ptr.cast::<u64>();
                for i in 0..32 {
                    unsafe { core::ptr::write_volatile(p.add(i), 0) };
                }
            } else {
                for word in w.iter_mut() {
                    unsafe { core::ptr::write_volatile(word, 0) };
                }
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            out
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
            let mut w = [0u32; 64];
            Self::load_block_words(block, &mut w);
            Self::compress_words(state, &mut w);
            // Scrub message schedule words so key-derived pad blocks do not linger.
            for word in &mut w {
                unsafe { core::ptr::write_volatile(word, 0) };
            }
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }

        #[inline(always)]
        fn load_block_words(block: &[u8; 64], w: &mut [u32; 64]) {
            for i in 0..16 {
                let off = i * 4;
                w[i] = u32::from_be_bytes([
                    block[off],
                    block[off + 1],
                    block[off + 2],
                    block[off + 3],
                ]);
            }
        }

        #[inline(never)]
        fn compress_words(state: &mut [u32; 8], w: &mut [u32; 64]) {
            // Phase 1: expand W[16..64] and fold K[0..64] into W[0..64] in place
            // before loading the 8 working state variables into registers. Keeping
            // schedule expansion separate from the round loop eliminates all GPR
            // spilling and dynamic `& 15` index computation in the hot round loop.
            for i in 16..64 {
                let w16 = w[i - 16];
                w[i] = w16
                    .wrapping_add(small_sigma0(w[i - 15]))
                    .wrapping_add(w[i - 7])
                    .wrapping_add(small_sigma1(w[i - 2]));
                w[i - 16] = w16.wrapping_add(K[i - 16]);
            }
            for i in 48..64 {
                w[i] = w[i].wrapping_add(K[i]);
            }

            #[cfg(debug_assertions)]
            {
                let mut v = *state;
                for &wk in w.iter() {
                    let t1 = v[7]
                        .wrapping_add(big_sigma1(v[4]))
                        .wrapping_add(ch(v[4], v[5], v[6]))
                        .wrapping_add(wk);
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
                // Scrub working variables so key-derived chaining states do not linger.
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
                    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident, $wk:expr) => {{
                        let t1 = $h
                            .wrapping_add(big_sigma1($e))
                            .wrapping_add(ch($e, $f, $g))
                            .wrapping_add($wk);
                        let t2 = big_sigma0($a).wrapping_add(maj($a, $b, $c));
                        $d = $d.wrapping_add(t1);
                        $h = t1.wrapping_add(t2);
                    }};
                }

                // Compact 8-round loop reading pre-added `wk = W[r] + K[r]`
                // sequentially: 8 state regs + 1 slice ptr + 4 scratch regs =
                // zero GPR spills and ~1 KiB L1I footprint.
                for chunk in w.chunks_exact(8) {
                    sha256_round!(a, b, c, d, e, f, g, h, chunk[0]);
                    sha256_round!(h, a, b, c, d, e, f, g, chunk[1]);
                    sha256_round!(g, h, a, b, c, d, e, f, chunk[2]);
                    sha256_round!(f, g, h, a, b, c, d, e, chunk[3]);
                    sha256_round!(e, f, g, h, a, b, c, d, chunk[4]);
                    sha256_round!(d, e, f, g, h, a, b, c, chunk[5]);
                    sha256_round!(c, d, e, f, g, h, a, b, chunk[6]);
                    sha256_round!(b, c, d, e, f, g, h, a, chunk[7]);
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
        }
    }

    /// Overwrite the stack region immediately below the caller's frame so any
    /// compiler-generated spill slots left behind by `Sha256::compress_state`
    /// (saved input state words or working variables) are erased in both debug
    /// and release builds.
    ///
    /// Sized strictly larger than `compress_state`'s frame (and its transitive
    /// `update`/`finalize_in_place` frames in `digest_from_midstate`):
    /// - release: `compress_words` ~64 B, `compress_state` ~320 B,
    ///   `update`/`finalize_in_place` ~128 B -> 512 B (64 u64 words) covers
    ///   the full callee stack footprint;
    /// - debug: `update`/`finalize_in_place` ~424 B + `compress_state` ~1048 B
    ///   -> 2048 B (256 u64 words) covers the full nested debug call footprint.
    #[inline(never)]
    pub fn scrub_crypto_stack() {
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
