// SPDX-License-Identifier: GPL-2.0

//! RawRl (Raw/RLX) **mode-2 video encoder** -- clean-room from the AArch64 DLM
//! decompile (sec 8.4 + `docs/decompile/arm64-blockencoder`/`-frame-markers`).
//! Emits packed-RGB565 frames the dock decodes WITHOUT the impractical Vino
//! Walsh-Hadamard entropy codec (sec 7.11). This is a **verbatim port** of the
//! `vino-codec::rawrl` oracle, whose encode/decode round-trip is unit-tested
//! (keyframe, differential, >256-pixel multi-block and >255 RLE run-splits all
//! reconstruct byte-exact); keep the two in lockstep. No real mode-2 capture
//! exists to diff against (sec 7.4), so that round-trip is the correctness anchor.
//! NOT yet wired into `probe()`: sending a frame the dock rejects USB-resets the
//! dock, so EP08 streaming is a supervised bring-up step.
#![allow(dead_code)] // Encoder/Mode variants validated by KUnit; live scanout uses the RLE path

use super::*;

pub(crate) const MAGIC_RAW16: u16 = 0x68af;
pub(crate) const MAGIC_RLE16: u16 = 0x69af;
/// Frame-init `0x40af` (`FUN_003330fc`: u32 `0xaf0440af` + u16 `0x0840`).
pub(crate) const FRAME_INIT: [u8; 6] = [0xaf, 0x40, 0x04, 0xaf, 0x40, 0x08];
/// Bare `0xa0af` sync (`FUN_00332a38`).
pub(crate) const SYNC: [u8; 2] = [0xaf, 0xa0];
/// Frame-end section->code table `DAT_005b7860`, indexed by `mode - 1`.
pub(crate) const SECTION_CODE: [u8; 7] = [0x01, 0x00, 0x03, 0x00, 0x05, 0x07, 0x07];
pub(crate) const MAX_BLOCK_PIXELS: usize = 256;

/// Per-run strategy: mode 0 raw-only, 1 RLE-only, 2 adaptive (sec 8.4).
#[derive(Clone, Copy)]
pub(crate) enum Mode {
    Raw = 0,
    Rle = 1,
    Adaptive = 2,
}

/// Pack 8-bit RGB into RGB565 (the XRGB framebuffer reduced for the
/// `0x68af`/`0x69af` path).
pub(crate) fn rgb565(r: u8, g: u8, b: u8) -> u16 {
    ((r as u16 >> 3) << 11) | ((g as u16 >> 2) << 5) | (b as u16 >> 3)
}

/// 6-byte block header: magic LE, 24-bit coord BE, count u8 (256 -> 0).
fn block_header(out: &mut KVec<u8>, magic: u16, coord: u32, count: usize) -> Result {
    out.extend_from_slice(&magic.to_le_bytes(), GFP_KERNEL)?;
    out.push(((coord >> 16) & 0xff) as u8, GFP_KERNEL)?;
    out.push(((coord >> 8) & 0xff) as u8, GFP_KERNEL)?;
    out.push((coord & 0xff) as u8, GFP_KERNEL)?;
    out.push((count & 0xff) as u8, GFP_KERNEL)?;
    Ok(())
}

fn encode_raw_into(out: &mut KVec<u8>, coord: u32, pix: &[u16]) -> Result {
    block_header(out, MAGIC_RAW16, coord, pix.len())?;
    for &p in pix {
        out.extend_from_slice(&p.to_be_bytes(), GFP_KERNEL)?;
    }
    Ok(())
}

fn encode_rle_into(out: &mut KVec<u8>, coord: u32, pix: &[u16]) -> Result {
    block_header(out, MAGIC_RLE16, coord, pix.len())?;
    let mut i = 0;
    while i < pix.len() {
        let v = pix[i];
        let mut run = 1;
        while i + run < pix.len() && pix[i + run] == v && run < 255 {
            run += 1;
        }
        out.push(run as u8, GFP_KERNEL)?;
        out.extend_from_slice(&v.to_be_bytes(), GFP_KERNEL)?;
        i += run;
    }
    Ok(())
}

fn run_count(pix: &[u16]) -> usize {
    let mut c = 0;
    let mut i = 0;
    while i < pix.len() {
        let v = pix[i];
        let mut j = i + 1;
        while j < pix.len() && pix[j] == v {
            j += 1;
        }
        c += 1;
        i = j;
    }
    c
}

fn encode_run_into(out: &mut KVec<u8>, mode: Mode, coord: u32, pix: &[u16]) -> Result {
    match mode {
        Mode::Raw => encode_raw_into(out, coord, pix),
        Mode::Rle => encode_rle_into(out, coord, pix),
        Mode::Adaptive => {
            let l = pix.len();
            let c = run_count(pix);
            if 2 * l < 3 * c + 1 {
                encode_raw_into(out, coord, pix)
            } else {
                encode_rle_into(out, coord, pix)
            }
        }
    }
}

/// Mode-2 frame encoder holding the shadow (previous-frame) buffer.
pub(crate) struct Encoder {
    width: usize,
    height: usize,
    mode: Mode,
    // vmalloc-backed: a `width*height` u16 buffer is ~4 MiB at 1080p, far above the
    // contiguous-kmalloc order limit (the page allocator WARNs and fails on it).
    shadow: VVec<u16>,
}

impl Encoder {
    pub(crate) fn new(width: usize, height: usize, mode: Mode) -> Result<Self> {
        let shadow = VVec::from_elem(0u16, width * height, GFP_KERNEL)?;
        Ok(Self { width, height, mode, shadow })
    }

    /// Encode `cur` (RGB565) into a mode-2 marker stream; updates the shadow.
    /// Change-detection is per row; changed runs chunk into <=256-px blocks.
    pub(crate) fn encode(&mut self, cur: &[u16]) -> Result<KVec<u8>> {
        let mut s = KVec::new();
        self.encode_into(cur, &mut s)?;
        Ok(s)
    }

    /// Like [`encode`](Self::encode) but appends the marker stream to a caller-owned
    /// `out` instead of allocating a fresh `KVec`. The hot scanout path
    /// ([`encode_and_send`](super::drm_sink::encode_and_send)) uses this to encode
    /// straight into a buffer that already reserves the EP08 transport header, so a
    /// frame costs one allocation with no separate framing copy.
    pub(crate) fn encode_into(&mut self, cur: &[u16], s: &mut KVec<u8>) -> Result {
        s.extend_from_slice(&FRAME_INIT, GFP_KERNEL)?;
        for y in 0..self.height {
            let row = y * self.width;
            let mut x = 0;
            while x < self.width {
                while x < self.width && cur[row + x] == self.shadow[row + x] {
                    x += 1;
                }
                if x >= self.width {
                    break;
                }
                let run_start = x;
                while x < self.width && cur[row + x] != self.shadow[row + x] {
                    x += 1;
                }
                let run_end = x;
                let mut p = run_start;
                while p < run_end {
                    let n = (run_end - p).min(MAX_BLOCK_PIXELS);
                    let coord = (((row + p) * 2) & 0xff_ffff) as u32;
                    encode_run_into(s, self.mode, coord, &cur[row + p..row + p + n])?;
                    p += n;
                }
            }
        }
        // `SECTION_CODE` (the decompile's `DAT_005b7860`) is indexed by the DL3 1-based
        // mode number minus 1; our 0-based `Mode` discriminant already equals that index
        // (Raw=0->0x01, Rle=1->0x00, Adaptive=2->0x03). The previous `saturating_sub(1)`
        // double-subtracted, collapsing Raw and Rle onto the same code.
        let code = SECTION_CODE[(self.mode as usize).min(SECTION_CODE.len() - 1)];
        s.extend_from_slice(&SYNC, GFP_KERNEL)?;
        s.extend_from_slice(&[0xaf, 0x20, 0x1f, code], GFP_KERNEL)?;
        s.extend_from_slice(&[0xaf, 0x20, 0xff, 0x00], GFP_KERNEL)?;
        s.extend_from_slice(&SYNC, GFP_KERNEL)?;
        // Commit the shadow ONLY after the whole frame has been emitted successfully.
        // Updating it incrementally (per changed run) left it half-updated if a later
        // `extend_from_slice` hit OOM, permanently desyncing every subsequent diff frame.
        // The encoder reads the pre-frame shadow throughout, so a single end-of-frame copy
        // is equivalent to the per-run writes on the success path. The loop already indexes
        // `cur` up to `width*height == shadow.len()`, so this slice is always in bounds.
        let n = self.shadow.len();
        self.shadow.copy_from_slice(&cur[..n]);
        Ok(())
    }
}

/// Vino (`0x2801`) Walsh-Hadamard codec -- the bandwidth-constrained / 4K path (the RLE path
/// above is what the dock currently runs; this is the lossy transform codec DLM uses when raw/
/// RLE won't fit the USB budget). See `docs/WHT-CODEC.md` + `docs/VIDEO.md` +
/// `captures/codec-vlc-table-breakthrough-20260623.md`.
///
/// **Scope (recovered + verified byte-exact vs DLM, 2026-06-23).** Every stage below is checked
/// against DLM's own captured output offline (no dock needed):
/// - [`colour`] `Y = 16R+32G+16B` (achromatic `Y = 64*gray`);
/// - [`transform`] the **8x8 2-D Haar (Mallat) wavelet** (`//64`), 320/320 real gradient blocks;
/// - [`quantize`] the per-position bias/step quantizer (`white -> Y_DC=16320 -> 1020`);
/// - [`CODEBOOK`]/[`Vlc`] the LSB-first unary-prefix magnitude VLC dumped from DLM's coder leaf
///   `0x5e68b0`, plus the [`SYNC13`] block framing -- `scripts/wht-block-codec.py` round-trips
///   DLM's per-block output 5/5 byte-for-byte.
///
/// **The coeff->strip grammar is now recovered end to end** ([`strip`] + [`encode_frame`], 2026-06-23):
/// the per-block significance code (a LAST-significant-position code, not a zerotree/context coder),
/// the across-block DC **DPCM** plane (`(Cr, Cb, Y)` residuals), the AC run/magnitude stream, the two
/// strip layouts (SOLID vs AC), and the **forward length-hint tail** (`tail[k] = L[k+1] - 2`, verified
/// 10529/10800 on the gradient capture). [`encode_frame`] tiles a luma frame into 64x16 strips and
/// composes the whole stream byte-exact for **achromatic** content.
///
/// **Two items remain genuinely unverified (so the live scanout path keeps using RLE -- emitting
/// guessed bits is forbidden):** (1) **chroma AC** -- every captured AC example was grey, so the
/// Cb/Cr high-frequency path has no ground truth and [`strip`] leaves chroma AC at zero; (2) the
/// rightmost-column **size-mispredict** -- DLM's forward hint occasionally predicts an anomalously
/// sized neighbour wrong (a framing micro-heuristic, ~2.5% of gradient strips); [`encode_frame`] uses
/// exact look-ahead instead, which matches DLM on 100% of constant-strip-size content. Both are
/// HW-unverifiable while the CP wall stands. The transform/quantizer/entropy stages are byte-exact.
#[allow(dead_code)] // Walsh-Hadamard codec: KUnit-validated, not yet on the live scanout path
pub(crate) mod wht {
    use super::*;

    /// Transform block geometry (recovered + byte-exact-verified 2026-06-23, see
    /// `captures/codec-vlc-table-breakthrough-20260623.md`): an **8x8 pixel** block is the input
    /// (`DIM` x `DIM` = `PIXELS` luma samples); the wavelet emits **32** coefficients (`COEFFS`) --
    /// it is lossy 64->32, dropping the level-1 LH/HH subbands. `BLOCK` aliases `PIXELS` for the
    /// `transform()` input length.
    pub(crate) const DIM: usize = 8;
    pub(crate) const PIXELS: usize = DIM * DIM;
    pub(crate) const COEFFS: usize = 32;
    pub(crate) const BLOCK: usize = PIXELS;

    /// Vino colour transform, in the codec's 64x fixed point: `Cb = 64(R-G)`,
    /// `Cr = 64(B-G)` (achromatic R=G=B -> Cb=Cr=0), and the reversible luma
    ///
    /// ```text
    ///     Y = 64*G + 64*((Cb_raw + Cr_raw) >> 2)   where Cb_raw=R-G, Cr_raw=B-G
    /// ```
    ///
    /// The `>> 2` is an arithmetic shift (floor toward -inf). This **replaces** the
    /// earlier `Y = 16R + 32G + 16B` form, which `validate-transform-encoderio.py`
    /// showed runs 16..48 HIGH for chromatic blocks (`16R+32G+16B = 64G + 16(Cb+Cr)`,
    /// i.e. the un-floored sum). The floored form reproduces DLM's transform DC for
    /// **every** measured colour -- the 6 saturated primaries/secondaries (incl. the
    /// signed green/cyan cases the floor must round toward -inf), grey, white and
    /// black (`scripts/validate-transform-encoderio.py`); achromatic input is
    /// unchanged (`64*G` since `Cb=Cr=0`).
    pub(crate) fn colour(r: u8, g: u8, b: u8) -> (i32, i32, i32) {
        let (r, g, b) = (r as i32, g as i32, b as i32);
        let (cb, cr) = (r - g, b - g);
        (64 * g + 64 * ((cb + cr) >> 2), 64 * cb, 64 * cr)
    }

    /// Per-coefficient `(step, bias)` quantization table, **derived 2026-06-23 from DLM's
    /// ground-truth `quant_leave` pre/post buffers** (captures/sig-library) -- the old
    /// decode-ep08 guess (pos3 step32/bias16, pos4-11 step4/bias2, pos16-47 step2/bias1) was
    /// WRONG and broke 4/25 strips. Note pos3 = (48, 32): a WIDE DEADZONE (so c3[3]=-48 -> -1,
    /// not -2). Keyed by coefficient position `0..32`.
    fn step_bias(i: usize) -> (i32, i32) {
        match i {
            0 => (16, 8),
            1 | 2 => (16, 2),
            3 => (48, 32),
            4..=11 => (4, 0),
            12 => (8, 2),
            13..=15 => (8, 0),
            _ => (2, 0), // 16..=31
        }
    }

    /// Quantize coefficient `coeff` at position `i`: `sign(coeff) * floor((|coeff| + bias) / step)`
    /// (byte-exact vs DLM, 25/25 library strips). Clamped to the 12-bit signed long-token range.
    pub(crate) fn quantize(coeff: i32, i: usize) -> i32 {
        let (step, bias) = step_bias(i);
        let q = (coeff.abs() + bias) / step;
        (if coeff < 0 { -q } else { q }).clamp(-2048, 2047)
    }

    /// One separable 2-D Haar step over the top-left `n`x`n` of `src` (row-major, `n` columns,
    /// `n` in {8,4,2}). The 1-D Haar butterfly is `lo = a + b`, `hi = a - b`; applied to rows then
    /// columns it splits the `n`x`n` block into four `(n/2)`x`(n/2)` subbands written to
    /// `ll`/`hl`/`lh`/`hh` (row-major, stride `n/2`). Unnormalized -- `transform()` floor-divides
    /// the final coefficients by 64. Mirrors `scripts/wht-transform.py` (verified byte-exact).
    ///
    /// **`#[inline(never)]` (2026-07-17, root cause of the `video.rs:294`/`encode_and_send_wht`
    /// kernel stack overflow -- see `project_stack_overflow_root_cause_found_20260717` memory):**
    /// LLVM was inlining this whole codec pipeline (`colour_frame_ep08` -> `colour_strip_blocks`
    /// -> `colour_block` -> `transform` -> `haar2d`, called from a loop over every strip in a
    /// frame) into a single function, summing every inlined callee's locals into ONE static stack
    /// frame instead of reusing space between sequential calls. `CONFIG_VMAP_STACK` +
    /// `CONFIG_SCHED_STACK_END_CHECK` caught it cleanly: `encode_and_send_wht`'s prologue alone
    /// allocated 0x3ed8 (16,088) bytes -- on a 16KB kernel stack, several frames deep inside a
    /// workqueue callback, that's a guaranteed overflow regardless of pixel content (explaining
    /// why a userspace repro with an 8MB stack never reproduced it). Forcing this and the other
    /// codec functions below to stay real, separate calls (each with its own small frame that is
    /// entered/freed per call, not accumulated) fixes this by construction -- no logic changed.
    #[inline(never)]
    fn haar2d(src: &[i32], n: usize, ll: &mut [i32], hl: &mut [i32], lh: &mut [i32], hh: &mut [i32]) {
        let h = n / 2;
        // Diagnostic (2026-07-16, see `project_bringup_video_panic_20260716` memory): a live HW
        // run hit `index out of bounds: the len is 0 but the index is 0` at this function's
        // column-pass write below, but every call site in `transform()` was hand-verified to pass
        // correctly-sized fixed arrays (never empty) -- so the exact call/size that actually
        // failed was never pinned down. This makes any future recurrence self-diagnosing instead
        // of a bare index panic: report `n`, the derived `h`, and every buffer's ACTUAL length
        // against what this function requires, so the message alone says which call site (and
        // which buffer) was wrong. Unconditional (not `debug_assert!`) so it fires regardless of
        // build profile until the real cause is confirmed and this can be removed/downgraded.
        assert!(
            src.len() == n * n
                && ll.len() == h * h
                && hl.len() == h * h
                && lh.len() == h * h
                && hh.len() == h * h,
            "vino: haar2d(n={n}, h={h}) buffer size mismatch -- src.len()={} (want {}), \
             ll.len()={} hl.len()={} lh.len()={} hh.len()={} (want {} each)",
            src.len(), n * n, ll.len(), hl.len(), lh.len(), hh.len(), h * h
        );
        // Row pass: L = row-lo, H = row-hi (each n rows x h cols).
        let mut l = [0i32; PIXELS];
        let mut hb = [0i32; PIXELS];
        for r in 0..n {
            for i in 0..h {
                let (a, b) = (src[r * n + 2 * i], src[r * n + 2 * i + 1]);
                l[r * h + i] = a + b;
                hb[r * h + i] = a - b;
            }
        }
        // Column pass: LL/LH = col-lo/hi of L, HL/HH = col-lo/hi of H (each h x h).
        for c in 0..h {
            for i in 0..h {
                let (a, b) = (l[2 * i * h + c], l[(2 * i + 1) * h + c]);
                ll[i * h + c] = a + b;
                lh[i * h + c] = a - b;
                let (a2, b2) = (hb[2 * i * h + c], hb[(2 * i + 1) * h + c]);
                hl[i * h + c] = a2 + b2;
                hh[i * h + c] = a2 - b2;
            }
        }
    }

    /// DLM's video transform (`FUN_007a7b60`), reverse-engineered + **verified byte-exact**
    /// (2026-06-23, 320/320 real gradient blocks + the 6 stripe/checker vectors): an **8x8 2-D
    /// Haar (Mallat) wavelet, floor-divided by 64**. The `block` is 8x8 luma (`Y = 16R+32G+16B`,
    /// achromatic `Y = 64*gray`); the output is 32 coefficients in DLM's Mallat layout:
    /// `c[0]` = LL; `c[1..4]` = level-3 HL/LH/HH; `c[4..8]/[8..12]/[12..16]` = level-2 HL/LH/HH
    /// (2x2 row-major each); `c[16..32]` = level-1 HL (4x4 row-major). The level-1 LH and HH
    /// subbands are dropped (the lossy 64->32 reduction). A uniform block yields `DC = mean`,
    /// all AC = 0. Replaces the prior flat 2-level Walsh-Hadamard, which did not match DLM for AC.
    ///
    /// `#[inline(never)]`: see `haar2d`'s doc comment -- part of the kernel-stack-overflow fix.
    #[inline(never)]
    pub(crate) fn transform(block: &[i32; PIXELS]) -> [i32; COEFFS] {
        let sh = |x: i32| x >> 6; // arithmetic shift = floor division by 64 (matches DLM/`//64`)
        let mut c = [0i32; COEFFS];
        // Level 1: 8x8 -> 4x4 subbands; the finest HL band is c[16..32]. DLM emits this 4x4 band
        // **column-major** (the entropy coder's coefficient reorder): wire position `p` reads band
        // element `(row = p % 4, col = p / 4)`. Recovered 2026-06-27 byte-exact from a real DLM
        // colour strip (cramp256 sink capture, `captures/codec-sink-094653/`): a horizontal ramp's
        // HL band is `[-2,0,-2,0; ...]` row-major but the wire groups it `[-2,-2,-2,-2, 0,0,0,0, ...]`
        // = the transpose. (The earlier achromatic byte-exact tests never exercised an asymmetric L1HL
        // band -- gentle gradients quantize it to zero -- so this latent scan bug was invisible until
        // steep colour content.) The lower bands (c[0..16]) decode in natural order.
        let (mut ll1, mut hl1, mut lh1, mut hh1) = ([0i32; 16], [0i32; 16], [0i32; 16], [0i32; 16]);
        haar2d(block, DIM, &mut ll1, &mut hl1, &mut lh1, &mut hh1);
        for p in 0..16 {
            c[16 + p] = sh(hl1[(p % 4) * 4 + p / 4]);
        }
        // Level 2: LL1 (4x4) -> 2x2 subbands; c[4..8]/[8..12]/[12..16].
        let (mut ll2, mut hl2, mut lh2, mut hh2) = ([0i32; 4], [0i32; 4], [0i32; 4], [0i32; 4]);
        haar2d(&ll1, 4, &mut ll2, &mut hl2, &mut lh2, &mut hh2);
        for i in 0..4 {
            c[4 + i] = sh(hl2[i]);
            c[8 + i] = sh(lh2[i]);
            c[12 + i] = sh(hh2[i]);
        }
        // Level 3: LL2 (2x2) -> 1x1 subbands; the DC c[0] and coarse c[1..4].
        let (mut ll3, mut hl3, mut lh3, mut hh3) = ([0i32; 1], [0i32; 1], [0i32; 1], [0i32; 1]);
        haar2d(&ll2, 2, &mut ll3, &mut hl3, &mut lh3, &mut hh3);
        c[0] = sh(ll3[0]);
        c[1] = sh(hl3[0]);
        c[2] = sh(lh3[0]);
        c[3] = sh(hh3[0]);
        // `lh1`/`hh1` (level-1 LH/HH) are intentionally unused -- the lossy 64->32 drop.
        let _ = (&lh1, &hh1);
        c
    }

    // ====================================================================================
    // ★ 2026-06-23 (live HW): the REAL entropy code, recovered + byte-exact-verified.
    //
    // The earlier MSB-first 5-bit "short/long token" model (now removed) was REFUTED: a value-axis
    // amplitude sweep (`scripts/codec-sweep-plan.py`) showed its decoded tokens were invariant to
    // the coefficient VALUE (identical `L589` across a 128x AC range) -- it never matched the coder.
    // The dock's entropy coder (DLM leaf `0x5e68b0`) is a **memory-resident unary-prefix VLC,
    // written LSB-first**, dumped from DLM and reproduced byte-for-byte by [`Vlc`] + [`CODEBOOK`]
    // (`scripts/wht-block-codec.py` reproduces DLM's per-block output 5/5; see
    // `captures/codec-vlc-table-breakthrough-20260623.md`). A coefficient's magnitude category is
    // `bit_length(|coeff|)` (verified across the sweep), code = unary(c)+0-terminator+remainder.
    //
    // VERIFIED here (KUnit): the codebook, the LSB-first packing, the 1-bit final padding, and the
    // magnitude-category rule. NOT yet generalized (the open work): the coeff->token GRAMMAR for
    // arbitrary content -- DC DPCM, the 2-D scan (incl. the real horizontal/vertical asymmetry),
    // and block modes -- so this is the byte-exact OUTPUT stage, not yet a wired general encoder.
    // ====================================================================================

    /// The dumped Vino entropy VLC, indexed by symbol: `(code, nbits)`, emitted **LSB-first**.
    /// Symbol 0 = the 1-bit code `0` (zero / most common); symbol 31 = the all-ones escape prefix.
    pub(crate) const CODEBOOK: [(u32, u8); 32] = [
        (0, 1), (1, 3), (5, 3), (3, 5), (19, 5), (11, 5), (27, 5), (7, 7), (71, 7), (39, 7),
        (103, 7), (23, 7), (87, 7), (55, 7), (119, 7), (15, 8), (143, 8), (79, 8), (207, 8),
        (47, 8), (175, 8), (111, 8), (239, 8), (31, 8), (159, 8), (95, 8), (223, 8), (63, 8),
        (191, 8), (127, 8), (255, 9), (511, 9),
    ];

    /// The constant 13-byte per-block sync literal (emitted twice), recovered from the wire.
    pub(crate) const SYNC13: [u8; 13] =
        [0x7c, 0x93, 0x6f, 0xf2, 0x4d, 0xbe, 0xc9, 0x37, 0xf9, 0x26, 0xdf, 0xe4, 0x9b];

    /// LSB-first VLC bit packer matching the dock (final byte padded with **1-bits** -- a
    /// truncated all-ones code, as DLM emits).
    pub(crate) struct Vlc {
        out: KVec<u8>,
        acc: u32,
        nbits: u32,
    }

    impl Vlc {
        pub(crate) fn new() -> Self {
            Self { out: KVec::new(), acc: 0, nbits: 0 }
        }

        /// Append one bit (LSB-first within each byte).
        fn bit(&mut self, b: u32) -> Result {
            self.acc |= (b & 1) << self.nbits;
            self.nbits += 1;
            if self.nbits == 8 {
                self.out.push((self.acc & 0xff) as u8, GFP_KERNEL)?;
                self.acc = 0;
                self.nbits = 0;
            }
            Ok(())
        }

        /// Emit codebook `sym`'s code, least-significant bit first.
        pub(crate) fn symbol(&mut self, sym: usize) -> Result {
            let (code, n) = CODEBOOK[sym];
            for k in 0..n as u32 {
                self.bit(code >> k)?;
            }
            Ok(())
        }

        /// Emit one quantized coefficient as DLM's JPEG-SSSS-style magnitude code (LSB-first),
        /// verified byte-exact against DLM's per-coefficient wire bits (q-4/q-8/q-16 -- see
        /// `scripts/wht-strip-encoder.py`). A zero coefficient is the 1-bit symbol 0. A nonzero
        /// `q` emits the unary category `c = bit_length(|q|)` (c ones + a 0 terminator), then the
        /// `(c-1)`-bit magnitude offset `|q| - 2^(c-1)` (MSB-first within the field), then a sign
        /// bit (`0` = negative, the captured polarity). Categories >= 9 use the 19-bit escape long
        /// form, which is not yet recovered -- those return `EOVERFLOW` rather than emit wrong bits.
        pub(crate) fn coeff(&mut self, q: i32) -> Result {
            if q == 0 {
                return self.symbol(0);
            }
            let c = mag_category(q); // bit_length(|q|)
            if c >= 9 {
                return Err(kernel::error::code::EOVERFLOW); // escape long form -- open RE
            }
            for _ in 0..c {
                self.bit(1)?; // unary category
            }
            self.bit(0)?; // terminator
            let offset = q.unsigned_abs() - (1 << (c - 1));
            for i in (0..c - 1).rev() {
                self.bit(offset >> i)?; // (c-1)-bit magnitude offset, MSB-first
            }
            self.bit(if q < 0 { 0 } else { 1 }) // sign bit (0 = negative)
        }

        /// Flush, padding the final byte with 1-bits (matches the dock's truncated all-ones code).
        pub(crate) fn finish(mut self) -> Result<KVec<u8>> {
            if self.nbits > 0 {
                while self.nbits < 8 {
                    self.acc |= 1 << self.nbits;
                    self.nbits += 1;
                }
                self.out.push((self.acc & 0xff) as u8, GFP_KERNEL)?;
            }
            Ok(self.out)
        }
    }

    /// Magnitude category of a quantized coefficient: `bit_length(|coeff|)` (verified 2026-06-23 --
    /// e.g. |4|->3, |8|->4, |255|->8). 0 for a zero coefficient.
    pub(crate) fn mag_category(coeff: i32) -> u32 {
        coeff.unsigned_abs().checked_ilog2().map_or(0, |l| l + 1)
    }

    // ====================================================================================
    // ★ 2026-06-23: the SOLID-colour strip encoder -- byte-exact-verified end to end vs DLM
    // (3508/3508 strips of grey128.bin + white). A solid 64x16 strip (16 uniform 8x8 blocks) is the
    // most common desktop case (backgrounds, flat UI). DLM codes it with a NO-sync framing distinct
    // from the AC-stripe path: a 16-byte header, a CONSTANT 30-byte "main frame" (identical for any
    // solid colour), the strip's absolute DC ESCAPE-coded (long form), then a fixed trailer. The DC
    // rule was cracked offline (`scripts/wht-strip-encoder.py`): code = unary(c) ++ offset(c-1,
    // MSB-first) ++ sign, c=bit_length(qDC), qDC=quantize(DC,0), DC=c3[0]=64*gray (achromatic).
    // ====================================================================================

    /// Bit offset where the per-plane DC escape begins (after the 16-byte header + the constant
    /// 30-byte main frame = byte 46). Verified 2026-06-23 across the grey sweep and solid primaries.
    const SOLID_DC_BIT: usize = 368;
    /// Maximum DC escape category; the maximum category omits the unary 0-terminator (a complete
    /// prefix code on categories `1..=SOLID_DC_CMAX`). `|qY| <= 1020 => c <= 10`, `|qCb| <= 255`.
    const SOLID_DC_CMAX: u32 = 10;
    /// Minimum trailing bits after the escape before the 2-byte length tail (empirical: fits all 14
    /// solid/colour DCs of `codec-grammar-20260623`; ~= the 16 blocks' empty-AC/EOB run).
    const SOLID_DC_MINPAD: usize = 61;
    /// Header (16 B, X/Y/w18/w1c patched per strip) + the constant 30-byte main frame (bytes 16..46)
    /// of a solid strip (the 16-block all-zero DC-residual / empty-AC structure, identical for any
    /// solid colour). Byte 46 (bit 368) onward carries the (Cr, Cb, Y) DC escape + trailer.
    const SOLID_MAIN: [u8; 46] = [
        0x01, 0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0x3a, 0, 0x3a, 0, 0, 0, // header (magic,X,Y,resv,w18,w1c,z)
        0xfc, 0x00, 0x7e, 0x00, 0x3f, 0x80, 0x1f, 0xc0, 0x0f, 0xe0, 0x07, 0xf0, 0x03, 0xf8, 0x01, 0xfc,
        0x00, 0x7e, 0x00, 0x3f, 0x80, 0x1f, 0xc0, 0x0f, 0xe0, 0x07, 0xf0, 0x03, 0xf8, 0x01, // main frame
    ];

    /// Quantize a per-plane Haar DC: luma (plane 0) step 16, chroma (planes 1/2) step 64, bias 8.
    /// Verified 2026-06-23 from the solid primaries (red qCb=255, cyan qY=764, ...).
    fn quantize_dc(plane: usize, v: i32) -> i32 {
        let step = if plane == 0 { 16 } else { 64 };
        let q = (((v.unsigned_abs() + 8) * (65536 / step)) >> 16) as i32;
        if v < 0 {
            -q
        } else {
            q
        }
    }

    /// Number of escape bits a signed value `v` occupies: `0 -> 1`; else `unary(c) ++ [term if
    /// c<cmax] ++ offset(c-1) ++ sign`.
    fn esc_len(v: i32, cmax: u32) -> usize {
        if v == 0 {
            return 1;
        }
        let c = mag_category(v);
        c as usize + usize::from(c < cmax) + (c as usize - 1) + 1
    }

    /// Encode one solid 64x16 coder strip at pixel `(x, y)` from its three per-plane Haar DCs
    /// (`ydc = c3[0]`, `cbdc = c4[0] = 64*(R-G)`, `crdc = c5[0] = 64*(B-G)`; achromatic => Cb=Cr=0,
    /// e.g. `ydc = 8192` for grey128). **Byte-exact-verified vs DLM** on the full grey sweep
    /// (c=8/9/10), white, and the 6 solid primaries/secondaries -- 14/14 strips (KUnit
    /// `wht_solid_strip_byte_exact` + `scripts/wht-strip-encoder.py`). Plane order on the wire is
    /// (Cr, Cb, Y); the escape begins at bit 368; the strip is zero-padded to its even length `L`
    /// with `w18 = w1c = tail = L - 2`.
    pub(crate) fn solid_strip(x: u16, y: u16, ydc: i32, cbdc: i32, crdc: i32) -> Result<KVec<u8>> {
        let esc = esc_len(quantize_dc(2, crdc), SOLID_DC_CMAX)
            + esc_len(quantize_dc(1, cbdc), SOLID_DC_CMAX)
            + esc_len(quantize_dc(0, ydc), SOLID_DC_CMAX);
        let need = (SOLID_DC_BIT + esc + SOLID_DC_MINPAD).div_ceil(8);
        let payload = need + (need & 1); // round up to even
        let len = payload + 2;

        let mut out = KVec::new();
        out.resize(len, 0, GFP_KERNEL)?;
        out[..46].copy_from_slice(&SOLID_MAIN);
        out[2..4].copy_from_slice(&x.to_le_bytes());
        out[4..6].copy_from_slice(&y.to_le_bytes());
        let l2 = (len - 2) as u16;
        out[10..12].copy_from_slice(&l2.to_le_bytes()); // w18
        out[12..14].copy_from_slice(&l2.to_le_bytes()); // w1c
        // No trailing echo on the wire (the record framing's strip_id carries the length); the
        // last 2 bytes stay the natural DC padding. See `frame_records`.

        // The (Cr, Cb, Y) DC escapes, LSB-first from bit 368.
        let mut bitpos = SOLID_DC_BIT;
        let mut push = |b: u32| {
            out[bitpos / 8] |= ((b & 1) as u8) << (bitpos % 8);
            bitpos += 1;
        };
        for &q in &[quantize_dc(2, crdc), quantize_dc(1, cbdc), quantize_dc(0, ydc)] {
            if q == 0 {
                push(0); // a zero value is the single bit 0
                continue;
            }
            let c = mag_category(q);
            let mag = q.unsigned_abs();
            let off = mag - (1 << (c - 1));
            for _ in 0..c {
                push(1); // unary category
            }
            if c < SOLID_DC_CMAX {
                push(0); // 0-terminator (omitted at the maximum category)
            }
            for i in (0..c.saturating_sub(1)).rev() {
                push(off >> i); // (c-1)-bit magnitude offset, MSB-first
            }
            push(u32::from(q > 0)); // sign bit = 1 for positive
        }
        Ok(out)
    }

    /// Max AC magnitude category (the maximum category omits the unary 0-terminator).
    const AC_CMAX: u32 = 9;

    /// LSB-first bit accumulator for the AC-strip coder (no final padding, unlike [`Vlc`]).
    struct Bits {
        out: KVec<u8>,
        n: usize,
    }

    impl Bits {
        fn new() -> Self {
            Self { out: KVec::new(), n: 0 }
        }

        fn bit(&mut self, b: u32) -> Result {
            if self.n % 8 == 0 {
                self.out.push(0, GFP_KERNEL)?;
            }
            self.out[self.n / 8] |= ((b & 1) as u8) << (self.n % 8);
            self.n += 1;
            Ok(())
        }

        /// The shared escape value code: a 0 is one `0` bit; else `unary(c) ++ [0-term IFF c<cmax]
        /// ++ offset(c-1, MSB-first) ++ sign(1=positive)`. `c = bit_length(|v|)`.
        fn esc(&mut self, v: i32, cmax: u32) -> Result {
            if v == 0 {
                return self.bit(0);
            }
            // Saturate a magnitude whose category exceeds the codebook maximum (`cmax`) to the
            // largest value that category `cmax` encodes. This keeps the unary prefix at most
            // `cmax` ones: a decoder that stops after `cmax` ones (the max-category escape, whose
            // 0-terminator is omitted) would otherwise read the (cmax+1)th one as an offset bit
            // and desync the rest of the strip. In-range coefficients (`c <= cmax`) are
            // unaffected; this only bounds the out-of-range case, which the recovered grammar does
            // not otherwise exercise.
            let c = mag_category(v).min(cmax);
            let off = v.unsigned_abs().min((1 << c) - 1) - (1 << (c - 1));
            for _ in 0..c {
                self.bit(1)?;
            }
            if c < cmax {
                self.bit(0)?;
            }
            for i in (0..c.saturating_sub(1)).rev() {
                self.bit(off >> i)?;
            }
            self.bit(u32::from(v > 0))
        }

        /// Per-block significance = LAST-significant-position code (byte-exact 24/24): AC block
        /// `00111110 ++ 5-bit(32-last) MSB`; flat block `00111111 ++ 0000000`.
        fn sync_unit(&mut self, last: usize) -> Result {
            for &b in &[0u32, 0, 1, 1, 1, 1, 1] {
                self.bit(b)?; // common prefix 0011111
            }
            if last == 0 {
                self.bit(1)?; // flat: 8th prefix bit = 1, then 7 zeros (15-bit unit)
                for _ in 0..7 {
                    self.bit(0)?;
                }
            } else {
                self.bit(0)?; // AC: 8th prefix bit = 0, then 5-bit (32-last) MSB-first (13-bit unit)
                let v = 32 - last as u32;
                for i in (0..5).rev() {
                    self.bit((v >> i) & 1)?;
                }
            }
            Ok(())
        }
    }

    /// Encode a UNIFORM 64x16 AC strip (16 identical 8x8 blocks) at pixel `(x, y)` from one block's
    /// 32 transform coeffs. **BYTE-EXACT vs DLM** (25/25 sig-library strips; KUnit `wht_ac_strip`).
    /// Achromatic (Cb=Cr=0). Layout: header(16) + per-block sync(last-position) + (Cr,Cb,Y) DC plane
    /// (block0 + 15 DPCM-zero blocks, 10 B) + AC-row(8 blocks: run-bit / magnitude) x2 + tail(L-2).
    /// For a fully flat block (no AC) use [`solid_strip`] instead.
    pub(crate) fn ac_strip(coeff: &[i32; COEFFS], x: u16, y: u16) -> Result<KVec<u8>> {
        let mut q = [0i32; COEFFS];
        for i in 0..COEFFS {
            q[i] = quantize(coeff[i], i);
        }
        let last = (1..COEFFS).rev().find(|&i| q[i] != 0).unwrap_or(0);

        let mut sync = Bits::new();
        for _ in 0..16 {
            sync.sync_unit(last)?;
        }
        let mut dc = Bits::new();
        dc.esc(0, SOLID_DC_CMAX)?; // Cr=0
        dc.esc(0, SOLID_DC_CMAX)?; // Cb=0
        dc.esc(q[0], SOLID_DC_CMAX)?; // Y absolute (block 0)
        for _ in 0..45 {
            dc.bit(0)?; // 15 DPCM-zero blocks x (Cr,Cb,Y)
        }
        let mut row = Bits::new();
        for _ in 0..8 {
            for i in 1..=last {
                if q[i] == 0 {
                    row.bit(0)?; // run bit (insignificant coeff)
                } else {
                    row.esc(q[i], AC_CMAX)?; // magnitude
                }
            }
        }

        let sync_b = sync.out.len();
        let dc_b = 10usize; // DC region fixed 10 B for 16-block uniform
        let mut rb = row.out.len();
        rb += rb & 1; // round row up to even bytes
        let w18 = 16 + sync_b + dc_b;
        let w1c = w18 + rb;
        let len = w1c + rb + 2;

        let mut out = KVec::new();
        out.resize(len, 0, GFP_KERNEL)?;
        out[0] = 0x01;
        out[1] = 0x28;
        out[2..4].copy_from_slice(&x.to_le_bytes());
        out[4..6].copy_from_slice(&y.to_le_bytes());
        out[10..12].copy_from_slice(&(w18 as u16).to_le_bytes());
        out[12..14].copy_from_slice(&(w1c as u16).to_le_bytes());
        out[16..16 + sync_b].copy_from_slice(&sync.out);
        out[16 + sync_b..16 + sync_b + dc.out.len()].copy_from_slice(&dc.out);
        out[w18..w18 + row.out.len()].copy_from_slice(&row.out);
        out[w1c..w1c + row.out.len()].copy_from_slice(&row.out);
        out[len - 2..len].copy_from_slice(&((len - 2) as u16).to_le_bytes());
        Ok(out)
    }

    /// Number of blocks across a 64-px-wide strip and the rows of blocks within its 16-px height.
    const STRIP_BLOCKS_X: usize = 8;
    const STRIP_ROW_BLOCKS: usize = 8; // blocks in one 8-row half (8 across x 1 down)
    const STRIP_BLOCKS: usize = 16; // 8 across x 2 down

    /// Round a byte count up to an even number (every coder sub-region is even-aligned).
    fn round_even(n: usize) -> usize {
        n + (n & 1)
    }

    /// Emit the 16-block DPCM DC plane into `b`: per block, the `(Cr, Cb, Y)` quantized DC as a
    /// RESIDUAL escape (residual = this block's DC minus the previous block's DC, previous = 0 for
    /// block 0). Byte-exact vs DLM on the varying-DC solid strips (vstripe8/hstripe8/checker8) and
    /// the uniform case (all residuals 0). `dc[k] = (qCr, qCb, qY)`.
    fn dc_plane(b: &mut Bits, dc: &[(i32, i32, i32); STRIP_BLOCKS]) -> Result {
        let (mut pcr, mut pcb, mut py) = (0i32, 0i32, 0i32);
        for &(cr, cb, y) in dc {
            b.esc(cr - pcr, SOLID_DC_CMAX)?;
            b.esc(cb - pcb, SOLID_DC_CMAX)?;
            b.esc(y - py, SOLID_DC_CMAX)?;
            (pcr, pcb, py) = (cr, cb, y);
        }
        Ok(())
    }

    /// Emit one block's luma AC coefficients (positions `1..=last`) into `b`: a run bit `0` for an
    /// insignificant coefficient, else the magnitude escape. No EOB -- the block's `last` (from the
    /// significance sync) bounds the loop. Achromatic only (chroma AC is not yet recovered).
    fn block_ac(b: &mut Bits, q: &[i32; COEFFS], last: usize) -> Result {
        for i in 1..=last {
            if q[i] == 0 {
                b.bit(0)?;
            } else {
                b.esc(q[i], AC_CMAX)?;
            }
        }
        Ok(())
    }

    /// Encode one general 64x16 coder strip at pixel `(x, y)` from its 16 blocks' luma transform
    /// coefficients (raster order: blocks 0..8 = top 8-px half, 8..16 = bottom half). Picks DLM's
    /// layout automatically: **SOLID** (every block flat -> header + 30-byte main frame + DPCM DC
    /// plane from bit 368) or **AC** (some block carries a nonzero AC coeff -> header + per-block
    /// significance sync + DPCM DC plane + AC-row0 + AC-row1). The 2-byte tail is set to this
    /// strip's own `L - 2`; [`encode_frame`] overwrites it with the *next* strip's forward length
    /// hint (the wire's actual tail).
    ///
    /// **Byte-exact vs DLM** (achromatic content) on uniform solid (grey sweep/white), varying-DC
    /// solid (vstripe8/hstripe8/checker8) and the 25/25 sig-library AC strips; gradient bodies match
    /// every coding layer. Chroma (Cb/Cr) AC is left at zero -- there is no captured colour-AC
    /// example to verify it against, so colourful textured content is *not* byte-exact here (the
    /// anti-fabrication boundary). Callers pass per-block luma coeffs from [`transform`].
    pub(crate) fn strip(blocks: &[[i32; COEFFS]; STRIP_BLOCKS], x: u16, y: u16) -> Result<KVec<u8>> {
        let mut q = [[0i32; COEFFS]; STRIP_BLOCKS];
        let mut lasts = [0usize; STRIP_BLOCKS];
        let mut dc = [(0i32, 0i32, 0i32); STRIP_BLOCKS];
        let mut any_ac = false;
        for k in 0..STRIP_BLOCKS {
            for i in 0..COEFFS {
                q[k][i] = quantize(blocks[k][i], i);
            }
            lasts[k] = (1..COEFFS).rev().find(|&i| q[k][i] != 0).unwrap_or(0);
            any_ac |= lasts[k] != 0;
            dc[k] = (0, 0, q[k][0]); // achromatic: Cr=Cb=0 (chroma DC plumbed by the caller's blocks)
        }

        let mut dcb = Bits::new();
        dc_plane(&mut dcb, &dc)?;

        let mut out = KVec::new();
        if !any_ac {
            // SOLID layout: header + constant 30-byte main frame + DPCM DC plane from bit 368.
            let l2 = round_even((SOLID_DC_BIT + dcb.n).div_ceil(8)) + 2;
            let len = l2 + 2;
            out.resize(len, 0, GFP_KERNEL)?;
            out[..46].copy_from_slice(&SOLID_MAIN);
            out[2..4].copy_from_slice(&x.to_le_bytes());
            out[4..6].copy_from_slice(&y.to_le_bytes());
            out[10..12].copy_from_slice(&(l2 as u16).to_le_bytes());
            out[12..14].copy_from_slice(&(l2 as u16).to_le_bytes());
            // The DPCM bits begin at bit 368 = byte 46 (byte-aligned); Bits zero-pads its tail, so a
            // plain byte copy preserves the LSB-first packing.
            out[46..46 + dcb.out.len()].copy_from_slice(&dcb.out);
            out[len - 2..len].copy_from_slice(&(l2 as u16).to_le_bytes());
            return Ok(out);
        }

        // AC layout.
        let mut sync = Bits::new();
        for k in 0..STRIP_BLOCKS {
            sync.sync_unit(lasts[k])?;
        }
        let mut row0 = Bits::new();
        for k in 0..STRIP_ROW_BLOCKS {
            block_ac(&mut row0, &q[k], lasts[k])?;
        }
        let mut row1 = Bits::new();
        for k in STRIP_ROW_BLOCKS..STRIP_BLOCKS {
            block_ac(&mut row1, &q[k], lasts[k])?;
        }

        let sync_b = sync.out.len();
        let dc_b = round_even(dcb.out.len()) + 2;
        let r0 = round_even(row0.out.len());
        let r1 = round_even(row1.out.len());
        let w18 = 16 + sync_b + dc_b;
        let w1c = w18 + r0;
        let len = w1c + r1 + 2;

        out.resize(len, 0, GFP_KERNEL)?;
        out[0] = 0x01;
        out[1] = 0x28;
        out[2..4].copy_from_slice(&x.to_le_bytes());
        out[4..6].copy_from_slice(&y.to_le_bytes());
        out[10..12].copy_from_slice(&(w18 as u16).to_le_bytes());
        out[12..14].copy_from_slice(&(w1c as u16).to_le_bytes());
        out[16..16 + sync_b].copy_from_slice(&sync.out);
        out[16 + sync_b..16 + sync_b + dcb.out.len()].copy_from_slice(&dcb.out);
        out[w18..w18 + row0.out.len()].copy_from_slice(&row0.out);
        out[w1c..w1c + row1.out.len()].copy_from_slice(&row1.out);
        // No forward-hint tail: on the EP08 wire the strip's last 2 bytes are the natural row1
        // bit-packing. The record framing carries the length as `strip_id == len`, so the in-strip
        // echo the sink hook showed is not transmitted on the wire. See `frame_records`.
        Ok(out)
    }

    // ====================================================================================
    // COLOUR strip codec (Cb/Cr planes). Recovered byte-exact 2026-06-27/28 from DLM
    // sink-hook captures (cramp/rramp/bramp period sweeps, captures/codec-sink-sweep-*):
    // 2700/2872 strips byte-identical across every significance combination. Tooling +
    // proof: scripts/codec-re/{coeffs,model,colourstrip,verify-colour-ac}.py.
    //
    // Per block the 3 planes are (Cr=64*(B-G), Cb=64*(R-G), Y=64*G + 64*((Cb+Cr)>>2)).
    //  * SYNC unit = [Cr field][Cb field][Y field]; chroma fields present only when last>0
    //    (the per-block plane mask), Y field always present (luma `sync_unit`).
    //  * DC plane = 16-block DPCM (Cr,Cb,Y), 3 tokens/block, chroma step 64 / luma step 16,
    //    round-half-up on the signed value.
    //  * AC rows (row0 blocks 0..8, row1 8..16): per block (Cr,Cb,Y) present planes, chroma
    //    quant flat step 16 (truncate toward zero), positions 1..last, run-bit `0` for zeros.
    //  * Strip length = w1c + round_even(row1) (the 2-byte tail overlaps row1's tail).
    // ====================================================================================

    /// Flat chroma AC quantizer: step 16, truncate toward zero. Coarser than luma's
    /// per-position `quantize`, so chroma `last` collapses to {0,1,7,31}.
    fn quantize_chroma_ac(coeff: i32) -> i32 {
        let q = coeff.abs() / 16;
        if coeff < 0 {
            -q
        } else {
            q
        }
    }

    /// Per-plane DC quantizer, round-half-up on the SIGNED value (toward +inf): luma (plane 0)
    /// step 16, chroma step 64. `+224/64 = 3.5 -> 4`; `-8416/64 = -131.5 -> -131`.
    fn quantize_dc_round(plane: usize, v: i32) -> i32 {
        let step = if plane == 0 { 16 } else { 64 };
        (v + step / 2).div_euclid(step)
    }

    impl Bits {
        /// The Cr significance field: `c = bit_length(last)`; emit `1`x`c` then `0`x`c`.
        fn cr_field(&mut self, last: usize) -> Result {
            let c = usize::BITS - last.leading_zeros();
            for _ in 0..c {
                self.bit(1)?;
            }
            for _ in 0..c {
                self.bit(0)?;
            }
            Ok(())
        }

        /// The Cb significance field: `c = bit_length(last)`; `10` if `c == 1`, else
        /// `0` ++ `1`x`c` ++ `0`x`(c-1)`.
        fn cb_field(&mut self, last: usize) -> Result {
            let c = usize::BITS - last.leading_zeros();
            if c == 1 {
                self.bit(1)?;
                return self.bit(0);
            }
            self.bit(0)?;
            for _ in 0..c {
                self.bit(1)?;
            }
            for _ in 0..c - 1 {
                self.bit(0)?;
            }
            Ok(())
        }

        /// One block's colour SYNC unit: present chroma fields (Cr, then Cb) then the Y field.
        fn colour_sync_unit(&mut self, lcr: usize, lcb: usize, ly: usize) -> Result {
            if lcr > 0 {
                self.cr_field(lcr)?;
            }
            if lcb > 0 {
                self.cb_field(lcb)?;
            }
            self.sync_unit(ly)
        }

        /// One block's colour AC: present planes in (Cr, Cb, Y) order, positions `1..=last`,
        /// run-bit `0` for an insignificant coefficient else the magnitude escape (cmax `AC_CMAX`).
        fn colour_block_ac(
            &mut self,
            qcr: &[i32; COEFFS],
            qcb: &[i32; COEFFS],
            qy: &[i32; COEFFS],
            lcr: usize,
            lcb: usize,
            ly: usize,
        ) -> Result {
            for &(q, last) in &[(qcr, lcr), (qcb, lcb), (qy, ly)] {
                for i in 1..=last {
                    if q[i] == 0 {
                        self.bit(0)?;
                    } else {
                        self.esc(q[i], AC_CMAX)?;
                    }
                }
            }
            Ok(())
        }
    }

    /// One quantized colour block: the three planes' 32 coefficients and their last-significant
    /// AC positions. Built by [`colour_block`] from a block's per-plane samples.
    pub(crate) struct ColourBlock {
        qcr: [i32; COEFFS],
        qcb: [i32; COEFFS],
        qy: [i32; COEFFS],
        lcr: usize,
        lcb: usize,
        ly: usize,
    }

    /// Transform + quantize one block's three planes (each 64 samples in the codec's x64 fixed
    /// point: `cr[i] = 64*(B-G)`, `cb[i] = 64*(R-G)`, `y[i] = 64*G + 64*((Cb+Cr)>>2)`). Luma uses
    /// the per-position `quantize`/col-major transform; chroma AC uses the flat step-16
    /// `quantize_chroma_ac`; all DCs use `quantize_dc_round`.
    ///
    /// `#[inline(never)]`: see `haar2d`'s doc comment -- part of the kernel-stack-overflow fix.
    #[inline(never)]
    pub(crate) fn colour_block(
        cr: &[i32; PIXELS],
        cb: &[i32; PIXELS],
        y: &[i32; PIXELS],
    ) -> ColourBlock {
        let tcr = transform(cr);
        let tcb = transform(cb);
        let ty = transform(y);
        let mut qcr = [0i32; COEFFS];
        let mut qcb = [0i32; COEFFS];
        let mut qy = [0i32; COEFFS];
        qcr[0] = quantize_dc_round(2, tcr[0]);
        qcb[0] = quantize_dc_round(1, tcb[0]);
        qy[0] = quantize_dc_round(0, ty[0]);
        for i in 1..COEFFS {
            qcr[i] = quantize_chroma_ac(tcr[i]);
            qcb[i] = quantize_chroma_ac(tcb[i]);
            qy[i] = quantize(ty[i], i);
        }
        let last = |q: &[i32; COEFFS]| (1..COEFFS).rev().find(|&i| q[i] != 0).unwrap_or(0);
        let (lcr, lcb, ly) = (last(&qcr), last(&qcb), last(&qy));
        ColourBlock { qcr, qcb, qy, lcr, lcb, ly }
    }

    /// Encode one 64x16 COLOUR strip at pixel `(x, y)` from its 16 quantized colour blocks
    /// (raster: 0..8 top 8-px half, 8..16 bottom). Byte-exact vs DLM on all measured chromatic
    /// content (see the section header). The 2-byte tail is this strip's own `L-2`;
    /// [`encode_frame`]/the scanout path overwrites it with the next strip's forward length hint.
    ///
    /// `#[inline(never)]`: see `haar2d`'s doc comment -- part of the kernel-stack-overflow fix.
    #[inline(never)]
    pub(crate) fn colour_strip(
        blocks: &[ColourBlock],
        x: u16,
        y: u16,
    ) -> Result<KVec<u8>> {
        let mut sync = Bits::new();
        for b in blocks {
            sync.colour_sync_unit(b.lcr, b.lcb, b.ly)?;
        }
        let mut dcb = Bits::new();
        let (mut pcr, mut pcb, mut py) = (0i32, 0i32, 0i32);
        for b in blocks {
            let (cr, cb, yv) = (b.qcr[0], b.qcb[0], b.qy[0]);
            dcb.esc(cr - pcr, SOLID_DC_CMAX)?;
            dcb.esc(cb - pcb, SOLID_DC_CMAX)?;
            dcb.esc(yv - py, SOLID_DC_CMAX)?;
            (pcr, pcb, py) = (cr, cb, yv);
        }
        let mut row0 = Bits::new();
        for b in &blocks[..STRIP_ROW_BLOCKS] {
            row0.colour_block_ac(&b.qcr, &b.qcb, &b.qy, b.lcr, b.lcb, b.ly)?;
        }
        let mut row1 = Bits::new();
        for b in &blocks[STRIP_ROW_BLOCKS..] {
            row1.colour_block_ac(&b.qcr, &b.qcb, &b.qy, b.lcr, b.lcb, b.ly)?;
        }

        let sync_b = sync.out.len();
        let dc_b = round_even(dcb.out.len()) + 2;
        let r0 = round_even(row0.out.len());
        let r1 = round_even(row1.out.len());
        let w18 = 16 + sync_b + dc_b;
        let w1c = w18 + r0;
        // The 2-byte tail overlaps the end of the row1 region (len = w1c + round_even(row1)).
        let len = w1c + r1;

        let mut out = KVec::new();
        out.resize(len, 0, GFP_KERNEL)?;
        out[0] = 0x01;
        out[1] = 0x28;
        out[2..4].copy_from_slice(&x.to_le_bytes());
        out[4..6].copy_from_slice(&y.to_le_bytes());
        out[10..12].copy_from_slice(&(w18 as u16).to_le_bytes());
        out[12..14].copy_from_slice(&(w1c as u16).to_le_bytes());
        out[16..16 + sync_b].copy_from_slice(&sync.out);
        out[16 + sync_b..16 + sync_b + dcb.out.len()].copy_from_slice(&dcb.out);
        out[w18..w18 + row0.out.len()].copy_from_slice(&row0.out);
        out[w1c..w1c + row1.out.len()].copy_from_slice(&row1.out);
        // No forward-hint tail: on the EP08 wire the strip's last 2 bytes are the natural row1
        // bit-packing. The record framing carries the length as `strip_id == len`, so the in-strip
        // echo the sink hook showed is not transmitted on the wire. See `frame_records`.
        Ok(out)
    }

    /// Transform one 8x8 luma block read from `luma` (row-major, `stride` samples per row, top-left
    /// at `[oy*stride + ox]`) into its 32 Haar coefficients.
    fn block_coeffs(luma: &[u8], stride: usize, ox: usize, oy: usize) -> [i32; COEFFS] {
        let mut blk = [0i32; PIXELS];
        for r in 0..DIM {
            for c in 0..DIM {
                // Achromatic: Y = 64 * gray (the colour transform's R=G=B case).
                blk[r * DIM + c] = 64 * luma[(oy + r) * stride + (ox + c)] as i32;
            }
        }
        transform(&blk)
    }

    /// Encode a full `width`x`height` achromatic (8-bit luma) frame into the Vino WHT EP08 strip
    /// stream (no transport header -- the caller prepends [`write_ep08_header`]). The frame is tiled
    /// into 64x16 strips in raster order; each strip's 16 blocks are transformed and handed to
    /// [`strip`]. A second pass writes the **forward length hint**: strip `k`'s 2-byte tail is set to
    /// strip `k+1`'s `L - 2` (the last strip keeps its own `L - 2`). This is the wire's exact tail
    /// rule -- verified 10529/10800 on the gradient capture and on 100% of constant-strip-size
    /// content; it deviates from DLM only where DLM *mispredicts* an anomalously-sized neighbour
    /// (the rightmost-column size heuristic, the single open framing micro-detail).
    ///
    /// `width`/`height` must be multiples of 64 and 16 respectively (the codec's strip geometry).
    /// Achromatic only (see [`strip`]); for colour or RGB565-reduced input this is not byte-exact, so
    /// the live scanout path keeps using RLE until the chroma-AC grammar is captured.
    pub(crate) fn encode_frame(luma: &[u8], width: usize, height: usize) -> Result<KVec<u8>> {
        if width % (STRIP_BLOCKS_X * DIM) != 0 || height % (2 * DIM) != 0 {
            return Err(kernel::error::code::EINVAL);
        }
        let strips_x = width / (STRIP_BLOCKS_X * DIM); // 64-px columns
        let strips_y = height / (2 * DIM); // 16-px rows
        // Build every strip body (tail = own L-2 for now), tracking each one's span in `out`.
        let mut out = KVec::new();
        let mut spans: KVec<(usize, usize)> = KVec::new(); // (start, len) per strip
        for sy in 0..strips_y {
            for sx in 0..strips_x {
                let (px, py) = (sx * STRIP_BLOCKS_X * DIM, sy * 2 * DIM);
                let mut blocks = [[0i32; COEFFS]; STRIP_BLOCKS];
                for k in 0..STRIP_BLOCKS {
                    let (bx, by) = (k % STRIP_BLOCKS_X, k / STRIP_BLOCKS_X);
                    blocks[k] = block_coeffs(luma, width, px + bx * DIM, py + by * DIM);
                }
                let s = strip(&blocks, px as u16, py as u16)?;
                let start = out.len();
                let slen = s.len();
                out.extend_from_slice(&s, GFP_KERNEL)?;
                spans.push((start, slen), GFP_KERNEL)?;
            }
        }
        // Second pass: forward length hint -- tail[k] = L[k+1] - 2.
        for k in 0..spans.len().saturating_sub(1) {
            let (start, slen) = spans[k];
            let next_l2 = (spans[k + 1].1 - 2) as u16;
            out[start + slen - 2..start + slen].copy_from_slice(&next_l2.to_le_bytes());
        }
        Ok(out)
    }

    /// Strip pixel geometry: a strip is 64 px wide and 16 px tall
    /// (`STRIP_BLOCKS_X * DIM` x `2 * DIM`).
    pub(crate) const STRIP_W: usize = STRIP_BLOCKS_X * DIM; // 64
    pub(crate) const STRIP_H: usize = 2 * DIM; // 16

    /// Gather one 64x16 strip's 16 colour blocks from a pixel source. `px(x, y)` returns the
    /// 8-bit `(R, G, B)` at absolute frame coordinate `(x, y)`; `(ox, oy)` is the strip's
    /// top-left pixel. Each block's three planes are built in the codec's x64 fixed point via
    /// [`colour`] (per-pixel `(Y, Cb, Cr)`, stored `(Cr, Cb, Y)` for [`colour_block`]). Blocks are
    /// raster order within the strip (0..8 top 8-px half, 8..16 bottom), matching [`colour_strip`].
    ///
    /// `#[inline(never)]`: see `haar2d`'s doc comment -- part of the kernel-stack-overflow fix.
    /// Returns a **heap-allocated** `KVec` rather than `[ColourBlock; STRIP_BLOCKS]` by value
    /// (~6.5KB): a live crash (`BUG: TASK stack guard page was hit`, `CONFIG_VMAP_STACK`/
    /// `CONFIG_SCHED_STACK_END_CHECK`) showed that a large by-value array return does not
    /// reliably get constructed directly into the caller's slot (no guaranteed RVO in Rust) --
    /// `colour_frame_ep08`'s own frame held a second ~6.5KB copy of the same data on top of this
    /// function's, and being nested calls (not siblings), those frames coexist on the stack
    /// simultaneously rather than reusing space. Heap-allocating this one, genuinely large,
    /// per-strip buffer removes it from the stack entirely.
    #[inline(never)]
    fn colour_strip_blocks(
        ox: usize,
        oy: usize,
        px: &mut impl FnMut(usize, usize) -> (u8, u8, u8),
    ) -> Result<KVec<ColourBlock>> {
        let mut blocks = KVec::with_capacity(STRIP_BLOCKS, GFP_KERNEL)?;
        for k in 0..STRIP_BLOCKS {
            let (bx, by) = (k % STRIP_BLOCKS_X, k / STRIP_BLOCKS_X);
            let (mut cr, mut cb, mut y) = ([0i32; PIXELS], [0i32; PIXELS], [0i32; PIXELS]);
            for r in 0..DIM {
                for c in 0..DIM {
                    let (rr, gg, bb) = px(ox + bx * DIM + c, oy + by * DIM + r);
                    let (yv, cbv, crv) = colour(rr, gg, bb);
                    let i = r * DIM + c;
                    (cr[i], cb[i], y[i]) = (crv, cbv, yv);
                }
            }
            blocks.push(colour_block(&cr, &cb, &y), GFP_KERNEL)?;
        }
        Ok(blocks)
    }

    /// Encode a full `width`x`height` 8-bit-RGB frame into the Vino WHT **colour** EP08 transfer(s)
    /// -- the colour counterpart of the luma [`encode_frame`], and the assembler the live scanout
    /// path drives once the CP wall falls. `px(x, y)` yields the source pixel's `(R, G, B)`; the
    /// caller applies any rotation / gamma / format conversion (so this stays a pure codec). The
    /// surface is tiled into 64x16 strips in raster order, each built from [`colour_block`] +
    /// [`colour_strip`], and the strip stream is framed for the wire by [`frame_records`] using
    /// DLM's real EP08 TLV record layout (one record per single-Y band, each strip prefixed with
    /// its `strip_id == len`), then chunked into `<= 65536`-byte USB transfers. There is **no**
    /// per-transfer [`write_ep08_header`] (that older framing made the dock fault -- see
    /// [`frame_records`]). `seq0` is currently reserved (record-level `fseq` is left at 0 by
    /// `frame_records`) and returned unchanged as the next `seq`.
    ///
    /// `width`/`height` must be multiples of 64 and 16 (`EINVAL` otherwise) -- the codec's strip
    /// geometry; the live scanout path falls back to RLE for non-aligned modes (see
    /// `docs/VIDEO-TODO.md`). Byte-exact for the recovered colour grammar (chroma sync/DC/AC); the
    /// anti-fabrication boundary is the synthetic steepest-chroma edge cases (`VIDEO-TODO.md` 8/9).
    ///
    /// `#[inline(never)]`: see `haar2d`'s doc comment -- part of the kernel-stack-overflow fix.
    #[inline(never)]
    pub(crate) fn colour_frame_ep08(
        width: usize,
        height: usize,
        seq0: u32,
        mut px: impl FnMut(usize, usize) -> (u8, u8, u8),
    ) -> Result<(KVec<KVec<u8>>, u32)> {
        if width % STRIP_W != 0 || height % STRIP_H != 0 {
            return Err(kernel::error::code::EINVAL);
        }
        // Build every strip body (raster order; each strip's natural row1 tail, no echo).
        let mut strips: KVec<KVec<u8>> = KVec::new();
        let mut sy = 0usize;
        while sy < height {
            let mut sx = 0usize;
            while sx < width {
                let blocks = colour_strip_blocks(sx, sy, &mut px)?;
                strips.push(colour_strip(&blocks, sx as u16, sy as u16)?, GFP_KERNEL)?;
                sx += STRIP_W;
            }
            sy += STRIP_H;
        }
        Ok((frame_records(&strips)?, seq0))
    }

    /// A strip's `y` (the EP08 record bands group strips by row). Reads the `y` field the strip
    /// builders write at byte offset 4 ([`colour_strip`] / [`solid_strip`]).
    fn strip_y(s: &[u8]) -> u16 {
        u16::from_le_bytes([s[4], s[5]])
    }

    /// Frame a raster-ordered list of strip bodies into EP08 USB transfers using DLM's real wire
    /// record framing (RE'd 2026-06-28 from a passive capture of DLM's EP08 output):
    ///
    /// ```text
    /// record (one per single-Y band of strips):
    ///   u16 pad   = 0
    ///   u16 size  = total record length (TLV..trailer, excludes the inter-record gap)
    ///   u32 type  = 4
    ///   u8[8]     prefix = [flag=0, 0, fseq=0, 0, 0,0,0,0]
    ///   per strip: u16 strip_id (== strip length) ++ strip bytes
    ///   u8[4]     trailer = 0
    /// then u8[4] inter-record gap = 0; stride = size + 4.
    /// ```
    ///
    /// The record stream is then chunked into `<= 65024`-byte USB transfers **on record
    /// boundaries only** -- see the chunking loop's own comment below for why a mid-record split
    /// was changed to never happen (2026-07-17 HW finding).  There is **no** per-transfer header
    /// (the old `write_ep08_header sub=0x30` over concatenated strips was wrong and made the dock
    /// fault). `flag`/`fseq` are record-level metadata left at 0 (content-derivation is an open
    /// detail; the dock-visible structure is the per-strip `strip_id == len` and the TLV framing).
    pub(crate) fn frame_records(strips: &[KVec<u8>]) -> Result<KVec<KVec<u8>>> {
        const PREFIX: usize = 8;
        const TRAILER: usize = 4;
        const GAP: usize = 4;
        const SIZE_CAP: usize = 0x4000; // keep `size` well within u16; matches DLM's record sizes
        let mut stream: KVec<u8> = KVec::new();
        // End offset (including the trailing inter-record GAP) of each record built below -- used
        // by the chunking pass so a USB transfer boundary never falls inside a record.
        let mut record_ends: KVec<usize> = KVec::new();
        let mut i = 0usize;
        while i < strips.len() {
            let y0 = strip_y(&strips[i]);
            let rec = stream.len();
            stream.extend_from_slice(&[0u8; 8 + PREFIX], GFP_KERNEL)?; // TLV(8) + prefix(8)
            stream[rec + 4..rec + 8].copy_from_slice(&4u32.to_le_bytes()); // type = 4
            let mut n = 0usize;
            while i < strips.len() && strip_y(&strips[i]) == y0 {
                let s = &strips[i];
                let projected = (stream.len() - rec) + 2 + s.len() + TRAILER;
                if n > 0 && projected > SIZE_CAP {
                    break;
                }
                stream.extend_from_slice(&(s.len() as u16).to_le_bytes(), GFP_KERNEL)?;
                stream.extend_from_slice(s, GFP_KERNEL)?;
                n += 1;
                i += 1;
            }
            stream.extend_from_slice(&[0u8; TRAILER], GFP_KERNEL)?;
            let size = (stream.len() - rec) as u16;
            stream[rec + 2..rec + 4].copy_from_slice(&size.to_le_bytes());
            stream.extend_from_slice(&[0u8; GAP], GFP_KERNEL)?;
            record_ends.push(stream.len(), GFP_KERNEL)?;
        }
        // Chunk the continuous record stream into transfers, **never splitting a record across a
        // chunk boundary** (2026-07-17: HW-tested, a mid-record split -- the original design,
        // matching the "a chunk may fall mid-record; the dock reassembles the byte stream"
        // assumption below -- made the dock disconnect immediately on the very first chunk of a
        // real multi-chunk frame; see `project_scanout_disconnect_narrowed_to_ac_codec_20260717`).
        // Cap at 65024 (a non-multiple of the EP08 wMaxPacketSize of 1024) so every full chunk
        // still ends in a short packet without needing ZLP support (which the in-kernel sync path
        // lacks) -- now a soft cap: a chunk is closed as soon as adding the NEXT whole record
        // would exceed it, even if that leaves the chunk short of 65024.
        const CHUNK: usize = 65024; // 63.5 * 1024
        let mut frames: KVec<KVec<u8>> = KVec::new();
        let mut off = 0usize;
        let mut chunk_start = 0usize;
        for &end in record_ends.iter() {
            if chunk_start != off && end - chunk_start > CHUNK {
                let mut t: KVec<u8> = KVec::new();
                t.extend_from_slice(&stream[chunk_start..off], GFP_KERNEL)?;
                frames.push(t, GFP_KERNEL)?;
                chunk_start = off;
            }
            off = end;
        }
        if chunk_start < stream.len() {
            let mut t: KVec<u8> = KVec::new();
            t.extend_from_slice(&stream[chunk_start..stream.len()], GFP_KERNEL)?;
            frames.push(t, GFP_KERNEL)?;
        }
        Ok(frames)
    }
}

/// Length of the EP08 transport header ([`write_ep08_header`]).
pub(crate) const EP08_HDR_LEN: usize = 16;

/// Write the 16-byte EP08 transport header into `hdr` for a `payload_len`-byte codec
/// stream: `type=4 sub=0x30 sub_len_dw=0` sec 3 framing (matches the live capture).
/// `size = payload_len + 12`. Used by the in-place scanout path. `hdr` must be at
/// least 16 bytes.
///
/// The wire `size` field is 16-bit, so a frame is limited to `u16::MAX - 12` payload
/// bytes; a larger codec stream cannot be expressed in a single frame and returns
/// `EOVERFLOW` rather than silently truncating `size` (which would desync the dock's
/// parser). The mode-2/RLE diff encoder keeps per-pageflip updates well under this;
/// an incompressible full-frame update that exceeds it must be split by the caller.
pub(crate) fn write_ep08_header(hdr: &mut [u8], payload_len: usize, seq: u32) -> Result {
    let size = payload_len.checked_add(12).filter(|&s| s <= u16::MAX as usize);
    let size = size.ok_or(kernel::error::code::EOVERFLOW)?;
    hdr[0] = 0;
    hdr[1] = 0;
    hdr[2..4].copy_from_slice(&(size as u16).to_le_bytes());
    hdr[4..8].copy_from_slice(&4u32.to_le_bytes());
    hdr[8..10].copy_from_slice(&0x30u16.to_le_bytes());
    hdr[10..12].copy_from_slice(&0u16.to_le_bytes());
    hdr[12..16].copy_from_slice(&seq.to_le_bytes());
    Ok(())
}
