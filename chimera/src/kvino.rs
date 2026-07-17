//! The in-kernel vino control-plane code, compiled verbatim in userspace.
//!
//! [`cp`] and [`proto`] are the **actual kernel source files**
//! (`drivers/gpu/drm/vino/{cp,proto}.rs`) pulled in with `include!`. They see
//! the kernel-prelude shim ([`crate::kshim`]) through their own `use super::*;`,
//! so the AES-CTR seal, the Dl3Cmac, the wire framing and every CP message
//! builder are byte-for-byte the code that ships in `vino.ko`.
//!
//! The kernel marks those items `pub(super)` (module-private to the driver), so
//! this module re-exposes the ones the rig drives through thin `pub` wrappers.
//! The wrappers add no logic — they just call straight into the included code.

// Bring the shim (KVec/GFP_KERNEL/Result/Error/EINVAL, and the `crypto` +
// `bindings` modules) into scope as the parent the included files resolve
// `super::*` against.
pub use crate::kshim::*;

// The literal kernel files, loaded as real modules (so their inner `//!` docs and
// `#![allow(..)]` resolve natively). They live in `chimera/vino/`, vendored from
// the kernel tree by `scripts/sync-kernel-sources.sh` so this project builds
// standalone. Never hand-edit them: edit the kernel tree and re-run that script,
// or the byte-exactness these proofs rest on quietly stops meaning anything.

/// The literal kernel `proto.rs` (wire framing + plaintext session-init).
/// `dead_code` is allowed because the rig drives only the CP subset of the file.
#[path = "../vino/proto.rs"]
#[allow(dead_code)]
pub mod proto;

/// The literal kernel `cp.rs` (CP message builders + the AES-CTR/Dl3Cmac seal).
#[path = "../vino/cp.rs"]
pub mod cp;

/// The literal kernel `video.rs` (Vino WHT codec + EP08 transport framing).
/// `dead_code` is allowed because the rig drives only the solid-strip path.
#[path = "../vino/video.rs"]
#[allow(dead_code)]
pub mod video;

/// The literal kernel `ake.rs` (HDCP 2.2 AKE wire-layer message builders + IN
/// parser). Pure functions -- no kernel-only types -- so it joins the shim with
/// zero drift, exactly like `cp`/`proto`.
#[path = "../vino/ake.rs"]
#[allow(dead_code)]
pub mod ake;

/// The literal kernel `hdcp.rs` (HDCP 2.2 KDF: dKey/kd/H'/L'/V, RSA-OAEP km wrap,
/// SKE `Edkey(ks)`). Also pure -- built on the shimmed `crypto`/`rng`.
#[path = "../vino/hdcp.rs"]
#[allow(dead_code)]
pub mod hdcp;

// ---- thin pub wrappers over the kernel's pub(super) CP API ------------------
//
// `super::cp::*` items are `pub(in crate::kvino)`, hence visible here. Each
// wrapper is a one-liner delegating into the included kernel function.

/// `cp::seal_interactive` — type=4 sub=0x24 interactive frame (CTR + live Dl3Cmac).
pub fn seal_interactive(
    ks: &[u8; 16],
    riv: &[u8; 8],
    id: u16,
    wire_seq: u32,
    content: &[u8],
) -> Result<Vec<u8>> {
    Ok(cp::seal_interactive(ks, riv, id, wire_seq, content)?.into_vec())
}

/// `cp::seal_stream` — general AES-CTR seal under an arbitrary stream key/sub
/// (the cap-phase `wsub=0x04` frames).
pub fn seal_stream(
    key: &[u8; 16],
    riv: &[u8; 8],
    wsub: u16,
    seq: u32,
    inner: &[u8],
) -> Result<Vec<u8>> {
    Ok(cp::seal_stream(key, riv, wsub, seq, inner)?.into_vec())
}

/// `cp::open_in` — AES-CTR decrypt a frame body with the given riv/seq.
pub fn open_in(ks: &[u8; 16], riv: &[u8; 8], seq: u32, ct: &[u8]) -> Result<Vec<u8>> {
    Ok(cp::open_in(ks, riv, seq, ct)?.into_vec())
}

/// `cp::in_riv` — derive the dock→host riv from the host→dock riv (identity).
pub fn in_riv(out_riv: &[u8; 8]) -> [u8; 8] {
    cp::in_riv(out_riv)
}

/// `cp::aux_for_id` — the per-inner-id wire-header `aux` constant.
pub fn aux_for_id(id: u16, body_len: usize) -> u16 {
    cp::aux_for_id(id, body_len)
}

/// `cp::dl3cmac_tag` — the DisplayLink CP integrity tag.
pub fn dl3cmac_tag(
    ks: &[u8; 16],
    riv: &[u8; 8],
    wire_seq: u64,
    ciphertext: &[u8],
) -> Result<[u8; 16]> {
    cp::dl3cmac_tag(ks, riv, wire_seq, ciphertext)
}

/// `cp::heartbeat` — OUT `id=0x16 sub=0x75` keepalive inner plaintext.
pub fn heartbeat(counter: u16) -> Result<Vec<u8>> {
    Ok(cp::heartbeat(counter)?.into_vec())
}

/// `cp::get_edid_req` — OUT `id=0x15 sub=0x21` EDID-read request inner plaintext.
pub fn get_edid_req(counter: u16) -> Result<Vec<u8>> {
    Ok(cp::get_edid_req(counter)?.into_vec())
}

/// `cp::get_edid_req_sub` — OUT `id=0x15` EDID-family request with an explicit sub
/// (`0x20` readiness probe / `0x21` fetch).
pub fn get_edid_req_sub(counter: u16, sub: u16) -> Result<Vec<u8>> {
    Ok(cp::get_edid_req_sub(counter, sub)?.into_vec())
}

/// `cp::device_query_req` — OUT `id=0x14` device-status/capability query with an
/// explicit sub (`0x0000` one-shot capability query / `0x000c` repeated status poll).
pub fn device_query_req(counter: u16, sub: u16) -> Result<Vec<u8>> {
    Ok(cp::device_query_req(counter, sub)?.into_vec())
}

/// `cp::edid_engage_req` — OUT `id=0x16 sub=0x0023` EDID-engage, sent (twice) once
/// early placeholder fetches keep failing, right before the long status-poll run.
pub fn edid_engage_req(counter: u16) -> Result<Vec<u8>> {
    Ok(cp::edid_engage_req(counter)?.into_vec())
}

/// `cp::edid_poll_ready` — decode an `id=0x0044 sub=0x0020` EDID-readiness probe
/// reply and report whether the dock's downstream DDC/EDID read has finished
/// (inner byte offset 26, `0x00` busy -> `0x80` ready). `None` if `wire` isn't a
/// decryptable `sub=0x0020` reply at all.
pub fn edid_poll_ready(ks: &[u8; 16], out_riv: &[u8; 8], wire: &[u8]) -> Option<bool> {
    cp::edid_poll_ready(ks, out_riv, wire)
}

/// `cp::cursor_create` inner plaintext.
pub fn cursor_create(counter: u16, head: u8, w: u16, h: u16) -> Result<Vec<u8>> {
    Ok(cp::cursor_create(counter, head, w, h)?.into_vec())
}

/// `cp::cursor_move` inner plaintext.
pub fn cursor_move(counter: u16, head: u8, x: u16, y: u16) -> Result<Vec<u8>> {
    Ok(cp::cursor_move(counter, head, x, y)?.into_vec())
}

/// `cp::cursor_image` inner plaintext (32-byte header + `w*h*4` BGRA bitmap).
pub fn cursor_image(counter: u16, head: u8, w: u16, h: u16, bgra: &[u8]) -> Result<Vec<u8>> {
    Ok(cp::cursor_image(counter, head, w, h, bgra)?.into_vec())
}

/// `cp::reply_info` — decode a dock→host frame's inner `(id, sub, ictr)`.
pub fn reply_info(ks: &[u8; 16], out_riv: &[u8; 8], wire: &[u8]) -> Option<(u16, u16, u16)> {
    cp::reply_info(ks, out_riv, wire)
}

/// `cp::parse_edid_from_reply` — pull the EDID blob from a dock EDID reply frame.
pub fn parse_edid_from_reply(
    ks: &[u8; 16],
    out_riv: &[u8; 8],
    wire: &[u8],
) -> Result<Option<Vec<u8>>> {
    Ok(cp::parse_edid_from_reply(ks, out_riv, wire)?.map(|v| v.into_vec()))
}

// ---- video: solid-colour frame builder over the kernel WHT codec ------------

/// Vino strip geometry: each `solid_strip` covers a 64-px-wide × 16-px-tall tile.
pub const STRIP_W: u16 = 64;
pub const STRIP_H: u16 = 16;
/// EP08 transport-header length (`video::EP08_HDR_LEN`).
pub const EP08_HDR_LEN: usize = video::EP08_HDR_LEN;
/// Max codec payload per EP08 frame (the wire `size` field is u16; `size =
/// payload + 12`, so payload ≤ u16::MAX − 12). Frames are split at strip
/// boundaries to stay under this.
pub const EP08_MAX_PAYLOAD: usize = u16::MAX as usize - 12;

/// `video::wht::colour` — the Vino integer colour transform
/// `(Y=16R+32G+16B, Cb=64(R−G), Cr=64(B−G))`, yielding the per-plane DC values.
pub fn colour(r: u8, g: u8, b: u8) -> (i32, i32, i32) {
    video::wht::colour(r, g, b)
}

/// One byte-exact solid 64×16 strip at `(x,y)` for the given per-plane DCs,
/// straight from the kernel `video::wht::solid_strip`.
pub fn solid_strip(x: u16, y: u16, ydc: i32, cbdc: i32, crdc: i32) -> Result<Vec<u8>> {
    Ok(video::wht::solid_strip(x, y, ydc, cbdc, crdc)?.into_vec())
}

/// `video::write_ep08_header` — the 16-byte `type=4 sub=0x30` EP08 transport header.
pub fn write_ep08_header(hdr: &mut [u8], payload_len: usize, seq: u32) -> Result {
    video::write_ep08_header(hdr, payload_len, seq)
}

/// `video::wht::strip` — encode one 64×16 strip from its 16 blocks' luma coeffs (the
/// general byte-exact luma path: solid / varying-DC / AC). Exposed so the RE harness
/// can generate a ground-truth strip and validate the wire decoder against it.
pub fn strip(blocks: &[[i32; 32]; 16], x: u16, y: u16) -> Result<Vec<u8>> {
    Ok(video::wht::strip(blocks, x, y)?.into_vec())
}

/// `video::wht::colour_strip` driven from 16 blocks of three raw planes (each 64 samples in
/// the codec's ×64 fixed point: `[Cr=64*(B-G), Cb=64*(R-G), Y=64*G+64*((Cb+Cr)>>2)]`). Runs the
/// LITERAL kernel `colour_block` + `colour_strip`, so the RE harness can prove the in-kernel
/// colour codec byte-exact against real DLM sink strips.
pub fn colour_strip_from_planes(planes: &[[[i32; 64]; 3]; 16], x: u16, y: u16) -> Result<Vec<u8>> {
    let blocks: [video::wht::ColourBlock; 16] = core::array::from_fn(|k| {
        video::wht::colour_block(&planes[k][0], &planes[k][1], &planes[k][2])
    });
    Ok(video::wht::colour_strip(&blocks, x, y)?.into_vec())
}

/// `video::wht::colour_frame_ep08` driven from a packed 8-bit RGB frame (`width*height*3`
/// bytes, R,G,B raster order). Runs the LITERAL kernel colour FRAME assembler (strip tiling +
/// forward-hint tail chaining + EP08 split), so the rig can prove the in-kernel colour frame
/// path, not just individual strips. Returns the ready-to-send EP08 frames and the next `seq`.
pub fn colour_frame_ep08(
    width: usize,
    height: usize,
    rgb: &[u8],
    seq0: u32,
) -> Result<(Vec<Vec<u8>>, u32)> {
    let (frames, seq) = video::wht::colour_frame_ep08(width, height, seq0, |x, y| {
        let i = (y * width + x) * 3;
        (rgb[i], rgb[i + 1], rgb[i + 2])
    })?;
    Ok((frames.into_vec().into_iter().map(|f| f.into_vec()).collect(), seq))
}

/// One byte-exact colour 64×16 strip at `(x,y)` from 16 blocks of three raw planes (each 64
/// samples in the codec's ×64 fixed point, `[Cr, Cb, Y]`), via the kernel `colour_strip`. Same
/// as [`colour_strip_from_planes`] but exposed for the frame-assembler proof to reconstruct each
/// strip independently and check the assembler matches it (tail aside).
pub fn colour_strip_blocks(planes: &[[[i32; 64]; 3]; 16], x: u16, y: u16) -> Result<Vec<u8>> {
    colour_strip_from_planes(planes, x, y)
}

/// `video::wht::transform` + `quantize` for one 8×8 plane (values already in the
/// codec's ×64 fixed point), returning the 32 quantized coeffs.
pub fn transform_quantize(plane: &[i32; 64]) -> [i32; 32] {
    let c = video::wht::transform(plane);
    let mut q = [0i32; 32];
    for i in 0..32 {
        q[i] = video::wht::quantize(c[i], i);
    }
    q
}

/// Build the EP08 frames that paint a whole `width`×`height` surface a single flat
/// colour, using the kernel solid-strip codec and the **literal kernel record framer**
/// ([`video::wht::frame_records`]): the surface is tiled into 64×16 strips in raster order
/// and handed to the same per-strip TLV record framing DLM puts on the wire (one record per
/// single-Y band, `strip_id == strip length`, chunked into ≤64 KB transfers). Returns the
/// ready-to-send EP08 transfers and the (unchanged) `seq`.
///
/// `width`/`height` must be multiples of 64 and 16.
pub fn solid_frame_ep08(
    width: u16,
    height: u16,
    rgb: (u8, u8, u8),
    seq0: u32,
) -> Result<(Vec<Vec<u8>>, u32)> {
    if width % STRIP_W != 0 || height % STRIP_H != 0 {
        return Err(crate::kshim::EINVAL);
    }
    let (ydc, cbdc, crdc) = colour(rgb.0, rgb.1, rgb.2);
    let mut strips: KVec<KVec<u8>> = KVec::new();
    let mut y = 0u16;
    while y < height {
        let mut x = 0u16;
        while x < width {
            strips.push(video::wht::solid_strip(x, y, ydc, cbdc, crdc)?, GFP_KERNEL)?;
            x += STRIP_W;
        }
        y += STRIP_H;
    }
    let frames = video::wht::frame_records(&strips)?;
    let mut out: Vec<Vec<u8>> = frames.into_vec().into_iter().map(|f| f.into_vec()).collect();
    out = patch_record_meta(out);
    Ok((out, seq0))
}

/// TEST-ONLY (chimera): override the per-record `flag` (off8) and/or `fseq` (off10) bytes in the
/// assembled EP08 record stream, controlled by env `VID_FLAG` / `VID_FSEQ` (decimal). The kernel
/// `frame_records` emits flag=0/fseq=0; DLM uses flag∈{0,1,0x11} (keyframe/delta/last markers) and
/// content-derived even `fseq`. This lets us HW-sweep those values to find what the dock's decoder
/// requires without recompiling the kernel codec. Records are walked on the reassembled stream
/// (cuts fall mid-record) and the stream is re-chunked at 64 KB exactly like `frame_records`.
fn patch_record_meta(frames: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let flag = std::env::var("VID_FLAG").ok().and_then(|s| s.parse::<u8>().ok());
    let fseq = std::env::var("VID_FSEQ").ok().and_then(|s| s.parse::<u8>().ok());
    if flag.is_none() && fseq.is_none() {
        return frames;
    }
    let mut stream: Vec<u8> = Vec::new();
    for f in &frames {
        stream.extend_from_slice(f);
    }
    // Walk records: pad(2)=0, size(2), type(4)=4, prefix(8)[flag,0,fseq,..]; stride = size+4.
    let mut off = 0usize;
    while off + 16 <= stream.len() {
        let pad = u16::from_le_bytes([stream[off], stream[off + 1]]);
        let size = u16::from_le_bytes([stream[off + 2], stream[off + 3]]) as usize;
        let typ = u32::from_le_bytes([stream[off + 4], stream[off + 5], stream[off + 6], stream[off + 7]]);
        if pad != 0 || typ != 4 || size == 0 || off + size > stream.len() {
            break;
        }
        if let Some(fl) = flag {
            stream[off + 8] = fl;
        }
        if let Some(fs) = fseq {
            stream[off + 10] = fs;
        }
        off += size + 4;
    }
    // Re-chunk at 64 KB (matches frame_records).
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut o = 0usize;
    while o < stream.len() {
        let end = core::cmp::min(o + 65536, stream.len());
        out.push(stream[o..end].to_vec());
        o = end;
    }
    out
}

// ---- thin pub wrappers over the kernel's pub(super) AKE/HDCP API -----------
//
// Same pattern as the CP wrappers above: `ake`/`hdcp` items are `pub(super)`
// inside the included kernel files, i.e. visible here (in `kvino`) but not
// outside it -- and NOTE that "outside it" includes other crates in this same
// Cargo workspace/package: each `[[bin]]` target compiles as its own crate
// linking `vino-chimera` as an external dependency, so even `pub(crate)` items
// (like `ake::id`) are invisible from `src/bin/*.rs`. Every item the
// orchestration binaries need gets a genuine `pub` wrapper here.

/// HDCP 2.2 message IDs (`ake::id` is `pub(crate)`, invisible from the `[[bin]]`
/// targets -- see the note above). Values copied by reference from the
/// literal kernel constants, not re-stated, so they can't drift.
pub mod id {
    use super::ake::id as k;
    pub const AKE_INIT: u8 = k::AKE_INIT;
    pub const AKE_SEND_CERT: u8 = k::AKE_SEND_CERT;
    pub const AKE_NO_STORED_KM: u8 = k::AKE_NO_STORED_KM;
    pub const AKE_SEND_H_PRIME: u8 = k::AKE_SEND_H_PRIME;
    pub const AKE_SEND_PAIRING_INFO: u8 = k::AKE_SEND_PAIRING_INFO;
    pub const LC_INIT: u8 = k::LC_INIT;
    pub const LC_SEND_L_PRIME: u8 = k::LC_SEND_L_PRIME;
    pub const SKE_SEND_EKS: u8 = k::SKE_SEND_EKS;
    pub const REPEATERAUTH_SEND_RECEIVERID_LIST: u8 = k::REPEATERAUTH_SEND_RECEIVERID_LIST;
    pub const REPEATERAUTH_SEND_ACK: u8 = k::REPEATERAUTH_SEND_ACK;
    pub const REPEATERAUTH_STREAM_MANAGE: u8 = k::REPEATERAUTH_STREAM_MANAGE;
    pub const REPEATERAUTH_STREAM_READY: u8 = k::REPEATERAUTH_STREAM_READY;
    pub const AKE_SEND_RRX: u8 = k::AKE_SEND_RRX;
    pub const RECEIVER_AUTH_STATUS: u8 = k::RECEIVER_AUTH_STATUS;
    pub const AKE_TRANSMITTER_INFO: u8 = k::AKE_TRANSMITTER_INFO;
    pub const AKE_RECEIVER_INFO: u8 = k::AKE_RECEIVER_INFO;
}

/// `proto::init_0`/`init_25`/`init_4_probe` — the plaintext session-init
/// messages (`pub(super)` in the kernel file, hence the wrapper).
pub fn init_0() -> Result<Vec<u8>> {
    Ok(proto::init_0()?.into_vec())
}
pub fn init_25() -> Result<Vec<u8>> {
    Ok(proto::init_25()?.into_vec())
}
pub fn init_4_probe() -> Result<Vec<u8>> {
    Ok(proto::init_4_probe()?.into_vec())
}
pub fn probe_resend() -> Result<Vec<u8>> {
    Ok(proto::probe_resend()?.into_vec())
}

/// `cp::seal_livemac` — seal `msg0` (fresh live Dl3Cmac over live content,
/// reusing a captured wire header's `seq`/`aux`). See `cp.rs` for the formula.
pub fn seal_livemac(ks: &[u8; 16], riv: &[u8; 8], header: &[u8], content: &[u8]) -> Result<Vec<u8>> {
    Ok(cp::seal_livemac(ks, riv, header, content)?.into_vec())
}

pub fn ake_init(hdcp_seq: u32, seq: u32, rtx: &[u8; 8], tx_caps: &[u8; 3]) -> Result<Vec<u8>> {
    Ok(ake::ake_init(hdcp_seq, seq, rtx, tx_caps)?.into_vec())
}
pub fn ake_transmitter_info(hdcp_seq: u32, seq: u32) -> Result<Vec<u8>> {
    Ok(ake::ake_transmitter_info(hdcp_seq, seq)?.into_vec())
}
pub fn ake_no_stored_km(hdcp_seq: u32, seq: u32, ekpub_km: &[u8; 128]) -> Result<Vec<u8>> {
    Ok(ake::ake_no_stored_km(hdcp_seq, seq, ekpub_km)?.into_vec())
}
pub fn lc_init(hdcp_seq: u32, seq: u32, rn: &[u8; 8]) -> Result<Vec<u8>> {
    Ok(ake::lc_init(hdcp_seq, seq, rn)?.into_vec())
}
pub fn ske_send_eks(hdcp_seq: u32, seq: u32, edkey_ks: &[u8; 16], riv: &[u8; 8]) -> Result<Vec<u8>> {
    Ok(ake::ske_send_eks(hdcp_seq, seq, edkey_ks, riv)?.into_vec())
}
pub fn repeater_auth_send_ack(hdcp_seq: u32, seq: u32, v: &[u8; 16]) -> Result<Vec<u8>> {
    Ok(ake::repeater_auth_send_ack(hdcp_seq, seq, v)?.into_vec())
}
pub fn repeater_auth_stream_manage(hdcp_seq: u32, seq: u32, type0: bool) -> Result<Vec<u8>> {
    Ok(ake::repeater_auth_stream_manage(hdcp_seq, seq, type0)?.into_vec())
}
/// `ake::parse_in` — parse an IN HDCP body into `(msg_id, payload)`.
pub fn ake_parse_in(body: &[u8]) -> Option<(u8, &[u8])> {
    ake::parse_in(body)
}

pub fn derive_kd(km: &[u8; 16], rtx: &[u8; 8], rrx: &[u8; 8]) -> Result<[u8; 32]> {
    hdcp::derive_kd(km, rtx, rrx)
}
pub fn compute_h(kd: &[u8; 32], rtx: &[u8; 8], repeater: bool) -> [u8; 32] {
    hdcp::compute_h(kd, rtx, repeater)
}
pub fn compute_l(kd: &[u8; 32], rrx: &[u8; 8], rn: &[u8; 8]) -> [u8; 32] {
    hdcp::compute_l(kd, rrx, rn)
}
pub fn compute_v_full(kd: &[u8; 32], list_header: &[u8]) -> [u8; 32] {
    hdcp::compute_v_full(kd, list_header)
}
pub fn oaep_encrypt_km(modulus: &[u8; 128], exponent: &[u8], km: &[u8; 16]) -> Result<[u8; 128]> {
    hdcp::oaep_encrypt_km(modulus, exponent, km)
}
pub fn compute_eks(
    km: &[u8; 16],
    rtx: &[u8; 8],
    rrx: &[u8; 8],
    rn: &[u8; 8],
    ks: &[u8; 16],
) -> Result<[u8; 16]> {
    hdcp::compute_eks(km, rtx, rrx, rn, ks)
}
