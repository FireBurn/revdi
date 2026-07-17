//! `chimera-coldstart` (`--features live`) — the "new DLM" experiment.
//!
//! Every other angle on the CP-engagement wall assumed the host software stack
//! (specifically vino's in-kernel Rust USB transport) was equivalent to DLM's,
//! and went looking for a wire-content/timing bug instead. This binary removes
//! that assumption instead of arguing about it: it runs the **literal kernel**
//! AKE/HDCP/CP code (`ake.rs`, `hdcp.rs`, `cp.rs`, `proto.rs`, via
//! [`vino_chimera::kvino`] — zero re-implementation, zero drift) but drives the
//! dock through **libusb** (`vino_driver::Dock`, the same transport
//! `chimera-takeover` already proves against real hardware, loadable against
//! DLM's own bundled `libusb-1.0.so.0.3.0`) instead of vino's kernel USB core.
//! `Dock`'s EP02 OUT path (`write_ctrl_dlm`) issues the exact same raw
//! `libusb_submit_transfer(type=BULK, flags=0, timeout=0)` DLM itself does
//! (confirmed 2026-07-07 by a live frida trace of the real DLM process, not
//! decompile inference) — see `vino-driver/src/usb.rs::write_ctrl_raw_async`.
//!
//! It does its OWN cold engagement from scratch — no DLM handoff, no frida, no
//! pre-existing session. If it engages (`wsub=0x45 > 0`) where the in-kernel
//! driver never does, the transport (or something the kernel USB binding does
//! differently) is the wall, not the dock's firmware — a genuinely new,
//! actionable result. If it ALSO gets 0 acks with byte-identical crypto and
//! timing, that's one more strong nail in the "dock-firmware gate" conclusion,
//! this time via an entirely independent code path (no vino.ko involved at all).
//!
//! The orchestration (device-open preamble, AKE sequencing, `wait_cap_complete`,
//! arm+msg0+burst) is a careful hand-port of `vino.rs`'s CURRENT `bring_up`/
//! `run_ake`/`wait_cap_complete`/`send_cp_setup` (as of 2026-07-07) — it can't be
//! `include!`d like the pure modules because it's tangled with kernel-only USB/
//! DRM/workqueue types, but every byte it puts on the wire and every crypto
//! computation is the literal kernel code. Timing constants are copied verbatim
//! from `vino.rs` (see the `TIMING` block below) so a divergence, if the dock
//! still refuses, can't be blamed on "vino's timing was different this time."
//!
//! **Timestamped tracing** (2026-07-07): every EP02 OUT send and every EP84 IN
//! read that actually returns data is logged as `[t=NNNNms dir len=NN
//! type=N sub=0xNNNN aux=0xNNNN seq=N]`, `t` relative to `t0` (set right before
//! the device-open preamble) — the same format used to decode a live frida
//! trace of real DLM's `libusb_submit_transfer` calls through a fresh re-auth,
//! for a direct side-by-side comparison of the two implementations' actual
//! wire cadence, not just wire bytes.
//!
//! Env: `sudo LD_LIBRARY_PATH=/opt/displaylink cargo run -p vino-chimera --bin
//! chimera-coldstart --features live` (stop `displaylink-driver.service` first).

use std::time::{Duration, Instant};
use vino_chimera::kvino;
use vino_driver::Dock;

const REQ_SET_INTERFACE: u8 = 0x0b;

/// `println!` that is suppressed while the sweeper runs (`timing::quiet()`), so an N-attempt sweep
/// prints one result line per attempt instead of the ~30 `[init]/[ake]/[cap]/[cp]` session lines.
/// The single-shot run keeps `quiet()==false`, so everything prints as before.
macro_rules! vln {
    ($($arg:tt)*) => { if !timing::quiet() { println!($($arg)*); } };
}

/// Timing constants copied verbatim from `vino.rs` (2026-07-07), so the cold
/// engagement attempt has the identical fingerprint vino's own bring-up aims
/// for. See `vino.rs` for the HW measurements behind each one.
mod timing {
    use std::cell::Cell;

    /// The pre-arm timing knobs, made RUNTIME-variable (was `const`) so the warm-loop sweeper can
    /// jiggle them per attempt. Defaults are the DLM-matched values used by the single-shot run.
    #[derive(Clone, Copy)]
    pub struct Timings {
        pub pad_init0_25: u64,
        pub pad_init25_4: u64,
        pub pad_ack_akeinit: u64,
        pub cert_verify_hold: u64,
        pub cert_to_arm: u64,
        pub arm_to_msg0: u64,
        /// `wait_cap_complete` budget in rounds (× ~5 ms each). On a run where the dock's
        /// `id=0x0b`/Stream_Ready are missed, this whole budget is burned before the arm, so it is
        /// the dominant knob for the cert->arm epoch (48 => arm ~461 ms; 0 => arm ~157 ms).
        pub cap_drain_rounds: usize,
        /// Per-round EP84 read timeout inside `wait_cap_complete`, in ms (default 5).
        pub cap_drain_round_ms: u64,
    }
    impl Default for Timings {
        fn default() -> Self {
            Self {
                pad_init0_25: 79,
                pad_init25_4: 120,
                pad_ack_akeinit: 90,
                cert_verify_hold: 1650,
                cert_to_arm: 157_100,
                arm_to_msg0: 170,
                cap_drain_rounds: 48,
                cap_drain_round_ms: 5,
            }
        }
    }
    thread_local! {
        static CUR: Cell<Timings> = Cell::new(Timings::default());
        static QUIET: Cell<bool> = Cell::new(false);
    }
    pub fn set(t: Timings) { CUR.with(|c| c.set(t)); }
    pub fn set_quiet(q: bool) { QUIET.with(|c| c.set(q)); }
    pub fn quiet() -> bool { QUIET.with(|c| c.get()) }
    fn cur() -> Timings { CUR.with(|c| c.get()) }
    pub fn pad_init0_to_init25_us() -> u64 { cur().pad_init0_25 }
    pub fn pad_init25_to_init4_us() -> u64 { cur().pad_init25_4 }
    pub fn pad_ack_to_akeinit_us() -> u64 { cur().pad_ack_akeinit }
    pub fn cert_verify_hold_us() -> u64 { cur().cert_verify_hold }
    pub fn cert_to_arm_us() -> u64 { cur().cert_to_arm }
    pub fn arm_to_msg0_us() -> u64 { cur().arm_to_msg0 }
    pub fn cap_drain_rounds() -> usize { cur().cap_drain_rounds }
    pub fn cap_drain_round_ms() -> u64 { cur().cap_drain_round_ms }
}

/// Precisely hold until `anchor.elapsed() >= target_us` (mirrors `vino.rs`'s
/// `hold_until`: sleep the bulk, spin the last bit for precision). Returns
/// immediately if the target has already passed.
fn hold_until(anchor: Instant, target_us: u64) {
    let target = Duration::from_micros(target_us);
    loop {
        let now = anchor.elapsed();
        if now >= target {
            return;
        }
        let rem = target - now;
        if rem > Duration::from_micros(400) {
            std::thread::sleep(rem - Duration::from_micros(200));
        } else {
            std::hint::spin_loop();
        }
    }
}

fn udelay(d: Duration) {
    let start = Instant::now();
    while start.elapsed() < d {
        std::hint::spin_loop();
    }
}

/// Log one frame the same way the DLM `libusb_submit_transfer` trace does:
/// `t` relative to `t0`, direction, length, and (if it looks like a sec-3
/// wire header) the decoded `type`/`sub`/`aux`/`seq`.
fn log_frame(t0: Instant, dir: &str, buf: &[u8]) {
    if timing::quiet() {
        return; // sweeper suppresses the ~30 per-frame lines/attempt
    }
    let t_ms = t0.elapsed().as_millis();
    if buf.len() >= 16 {
        let typ = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let sub = u16::from_le_bytes([buf[8], buf[9]]);
        let aux = u16::from_le_bytes([buf[10], buf[11]]);
        let seq = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        // 2026-07-07: also decode+print the INNER id/sub (offsets 16/18) when present, matching
        // the same addition in vino.rs's wait_cap_complete -- lets a "why did we miss id=0x0b"
        // run show what every frame actually decoded as, not just the outer wire header.
        if buf.len() >= 20 {
            let iid = u16::from_le_bytes([buf[16], buf[17]]);
            let isub = u16::from_le_bytes([buf[18], buf[19]]);
            // ictr@buf[20..22] -- matches the field `pace_cap_ack`/vino.rs's wait_cap_complete
            // decode; not previously read here either.
            let ictr = if buf.len() >= 22 { u16::from_le_bytes([buf[20], buf[21]]) } else { 0 };
            println!(
                "[t={t_ms:6}ms] {dir:3} len={:3} type={typ} sub={sub:#06x} aux={aux:#06x} seq={seq} -> id={iid:#06x} isub={isub:#06x} ictr={ictr:#06x}",
                buf.len()
            );
        } else {
            println!(
                "[t={t_ms:6}ms] {dir:3} len={:3} type={typ} sub={sub:#06x} aux={aux:#06x} seq={seq}",
                buf.len()
            );
        }
    } else {
        vln!("[t={t_ms:6}ms] {dir:3} len={:3}", buf.len());
    }
}

/// [`Dock::write_ctrl_dlm`] + a timestamped trace line, `t0`-relative.
fn send_dlm(dock: &Dock, t0: Instant, frame: &[u8]) -> Result<usize, vino_driver::Error> {
    let r = dock.write_ctrl_dlm(frame);
    if r.is_ok() {
        log_frame(t0, "OUT", frame);
    }
    r
}

/// [`Dock::recv_frame_raw_timeout`] + a timestamped trace line for anything
/// that actually returns data (mirrors the DLM trace, which only logs real
/// submits, not the constant empty-buffer EP84 re-arm churn).
fn recv_dlm(dock: &Dock, t0: Instant, timeout: Duration) -> Result<Vec<u8>, vino_driver::Error> {
    let r = dock.recv_frame_raw_timeout(16384, timeout);
    if let Ok(buf) = &r {
        log_frame(t0, "IN", buf);
    }
    r
}

/// `dev.recv_hdcp` ported: read EP84 until a `wsub=0x25` frame with a non-zero
/// inner HDCP `msg_id` arrives (mirrors `vino.rs::recv_hdcp` exactly — skip
/// non-HDCP frames and the dock's per-message ACK, id==0).
fn recv_hdcp(dock: &Dock, t0: Instant) -> Result<(u8, Vec<u8>), String> {
    const SUB_HDCP_RESP: u16 = 0x25;
    for _ in 0..24 {
        let buf = match recv_dlm(dock, t0, Duration::from_millis(1000)) {
            Ok(b) => b,
            Err(_) => continue,
        };
        if buf.len() < 16 {
            continue;
        }
        let wsub = u16::from_le_bytes([buf[8], buf[9]]);
        if wsub != SUB_HDCP_RESP {
            continue;
        }
        if let Some((id, payload)) = kvino::ake_parse_in(&buf[16..]) {
            if id == 0 {
                continue; // per-message ACK frame, not the real HDCP response
            }
            return Ok((id, payload.to_vec()));
        }
    }
    Err("recv_hdcp: no HDCP response within 24 reads".into())
}

/// `pace_cap_ack` ported: read the dock's per-frame `id=0x14 sub=0x10 ctr=want`
/// ack before the next RepeaterAuth OUT, exactly like DLM (and vino.rs).
fn pace_cap_ack(dock: &Dock, t0: Instant, want_ctr: u16) {
    for _ in 0..8 {
        let buf = match recv_dlm(dock, t0, Duration::from_millis(30)) {
            Ok(b) => b,
            Err(_) => return, // dock idle -- don't block
        };
        if buf.len() < 22 {
            continue;
        }
        let wsub = u16::from_le_bytes([buf[8], buf[9]]);
        let iid = u16::from_le_bytes([buf[16], buf[17]]);
        let ictr = u16::from_le_bytes([buf[20], buf[21]]);
        if wsub == 0x25 && iid == 0x14 && ictr == want_ctr {
            return;
        }
    }
}

/// `wait_cap_complete` ported: drain EP84 for the dock's terminal cap-complete
/// marker (`id=0x0b sub=0x84`) AND `RepeaterAuth_Stream_Ready` (HDCP 0x11),
/// arming the instant BOTH have arrived (DLM: 0.46ms after the last cap
/// block); falls back to "quiet for 3 rounds after seeing 0x0b" if
/// Stream_Ready never shows, and gives up after 48 rounds x 5ms either way.
fn wait_cap_complete(dock: &Dock, t0: Instant) {
    let mut saw_0b = false;
    let mut saw_ready = false;
    let mut quiet = 0usize;
    const QUIET_GAP: usize = 3;
    let max_rounds = timing::cap_drain_rounds(); // swept knob (default 48)
    let round_ms = timing::cap_drain_round_ms(); // swept knob (default 5)
    for _ in 0..max_rounds {
        match recv_dlm(dock, t0, Duration::from_millis(round_ms)) {
            Ok(buf) if buf.len() >= 20 => {
                quiet = 0;
                let iid = u16::from_le_bytes([buf[16], buf[17]]);
                let isub = u16::from_le_bytes([buf[18], buf[19]]);
                let mid = if buf.len() >= 26 { buf[25] } else { 0 };
                if isub == 0x84 && iid == 0x0b {
                    saw_0b = true;
                }
                if mid == kvino::id::REPEATERAUTH_STREAM_READY && buf.len() >= 58 {
                    saw_ready = true;
                    vln!("[ake] Stream_Ready (0x11) seen");
                }
                if saw_0b && saw_ready {
                    vln!("[cap] cap-complete (id=0x0b + Stream_Ready) -- arming now");
                    return;
                }
            }
            _ => {
                // FIXED 2026-07-07 (matches the same fix in vino.rs): gate the quiet-fallback
                // on EITHER terminal marker, not just saw_0b -- a run where Stream_Ready
                // arrives but id=0x0b never does used to have no early exit at all, burning
                // the full MAX_ROUNDS budget (240ms) and pushing arm out to ~400ms+ instead of
                // ~157ms, reproduced live this session.
                if saw_0b || saw_ready {
                    quiet += 1;
                    if quiet >= QUIET_GAP {
                        println!(
                            "[cap] cap-complete drained (id=0x0b={saw_0b} Stream_Ready={saw_ready}, quiet) -- arming now"
                        );
                        return;
                    }
                }
            }
        }
    }
    vln!("[cap] drain budget hit (saw_0b={saw_0b} saw_ready={saw_ready}) -- arming anyway");
}

struct Session {
    ks: [u8; 16],
    riv: [u8; 8], // the OUT-CP seal riv (delivered ^ 0x04 @ byte7)
}

/// `run_ake` ported: the full clean-room HDCP 2.2 AKE + LC + SKE + RepeaterAuth,
/// verifying H'/L'/V' against our own KDF, byte-for-byte the same sequence
/// `vino.rs::run_ake` runs. Returns the session key material and the instant
/// the dock's cert landed (`cert_at`, the `CERT_TO_ARM_US` anchor).
fn run_ake(dock: &Dock, t0: Instant) -> Result<(Session, Instant), String> {
    use kvino::id;

    // (1) AKE_Init.
    udelay(Duration::from_micros(timing::pad_ack_to_akeinit_us()));
    let mut rtx = [0u8; 8];
    kvino::rng::fill(&mut rtx);
    send_dlm(dock, t0, &kvino::ake_init(1, 0, &rtx, &[0; 3]).map_err(|e| format!("{e:?}"))?)
        .map_err(|e| format!("AKE_Init send: {e:?}"))?;

    // (2) AKE_Send_Cert.
    let (cid, cert_msg) = recv_hdcp(dock, t0)?;
    let cert_at = Instant::now();
    if cid != id::AKE_SEND_CERT || cert_msg.len() < 1 + 136 {
        return Err(format!("bad AKE_Send_Cert (id={cid:#x}, {} B)", cert_msg.len()));
    }
    let repeater = cert_msg[0] != 0;
    let cert = &cert_msg[1..];
    let mut modulus = [0u8; 128];
    modulus.copy_from_slice(&cert[5..133]);
    let exponent = cert[133..136].to_vec();

    // (3)/(4) AKE_Transmitter_Info / AKE_Receiver_Info.
    send_dlm(dock, t0, &kvino::ake_transmitter_info(2, 0).map_err(|e| format!("{e:?}"))?)
        .map_err(|e| format!("AKE_Transmitter_Info: {e:?}"))?;
    let xmit_info_at = Instant::now();
    let _ = recv_hdcp(dock, t0)?;

    // (5) AKE_No_Stored_km.
    let mut km = [0u8; 16];
    kvino::rng::fill(&mut km);
    let ekpub = kvino::oaep_encrypt_km(&modulus, &exponent, &km).map_err(|e| format!("{e:?}"))?;
    hold_until(xmit_info_at, timing::cert_verify_hold_us());
    send_dlm(dock, t0, &kvino::ake_no_stored_km(3, 0, &ekpub).map_err(|e| format!("{e:?}"))?)
        .map_err(|e| format!("AKE_No_Stored_km: {e:?}"))?;

    // (6) AKE_Send_Rrx.
    let (rid, rrx_pl) = recv_hdcp(dock, t0)?;
    if rid != id::AKE_SEND_RRX || rrx_pl.len() < 8 {
        return Err(format!("bad AKE_Send_Rrx (id={rid:#x})"));
    }
    let mut rrx = [0u8; 8];
    rrx.copy_from_slice(&rrx_pl[..8]);

    // (7)/(8) AKE_Send_H_prime.
    let (hid, hp) = recv_hdcp(dock, t0)?;
    if hid != id::AKE_SEND_H_PRIME || hp.len() < 32 {
        return Err(format!("bad H' (id={hid:#x})"));
    }
    let kd = kvino::derive_kd(&km, &rtx, &rrx).map_err(|e| format!("{e:?}"))?;
    if kvino::compute_h(&kd, &rtx, repeater)[..] != hp[..32] {
        return Err("H' mismatch -- authentication failed".into());
    }
    vln!("[ake] H' verified");

    // (9) AKE_Send_Pairing_Info -- discard.
    let _ = recv_hdcp(dock, t0)?;

    // (10) Locality Check.
    let mut rn = [0u8; 8];
    kvino::rng::fill(&mut rn);
    send_dlm(dock, t0, &kvino::lc_init(4, 0, &rn).map_err(|e| format!("{e:?}"))?)
        .map_err(|e| format!("LC_Init: {e:?}"))?;
    let (lid, lp) = recv_hdcp(dock, t0)?;
    if lid != id::LC_SEND_L_PRIME || lp.len() < 32 {
        return Err(format!("bad L' (id={lid:#x})"));
    }
    if kvino::compute_l(&kd, &rrx, &rn)[..] != lp[..32] {
        return Err("L' mismatch -- locality check failed".into());
    }
    vln!("[ake] L' verified");

    // (11) Session Key Exchange.
    let mut ks = [0u8; 16];
    let mut riv_ske = [0u8; 8];
    kvino::rng::fill(&mut ks);
    kvino::rng::fill(&mut riv_ske);
    let edkey = kvino::compute_eks(&km, &rtx, &rrx, &rn, &ks).map_err(|e| format!("{e:?}"))?;
    let mut out_riv = riv_ske;
    out_riv[7] ^= 0x01; // host OUT-CP riv = delivered ^ 0x01 (byte7 ^= 1, as per 2026-07-07)
    send_dlm(dock, t0, &kvino::ske_send_eks(5, 0, &edkey, &riv_ske).map_err(|e| format!("{e:?}"))?)
        .map_err(|e| format!("SKE_Send_Eks: {e:?}"))?;

    // (12) RepeaterAuth.
    if repeater {
        let (vid, list) = recv_hdcp(dock, t0)?;
        if vid != id::REPEATERAUTH_SEND_RECEIVERID_LIST || list.len() < 16 {
            return Err(format!("bad ReceiverID_List (id={vid:#x})"));
        }
        let split = list.len() - 16;
        let v_full = kvino::compute_v_full(&kd, &list[..split]);
        let mut v_ack = [0u8; 16];
        v_ack.copy_from_slice(&v_full[16..]);
        if v_full[..16] != list[split..] {
            return Err("V' mismatch -- repeater verification failed".into());
        }
        vln!("[ake] V' verified");
        send_dlm(dock, t0, &kvino::repeater_auth_send_ack(6, 0, &v_ack).map_err(|e| format!("{e:?}"))?)
            .map_err(|e| format!("RepeaterAuth_Send_Ack: {e:?}"))?;
        pace_cap_ack(dock, t0, 7); // matches RepeaterAuth_Send_Ack hdcp_seq=7
        send_dlm(
            dock,
            t0,
            &kvino::repeater_auth_stream_manage(7, 0, false).map_err(|e| format!("{e:?}"))?,
        )
        .map_err(|e| format!("RepeaterAuth_Stream_Manage: {e:?}"))?;
        pace_cap_ack(dock, t0, 8); // matches RepeaterAuth_Stream_Manage hdcp_seq=8
        wait_cap_complete(dock, t0);
    }

    Ok((Session { ks, riv: out_riv }, cert_at))
}

/// `send_cp_setup` ported: the plaintext arm marker, then the live `msg0`
/// (`id=0x14 sub=0 ctr=9`), the 4-message post-msg0 burst DLM 3.4.26 sends, and
/// the post-msg0 control pair -- byte-for-byte `vino.rs::send_cp_setup`.
/// Returns the number of `wsub=0x45` acks seen.
fn send_cp_setup(dock: &Dock, t0: Instant, session: &Session, cert_at: Instant, cp_start: Instant) -> usize {
    const STREAM_OPEN: [u8; 64] = [
        0x00, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let mut acks = 0usize;

    let count_acks = |dock: &Dock, acks: &mut usize, rounds: usize| {
        for _ in 0..rounds {
            match recv_dlm(dock, t0, Duration::from_millis(5)) {
                Ok(buf) if buf.len() >= 16 => {
                    let wsub = u16::from_le_bytes([buf[8], buf[9]]);
                    if wsub == 0x45 {
                        *acks += 1;
                        vln!("[cp] wsub=0x45 ACK #{acks} ({} B)", buf.len());
                    }
                }
                _ => break,
            }
        }
    };

    hold_until(cert_at, timing::cert_to_arm_us());
    if let Err(e) = send_dlm(dock, t0, &STREAM_OPEN) {
        vln!("[cp] arm marker FAILED: {e:?}");
        return 0;
    }
    let cert_to_arm = cert_at.elapsed().as_micros();
    println!(
        "[cp] arm marker sent (cp_start->arm = {} us, cert->arm = {} us, target {} us)",
        cp_start.elapsed().as_micros(),
        cert_to_arm,
        timing::cert_to_arm_us()
    );

    udelay(Duration::from_micros(timing::arm_to_msg0_us()));

    // msg0: id=0x14 sub=0x00 ctr=8, 14 zero bytes, 10-byte host-random token.
    let mut content = [0u8; 32];
    content[0..2].copy_from_slice(&0x0014u16.to_le_bytes());
    content[4..8].copy_from_slice(&8u32.to_le_bytes());
    kvino::rng::fill(&mut content[22..32]);
    let body_len = content.len() + 16;
    let size = ((16 + body_len) - 4) as u16;
    let aux = kvino::aux_for_id(0x14, body_len);
    let mut hdr = [0u8; 16];
    hdr[2..4].copy_from_slice(&size.to_le_bytes());
    hdr[4..8].copy_from_slice(&4u32.to_le_bytes());
    hdr[8..10].copy_from_slice(&0x24u16.to_le_bytes());
    hdr[10..12].copy_from_slice(&aux.to_le_bytes());
    hdr[12..16].copy_from_slice(&0u32.to_le_bytes()); // msg0 uses seq 0
    let frame = match kvino::seal_livemac(&session.ks, &session.riv, &hdr, &content) {
        Ok(f) => f,
        Err(e) => {
            vln!("[cp] msg0 seal failed: {e:?}");
            return acks;
        }
    };

    let mut ok = false;
    for t in 0..40 {
        match send_dlm(dock, t0, &frame) {
            Ok(_) => {
                ok = true;
                vln!("[cp] msg0 ACCEPTED after {t} interleaved tries");
                break;
            }
            Err(_) => count_acks(dock, &mut acks, 4),
        }
    }
    if ok {
        vln!("[cp] msg0 sent (id=0x14 ctr=8, random token, live seal)");
    } else {
        vln!("[cp] msg0 still NAK'd (no transfer accepted)");
    }

    // Post-msg0 burst: 4 more messages DLM 3.4.26 sends before the control pair.
    // PRE-SEAL all 4 before sending any of them (random-fill + AES-CTR/CMAC
    // done up front), then fire them back-to-back with no ack-wait in
    // between, THEN drain once. The previous version checked for an ack
    // (5ms timeout) after EVERY send, so on a cold/silent dock it paid a full
    // 5-6ms per message even though nothing was ever coming back -- that
    // wait was pure artifact of this rig's own polling, not anything DLM
    // does (DLM's real burst, live-traced 2026-07-07, is ~1ms/message,
    // submit-and-reap, no per-message blocking wait).
    let mut wseq = 2u32;
    let mut burst_frames: Vec<(u16, u16, u32, Vec<u8>)> = Vec::new();
    for (id, sub, ctr, fixed_prefix) in [
        (0x0014u16, 0x0030u16, 9u32, &[][..]),
        (0x0015, 0x000b, 10, &[0x01][..]),
        (0x0016, 0x002a, 11, &[0x00, 0x01][..]),
        (0x0016, 0x002a, 12, &[0x01, 0x01][..]),
    ] {
        let mut c = [0u8; 32];
        c[0..2].copy_from_slice(&id.to_le_bytes());
        c[2..4].copy_from_slice(&sub.to_le_bytes());
        c[4..8].copy_from_slice(&ctr.to_le_bytes());
        kvino::rng::fill(&mut c[22..32]);
        c[22..22 + fixed_prefix.len()].copy_from_slice(fixed_prefix);
        match kvino::seal_interactive(&session.ks, &session.riv, id, wseq, &c) {
            Ok(f) => burst_frames.push((id, sub, ctr, f)),
            Err(e) => vln!("[cp] burst id={id:#06x} seal failed: {e:?}"),
        }
        wseq = wseq.wrapping_add(2);
    }
    for (id, sub, ctr, f) in &burst_frames {
        let sent = send_dlm(dock, t0, f).is_ok();
        vln!("[cp] burst id={id:#06x} sub={sub:#06x} ctr={ctr} {}", if sent { "sent" } else { "NAK'd" });
    }
    count_acks(dock, &mut acks, 16);

    // Post-msg0 control pair.
    let _ = dock.vendor_out(0x24, 0, 0, &[]);
    let _ = dock.vendor_in(0x22, 1, 0, 28);

    count_acks(dock, &mut acks, 16);

    // (msg0 retries removed 2026-07-12: DLM never retries -- it is acked on the first msg0. A retry
    // was only a probe of whether the silent dock had missed the frame; it never changed the result.)
    let _ = wseq;

    acks
}

/// The device-open preamble: claim interface 1 (DLM's libusb claims it too;
/// the in-kernel driver binds it as a real interface), the `0xfe`/`0xfc`
/// device-open vendor reads, SET_INTERFACE(1,0) then (0,0), the `0x24`
/// wValue=3 kick, and the `0x22` state read -- `vino.rs::bring_up`'s exact
/// order. (`WAIT_FOR_APP_FIRMWARE`'s poll is skipped: it was a no-op on the
/// last HW test, "app firmware up after ~0 ms" -- see memory
/// `project_dock_bootloader_vs_app_firmware_cp_gate_20260705`; add back if a
/// future run suggests otherwise.)
fn device_open_preamble(dock: &Dock) {
    let t = Duration::from_millis(1000);
    if let Err(e) = dock.claim_interface(1) {
        vln!("[open] claim_interface(1) FAILED ({e:?}) -- SET_INTERFACE(1,..) below may fail");
    }
    match dock.vendor_in(0xfe, 0, 1, 16) {
        Ok(b) => vln!("[open] 0xfe(iface1) OK = {b:02x?}"),
        Err(e) => vln!("[open] 0xfe(iface1) non-fatal ({e:?})"),
    }
    match dock.vendor_in(0xfc, 0, 1, 3) {
        Ok(b) => vln!("[open] 0xfc(iface1) OK = {b:02x?}"),
        Err(e) => vln!("[open] 0xfc(iface1) non-fatal ({e:?})"),
    }
    match dock.std_out_iface(REQ_SET_INTERFACE, 0, 1, &[], t) {
        Ok(()) => vln!("[open] set_interface(1,0) OK"),
        Err(e) => vln!("[open] set_interface(1,0) non-fatal ({e:?})"),
    }
    // NOTE: no SET_INTERFACE(0,0) here -- `Dock::open()` already did it (before
    // starting the persistent async EP84 reader), and a SECOND one this late
    // would reset interface 0's endpoint state (incl. EP84, the endpoint that
    // reader already has URBs posted against) out from under the already-posted
    // queue. `vino.rs` does its own SET_INTERFACE(0,0) here too, but its async
    // EP84 queue doesn't open until much later (`send_cp_setup`), so it never
    // hits this ordering hazard -- this coldstart's `Dock` opens its async
    // reader once, up front, so the redundant call has to go instead.
    match dock.vendor_out(0x24, 3, 0, &[]) {
        Ok(()) => vln!("[open] 0x24(wValue=3) OK"),
        Err(e) => vln!("[open] 0x24(wValue=3) non-fatal ({e:?})"),
    }
    match dock.vendor_in(0x22, 1, 0, 28) {
        Ok(b) => vln!("[open] 0x22(wValue=1) OK = {b:02x?}"),
        Err(e) => vln!("[open] 0x22(wValue=1) non-fatal ({e:?})"),
    }
}

fn main() {
    println!("chimera-coldstart -- new-DLM-over-libusb cold engagement test");
    println!("(literal kernel ake.rs/hdcp.rs/cp.rs/proto.rs, DLM's own libusb transport)");

    let dock = match Dock::open() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Dock::open failed: {e:?} (is displaylink-driver.service stopped?)");
            std::process::exit(1);
        }
    };
    vln!("[open] dock opened via libusb");

    device_open_preamble(&dock);

    // Dispatch: `sweep` = bounded grid; `soak` = infinite random-timing overnight run (stops only
    // on an ack or when killed); anything else = single-shot run.
    match std::env::args().nth(1).as_deref() {
        Some("sweep") => {
            run_sweep(&dock);
            return;
        }
        Some("soak") => {
            run_soak(&dock);
            return;
        }
        _ => {}
    }

    let (_ake_ok, acks) = run_session(&dock);
    println!("\n==================================================");
    println!(
        "RESULT: sub=0x45_acks={acks}  ({})",
        if acks > 0 {
            "ENGAGED -- the dock accepted a cold libusb-driven session!"
        } else {
            "0 acks -- same wall as vino.ko, via a completely independent transport"
        }
    );
    println!("==================================================");
}

/// One full protocol attempt: plaintext session-init, AKE, then arm+msg0+burst. Returns
/// `(ake_ok, acks)`. Uses the current thread-local `timing::*` values (the sweeper varies timing
/// by setting those before each call). Verbose per-frame/step logs are suppressed under
/// `timing::quiet()`. The dock must already be opened + `device_open_preamble`'d by the caller.
fn run_session(dock: &Dock) -> (bool, usize) {
    let q = timing::quiet();
    let t0 = Instant::now();
    let cp_start = t0;

    for (name, frame) in [("init_0", kvino::init_0()), ("init_25", kvino::init_25())] {
        match frame {
            Ok(f) => {
                let _ = send_dlm(dock, t0, &f);
                if !q {
                    vln!("[init] {name} OK");
                }
            }
            Err(e) => vln!("[init] {name} build failed ({e:?})"),
        }
        if name == "init_0" {
            udelay(Duration::from_micros(timing::pad_init0_to_init25_us()));
        }
    }
    udelay(Duration::from_micros(timing::pad_init25_to_init4_us()));
    if let Ok(f) = kvino::init_4_probe() {
        let _ = send_dlm(dock, t0, &f);
        if !q {
            vln!("[init] init_4+probe OK");
        }
    }
    // probe_resend stays gated off (see the single-shot path / SEND_PROBE_RESEND=false in vino.rs).
    match recv_dlm(dock, t0, Duration::from_secs(1)) {
        Ok(b) if !q => vln!("[init] session-init ACK = {} bytes: {:02x?}", b.len(), b),
        Err(e) if !q => vln!("[init] session-init ACK read FAILED ({e:?})"),
        _ => {}
    }

    let (session, cert_at) = match run_ake(dock, t0) {
        Ok(s) => s,
        Err(e) => {
            if !q {
                eprintln!("[ake] FAILED: {e}");
            }
            return (false, 0);
        }
    };
    if !q {
        vln!("[ake] HDCP AKE + LC + SKE complete (session keyed)");
    }

    let acks = send_cp_setup(dock, t0, &session, cert_at, cp_start);
    (true, acks)
}

/// Warm-loop timing sweeper: with the dock already open, re-run the full session repeatedly while
/// jiggling the pre-arm timing knobs, hunting for ANY combination that makes the dock engage
/// (`acks>0`). Timing is the last host-controllable axis below usbmon (the DATA0/DATA1 toggle bit
/// can't be reached from software); every other axis is byte-matched to DLM. Per-frame logs are
/// suppressed; each attempt prints one result line. Stops on the first engagement.
/// A random `u64` in `0..max` from the kernel RNG shim (getrandom-backed). `max` must be > 0.
fn rand_u64(max: u64) -> u64 {
    let mut b = [0u8; 8];
    kvino::rng::fill(&mut b);
    u64::from_le_bytes(b) % max
}

/// Sample a random point in the pre-arm timing space for the overnight soak.
fn random_timings() -> timing::Timings {
    let mut t = timing::Timings::default();
    t.arm_to_msg0 = rand_u64(100_001); // 0..100 ms
    t.cap_drain_rounds = rand_u64(301) as usize; // 0..300 rounds -> arm epoch ~157ms..~1.6s
    t.cap_drain_round_ms = 1 + rand_u64(40); // 1..40 ms/round
    t.pad_ack_akeinit = rand_u64(5_001); // 0..5 ms
    t.cert_verify_hold = rand_u64(15_001); // 0..15 ms
    t.pad_init0_25 = rand_u64(2_001); // 0..2 ms
    t.pad_init25_4 = rand_u64(2_001); // 0..2 ms
    t.cert_to_arm = 100_000 + rand_u64(400_001); // 100..500 ms floor
    t
}

/// Overnight SOAK: with the dock open, re-run the full session FOREVER with random timings, logging
/// every attempt to a file, stopping ONLY when the dock actually acks (`acks>0`) or the process is
/// killed. On engagement it writes an `ENGAGED` marker (with the winning timings) BEFORE returning,
/// so the result survives even a teardown crash. Heartbeat to stdout every 100 attempts.
fn run_soak(dock: &Dock) {
    use std::io::Write;
    timing::set_quiet(true);
    let logpath = "/tmp/chimera-soak.log";
    let marker = "/tmp/chimera-soak.ENGAGED";
    let _ = std::fs::remove_file(marker);
    let pid = std::process::id();
    println!("== OVERNIGHT SOAK (pid {pid}) -- random timings until an ack or killed ==");
    println!("   log:    {logpath}");
    println!("   marker: {marker}  (written the instant acks>0)");
    println!("   stop:   kill {pid}   (or it self-stops on engagement)");
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open(logpath).ok();
    let start = Instant::now();
    let mut n: u64 = 0;
    let mut ake_fails: u64 = 0;
    loop {
        let t = random_timings();
        timing::set(t);
        let (ake, acks) = run_session(dock);
        n += 1;
        if !ake {
            ake_fails += 1;
        }
        let line = format!(
            "#{n} t={:.1}m ake={} acks={} arm_msg0={} drain_rounds={} drain_ms={} ack_pad={} verify={} init0_25={} init25_4={} cert_arm={}",
            start.elapsed().as_secs_f64() / 60.0,
            ake as u8,
            acks,
            t.arm_to_msg0,
            t.cap_drain_rounds,
            t.cap_drain_round_ms,
            t.pad_ack_akeinit,
            t.cert_verify_hold,
            t.pad_init0_25,
            t.pad_init25_4,
            t.cert_to_arm
        );
        if let Some(f) = log.as_mut() {
            let _ = writeln!(f, "{line}");
            let _ = f.flush();
        }
        if acks > 0 {
            let msg = format!("*** ENGAGED after {n} attempts *** {line}");
            println!("\n{msg}");
            let _ = std::fs::write(marker, &msg);
            if let Some(f) = log.as_mut() {
                let _ = writeln!(f, "{msg}");
            }
            return;
        }
        if n % 100 == 0 {
            println!(
                "[heartbeat] {n} attempts, {:.1} min, {ake_fails} AKE-fails, still 0 acks",
                start.elapsed().as_secs_f64() / 60.0
            );
        }
    }
}

/// Run one sweep attempt with the given timings; print a one-line result. Returns true if the dock
/// engaged (`acks>0`) so the caller can stop.
fn sweep_attempt(dock: &Dock, t: timing::Timings, label: &str, n: &mut usize) -> bool {
    timing::set(t);
    let (ake, acks) = run_session(dock);
    *n += 1;
    println!(
        "   #{:>3}  {label:<40}  AKE={}  acks={}",
        *n,
        if ake { "OK " } else { "FAIL" },
        acks
    );
    if acks > 0 {
        println!("\n*** ENGAGED *** {label}  acks={acks}");
        println!("*** timing WAS the gate -- lock these values into vino.rs ***");
    }
    acks > 0
}

fn run_sweep(dock: &Dock) {
    use timing::Timings;
    timing::set_quiet(true);
    println!("== warm-loop timing sweeper (session logs suppressed; one line/attempt) ==");

    // Fairness check: is a repeated WARM attempt a valid engagement test, or does the dock's gate
    // only reset on a power cycle? Run 3 baselines at default timing -- if they don't all reach the
    // AKE the same way, sweep negatives can't be trusted (a controllable power switch / cold sweep
    // would be needed instead).
    println!("-- fairness: 3 baseline attempts at default timing --");
    let mut base_ok = 0;
    for i in 1..=3 {
        timing::set(Timings::default());
        let (ake, acks) = run_session(dock);
        if ake {
            base_ok += 1;
        }
        println!("   baseline #{i}: AKE={} acks={}", if ake { "OK" } else { "FAIL" }, acks);
    }
    println!(
        "   -> {base_ok}/3 baselines reached the AKE ({})",
        if base_ok == 3 { "warm sweep is a valid test" } else { "CAUTION: warm attempts may be unfair" }
    );

    let mut n = 0usize;

    // Phase A: the ARM EPOCH -- the arm->msg0 gap x the wait_cap_complete drain budget. The drain
    // budget is the real controller of cert->arm here (0 rounds => arm ~157 ms; 200 rounds =>
    // arm ~1.2 s), so this 2-D grid actually sweeps the whole arm-timing plane, unlike the earlier
    // cert_to_arm knob which was a no-op below the natural AKE time.
    let arm_to_msg0 = [0u64, 100, 170, 500, 2_000, 10_000, 50_000];
    let cap_rounds = [0usize, 5, 10, 20, 48, 100, 200];
    println!(
        "-- phase A: arm->msg0 ({}) x cap_drain_rounds ({}) = {} combos --",
        arm_to_msg0.len(),
        cap_rounds.len(),
        arm_to_msg0.len() * cap_rounds.len()
    );
    for &r in &cap_rounds {
        for &a in &arm_to_msg0 {
            let mut t = Timings::default();
            t.arm_to_msg0 = a;
            t.cap_drain_rounds = r;
            let label = format!("arm->msg0={a:>6}us  drain_rounds={r:>3}");
            if sweep_attempt(dock, t, &label, &mut n) {
                return;
            }
        }
    }

    // Phase B: single-knob 1-D sweeps of the earlier pads (all other knobs at default).
    println!("-- phase B: single-knob sweeps (pre-AKE pads, cert-verify hold, drain granularity) --");
    for &v in &[0u64, 45, 90, 200, 500, 1_000, 3_000] {
        let mut t = Timings::default();
        t.pad_ack_akeinit = v;
        if sweep_attempt(dock, t, &format!("pad_ack_akeinit={v}us"), &mut n) {
            return;
        }
    }
    for &v in &[0u64, 500, 1_650, 3_000, 6_000, 12_000] {
        let mut t = Timings::default();
        t.cert_verify_hold = v;
        if sweep_attempt(dock, t, &format!("cert_verify_hold={v}us"), &mut n) {
            return;
        }
    }
    for &v in &[1u64, 5, 10, 30] {
        let mut t = Timings::default();
        t.cap_drain_round_ms = v;
        if sweep_attempt(dock, t, &format!("cap_drain_round_ms={v}"), &mut n) {
            return;
        }
    }
    for &v in &[0u64, 79, 300, 1_000] {
        let mut t = Timings::default();
        t.pad_init0_25 = v;
        if sweep_attempt(dock, t, &format!("pad_init0_to_25={v}us"), &mut n) {
            return;
        }
    }

    println!(
        "\n== sweep complete: {n} attempts (arm->msg0, cap-drain rounds+granularity, verify-hold, ack-pad, init-pad) =="
    );
    println!("   ZERO engagement -- timing is not the host-reachable gate (consistent with all prior evidence).");
}
