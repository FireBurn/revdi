//! Live EDID-fetch state machine — the userspace ("chimera-first") rehearsal of the exact
//! sequence `VinoDriver::send_cp_setup` runs in-kernel (`drm/drivers/gpu/drm/vino/vino.rs`),
//! built from the SAME shared `cp.rs` message builders via [`crate::kvino`]. This exists so the
//! sequence can be exercised against a real, taken-over engaged dock in userspace — no `vino.ko`
//! load/unload cycle, no risk to a live desktop session if it goes wrong — before it is trusted
//! in the kernel driver.
//!
//! Ground truth (see `docs/CP-HANDSHAKE.md` sec 4f and memory
//! `project_edid_wait_loop_and_poll_gate_20260717`): after two placeholder (`id=0x114`) fetches
//! fail, DLM sends `id=0x16 sub=0x0023` twice, then spins up to ~66 `id=0x14 sub=0x000c`
//! device-status polls while the dock's downstream DDC/EDID read completes in real time, gated
//! on an exact readiness bit (inner byte offset 26 of the `id=0x0044 sub=0x0020` probe reply,
//! `0x00` busy → `0x80` ready).

use crate::kvino;
use std::time::Duration;
use vino_driver::Dock;

const STEP_DELAY: Duration = Duration::from_millis(100);
const POLL_DELAY: Duration = Duration::from_millis(20);
const RECV_TIMEOUT: Duration = Duration::from_millis(5);
const EARLY_ROUNDS: usize = 3;
const POLL_ITERS: usize = 100;
const POLL_PROBE_EVERY: usize = 8;

/// Seal `content` under `id` at the running wire sequence, send it on the CP control endpoint,
/// and advance `counter` by the number of AES-CTR blocks just consumed. Returns whether the send
/// itself succeeded (a NAK/USB error, not whether the dock liked the content).
fn send(dock: &Dock, ks: &[u8; 16], riv: &[u8; 8], counter: &mut u32, id: u16, content: &[u8]) -> bool {
    let Ok(frame) = kvino::seal_interactive(ks, riv, id, *counter, content) else {
        return false;
    };
    let ok = dock.write_ctrl_raw(&frame).is_ok();
    *counter = counter.wrapping_add(content.len().div_ceil(16) as u32);
    ok
}

/// Drain one pending EP84 reply (short timeout — this is a rehearsal loop, not the persistent
/// async queue `vino.ko` keeps). Opportunistically captures a real EDID and reports whether this
/// reply was a `sub=0x0020` probe whose readiness bit is set.
fn drain_once(dock: &Dock, ks: &[u8; 16], riv: &[u8; 8], edid: &mut Option<Vec<u8>>) -> bool {
    let Ok(reply) = dock.recv_frame_raw_timeout(4096, RECV_TIMEOUT) else {
        return false;
    };
    if edid.is_none() {
        if let Ok(Some(e)) = kvino::parse_edid_from_reply(ks, riv, &reply) {
            *edid = Some(e);
        }
    }
    matches!(kvino::edid_poll_ready(ks, riv, &reply), Some(true))
}

/// Run the full derived EDID-wait sequence against a live, engaged dock. `counter` is the
/// caller's running CP wire sequence (shared with heartbeats/painting elsewhere in the same
/// session — advance it the same way `vino.rs`'s `wseq` is advanced). Returns the raw EDID bytes
/// (base block + extensions) the dock delivers, or `None` if it never does within budget.
///
/// Mirrors `VinoDriver::send_cp_setup`'s get-EDID loop message-for-message: two early
/// probe(x2)+fetch rounds, then — if still no real EDID — the engage pair and the readiness-
/// gated status-poll run. See this module's doc comment for the ground truth.
pub fn fetch_edid(dock: &Dock, ks: &[u8; 16], riv: &[u8; 8], counter: &mut u32) -> Option<Vec<u8>> {
    let mut edid: Option<Vec<u8>> = None;
    let mut ctr: u16 = 0;
    let mut next_ctr = move || {
        ctr = ctr.wrapping_add(1);
        ctr
    };

    for round in 0..EARLY_ROUNDS {
        if edid.is_some() {
            break;
        }
        println!("  chimera-edid: early round {round}");
        for _ in 0..2 {
            if let Ok(probe) = kvino::get_edid_req_sub(next_ctr(), 0x20) {
                send(dock, ks, riv, counter, 0x15, &probe);
            }
            drain_once(dock, ks, riv, &mut edid);
            std::thread::sleep(STEP_DELAY);
        }
        if let Ok(req) = kvino::get_edid_req(next_ctr()) {
            send(dock, ks, riv, counter, 0x15, &req);
        }
        drain_once(dock, ks, riv, &mut edid);
        if edid.is_some() {
            break;
        }
        std::thread::sleep(STEP_DELAY);
    }

    if edid.is_none() {
        println!("  chimera-edid: still no real EDID after {EARLY_ROUNDS} rounds — engaging + polling");
        for _ in 0..2 {
            if let Ok(engage) = kvino::edid_engage_req(next_ctr()) {
                send(dock, ks, riv, counter, 0x16, &engage);
            }
            drain_once(dock, ks, riv, &mut edid);
            std::thread::sleep(STEP_DELAY);
        }
        let mut ready = false;
        for i in 0..POLL_ITERS {
            if edid.is_some() || ready {
                break;
            }
            if let Ok(poll) = kvino::device_query_req(next_ctr(), 0x000c) {
                send(dock, ks, riv, counter, 0x14, &poll);
            }
            if drain_once(dock, ks, riv, &mut edid) {
                ready = true;
            }
            if i % POLL_PROBE_EVERY == POLL_PROBE_EVERY - 1 {
                if let Ok(probe) = kvino::get_edid_req_sub(next_ctr(), 0x20) {
                    send(dock, ks, riv, counter, 0x15, &probe);
                }
                if drain_once(dock, ks, riv, &mut edid) {
                    ready = true;
                }
            }
            if edid.is_some() || ready {
                break;
            }
            std::thread::sleep(POLL_DELAY);
        }
        println!("  chimera-edid: readiness poll finished (ready={ready})");
        if edid.is_none() {
            if let Ok(req) = kvino::get_edid_req(next_ctr()) {
                send(dock, ks, riv, counter, 0x15, &req);
            }
            drain_once(dock, ks, riv, &mut edid);
        }
    }
    edid
}
