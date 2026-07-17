//! Minimal FFI bindings to `libevdi` (revdi's `evdi_lib.h` C ABI, feature-gated as `revdi` so the
//! rest of chimera builds without it).
//!
//! Why this exists: the `/goal` for this session is to prove EDID-fetch + real video content end
//! to end WITHOUT touching `vino.ko` — a live-kernel driver that has already crashed a desktop
//! session once (`project_ep08_scanout_crash_incident_20260716`). `revdi` is a separate, already-
//! stable kernel module (a from-scratch evdi replacement) that gives a compositor a real virtual
//! display to render into. The idea: fetch the dock's REAL EDID over the taken-over live CP
//! session (`crate::edid_fetch`), hand it to a `revdi` virtual card so a real compositor picks a
//! real mode and renders real content into it, grab that content back out via `evdi_grab_pixels`,
//! encode it with the literal kernel colour codec (`kvino::colour_frame_ep08`, already proven byte
//! -exact against DLM), and send it to the SAME real dock. Every piece except `vino.ko` itself is
//! exercised this way.
//!
//! Written directly from `revdi/library/evdi_lib.h` + `revdi/library/src/lib.rs`'s ioctl
//! semantics. **NOT YET RUN** against a live revdi module / real compositor — this crate has no
//! way to load kernel modules itself (that stays the user's call, same as `vino.ko`), so the
//! runtime path here is unverified until exercised on real hardware.

#![allow(non_camel_case_types)]

use std::ffi::{c_int, c_uint, c_void};
use std::time::{Duration, Instant};

#[repr(C)]
struct EvdiDeviceContext {
    _opaque: [u8; 0],
}
type EvdiHandle = *mut EvdiDeviceContext;

/// `enum evdi_device_status`: AVAILABLE=0, UNRECOGNIZED=1, NOT_PRESENT=2.
const EVDI_STATUS_AVAILABLE: c_int = 0;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct EvdiRect {
    x1: c_int,
    y1: c_int,
    x2: c_int,
    y2: c_int,
}

/// `struct evdi_mode` (evdi_lib.h): the mode a compositor negotiated for this virtual output.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EvdiMode {
    pub width: c_int,
    pub height: c_int,
    pub refresh_rate: c_int,
    pub bits_per_pixel: c_int,
    pub pixel_format: c_uint,
}

#[repr(C)]
struct EvdiBuffer {
    id: c_int,
    buffer: *mut c_void,
    width: c_int,
    height: c_int,
    stride: c_int,
    rects: *mut EvdiRect,
    rect_count: c_int,
}

/// Matches `struct evdi_event_context`'s layout: every handler slot is exactly one function-
/// pointer wide regardless of its (correct or placeholder) parameter list, so only
/// `mode_changed_handler`/`update_ready_handler` — the two this module actually populates and
/// the C side actually calls — need their real C signature; the rest stay `None` (null) and are
/// never invoked, so their placeholder parameter types cannot cause a real ABI mismatch.
#[repr(C)]
struct EvdiEventContext {
    dpms_handler: Option<extern "C" fn(c_int, *mut c_void)>,
    mode_changed_handler: Option<extern "C" fn(EvdiMode, *mut c_void)>,
    update_ready_handler: Option<extern "C" fn(c_int, *mut c_void)>,
    crtc_state_handler: Option<extern "C" fn(c_int, *mut c_void)>,
    cursor_set_handler: Option<extern "C" fn(*const c_void, *mut c_void)>,
    cursor_move_handler: Option<extern "C" fn(*const c_void, *mut c_void)>,
    ddcci_data_handler: Option<extern "C" fn(*const c_void, *mut c_void)>,
    user_data: *mut c_void,
}

#[link(name = "evdi")]
extern "C" {
    fn evdi_check_device(device: c_int) -> c_int;
    fn evdi_open(device: c_int) -> EvdiHandle;
    fn evdi_add_device() -> c_int;
    fn evdi_close(handle: EvdiHandle);
    fn evdi_connect2(
        handle: EvdiHandle,
        edid: *const u8,
        edid_length: c_uint,
        pixel_area_limit: u32,
        pixel_per_second_limit: u32,
    );
    fn evdi_disconnect(handle: EvdiHandle);
    fn evdi_register_buffer(handle: EvdiHandle, buffer: EvdiBuffer);
    fn evdi_request_update(handle: EvdiHandle, buffer_id: c_int) -> bool;
    fn evdi_grab_pixels(handle: EvdiHandle, rects: *mut EvdiRect, num_rects: *mut c_int);
    fn evdi_handle_events(handle: EvdiHandle, evtctx: *mut EvdiEventContext);
    fn evdi_get_event_ready(handle: EvdiHandle) -> c_int;
}

fn wait_readable(fd: c_int, timeout: Duration) -> bool {
    if fd < 0 {
        return false;
    }
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: `pfd` is a single, valid, stack-local pollfd; `poll` writes only `revents`.
    let r = unsafe { libc::poll(&mut pfd, 1, ms) };
    r > 0 && (pfd.revents & libc::POLLIN) != 0
}

#[derive(Default)]
struct EventState {
    mode: std::sync::Mutex<Option<EvdiMode>>,
    ready_buffer: std::sync::Mutex<Option<c_int>>,
}

extern "C" fn on_mode_changed(mode: EvdiMode, user_data: *mut c_void) {
    // SAFETY: `user_data` is always `&EventState` owned by the live `RevdiCard`, set right
    // before every `evdi_handle_events` call that can reach this callback.
    let state = unsafe { &*(user_data as *const EventState) };
    *state.mode.lock().unwrap() = Some(mode);
}
extern "C" fn on_update_ready(buffer_id: c_int, user_data: *mut c_void) {
    // SAFETY: see `on_mode_changed`.
    let state = unsafe { &*(user_data as *const EventState) };
    *state.ready_buffer.lock().unwrap() = Some(buffer_id);
}

const BUF_ID: c_int = 1;

/// A virtual display created via `revdi`'s `libevdi`. Open, [`connect`](Self::connect) it with a
/// real fetched EDID, [`wait_for_mode`](Self::wait_for_mode) for a compositor to attach, then
/// [`grab_frame`](Self::grab_frame) in a loop.
pub struct RevdiCard {
    handle: EvdiHandle,
    state: Box<EventState>,
    buf: Vec<u8>,
    width: usize,
    height: usize,
    stride: usize,
}

impl RevdiCard {
    /// Find an `AVAILABLE` `/dev/dri/cardN` evdi device (adding one via `evdi_add_device` if none
    /// is free) and open it.
    pub fn open() -> Result<Self, String> {
        const MAX_INDEX: c_int = 64;
        let find_available = || (0..MAX_INDEX).find(|&i| {
            // SAFETY: FFI call with a plain integer argument, no pointers involved.
            (unsafe { evdi_check_device(i) }) == EVDI_STATUS_AVAILABLE
        });
        let mut idx = find_available();
        if idx.is_none() {
            // `evdi_add_device()`'s return value is a byte count from the underlying sysfs
            // write (always 1 on success), NOT the new card's device index — rescan instead of
            // trusting it. See memory `project_chimera_revdi_live_video_20260717` for how this
            // was found (a real `RevdiCard::open` bug, not a `revdi` bug).
            // SAFETY: no arguments.
            if unsafe { evdi_add_device() } < 0 {
                return Err("evdi_add_device: sysfs add failed".into());
            }
            idx = find_available();
        }
        let idx = idx.ok_or("no AVAILABLE evdi device even after evdi_add_device")?;
        // SAFETY: `idx` is a device index just proven AVAILABLE (or freshly added).
        let handle = unsafe { evdi_open(idx) };
        if handle.is_null() {
            return Err(format!("evdi_open({idx}) returned a null handle"));
        }
        Ok(Self { handle, state: Box::default(), buf: Vec::new(), width: 0, height: 0, stride: 0 })
    }

    /// Connect the virtual display with the dock's real EDID, so a compositor sees the actual
    /// monitor and picks a real mode instead of a generic fallback.
    pub fn connect(&self, edid: &[u8]) {
        // A generous limit (4K@60): this only bounds what modes the kernel side advertises, not
        // what we'll actually encode (the WHT codec's own 64x16 alignment requirement gates that
        // downstream in `colour_frame_ep08`).
        const LIMIT_PX: u32 = 3840 * 2160;
        // SAFETY: `edid` is a valid slice for `edid.len()` bytes; `handle` is open.
        unsafe {
            evdi_connect2(self.handle, edid.as_ptr(), edid.len() as c_uint, LIMIT_PX, LIMIT_PX * 60);
        }
    }

    /// Pump one round of `revdi` events. Re-registers the pixel buffer whenever the negotiated
    /// mode changes (i.e. the first time a compositor attaches, and on any later mode switch).
    /// Returns whether a (new) mode is now known.
    fn poll_events(&mut self, timeout: Duration) -> bool {
        // SAFETY: `handle` is open.
        let fd = unsafe { evdi_get_event_ready(self.handle) };
        if !wait_readable(fd, timeout) {
            return self.width > 0;
        }
        let mut ctx = EvdiEventContext {
            dpms_handler: None,
            mode_changed_handler: Some(on_mode_changed),
            update_ready_handler: Some(on_update_ready),
            crtc_state_handler: None,
            cursor_set_handler: None,
            cursor_move_handler: None,
            ddcci_data_handler: None,
            user_data: (&*self.state as *const EventState) as *mut c_void,
        };
        // SAFETY: `ctx` is a valid, fully-initialised `EvdiEventContext` on the stack for the
        // duration of this call; the handlers it points at are the module-level `extern "C" fn`s
        // above, valid for the program's lifetime.
        unsafe { evdi_handle_events(self.handle, &mut ctx) };
        let mode = *self.state.mode.lock().unwrap();
        if let Some(m) = mode {
            let (w, h) = (m.width.max(0) as usize, m.height.max(0) as usize);
            if w > 0 && h > 0 && (w != self.width || h != self.height) {
                self.register_buffer(w, h);
            }
        }
        self.width > 0
    }

    fn register_buffer(&mut self, w: usize, h: usize) {
        self.width = w;
        self.height = h;
        self.stride = w * 4; // XRGB8888, unpadded — matches evdi's own default expectation.
        self.buf = vec![0u8; self.stride * h];
        let buffer = EvdiBuffer {
            id: BUF_ID,
            buffer: self.buf.as_mut_ptr() as *mut c_void,
            width: w as c_int,
            height: h as c_int,
            stride: self.stride as c_int,
            rects: std::ptr::null_mut(),
            rect_count: 0,
        };
        // SAFETY: `buffer.buffer` points into `self.buf`, which outlives every `evdi_grab_pixels`
        // call made against this registration (it is replaced, not freed, by a later
        // `register_buffer` call, and `evdi_unregister_buffer` is not needed for a single-buffer
        // card whose lifetime matches `self`).
        unsafe { evdi_register_buffer(self.handle, buffer) };
    }

    /// Block (up to `timeout`) for a compositor to attach and negotiate a mode.
    pub fn wait_for_mode(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.poll_events(Duration::from_millis(200)) {
                return true;
            }
        }
        false
    }

    /// Request an update, wait (up to `timeout`) for the compositor to render one, grab it, and
    /// return `(xrgb8888 bytes, width, height, stride)`. `None` on timeout or before a mode is
    /// known.
    pub fn grab_frame(&mut self, timeout: Duration) -> Option<(&[u8], usize, usize, usize)> {
        if self.width == 0 {
            return None;
        }
        // SAFETY: `handle` is open and a buffer with id `BUF_ID` is registered.
        unsafe {
            evdi_request_update(self.handle, BUF_ID);
        }
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            self.poll_events(deadline.saturating_duration_since(Instant::now()));
            let ready = self.state.ready_buffer.lock().unwrap().take();
            if ready == Some(BUF_ID) {
                let mut rects = [EvdiRect::default(); 16];
                let mut n: c_int = rects.len() as c_int;
                // SAFETY: `rects` has `n` valid slots; `handle` has buffer `BUF_ID` registered.
                unsafe { evdi_grab_pixels(self.handle, rects.as_mut_ptr(), &mut n) };
                return Some((&self.buf, self.width, self.height, self.stride));
            }
        }
        None
    }
}

impl Drop for RevdiCard {
    fn drop(&mut self) {
        // SAFETY: `handle` is a live handle owned solely by this `RevdiCard`.
        unsafe {
            evdi_disconnect(self.handle);
            evdi_close(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real hardware smoke test: open a fresh revdi card, connect it with a REAL captured EDID
    /// (this exact dock's downstream MSI monitor, `captures/archive-pre-3426/
    /// vino-matched-session-20260604-083018/edid-card2-DVI-I-1.bin`), and wait a short while for
    /// a compositor to hotplug + negotiate a mode. Needs `revdi.ko` loaded
    /// (`sudo modprobe evdi`) — `#[ignore]`d so the offline test suite stays hardware-free; run
    /// explicitly with `cargo test -p vino-chimera --features revdi -- --ignored revdi_smoke`.
    #[test]
    #[ignore = "needs revdi.ko loaded on real hardware"]
    fn revdi_smoke_open_connect_wait_mode() {
        let edid = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../captures/archive-pre-3426/vino-matched-session-20260604-083018/edid-card2-DVI-I-1.bin",
        ))
        .expect("real EDID fixture");
        let mut card = RevdiCard::open().expect("evdi_open (is revdi.ko loaded?)");
        card.connect(&edid);
        let got_mode = card.wait_for_mode(Duration::from_secs(15));
        println!("mode negotiated: {got_mode} (width={} height={})", card.width, card.height);
    }
}

/// Convert a raw `XRGB8888` framebuffer (as delivered by [`RevdiCard::grab_frame`]) into the
/// packed 8-bit `R,G,B` raster [`crate::kvino::colour_frame_ep08`] expects. Byte extraction
/// mirrors the in-kernel scanout path's own XRGB8888 read
/// (`drm/drivers/gpu/drm/vino/drm_sink.rs::encode_and_send_wht`) so both consumers of the same
/// pixel format agree on channel order.
pub fn to_rgb888(buf: &[u8], width: usize, height: usize, stride: usize) -> Vec<u8> {
    let mut out = vec![0u8; width * height * 3];
    for y in 0..height {
        for x in 0..width {
            let o = y * stride + x * 4;
            if o + 4 > buf.len() {
                continue;
            }
            let px = u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
            let i = (y * width + x) * 3;
            out[i] = ((px >> 16) & 0xff) as u8;
            out[i + 1] = ((px >> 8) & 0xff) as u8;
            out[i + 2] = (px & 0xff) as u8;
        }
    }
    out
}
