//! USB I/O for the D6000 dock.
//!
//! Backed by **rusb** (safe Rust bindings over the libusb-1.0 C library) so the
//! userspace RE tools (chimera, bringup, sniff) drive the dock through the *same
//! libusb DisplayLinkManager itself uses*. libusb resolves by soname
//! `libusb-1.0.so.0`; run the binary with cwd `/opt/displaylink` (DLM's own
//! resolution) or `LD_LIBRARY_PATH=/opt/displaylink` / `LD_PRELOAD=/opt/
//! displaylink/libusb-1.0.so.0.3.0` to load DLM's exact bundled build rather than
//! the system libusb — closing the "different libusb version" variable that
//! neither nusb nor rusb-against-system-libusb removes.
//!
//! Execution model mirrors DLM (verified against the DLM decompile,
//! `project_async_out_binding_and_microdiff_20260616`): control transfers and
//! bulk **OUT** (EP 0x02 control, 0x08/0x0b video) are synchronous
//! `libusb_bulk_transfer`/`libusb_control_transfer` with `flags=0`; the EP 0x84
//! dock-reply **IN** path is a *persistently posted* pool of asynchronous
//! `libusb_transfer`s reaped via `libusb_handle_events`, so a read URB is always
//! waiting in the kernel the instant the dock produces a reply (the "host wasn't
//! ready" window a sync `read_bulk`-per-call model could open never exists).
//! Video OUT frames use a bounded async submit/reap window (depth 8) matching
//! DLM's measured submit-ahead.

use crate::{frame::Frame, EP_IN_CTRL, EP_OUT_CTRL, PID, VID};
use rusb::constants::{
    LIBUSB_TRANSFER_COMPLETED, LIBUSB_TRANSFER_TYPE_BULK,
};
use rusb::ffi::{
    libusb_alloc_transfer, libusb_cancel_transfer, libusb_context, libusb_device_handle,
    libusb_free_transfer, libusb_handle_events_timeout_completed, libusb_submit_transfer,
    libusb_transfer,
};
use rusb::{Context, DeviceHandle, UsbContext};
use std::collections::VecDeque;
use std::os::raw::{c_int, c_uint, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Depth of the EP 0x84 read queue kept perpetually posted to the kernel.
const RECV_QUEUE_DEPTH: usize = 4;
/// Buffer size for each queued EP 0x84 read. Dock control/HDCP responses are
/// well under 1 KiB; 8 KiB is generous and avoids per-call size juggling.
const RECV_BUF_LEN: usize = 8192;
/// Head-1 video endpoint (bulk OUT). The passive EP08 capture shows DLM drives
/// head 0 on EP 0x08 and head 1 on EP **0x0b**.
const EP_OUT_VIDEO2: u8 = 0x0b;
/// EP 0x83 status interrupt (on interface 2) that DLM polls.
const EP_INTR: u8 = 0x83;

/// bmRequestType bytes (direction | type | recipient).
const RT_VENDOR_IN_IFACE: u8 = 0xc1; // IN  | Vendor   | Interface
const RT_VENDOR_OUT_DEV: u8 = 0x40; //  OUT | Vendor   | Device
const RT_STD_IN_DEV: u8 = 0x80; //      IN  | Standard | Device
const RT_STD_OUT_IFACE: u8 = 0x01; //   OUT | Standard | Interface
const RT_STD_OUT_DEV: u8 = 0x00; //     OUT | Standard | Device
const RT_CLASS_OUT_DEV: u8 = 0x20; //   OUT | Class    | Device

/// Depth of the video OUT submit-ahead window (DLM keeps ~8 outstanding).
const PIPELINE_DEPTH: usize = 8;

pub struct Dock {
    /// EP 0x84 bulk IN — dock → host responses (persistently queued async).
    ///
    /// DECLARED FIRST on purpose so it DROPS FIRST. Rust drops struct fields in declaration order;
    /// `AsyncIn::drop` cancels its in-flight transfers and then pumps libusb events
    /// (`pump_events(self.ctx)`) to drain the completion callbacks before freeing the transfers --
    /// which requires the libusb context to still be alive. If `handle` (device close) and `ctx`
    /// (`libusb_exit`) dropped first, that pump/cancel would run against an already-exited context
    /// and segfault inside libusb (observed: `segfault at 50 in libusb-1.0.so`). Keep `ep84` above
    /// `handle`/`ctx`. See the 2026-07-12 teardown-crash fix.
    ep84: Mutex<AsyncIn>,
    handle: DeviceHandle<Context>,
    ctx: Context,
    pub timeout: Duration,
    /// Serialises host→dock bulk OUT (EP 0x02) — libusb sync bulk is thread-safe
    /// but we keep frame ordering deterministic.
    out_lock: Mutex<()>,
    has_video: bool,
    has_video2: bool,
    has_intr: bool,
    /// Process-relative time base for DLM_TIMING gap pacing.
    epoch: Instant,
    /// Nanoseconds since `epoch` of the last successful EP 0x84 read. Used by
    /// DLM_TIMING to pace each host→dock send to DLM's measured wire gap.
    last_recv_ns: AtomicU64,
}

#[derive(Debug)]
pub enum Error {
    DeviceNotFound,
    /// Transfer timed out.
    Timeout,
    /// Endpoint STALL / halt condition (libusb `Pipe`).
    Stall,
    /// Device went away mid-transfer.
    Disconnected,
    /// Any other libusb error (open, claim, config, transfer).
    Usb(rusb::Error),
    Decode,
    ShortRead(usize),
}

impl From<rusb::Error> for Error {
    fn from(e: rusb::Error) -> Self {
        map_err(e)
    }
}

/// Normalise a libusb error into our `Error` so callers can match on the common
/// cases (`Timeout`, `Stall`, `Disconnected`) directly.
fn map_err(e: rusb::Error) -> Error {
    match e {
        rusb::Error::Timeout => Error::Timeout,
        rusb::Error::Pipe => Error::Stall,
        rusb::Error::NoDevice | rusb::Error::NotFound => Error::Disconnected,
        other => Error::Usb(other),
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DeviceNotFound => write!(f, "DisplayLink D6000 (17e9:6006) not found"),
            Error::Timeout => write!(f, "USB transfer timed out"),
            Error::Stall => write!(f, "endpoint stalled (Pipe)"),
            // Keep the "NoDevice" token so existing string-based disconnect
            // checks in callers (`contains(\"NoDevice\")`) still fire.
            Error::Disconnected => write!(f, "device disconnected (NoDevice)"),
            Error::Usb(e) => write!(f, "USB error: {e}"),
            Error::Decode => write!(f, "frame decode failed"),
            Error::ShortRead(n) => write!(f, "short read: {n} bytes"),
        }
    }
}

impl std::error::Error for Error {}

// ---------------------------------------------------------------------------
// Persistent async IN pool for EP 0x84 (DLM's "always-posted read URB" model).
// ---------------------------------------------------------------------------

/// State shared between the Rust side and the libusb completion callback.
/// Referenced by raw pointer from `libusb_transfer::user_data`; kept alive in a
/// `Box` inside `AsyncIn` and only freed once every transfer is idle.
struct InShared {
    /// Completed dock replies, in arrival order.
    ready: Mutex<VecDeque<Vec<u8>>>,
    /// Transfers currently owned by libusb (submitted, callback not yet final).
    inflight: AtomicI32,
    /// Set during teardown so the callback stops re-arming.
    closing: AtomicBool,
}

/// libusb completion callback for an EP 0x84 IN transfer. Runs on whichever
/// thread is inside `libusb_handle_events`.
extern "system" fn ep84_complete(transfer: *mut libusb_transfer) {
    // SAFETY: `transfer` is a live transfer we allocated; `user_data` points at
    // the `InShared` boxed in the owning `AsyncIn`, which outlives all transfers.
    unsafe {
        let t = &*transfer;
        let shared = &*(t.user_data as *const InShared);
        if t.status == LIBUSB_TRANSFER_COMPLETED && !shared.closing.load(Ordering::Acquire) {
            let n = t.actual_length as usize;
            if n > 0 {
                let data = std::slice::from_raw_parts(t.buffer, n).to_vec();
                shared.ready.lock().unwrap().push_back(data);
            }
            // Re-arm to keep the queue perpetually posted (DLM model).
            if libusb_submit_transfer(transfer) != 0 {
                shared.inflight.fetch_sub(1, Ordering::AcqRel);
            }
        } else {
            // Cancelled, closing, device gone, or error: transfer is now idle.
            shared.inflight.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

struct AsyncIn {
    ctx: *mut libusb_context,
    transfers: Vec<*mut libusb_transfer>,
    /// Stable heap backing for each transfer's buffer (kept alive until Drop).
    _buffers: Vec<Box<[u8]>>,
    shared: Box<InShared>,
}

// SAFETY: every access to the raw pointers goes through `Dock`'s `Mutex<AsyncIn>`;
// the pointers address libusb objects / heap buffers this `AsyncIn` owns.
unsafe impl Send for AsyncIn {}

impl AsyncIn {
    fn new(handle: *mut libusb_device_handle, ctx: *mut libusb_context, ep: u8) -> AsyncIn {
        let shared = Box::new(InShared {
            ready: Mutex::new(VecDeque::new()),
            inflight: AtomicI32::new(0),
            closing: AtomicBool::new(false),
        });
        let shared_ptr = &*shared as *const InShared as *mut c_void;
        let mut buffers: Vec<Box<[u8]>> = Vec::with_capacity(RECV_QUEUE_DEPTH);
        let mut transfers: Vec<*mut libusb_transfer> = Vec::with_capacity(RECV_QUEUE_DEPTH);
        for _ in 0..RECV_QUEUE_DEPTH {
            let mut buf = vec![0u8; RECV_BUF_LEN].into_boxed_slice();
            let bptr = buf.as_mut_ptr();
            // SAFETY: alloc a bulk transfer (0 iso packets) and fill its fields;
            // `libusb_fill_bulk_transfer` is a C inline, so we set them directly.
            let t = unsafe { libusb_alloc_transfer(0) };
            assert!(!t.is_null(), "libusb_alloc_transfer failed");
            unsafe {
                let tr = &mut *t;
                tr.dev_handle = handle;
                tr.endpoint = ep;
                tr.transfer_type = LIBUSB_TRANSFER_TYPE_BULK;
                tr.timeout = 0; // infinite: stays posted until data or cancel
                tr.buffer = bptr;
                tr.length = RECV_BUF_LEN as c_int;
                tr.callback = ep84_complete;
                tr.user_data = shared_ptr;
                tr.flags = 0;
                tr.num_iso_packets = 0;
            }
            buffers.push(buf);
            transfers.push(t);
        }
        let ai = AsyncIn { ctx, transfers, _buffers: buffers, shared };
        for &t in &ai.transfers {
            // SAFETY: `t` is a filled, un-submitted transfer.
            if unsafe { libusb_submit_transfer(t) } == 0 {
                ai.shared.inflight.fetch_add(1, Ordering::AcqRel);
            }
        }
        ai
    }

    /// Read one dock reply, pumping libusb events until one lands or `timeout`.
    fn recv(&self, timeout: Duration) -> Result<Vec<u8>, Error> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(b) = self.shared.ready.lock().unwrap().pop_front() {
                return Ok(b);
            }
            if self.shared.inflight.load(Ordering::Acquire) == 0 {
                // No posted URBs left (device gone at submit time) and nothing ready.
                return Err(Error::Disconnected);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Error::Timeout);
            }
            let slice = (deadline - now).min(Duration::from_millis(20));
            pump_events(self.ctx, slice);
        }
    }
}

impl Drop for AsyncIn {
    fn drop(&mut self) {
        self.shared.closing.store(true, Ordering::Release);
        for &t in &self.transfers {
            // SAFETY: cancelling a live or already-idle transfer is safe
            // (returns NOT_FOUND if not in flight); ignore the result.
            unsafe { libusb_cancel_transfer(t) };
        }
        // Drain callbacks so no transfer is still owned by libusb before we free.
        let deadline = Instant::now() + Duration::from_millis(500);
        while self.shared.inflight.load(Ordering::Acquire) > 0 && Instant::now() < deadline {
            pump_events(self.ctx, Duration::from_millis(20));
        }
        for &t in &self.transfers {
            // SAFETY: transfer is idle (callback fired) — safe to free.
            unsafe { libusb_free_transfer(t) };
        }
    }
}

/// Run libusb's event handler for up to `slice`. Multiple threads may call this
/// concurrently; libusb serialises via its internal event lock.
fn pump_events(ctx: *mut libusb_context, slice: Duration) {
    let tv = libc::timeval {
        tv_sec: slice.as_secs() as libc::time_t,
        tv_usec: slice.subsec_micros() as libc::suseconds_t,
    };
    let mut completed: c_int = 0;
    // SAFETY: `ctx` is a live libusb context; `tv`/`completed` are stack locals.
    unsafe { libusb_handle_events_timeout_completed(ctx, &tv, &mut completed) };
}

fn status_to_err(status: c_int) -> Error {
    match status {
        rusb::constants::LIBUSB_TRANSFER_TIMED_OUT => Error::Timeout,
        rusb::constants::LIBUSB_TRANSFER_STALL => Error::Stall,
        rusb::constants::LIBUSB_TRANSFER_NO_DEVICE => Error::Disconnected,
        _ => Error::Usb(rusb::Error::Other),
    }
}

impl Dock {
    /// Open the first D6000 found. Detaches any existing kernel driver and
    /// claims the bulk interface.
    pub fn open() -> Result<Self, Error> {
        let ctx = Context::new().map_err(map_err)?;

        let find_open = |ctx: &Context| -> Result<DeviceHandle<Context>, Error> {
            for dev in ctx.devices().map_err(map_err)?.iter() {
                if let Ok(desc) = dev.device_descriptor() {
                    if desc.vendor_id() == VID && desc.product_id() == PID {
                        return dev.open().map_err(map_err);
                    }
                }
            }
            Err(Error::DeviceNotFound)
        };

        // HARD_RESET=1: issue a real USB bus reset before bring-up. Unlike `echo
        // 0/1 authorized` (a logical de-authorize that only re-triggers HDCP), a
        // bus reset re-initialises the dock's USB device state machine. The
        // handle is invalid after reset, so re-open once the dock re-enumerates.
        let handle = {
            let h = find_open(&ctx)?;
            if env_flag("HARD_RESET") {
                eprintln!("[usb] HARD_RESET: issuing USB bus reset...");
                match h.reset() {
                    Ok(()) => eprintln!("[usb] HARD_RESET: reset issued; waiting for re-enumeration"),
                    Err(e) => eprintln!("[usb] HARD_RESET: reset returned {e}; waiting anyway"),
                }
                drop(h);
                let deadline = Instant::now() + Duration::from_secs(8);
                loop {
                    std::thread::sleep(Duration::from_millis(250));
                    match find_open(&ctx) {
                        Ok(h2) => {
                            eprintln!("[usb] HARD_RESET: dock re-enumerated and re-opened ✓");
                            break h2;
                        }
                        Err(_) if Instant::now() < deadline => continue,
                        Err(e) => return Err(e),
                    }
                }
            } else {
                h
            }
        };

        let early_check = env_flag("EARLY_VENDOR_CHECK");
        let skip_set_config = env_flag("SKIP_SET_CONFIG");
        // SOFT_ALT: in SKIP_SET_CONFIG mode still set the interface alt-setting and
        // clear the control-endpoint halts WITHOUT issuing SET_CONFIGURATION.
        let soft_alt = env_flag("SOFT_ALT");
        // KEEP_AUDIO: mirror DLM's multi-interface environment — leave
        // snd-usb-audio bound to interfaces 2–4, claim ONLY interface 0. Implies
        // skipping set_configuration (fails -EBUSY while audio is bound, and DLM
        // never issues it) and the EP 0x83 poll (would claim audio iface 2).
        let keep_audio = env_flag("KEEP_AUDIO");
        // SKIP_VIDEO_CLEAR_HALT: do NOT clear_halt the video EPs (0x08/0x0b) on
        // open — isolates the warm-handoff hypothesis that the open-time
        // CLEAR_FEATURE(ENDPOINT_HALT) itself de-arms the dock's video pipe.
        let skip_video_clear_halt = env_flag("SKIP_VIDEO_CLEAR_HALT");
        // VIDEO_SET_ALT: force SET_INTERFACE(alt 0) even in SKIP_SET_CONFIG mode
        // WITHOUT SOFT_ALT's CP-EP clear_halt.
        let video_set_alt = env_flag("VIDEO_SET_ALT");

        // Read vendor_in 0x22 at a labelled point (best-effort, diagnostics).
        let early_read = |h: &DeviceHandle<Context>, label: &str| {
            let mut buf = [0u8; 28];
            match h.read_control(
                RT_VENDOR_IN_IFACE, 0x22, 0, 0, &mut buf, Duration::from_millis(500),
            ) {
                Ok(_) => eprintln!("[early_check] {label}: byte[9]=0x{:02x}", buf[9]),
                Err(_) => eprintln!("[early_check] {label}: control transfer failed"),
            }
        };

        if early_check {
            early_read(&handle, "BEFORE detach");
        }

        // Detach any kernel drivers (audio etc.) so they don't interfere; ignore
        // errors. KEEP_AUDIO: detach only interface 0.
        let detach_range = if keep_audio { 0u8..1 } else { 0u8..8 };
        for iface in detach_range {
            let _ = handle.detach_kernel_driver(iface);
        }

        if early_check {
            early_read(&handle, "AFTER detach, BEFORE config");
        }

        // SET_CONFIGURATION on an already-configured device may reset the dock's
        // HDCP session state. Skip for warm-start tests / KEEP_AUDIO.
        if skip_set_config || keep_audio {
            eprintln!(
                "[usb] skipping set_configuration ({})",
                if keep_audio { "KEEP_AUDIO=1" } else { "SKIP_SET_CONFIG=1" }
            );
        } else {
            let _ = handle.set_active_configuration(1);
        }

        if early_check && !skip_set_config {
            early_read(&handle, "AFTER set_config, BEFORE claim");
        }

        // Detach (again, in case config reset re-attached) and claim interface 0.
        let _ = handle.detach_kernel_driver(0);
        handle.claim_interface(0).map_err(map_err)?;

        if early_check {
            early_read(&handle, "AFTER claim, BEFORE set_alt");
        }

        // SET_INTERFACE (alt setting) resets endpoint toggles and signals the
        // dock to drop streaming state. Skip in warm-start mode unless SOFT_ALT.
        if (skip_set_config && !soft_alt) && !video_set_alt {
            eprintln!("[usb] skipping set_alt_setting (SKIP_SET_CONFIG=1)");
        } else {
            if skip_set_config && (soft_alt || video_set_alt) {
                eprintln!(
                    "[usb] {}: set_alt_setting(0) despite SKIP_SET_CONFIG",
                    if video_set_alt { "VIDEO_SET_ALT" } else { "SOFT_ALT" }
                );
            }
            let _ = handle.set_alternate_setting(0, 0);
        }

        if early_check {
            early_read(&handle, "AFTER set_alt");
        }

        // Discover which optional endpoints the active config exposes.
        let has_video = has_endpoint(&handle, crate::EP_OUT_VIDEO);
        let has_video2 = has_endpoint(&handle, EP_OUT_VIDEO2);
        if !has_video {
            eprintln!("[usb] EP_OUT_VIDEO (0x{:02x}) unavailable", crate::EP_OUT_VIDEO);
        }
        if !has_video2 {
            eprintln!("[usb] EP 0x{EP_OUT_VIDEO2:02x} (head 1 video) unavailable");
        }

        // EP 0x83 (status interrupt DLM polls) lives on interface 2 — claim it
        // separately. Best-effort: the poller's events don't affect the verdict.
        let has_intr = if keep_audio {
            eprintln!("[usb] KEEP_AUDIO: skipping EP 0x83 poll (would claim audio iface 2)");
            false
        } else {
            let _ = handle.detach_kernel_driver(2);
            match handle.claim_interface(2) {
                Ok(()) => has_endpoint(&handle, EP_INTR),
                Err(e) => {
                    eprintln!("[usb] claim iface 2 (for EP 0x83 poll) failed: {e}");
                    false
                }
            }
        };

        // Clear stale halts. In warm-start mode skip clearing the control
        // endpoints (may reset HDCP state); always clear the video EP unless
        // SKIP_VIDEO_CLEAR_HALT — a killed DLM can leave it stalled.
        if !skip_set_config || soft_alt {
            if skip_set_config && soft_alt {
                eprintln!("[usb] SOFT_ALT: clear_halt(EP 0x02/0x84) despite SKIP_SET_CONFIG");
            }
            let _ = handle.clear_halt(EP_OUT_CTRL);
            let _ = handle.clear_halt(EP_IN_CTRL);
        }
        if skip_video_clear_halt {
            eprintln!("[usb] SKIP_VIDEO_CLEAR_HALT: leaving EP 0x08/0x0b halt state untouched");
        } else {
            if has_video {
                match handle.clear_halt(crate::EP_OUT_VIDEO) {
                    Ok(()) => eprintln!("[usb] clear_halt(EP_OUT_VIDEO=0x{:02x}) ok", crate::EP_OUT_VIDEO),
                    Err(e) => eprintln!("[usb] clear_halt(EP_OUT_VIDEO) FAILED: {e}"),
                }
            }
            if has_video2 {
                if let Err(e) = handle.clear_halt(EP_OUT_VIDEO2) {
                    eprintln!("[usb] clear_halt(EP 0x0b) FAILED: {e}");
                }
            }
        }

        // Bring up the persistent async EP 0x84 IN pool.
        let ep84 = AsyncIn::new(handle.as_raw(), ctx.as_raw(), EP_IN_CTRL);

        Ok(Self {
            handle,
            ctx,
            timeout: Duration::from_millis(2000),
            ep84: Mutex::new(ep84),
            out_lock: Mutex::new(()),
            has_video,
            has_video2,
            has_intr,
            epoch: Instant::now(),
            last_recv_ns: AtomicU64::new(0),
        })
    }

    /// Issue a vendor-specific IN control transfer (bmRequestType=0xc1).
    pub fn vendor_in(&self, request: u8, value: u16, index: u16, length: u16)
        -> Result<Vec<u8>, Error>
    {
        let mut buf = vec![0u8; length as usize];
        let n = self
            .handle
            .read_control(RT_VENDOR_IN_IFACE, request, value, index, &mut buf, self.timeout)
            .map_err(map_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Issue a vendor-specific OUT control transfer (bmRequestType=0x40).
    pub fn vendor_out(&self, request: u8, value: u16, index: u16, data: &[u8])
        -> Result<(), Error>
    {
        self.handle
            .write_control(RT_VENDOR_OUT_DEV, request, value, index, data, self.timeout)
            .map(|_| ())
            .map_err(map_err)
    }

    /// Standard IN control transfer (e.g. GET_DESCRIPTOR), recipient=device.
    pub fn std_in(&self, request: u8, value: u16, index: u16, length: u16, timeout: Duration)
        -> Result<Vec<u8>, Error>
    {
        let mut buf = vec![0u8; length as usize];
        let n = self
            .handle
            .read_control(RT_STD_IN_DEV, request, value, index, &mut buf, timeout)
            .map_err(map_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Standard OUT control transfer with recipient=interface (e.g. SET_INTERFACE).
    pub fn std_out_iface(&self, request: u8, value: u16, index: u16, data: &[u8], timeout: Duration)
        -> Result<(), Error>
    {
        self.handle
            .write_control(RT_STD_OUT_IFACE, request, value, index, data, timeout)
            .map(|_| ())
            .map_err(map_err)
    }

    /// Class OUT control transfer with recipient=device. DLM issues
    /// `bmRequestType=0x20 bRequest=0x0c wValue=0/1` (no data) during early setup.
    pub fn class_out_device(&self, request: u8, value: u16, index: u16, data: &[u8])
        -> Result<(), Error>
    {
        self.handle
            .write_control(RT_CLASS_OUT_DEV, request, value, index, data, self.timeout)
            .map(|_| ())
            .map_err(map_err)
    }

    /// Claim an additional interface beyond the ones `open()` claims by default
    /// (0 for the control plane, 2 for the EP 0x83 status poll). DLM's libusb
    /// claims interface 1 (the DFU/app-specific interface) too, via its own
    /// `usbfs` open, and the in-kernel driver binds it as a real driver
    /// (confirmed live: `vino 2-1.1:1.1: bound D6000 interface 1`) -- needed
    /// before `std_out_iface`'s `SET_INTERFACE` on it will succeed.
    pub fn claim_interface(&self, iface: u8) -> Result<(), Error> {
        let _ = self.handle.detach_kernel_driver(iface);
        self.handle.claim_interface(iface).map_err(map_err)
    }

    /// Issue an empty SET (host→device) control transfer — DLM does this between
    /// vendor requests; function unknown but apparently benign.
    pub fn ctrl_noop(&self) -> Result<(), Error> {
        let _ = self
            .handle
            .write_control(RT_STD_OUT_DEV, 0, 0, 0, &[], self.timeout);
        Ok(())
    }

    /// Write raw bytes to the control-plane bulk OUT endpoint (EP 0x02) via the
    /// SAME raw `libusb_submit_transfer` path DLM itself uses for this
    /// endpoint (confirmed 2026-07-07 by a live frida trace of the real DLM
    /// process: EP 0x02 submissions are `type=BULK flags=0 timeout=0`, NOT the
    /// synchronous `libusb_bulk_transfer` convenience wrapper `write_ctrl_raw`
    /// below calls — DLM never calls `libusb_bulk_transfer` at all, for either
    /// direction). `timeout=0` on the libusb transfer itself matches DLM
    /// exactly (infinite — no libusb-level auto-cancel); `safety_deadline` is
    /// a Rust-side-only escape hatch (cancels + frees the transfer if nothing
    /// completes in time) so a genuinely wedged dock can't hang the caller
    /// forever the way a literal `timeout=0` would if taken completely
    /// literally on a coldstart rig with no other watchdog.
    pub fn write_ctrl_raw_async(&self, bytes: &[u8], safety_deadline: Duration) -> Result<usize, Error> {
        struct OutShared {
            done: AtomicBool,
            status: AtomicI32,
            actual_length: AtomicI32,
        }
        extern "system" fn out_complete(transfer: *mut libusb_transfer) {
            // SAFETY: `transfer` is the one transfer this call owns; `user_data`
            // points at the `OutShared` kept alive on this function's stack
            // until the transfer is known idle (join loop below).
            unsafe {
                let t = &*transfer;
                let shared = &*(t.user_data as *const OutShared);
                shared.status.store(t.status, Ordering::Release);
                shared.actual_length.store(t.actual_length, Ordering::Release);
                shared.done.store(true, Ordering::Release);
            }
        }

        let _g = self.out_lock.lock().unwrap();
        let shared = Box::new(OutShared {
            done: AtomicBool::new(false),
            status: AtomicI32::new(-1),
            actual_length: AtomicI32::new(0),
        });
        let shared_ptr = &*shared as *const OutShared as *mut c_void;

        // SAFETY: alloc a bulk transfer (0 iso packets); fields set directly,
        // mirroring `AsyncIn::new`'s pattern for the IN side.
        let t = unsafe { libusb_alloc_transfer(0) };
        assert!(!t.is_null(), "libusb_alloc_transfer failed");
        // `bytes` outlives the transfer (freed/cancelled before this fn
        // returns), so casting away constness for the C struct is sound: the
        // OUT direction never has libusb write back into this buffer.
        unsafe {
            let tr = &mut *t;
            tr.dev_handle = self.handle.as_raw();
            tr.endpoint = EP_OUT_CTRL;
            tr.transfer_type = LIBUSB_TRANSFER_TYPE_BULK;
            tr.timeout = 0; // matches DLM exactly -- see doc comment above
            tr.buffer = bytes.as_ptr() as *mut u8;
            tr.length = bytes.len() as c_int;
            tr.callback = out_complete;
            tr.user_data = shared_ptr;
            tr.flags = 0;
            tr.num_iso_packets = 0;
        }
        // SAFETY: `t` is a filled, un-submitted transfer.
        if unsafe { libusb_submit_transfer(t) } != 0 {
            unsafe { libusb_free_transfer(t) };
            return Err(Error::Usb(rusb::Error::Io));
        }

        let deadline = Instant::now() + safety_deadline;
        while !shared.done.load(Ordering::Acquire) {
            if Instant::now() >= deadline {
                // Rust-side safety net only -- DLM has no equivalent and would
                // wait forever; we cancel so the caller doesn't hang.
                unsafe { libusb_cancel_transfer(t) };
                let cancel_deadline = Instant::now() + Duration::from_millis(500);
                while !shared.done.load(Ordering::Acquire) && Instant::now() < cancel_deadline {
                    pump_events(self.ctx.as_raw(), Duration::from_millis(20));
                }
                unsafe { libusb_free_transfer(t) };
                return Err(Error::Timeout);
            }
            pump_events(self.ctx.as_raw(), Duration::from_millis(20));
        }
        let status = shared.status.load(Ordering::Acquire);
        let actual = shared.actual_length.load(Ordering::Acquire) as usize;
        unsafe { libusb_free_transfer(t) };
        if status == LIBUSB_TRANSFER_COMPLETED {
            Ok(actual)
        } else {
            Err(status_to_err(status))
        }
    }

    /// [`write_ctrl_raw_async`] with a fixed 2s Rust-side safety deadline —
    /// the convenient default for callers that just want DLM's exact EP 0x02
    /// libusb call shape without picking their own timeout each call site.
    pub fn write_ctrl_dlm(&self, bytes: &[u8]) -> Result<usize, Error> {
        self.write_ctrl_raw_async(bytes, Duration::from_secs(2))
    }

    /// Write raw bytes to the control-plane bulk OUT endpoint (EP 0x02) via
    /// the SYNCHRONOUS `libusb_bulk_transfer` convenience wrapper. Kept as the
    /// default for callers that don't need DLM-exact transport fidelity;
    /// prefer [`write_ctrl_raw_async`] to match DLM's actual libusb usage on
    /// this endpoint. Returns the number of bytes written.
    pub fn write_ctrl_raw(&self, bytes: &[u8]) -> Result<usize, Error> {
        let _g = self.out_lock.lock().unwrap();
        self.handle
            .write_bulk(EP_OUT_CTRL, bytes, self.timeout)
            .map_err(map_err)
    }

    /// Send one HDCP frame on EP 0x02 (with optional DLM-timing pacing).
    pub fn send_frame(&self, f: &Frame) -> Result<(), Error> {
        // §8.2 timing test: DLM pauses ~1-2ms before each AKE reply; our driver
        // fires back-to-back. MSG_GAP_MS inserts a per-message gap.
        if let Ok(ms) = std::env::var("MSG_GAP_MS") {
            if let Ok(ms) = ms.parse::<u64>() {
                if ms > 0 {
                    std::thread::sleep(Duration::from_millis(ms));
                }
            }
        }
        // DLM_TIMING=1: replicate DLM's per-message wire gaps (µs), keyed on the
        // HDCP msg_id at body[27]. Target the gap (sleep only the remainder after
        // our own compute + USB latency) rather than adding the full delay.
        if env_flag("DLM_TIMING") {
            let target_us: u64 = match f.body.get(27).copied() {
                Some(0x02) => 110,  // AKE_Init
                Some(0x13) => 4,    // AKE_Transmitter_Info
                Some(0x04) => 1392, // AKE_No_Stored_km (mostly RSA-OAEP compute)
                Some(0x09) => 84,   // LC_Init
                Some(0x0b) => 54,   // SKE_Send_Eks
                Some(0x0f) => 28,   // RepeaterAuth_Send_ACK
                Some(0x10) => 905,  // Stream_Manage (SM2)
                _ => 0,
            };
            if target_us > 0 {
                self.pace_to_gap(target_us);
            }
        }
        let bytes = f.encode();
        let n = self.write_ctrl_raw(&bytes)?;
        if n != bytes.len() {
            return Err(Error::ShortRead(n));
        }
        Ok(())
    }

    /// Write a video frame on EP 0x08. Returns bytes written.
    pub fn write_video(&self, bytes: &[u8]) -> Result<usize, Error> {
        if !self.has_video {
            return Err(Error::Disconnected);
        }
        self.handle
            .write_bulk(crate::EP_OUT_VIDEO, bytes, self.timeout)
            .map_err(map_err)
    }

    /// Write one video frame to EP 0x0b (head 1). Mirrors [`write_video`].
    pub fn write_video2(&self, bytes: &[u8]) -> Result<usize, Error> {
        if !self.has_video2 {
            return Err(Error::Disconnected);
        }
        self.handle
            .write_bulk(EP_OUT_VIDEO2, bytes, self.timeout)
            .map_err(map_err)
    }

    /// Pipeline a whole frame's chunks on the head-0 video EP (0x08): submit up
    /// to [`PIPELINE_DEPTH`] transfers to the URB ring, reap completions, and
    /// submit-ahead — matching DLM's async libusb submission so the dock's frame
    /// assembler never sees a host-side stall mid-frame. Returns total bytes.
    pub fn write_video_frame(&self, chunks: &[Vec<u8>]) -> Result<usize, Error> {
        if !self.has_video {
            return Err(Error::Disconnected);
        }
        self.pipeline_out(crate::EP_OUT_VIDEO, chunks)
    }

    /// [`write_video_frame`] for head 1 (EP 0x0b).
    pub fn write_video2_frame(&self, chunks: &[Vec<u8>]) -> Result<usize, Error> {
        if !self.has_video2 {
            return Err(Error::Disconnected);
        }
        self.pipeline_out(EP_OUT_VIDEO2, chunks)
    }

    /// Bounded async submit/reap of `chunks` on a bulk OUT endpoint. Keeps at
    /// most [`PIPELINE_DEPTH`] transfers outstanding (DLM's measured depth),
    /// submitting the next chunk the instant one completes.
    fn pipeline_out(&self, ep: u8, chunks: &[Vec<u8>]) -> Result<usize, Error> {
        if chunks.is_empty() {
            return Ok(0);
        }
        let _g = self.out_lock.lock().unwrap();
        let handle = self.handle.as_raw();
        let ctx = self.ctx.as_raw();
        let depth = PIPELINE_DEPTH.min(chunks.len());
        // Completions land here (transfer ptr, status, actual_length). Callbacks
        // fire on this thread inside `pump_events`, so no cross-thread hazard.
        let completions: Box<Mutex<VecDeque<(*mut libusb_transfer, c_int, c_int)>>> =
            Box::new(Mutex::new(VecDeque::new()));
        let cptr = &*completions as *const Mutex<VecDeque<(*mut libusb_transfer, c_int, c_int)>>
            as *mut c_void;

        let transfers: Vec<*mut libusb_transfer> =
            (0..depth).map(|_| unsafe { libusb_alloc_transfer(0) }).collect();
        assert!(transfers.iter().all(|t| !t.is_null()), "libusb_alloc_transfer failed");
        let timeout_ms = self.timeout.as_millis() as c_uint;

        // SAFETY: fill+submit a transfer for chunk `ci` on transfer object `t`.
        let submit = |t: *mut libusb_transfer, ci: usize| -> c_int {
            unsafe {
                let tr = &mut *t;
                tr.dev_handle = handle;
                tr.endpoint = ep;
                tr.transfer_type = LIBUSB_TRANSFER_TYPE_BULK;
                tr.timeout = timeout_ms;
                tr.buffer = chunks[ci].as_ptr() as *mut u8;
                tr.length = chunks[ci].len() as c_int;
                tr.callback = out_complete;
                tr.user_data = cptr;
                tr.flags = 0;
                tr.num_iso_packets = 0;
                libusb_submit_transfer(t)
            }
        };

        let mut next = 0usize;
        let mut submitted = 0usize;
        let mut reaped = 0usize;
        let mut total = 0usize;
        let mut err: Option<Error> = None;

        // Prime the window.
        for &t in &transfers {
            if next >= chunks.len() {
                break;
            }
            if submit(t, next) == 0 {
                submitted += 1;
                next += 1;
            } else {
                err = Some(Error::Disconnected);
                break;
            }
        }

        // Reap and submit-ahead until every submitted transfer has completed.
        let deadline = Instant::now() + self.timeout + Duration::from_millis(500);
        while reaped < submitted {
            let done = completions.lock().unwrap().pop_front();
            let (t, status, actual) = match done {
                Some(x) => x,
                None => {
                    if Instant::now() >= deadline {
                        err = err.or(Some(Error::Timeout));
                        break;
                    }
                    pump_events(ctx, Duration::from_millis(20));
                    continue;
                }
            };
            reaped += 1;
            if status != LIBUSB_TRANSFER_COMPLETED {
                if err.is_none() {
                    err = Some(status_to_err(status));
                }
                continue;
            }
            total += actual.max(0) as usize;
            // Submit-ahead: reuse the just-completed transfer for the next chunk.
            if err.is_none() && next < chunks.len() {
                if submit(t, next) == 0 {
                    submitted += 1;
                    next += 1;
                } else if err.is_none() {
                    err = Some(Error::Disconnected);
                }
            }
        }

        // Teardown: cancel anything still outstanding and drain its callback so
        // no transfer is owned by libusb when we free.
        for &t in &transfers {
            unsafe { libusb_cancel_transfer(t) };
        }
        let drain_deadline = Instant::now() + Duration::from_millis(500);
        while reaped < submitted && Instant::now() < drain_deadline {
            if let Some(_) = completions.lock().unwrap().pop_front() {
                reaped += 1;
            } else {
                pump_events(ctx, Duration::from_millis(20));
            }
        }
        for &t in &transfers {
            unsafe { libusb_free_transfer(t) };
        }

        match err {
            Some(e) => Err(e),
            None => Ok(total),
        }
    }

    /// Clear the halt/stall condition on the head-1 video endpoint (EP 0x0b).
    pub fn clear_video2_halt(&self) -> Result<(), Error> {
        if !self.has_video2 {
            return Err(Error::Disconnected);
        }
        self.handle.clear_halt(EP_OUT_VIDEO2).map_err(map_err)
    }

    /// Clear the halt/stall condition on the video endpoint (EP 0x08).
    pub fn clear_video_halt(&self) -> Result<(), Error> {
        if !self.has_video {
            return Err(Error::Disconnected);
        }
        self.handle.clear_halt(crate::EP_OUT_VIDEO).map_err(map_err)
    }

    /// Read one EP 0x83 interrupt event into `buf`. Returns the byte count
    /// (0 on timeout — matching the old poller's "no event" handling).
    pub fn read_intr(&self, buf: &mut [u8], timeout: Duration) -> Result<usize, Error> {
        if !self.has_intr {
            return Err(Error::Disconnected);
        }
        match self.handle.read_interrupt(EP_INTR, buf, timeout) {
            Ok(n) => Ok(n),
            Err(rusb::Error::Timeout) => Ok(0), // no event
            Err(e) => Err(map_err(e)),
        }
    }

    /// Read one frame from EP 0x84 using the persistent read queue. Uses the
    /// default timeout.
    pub fn recv_frame_raw(&self, max_len: usize) -> Result<Vec<u8>, Error> {
        self.recv_frame_raw_timeout(max_len, self.timeout)
    }

    /// Read one frame from EP 0x84 with an explicit timeout. The async pool keeps
    /// `RECV_QUEUE_DEPTH` URBs posted so the dock always has a waiting buffer.
    pub fn recv_frame_raw_timeout(&self, _max_len: usize, timeout: Duration) -> Result<Vec<u8>, Error> {
        let ep = self.ep84.lock().unwrap();
        let r = ep.recv(timeout);
        if r.is_ok() {
            // Stamp the time of this dock response so DLM_TIMING can pace the
            // next send relative to it.
            self.last_recv_ns
                .store(self.epoch.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }
        r
    }

    /// Block until `target_us` has elapsed since the dock's last response, so a
    /// host→dock send lands at DLM's measured wire gap. Used by DLM_TIMING.
    fn pace_to_gap(&self, target_us: u64) {
        let last = self.last_recv_ns.load(Ordering::Relaxed);
        if last == 0 {
            return; // no dock response read yet — nothing to pace against
        }
        let target_ns = target_us * 1_000;
        const SPIN_TAIL_NS: u64 = 150_000; // spin the last 150 µs for precision
        let elapsed = || (self.epoch.elapsed().as_nanos() as u64).saturating_sub(last);
        let rem = target_ns.saturating_sub(elapsed());
        if rem == 0 {
            return; // our compute already met or exceeded DLM's gap
        }
        if rem > SPIN_TAIL_NS {
            std::thread::sleep(Duration::from_nanos(rem - SPIN_TAIL_NS));
        }
        while elapsed() < target_ns {
            std::hint::spin_loop();
        }
    }

    pub fn recv_frame(&self, max_len: usize) -> Result<Frame, Error> {
        let bytes = self.recv_frame_raw(max_len)?;
        Frame::decode(&bytes).ok_or(Error::Decode)
    }

    /// Read frames until one arrives where body[9] (HDCP msg_id) is non-zero.
    /// Silently discards ACK/control frames. Up to `max_tries` reads.
    pub fn recv_hdcp_msg(&self, max_len: usize, max_tries: usize) -> Result<Frame, Error> {
        for _ in 0..max_tries {
            let bytes = self.recv_frame_raw(max_len)?;
            if let Some(frame) = Frame::decode(&bytes) {
                if frame.body.len() >= 10 && frame.body[9] != 0x00 {
                    return Ok(frame);
                }
            }
        }
        Err(Error::Decode)
    }
}

/// libusb completion callback for a video OUT transfer (see [`Dock::pipeline_out`]).
extern "system" fn out_complete(transfer: *mut libusb_transfer) {
    // SAFETY: `user_data` points at the `completions` queue boxed on the stack of
    // the `pipeline_out` call that submitted this transfer; that call does not
    // return until every transfer it submitted has been reaped or cancelled.
    unsafe {
        let t = &*transfer;
        let q = &*(t.user_data
            as *const Mutex<VecDeque<(*mut libusb_transfer, c_int, c_int)>>);
        q.lock().unwrap().push_back((transfer, t.status, t.actual_length));
    }
}

/// Does the active configuration expose an endpoint with address `addr`?
fn has_endpoint(handle: &DeviceHandle<Context>, addr: u8) -> bool {
    let dev = handle.device();
    let Ok(config) = dev.active_config_descriptor() else {
        return false;
    };
    config
        .interfaces()
        .flat_map(|i| i.descriptors())
        .flat_map(|d| d.endpoint_descriptors())
        .any(|e| e.address() == addr)
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).map(|v| !v.is_empty()).unwrap_or(false)
}
