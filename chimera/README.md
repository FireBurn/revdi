# chimera

The beginning of an open replacement for the closed `DisplayLinkManager` (DLM)
binary — the last proprietary piece of the DisplayLink stack once `revdi`'s module
and library have replaced `evdi` and `libevdi`.

A **chimera** because it is one body with two heads: it runs the *actual in-kernel
vino driver code* (the control-plane crypto, the HDCP AKE, the video codec) but
drives the dock from **userspace over libusb** instead of through the kernel USB
core.

## The trick: compile the literal kernel sources

The point is to never re-implement the driver. A port drifts; a port that drifts
silently invalidates every proof built on it. So chimera compiles the **kernel
files themselves**:

```
src/kvino.rs:  #[path = "../vino/cp.rs"]    pub mod cp;      // and proto/video/ake/hdcp
src/kshim.rs:  userspace stand-ins for KVec / GFP_KERNEL / Result / crypto / bindings
```

Those files resolve their own `use super::*` against the shim, so the AES-CTR
seal, the Dl3Cmac, the wire framing, the AKE and the WHT codec are **byte-for-byte
the code that ships in `vino.ko`**. The only non-kernel code is the ~30-line
AES-CMAC in the shim, built on the `aes` block cipher — the same RFC 4493 math the
kernel's `lib/crypto` `aes_cmac()` runs.

`vino/*.rs` are vendored copies, refreshed from a kernel tree by
`../scripts/sync-kernel-sources.sh` (`make sync` at the project root). **Never
hand-edit them** — that reintroduces exactly the drift this design exists to rule
out. Edit the kernel tree and re-sync.

## Binaries

### `chimera-prove` — offline, no hardware

```sh
cargo run --bin chimera-prove
cargo test                      # same proof, as a CI gate
```

Replays a real engaged DLM session (`cold-ref-20260608-200850`, embedded as
compact fixtures) through the kernel code and asserts:

1. **Seal equivalence** — for every OUT CP frame DLM put on the wire, recover the
   inner plaintext (`cp::open_in`), re-seal it (`cp::seal_interactive` /
   `cp::seal_stream`), and assert the regenerated frame is byte-identical to DLM's.
   *Current result: 192/192 frames byte-identical.*
2. **Builder equivalence** — regenerate the inner plaintext for the messages the
   kernel builds from scratch (`heartbeat`, `cursor_{create,move,image}`) from the
   fields DLM used, and assert it matches DLM's recovered plaintext (modulo the
   documented uninitialised regions DLM leaks: heartbeat off24..32, cursor
   off28..31 — bytes the dock cannot validate because they vary per frame).
   *Current result: 34/34 ok.*

This proves the encryption and the post-msg0 builders correct **by construction**,
using the kernel's own code.

### `chimera-coldstart` — the cold-boot path (`--features live`)

```sh
# Load DLM's OWN bundled libusb (0.3.0) rather than the system one, so the
# transport is the exact C library DLM drives the dock with:
LD_LIBRARY_PATH=/opt/displaylink cargo run --bin chimera-coldstart --features live
```

Does its **own cold engagement from scratch** — no DLM, no frida handoff, no
pre-existing session. It runs the literal kernel `ake.rs`/`hdcp.rs`/`cp.rs` but
drives the dock through libusb (`vino_driver::Dock`), and the dock engages.

This is the piece that grows into the DLM replacement: it already does the hard
half (HDCP AKE → CP engagement → the post-msg0 setup burst). What it does *not*
yet do is paint a real desktop — that needs the revdi virtual display wired to
its pixel source, and the EP08 scanout blocker below resolved.

**Transport.** libusb (via `rusb`), linked by soname `libusb-1.0.so.0`, so
`LD_LIBRARY_PATH=/opt/displaylink` makes it load DLM's exact bundled build. The
execution model mirrors DLM: control and bulk-OUT are synchronous
`libusb_bulk_transfer`/`libusb_control_transfer` (`flags=0`); the EP 0x84
dock-reply IN path is a persistently posted pool of async `libusb_transfer`s
reaped via `libusb_handle_events`.

### `dumpframe`, `gencolour`, `genstrip`

Codec helpers: encode a frame/strip with the literal kernel `video.rs` and dump it
for offline comparison against captured DLM output.

## What is and is not proven

* **Proven:** the control-plane crypto and the post-msg0 message path, byte-exact
  against real DLM sessions (offline), *and* a real dock cold-engaging from this
  code over libusb. The WHT video codec is byte-exact against captured DLM strips
  (luma + colour).
* **Not proven:** video actually reaching the panels. The first real EP08 scanout
  write disconnects the dock — even for a solid grey frame with byte-exact colour,
  which rules out pixel content and points at framing/arming/sequencing. This is
  the live blocker for both chimera and `vino.ko`.
* **Not yet built:** the daemon itself. Fetching the dock's EDID, handing it to a
  revdi virtual display, and pumping real compositor frames exist as library
  pieces here (`edid_fetch`, `revdi`) but nothing drives them unattended.

## History

Chimera was built to answer a different question. For months the dock refused to
engage the control plane for any host but DLM, and the leading theory was that
vino's in-kernel USB transport differed from DLM's libusb in some way nobody could
see on the wire. Chimera removed that variable instead of arguing about it: same
driver code, different transport.

That wall fell on 2026-07-16, and it was never the transport — it was a single bit
in the AES-CTR content nonce (a mid-session refactor folded the Dl3Cmac's
`byte0^0x80` into the CTR nonce, so the dock decrypted msg0 to garbage and dropped
it silently, while our own MAC still self-verified). With the wall down, chimera
stopped being a diagnostic and became the natural home for the DLM replacement:
it already speaks the whole protocol from userspace.

Two handoff-based binaries from that era — `chimera-takeover` and
`chimera-live-video`, which both needed an already-engaged DLM session to hand
over from — were deliberately left out of this project. They were instruments for
probing the wall, not steps toward replacing DLM. They live on in the `dl-scripts`
RE tree.
