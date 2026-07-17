//! Just enough of the real `kernel` crate's surface for `ake.rs`'s nested `id`
//! submodule to resolve `use kernel::bindings;` (a bare path that, inside a
//! nested module, can only resolve via the extern prelude -- see the
//! description in `Cargo.toml`). Values match `<drm/display/drm_hdcp.h>`.

pub mod bindings {
    pub const HDCP_2_2_AKE_INIT: u32 = 2;
    pub const HDCP_2_2_AKE_SEND_CERT: u32 = 3;
    pub const HDCP_2_2_AKE_NO_STORED_KM: u32 = 4;
    pub const HDCP_2_2_AKE_SEND_HPRIME: u32 = 7;
    pub const HDCP_2_2_AKE_SEND_PAIRING_INFO: u32 = 8;
    pub const HDCP_2_2_LC_INIT: u32 = 9;
    pub const HDCP_2_2_LC_SEND_LPRIME: u32 = 10;
    pub const HDCP_2_2_SKE_SEND_EKS: u32 = 11;
    pub const HDCP_2_2_REP_SEND_RECVID_LIST: u32 = 12;
    pub const HDCP_2_2_REP_SEND_ACK: u32 = 15;
    pub const HDCP_2_2_REP_STREAM_MANAGE: u32 = 16;
    pub const HDCP_2_2_REP_STREAM_READY: u32 = 17;
}
