//! `CameraHost` trait: frame source + property backend supplied by the embedder.
//!
//! Populated in Step 3 alongside the DVC processors. The trait is the seam
//! that keeps codec/driver details out of this `no_std` crate -- the host
//! hands over opaque sample bytes and answers property get/set.
