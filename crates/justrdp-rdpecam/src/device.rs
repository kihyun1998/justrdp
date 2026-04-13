//! `RdpecamDeviceClient` -- processor for per-device DVCs. Populated in Step 3.
//!
//! Responsibilities: stream list, media type negotiation, start/stop, sample
//! delivery, and property get/set, all delegating to `CameraHost`.
