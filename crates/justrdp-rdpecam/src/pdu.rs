//! MS-RDPECAM wire-format PDUs.
//!
//! Populated in Step 2 from `specs/ms-rdpecam-checklist.md` §2-§4. Submodules
//! group messages by family; each message implements `Encode`/`Decode`.

pub mod header;
pub mod enumeration;
pub mod device;
pub mod stream;
pub mod capture;
pub mod property;
