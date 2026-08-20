// Copyright (C) 2016 Raphael Catolino

//! PAM Service Module wrappers
//! # Usage
//! For example, here is a time based authentication module :
//!
//! ```rust,no_run
//! #[macro_use] extern crate pamsm;
//! extern crate time;
//!
//! use pamsm::{PamServiceModule, Pam, PamFlags, PamError};
//!
//! struct PamTime;
//!
//! impl PamServiceModule for PamTime {
//!     fn authenticate(pamh: Pam, _: PamFlags, args: Vec<String>) -> PamError {
//!         let hour = time::OffsetDateTime::now_utc().hour();
//!         if hour != 4 {
//!             // Only allow authentication when it's 4 AM
//!             PamError::SUCCESS
//!         } else {
//!             PamError::AUTH_ERR
//!         }
//!     }
//! }
//!
//! pam_module!(PamTime);
//! ```
#[macro_use]
extern crate bitflags;

#[cfg(feature = "libpam")]
mod libpam;
mod pam;
mod pam_types;

pub use pam::{Pam, PamError, PamFlags, PamSendRef, PamServiceModule};

#[cfg(feature = "libpam")]
pub use libpam::{PamCleanupCb, PamData, PamLibExt, PamResult};
#[cfg(feature = "libpam")]
pub use pam_types::{LogLvl, PamMsgStyle};
