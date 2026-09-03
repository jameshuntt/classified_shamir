//! Shamir secret sharing in [`classified`] containers.
//!
//! [`honest_shamir`] does the arithmetic on plain bytes. This crate keeps the
//! bytes inside [`classified`] containers on both sides of it: the secret
//! goes in as a [`ClassifiedBuffer`] or [`ClassifiedBytes`], each share
//! comes out as a [`ClassifiedShare`], and reconstruction hands back a
//! container again. Nothing is ever a bare `Vec<u8>` in the caller's
//! hands, `Debug` prints `[REDACTED]` at every step, equality is constant
//! time, and every intermediate copy is zeroized when the call returns.
//!
//! ```
//! use classified::ClassifiedBytes;
//! use classified_shamir::{reconstruct_bytes, split_bytes_with, Threshold};
//! use rand_chacha::ChaCha20Rng;
//! use classified_shamir::rand_core::SeedableRng;
//!
//! let key = ClassifiedBytes::<32>::new([0x42; 32]).unwrap();
//! let threshold = Threshold::new(2, 3).unwrap();
//! let shares = split_bytes_with(&key, threshold, &mut ChaCha20Rng::seed_from_u64(1)).unwrap();
//!
//! assert_eq!(format!("{:?}", shares[0]), r#"ClassifiedShare { index: 1, len: 32, value: "[REDACTED]" }"#);
//!
//! let rebuilt: ClassifiedBytes<32> = reconstruct_bytes([&shares[2], &shares[0]], threshold).unwrap();
//! assert!(rebuilt.ct_eq(&key));
//! ```
//!
//! The threshold policy, the share validation rules and the caveats are
//! `honest_shamir`'s: any `k` of `n` shares rebuild the secret, `k` is at
//! least 2, and shares are not authenticated, so a tampered share rebuilds
//! a wrong secret without complaint. Verify the result with something
//! kept beside the shares before trusting it.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod scheme;
mod share;

pub use error::Error;
pub use honest_shamir::{rand_core, ShamirError, Threshold};
pub use scheme::{reconstruct, reconstruct_bytes, refresh_with, split_bytes_with, split_with};
#[cfg(feature = "os-rng")]
pub use scheme::{refresh, split, split_bytes};
pub use share::ClassifiedShare;

#[doc(no_inline)]
pub use classified::{ClassifiedBuffer, ClassifiedBytes};

#[cfg(all(doctest, feature = "os-rng"))]
#[doc = include_str!("../README.md")]
mod readme_doctests {}
