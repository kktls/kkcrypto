//! Set of cryptographic trait abstractions.

#![no_std]

extern crate alloc;

pub mod algorithms;
pub mod base;
mod error;
pub mod markers;

pub use error::*;
