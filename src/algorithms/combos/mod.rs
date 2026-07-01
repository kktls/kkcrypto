//! Domain-specific combinations of cryptographic primitives.
//!
//! This module contains tightly coupled algorithm combos (Cipher Suites,
//! crypto boxes, KDFs bound to specific hashes) that are frequently treated
//! as a single monolithic primitive in higher-level protocols.pub mod tls;
pub mod blockchain;
pub mod fido;
pub mod hpke;
pub mod ipsec;
pub mod jose;
pub mod messengers;
pub mod nacl;
pub mod noise;
pub mod pgp;
pub mod ssh;
pub mod tls;
pub mod wifi;
