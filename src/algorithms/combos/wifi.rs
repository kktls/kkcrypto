//! IEEE 802.11 / Wi-Fi Protected Access combinations.

use alloc::vec::Vec;

use crate::{
    error::Result,
    markers,
};

/// WPA2 CCMP (Counter Mode CBC-MAC Protocol).
///
/// Defined in [IEEE 802.11i Specification](https://standards.ieee.org/ieee/802.11i/3452/).
pub trait Wpa2Ccmp: markers::Combo {
    /// Encrypts an MPDU payload using CCMP.
    fn encrypt_mpdu(key: &[u8; 16], pn: u64, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts an MPDU payload using CCMP.
    fn decrypt_mpdu(key: &[u8; 16], pn: u64, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>>;
}

/// WPA3 SAE (Simultaneous Authentication of Equals).
///
/// Defined in [IEEE 802.11-2020 Specification](https://standards.ieee.org/ieee/802.11/7028/).
pub trait Wpa3Sae: markers::Combo {
    /// Computes the SAE commit phase parameters using Dragonfly Key Exchange.
    fn sae_commit(password: &[u8], mac_local: &[u8; 6], mac_peer: &[u8; 6]) -> Result<(Vec<u8>, Vec<u8>)>; // returns (commit_scalar, commit_element)
    /// Derives the PMK from the SAE exchange.
    fn derive_pmk(k: &[u8]) -> Result<[u8; 32]>;
}
