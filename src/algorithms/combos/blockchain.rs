//! Cryptocurrency and Blockchain specific combinations.

use alloc::vec::Vec;

use crate::{
    error::Result,
    markers,
};

/// Bitcoin Hash160
///
/// Combines SHA-256 and RIPEMD-160 (`RIPEMD160(SHA256(data))`).
/// Defined in the [Bitcoin Developer Reference](https://developer.bitcoin.org/reference/).
pub trait BitcoinHash160: markers::Combo {
    /// Computes RIPEMD160(SHA256(data)).
    fn hash160(data: &[u8]) -> [u8; 20];
}

/// Bitcoin Hash256 (Double SHA-256)
///
/// Combines SHA-256 executed twice (`SHA256(SHA256(data))`).
/// Defined in the [Bitcoin Developer Reference](https://developer.bitcoin.org/reference/).
pub trait BitcoinHash256: markers::Combo {
    /// Computes SHA256(SHA256(data)).
    fn hash256(data: &[u8]) -> [u8; 32];
}

/// BIP32 Hierarchical Deterministic (HD) Wallets
///
/// Combines SECP256k1 and HMAC-SHA512.
/// Defined in [BIP 32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki).
pub trait Bip32HdWallet: markers::Combo {
    /// Derives a child extended key from a parent extended key.
    /// Returns the new `(private_key, chain_code)` or `(public_key,
    /// chain_code)`.
    fn derive_child_key(parent_key: &[u8], parent_chain_code: &[u8; 32], index: u32) -> Result<(Vec<u8>, [u8; 32])>;
}

/// BIP39 Mnemonic Phrase Key Derivation
///
/// Combines PBKDF2-HMAC-SHA512 and SHA-256.
/// Defined in [BIP 39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).
pub trait Bip39Mnemonic: markers::Combo {
    /// Generates a cryptographic seed from a human-readable mnemonic and
    /// optional passphrase.
    fn mnemonic_to_seed(mnemonic: &str, passphrase: &str, seed: &mut [u8; 64]) -> Result<()>;
}

/// Ethereum ECIES (Elliptic Curve Integrated Encryption Scheme)
///
/// Combines SECP256k1, AES-128-CTR, HMAC-SHA256, and NIST SP 800-56A KDF.
/// Defined in [Ethereum DEVp2p Specification](https://github.com/ethereum/devp2p/blob/master/rlpx.md#ecies-encryption).
pub trait EthereumEcies: markers::Combo {
    /// Encrypts an ECIES payload to the given SECP256k1 public key.
    fn encrypt(pubkey: &[u8; 65], pt: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts an ECIES payload using a SECP256k1 private key.
    fn decrypt(privkey: &[u8; 32], ct: &[u8]) -> Result<Vec<u8>>;
}

/// Ethereum Keccak-256
///
/// Ethereum's specific variant of Keccak (pre-NIST SHA-3).
/// Defined in the [Ethereum Yellow Paper](https://ethereum.github.io/yellowpaper/paper.pdf).
pub trait EthereumKeccak256: markers::Combo {
    /// Computes the Keccak-256 hash of the data.
    fn keccak256(data: &[u8]) -> [u8; 32];
}
