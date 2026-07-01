//! Transport Layer Security (TLS) cipher suites.
//!
//! This module strictly focuses on TLS 1.3 cipher suites.
//! Unlike TLS 1.2 (which independently negotiates Key Exchange, Auth, and
//! MACs), TLS 1.3 cleanly defines cipher suites as an indivisible combination
//! of a Hash (used for HKDF) and an AEAD algorithm.

use crate::{
    error::Result,
    markers,
};

/// Generates a tightly coupled TLS 1.3 Cipher Suite trait.
macro_rules! define_tls13_suite {
    (
        $(#[$meta:meta])*
        pub trait $name:ident {
            hash_len = $hash_len:expr;
            key_len = $key_len:expr;
            nonce_len = $nonce_len:expr;
            tag_len = $tag_len:expr;
        }
    ) => {
        $(#[$meta])*
        pub trait $name: markers::Combo {
            /// Extracts pseudo-random key material using the suite's hash function.
            fn extract(salt: &[u8], ikm: &[u8], prk: &mut [u8; $hash_len]) -> Result<()>;

            /// Expands key material using the suite's KDF and hash function.
            fn expand_label(
                secret: &[u8],
                label: &[u8],
                context: &[u8],
                length: u16,
                okm: &mut [u8],
            ) -> Result<()>;

            /// Encrypts a TLS 1.3 record payload using the suite's AEAD.
            fn encrypt_record(
                key: &[u8; $key_len],
                nonce: &[u8; $nonce_len],
                aad: &[u8],
                pt: &[u8],
                ct: &mut [u8],
                tag: &mut [u8; $tag_len],
            ) -> Result<()>;

            /// Decrypts a TLS 1.3 record payload using the suite's AEAD.
            fn decrypt_record(
                key: &[u8; $key_len],
                nonce: &[u8; $nonce_len],
                aad: &[u8],
                ct: &[u8],
                tag: &[u8; $tag_len],
                pt: &mut [u8],
            ) -> Result<()>;
        }
    };
}

// ==========================================
// IETF Standard Suites (RFC 8446)
// ==========================================

define_tls13_suite! {
    /// TLS 1.3: `TLS_AES_128_GCM_SHA256`
    ///
    /// Defined in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446).
    pub trait Tls13Aes128GcmSha256 {
        hash_len = 32;
        key_len = 16;
        nonce_len = 12;
        tag_len = 16;
    }
}

define_tls13_suite! {
    /// TLS 1.3: `TLS_AES_256_GCM_SHA384`
    ///
    /// Defined in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446).
    pub trait Tls13Aes256GcmSha384 {
        hash_len = 48;
        key_len = 32;
        nonce_len = 12;
        tag_len = 16;
    }
}

define_tls13_suite! {
    /// TLS 1.3: `TLS_CHACHA20_POLY1305_SHA256`
    ///
    /// Defined in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446).
    pub trait Tls13ChaCha20Poly1305Sha256 {
        hash_len = 32;
        key_len = 32;
        nonce_len = 12;
        tag_len = 16;
    }
}

define_tls13_suite! {
    /// TLS 1.3: `TLS_AES_128_CCM_SHA256`
    ///
    /// Defined in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446).
    pub trait Tls13Aes128CcmSha256 {
        hash_len = 32;
        key_len = 16;
        nonce_len = 12;
        tag_len = 16;
    }
}

define_tls13_suite! {
    /// TLS 1.3: `TLS_AES_128_CCM_8_SHA256`
    ///
    /// Defined in [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446).
    pub trait Tls13Aes128Ccm8Sha256 {
        hash_len = 32;
        key_len = 16;
        nonce_len = 12;
        tag_len = 8;
    }
}

// ==========================================
// ShangMi / Chinese Commercial Cryptography
// ==========================================

define_tls13_suite! {
    /// TLS 1.3: `TLS_SM4_GCM_SM3`
    ///
    /// Defined in [RFC 8998](https://datatracker.ietf.org/doc/html/rfc8998).
    pub trait Tls13Sm4GcmSm3 {
        hash_len = 32;
        key_len = 16;
        nonce_len = 12;
        tag_len = 16;
    }
}

define_tls13_suite! {
    /// TLS 1.3: `TLS_SM4_CCM_SM3`
    ///
    /// Defined in [RFC 8998](https://datatracker.ietf.org/doc/html/rfc8998).
    pub trait Tls13Sm4CcmSm3 {
        hash_len = 32;
        key_len = 16;
        nonce_len = 12;
        tag_len = 16;
    }
}

// ==========================================
// GOST / Russian National Standard
// ==========================================

define_tls13_suite! {
    /// TLS 1.3: `TLS_KUZNYECHIK_MGM_L_GOST341112_256`
    ///
    /// Defined in [RFC 9151](https://datatracker.ietf.org/doc/html/rfc9151).
    pub trait Tls13KuznyechikMgmLGost341112_256 {
        hash_len = 32;
        key_len = 32;
        nonce_len = 12;
        tag_len = 16;
    }
}

define_tls13_suite! {
    /// TLS 1.3: `TLS_MAGMA_MGM_L_GOST341112_256`
    ///
    /// Defined in [RFC 9151](https://datatracker.ietf.org/doc/html/rfc9151).
    pub trait Tls13MagmaMgmLGost341112_256 {
        hash_len = 32;
        key_len = 32;
        nonce_len = 12;
        tag_len = 16;
    }
}
