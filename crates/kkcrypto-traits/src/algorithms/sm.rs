//! Chinese Commercial Cryptography (ShangMi).

use crate::{
    base,
    markers,
};

/// Output length for SM3 hash function in bytes (256 bits).
pub const SM3_OUT_LEN: usize = 32;

/// Length of an SM4 block in bytes (128 bits).
pub const SM4_BLOCK_LEN: usize = 16;
/// Length of an SM4 key in bytes (128 bits).
pub const SM4_KEY_LEN: usize = 16;

/// SM2 Digital Signature Scheme (ECC).
///
/// Referenced in [RFC 8998](https://datatracker.ietf.org/doc/html/rfc8998) (GB/T 32918-2016).
pub trait Sm2Signature:
    base::SignatureScheme + markers::Asymmetric + markers::Signature + markers::EllipticCurve
{
}

/// SM2 Key Exchange Protocol (ECC).
///
/// Referenced in [RFC 8998](https://datatracker.ietf.org/doc/html/rfc8998) (GB/T 32918-2016).
pub trait Sm2KeyExchange:
    base::KeyExchange + markers::Asymmetric + markers::KeyExchange + markers::EllipticCurve
{
}

/// SM3 Cryptographic Hash Function (256-bit).
///
/// Referenced in [RFC 8998](https://datatracker.ietf.org/doc/html/rfc8998) (GB/T 32905-2016).
pub trait Sm3: base::Digest<SM3_OUT_LEN> + markers::Hash {}

/// SM4 Block Cipher (128-bit block, 128-bit key).
///
/// Referenced in [RFC 8998](https://datatracker.ietf.org/doc/html/rfc8998) (GB/T 32907-2016).
pub trait Sm4:
    base::KeyInit<SM4_KEY_LEN> + base::BlockCipher<SM4_BLOCK_LEN> + markers::Symmetric + markers::BlockCipher
{
}
