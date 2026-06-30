//! MD4 and MD5 Legacy Hash Functions.

use crate::{
    base,
    markers,
};

/// Output length for MD4 and MD5 in bytes (128 bits).
pub const MD_OUT_LEN: usize = 16;
/// Output length for concatenated MD5 and SHA-1 in bytes.
pub const MD5_SHA1_OUT_LEN: usize = 36;

/// MD4 hash function.
///
/// Defined in [RFC 1320](https://datatracker.ietf.org/doc/html/rfc1320).
pub trait Md4: base::Digest<MD_OUT_LEN> + markers::Hash {}

/// MD5 hash function.
///
/// Defined in [RFC 1321](https://datatracker.ietf.org/doc/html/rfc1321).
pub trait Md5: base::Digest<MD_OUT_LEN> + markers::Hash {}

/// Concatenated MD5 and SHA-1 hash (36-byte output) used in legacy TLS
/// handshake signatures.
///
/// Defined in [RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246).
pub trait Md5Sha1: base::Digest<MD5_SHA1_OUT_LEN> + markers::Hash {}
