//! MD4 and MD5 Legacy Hash Functions.

use crate::{
    base,
    markers,
};

/// MD4 hash function.
///
/// Defined in [RFC 1320](https://datatracker.ietf.org/doc/html/rfc1320).
pub trait Md4: base::Digest<16> + markers::Hash {}

/// MD5 hash function.
///
/// Defined in [RFC 1321](https://datatracker.ietf.org/doc/html/rfc1321).
pub trait Md5: base::Digest<16> + markers::Hash {}

/// Concatenated MD5 and SHA-1 hash (36-byte output) used in legacy TLS
/// handshake signatures.
///
/// Defined in [RFC 5246](https://datatracker.ietf.org/doc/html/rfc5246).
pub trait Md5Sha1: base::Digest<36> + markers::Hash {}
