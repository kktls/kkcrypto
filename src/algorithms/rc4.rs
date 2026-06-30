//! RC4 (ARCFOUR) Stream Cipher.

use crate::{
    base,
    markers,
};

/// RC4 does not utilize a nonce (0 bytes).
pub const RC4_NONCE_LEN: usize = 0;

/// RC4 (ARCFOUR) stream cipher.
pub trait Rc4:
    base::VariableKeyInit
    + base::StreamCipher<RC4_NONCE_LEN>
    + markers::Symmetric
    + markers::StreamCipher
    + markers::VariableLengthKey
{
}
