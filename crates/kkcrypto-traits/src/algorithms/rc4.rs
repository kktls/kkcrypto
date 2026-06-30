//! RC4 (ARCFOUR) Stream Cipher.

use crate::{
    base,
    markers,
};

/// RC4 (ARCFOUR) stream cipher.
pub trait Rc4:
    base::VariableKeyInit + base::StreamCipher<0> + markers::Symmetric + markers::StreamCipher + markers::VariableLengthKey
{
}
