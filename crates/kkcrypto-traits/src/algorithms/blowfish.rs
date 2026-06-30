//! Blowfish Block Cipher.

use crate::{
    base,
    markers,
};

/// Blowfish block cipher. Takes a variable-length key up to 448 bits (56
/// bytes).
///
/// Defined in [Fast Software Encryption (1993)](https://www.schneier.com/academic/blowfish/).
pub trait Blowfish:
    base::VariableKeyInit + base::BlockCipher<8> + markers::Symmetric + markers::BlockCipher + markers::VariableLengthKey
{
}
