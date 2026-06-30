//! Marker traits classifying algorithmic characteristics.

/// Marker for symmetric-key algorithms.
pub trait Symmetric {}
/// Marker for asymmetric-key algorithms.
pub trait Asymmetric {}
/// Marker for block ciphers.
pub trait BlockCipher {}
/// Marker for stream ciphers.
pub trait StreamCipher {}
/// Marker for Authenticated Encryption with Associated Data.
pub trait Aead {}
/// Marker for Key Encapsulation Mechanisms.
pub trait Kem {}
/// Marker for Digital Signature Schemes.
pub trait Signature {}
/// Marker for Hash functions and XOFs.
pub trait Hash {}

/// Marker for Key Exchange mechanisms.
pub trait KeyExchange {}
/// Marker for traditional Public Key Encryption (e.g., RSA).
pub trait PublicKeyEncryption {}
/// Marker for Message Authentication Codes.
pub trait Mac {}
/// Marker for Key Derivation Functions.
pub trait Kdf {}
/// Marker for algorithms that support variable-length keys.
pub trait VariableLengthKey {}

/// Marker for algorithms based on Elliptic Curve Cryptography (ECC).
pub trait EllipticCurve {}

/// Marker for Key Exchange mechanisms that utilize the Diffie-Hellman paradigm
/// (requires commutative mathematical operations).
pub trait DiffieHellman {}

/// Marker for Finite Field Diffie-Hellman (FFDHE) mechanisms.
pub trait FiniteFieldDh {}

/// Marker for algorithms utilizing integer factorization or discrete logarithms
/// over finite fields (e.g., RSA, standard DH).
pub trait TraditionalMath {}

/// Marker for algorithms believed to be resistant to cryptanalysis by
/// large-scale quantum computers.
pub trait PostQuantum {}

/// Marker for PQC algorithms based on Lattice problems (e.g., ML-KEM, ML-DSA).
pub trait LatticeBased: PostQuantum {}

/// Marker for PQC algorithms based on Hash functions (e.g., SLH-DSA, XMSS).
pub trait HashBased: PostQuantum {}

/// Marker for PQC algorithms based on Error-Correcting Codes (e.g., McEliece).
pub trait CodeBased: PostQuantum {}

/// Marker for Cipher Block Chaining (CBC) mode.
pub trait Cbc {}

/// Marker for Counter with CBC-MAC (CCM) mode.
pub trait Ccm {}
