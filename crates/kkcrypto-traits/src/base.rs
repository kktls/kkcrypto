//! Foundational cryptographic abstractions.

use alloc::vec::Vec;

use crate::error::Result;

/// Initializes a symmetric primitive (Cipher, AEAD, MAC) from a secret key.
pub trait KeyInit<const KEY_LEN: usize> {
    /// Instantiates the primitive with the given key material.
    fn new(key: &[u8; KEY_LEN]) -> Result<Self>
    where
        Self: Sized;
}

/// A raw block cipher that operates on fixed-size blocks of data.
pub trait BlockCipher<const BLOCK_LEN: usize> {
    /// Encrypts a single block in-place.
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]);
    /// Decrypts a single block in-place.
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]);
}

/// Cipher Block Chaining (CBC) mode interface.
pub trait Cbc<const BLOCK_LEN: usize> {
    /// Encrypts the data in-place using the provided Initialization Vector
    /// (IV). The length of `data` must be a multiple of `BLOCK_LEN`.
    fn encrypt_cbc(&self, iv: &[u8; BLOCK_LEN], data: &mut [u8]) -> Result<()>;

    /// Decrypts the data in-place using the provided Initialization Vector
    /// (IV). The length of `data` must be a multiple of `BLOCK_LEN`.
    fn decrypt_cbc(&self, iv: &[u8; BLOCK_LEN], data: &mut [u8]) -> Result<()>;
}

/// A stream cipher that generates a keystream and XORs it with the input data.
pub trait StreamCipher<const NONCE_LEN: usize> {
    /// Initializes the stream cipher with a nonce/IV.
    fn set_nonce(&mut self, nonce: &[u8; NONCE_LEN]) -> Result<()>;
    /// Applies the keystream to the provided data in-place.
    fn apply_keystream(&mut self, data: &mut [u8]) -> Result<()>;
    /// Seeks to an absolute byte offset in the keystream.
    fn seek(&mut self, offset: u64) -> Result<()> {
        let _ = offset;
        Err(crate::error::CryptoError::UnsupportedOperation)
    }
}

/// Authenticated Encryption with Associated Data (AEAD).
pub trait Aead<const NONCE_LEN: usize, const TAG_LEN: usize> {
    /// Encrypts the plaintext and authenticates both the ciphertext and `aad`.
    fn encrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
        tag: &mut [u8; TAG_LEN],
    ) -> Result<()>;

    /// Decrypts the ciphertext and verifies the authentication tag.
    fn decrypt(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
        tag: &[u8; TAG_LEN],
        plaintext: &mut [u8],
    ) -> Result<()>;
}

/// A cryptographic hash function yielding a fixed-size output.
pub trait Digest<const OUT_LEN: usize> {
    /// Feeds data into the hash function.
    fn update(&mut self, data: &[u8]);
    /// Consumes the hash function and returns the final digest.
    fn finalize(self) -> [u8; OUT_LEN];
    /// Resets the internal state to allow hashing a new message.
    fn reset(&mut self);
    /// Convenience method to hash data in a single shot.
    fn hash(data: &[u8]) -> [u8; OUT_LEN];
}

/// An Extendable-Output Function (XOF) for variable-length hash outputs.
pub trait Xof {
    /// Feeds data into the XOF.
    fn update(&mut self, data: &[u8]);
    /// Squeezes pseudo-random bytes into the output buffer.
    /// This can be called multiple times to generate a continuous stream of
    /// bytes.
    fn squeeze(&mut self, out: &mut [u8]);
    /// Resets the XOF state.
    fn reset(&mut self);
}

/// A Message Authentication Code (MAC) for symmetric message integrity.
pub trait Mac<const OUT_LEN: usize> {
    /// Feeds data into the MAC.
    fn update(&mut self, data: &[u8]);
    /// Computes the final authentication tag.
    fn finalize(self) -> [u8; OUT_LEN];
    /// Verifies the provided tag against the computed state in constant-time.
    fn verify(self, tag: &[u8; OUT_LEN]) -> Result<()>;
}

/// Key Encapsulation Mechanism (KEM).
pub trait Kem {
    /// The public encapsulation key.
    type PublicKey;
    /// The private decapsulation key.
    type PrivateKey;
    /// The encapsulated ciphertext.
    type Ciphertext;
    /// The resulting shared symmetric secret.
    type SharedSecret;

    /// Generates a new public/private key pair (backend handles entropy).
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)>;
    /// Encapsulates a shared secret to the given public key.
    fn encaps(pk: &Self::PublicKey) -> Result<(Self::Ciphertext, Self::SharedSecret)>;
    /// Decapsulates the ciphertext to recover the shared secret.
    fn decaps(sk: &Self::PrivateKey, ct: &Self::Ciphertext) -> Result<Self::SharedSecret>;
}

/// A digital signature scheme for asymmetric authentication.
pub trait SignatureScheme {
    /// The public verification key.
    type PublicKey;
    /// The private signing key.
    type PrivateKey;
    /// The resulting signature.
    type Signature;

    /// Generates a new public/private key pair.
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)>;
    /// Signs the given message.
    fn sign(sk: &Self::PrivateKey, message: &[u8]) -> Result<Self::Signature>;
    /// Verifies the signature against the given message and public key.
    fn verify(pk: &Self::PublicKey, message: &[u8], signature: &Self::Signature) -> Result<()>;
}

/// A digital signature scheme operating on pre-hashed data.
pub trait PrehashedSignatureScheme {
    /// The public verification key.
    type PublicKey;
    /// The private signing key.
    type PrivateKey;
    /// The resulting signature.
    type Signature;

    /// Signs a pre-computed cryptographic digest instead of the raw message.
    fn sign_prehashed(sk: &Self::PrivateKey, digest: &[u8]) -> Result<Self::Signature>;
    /// Verifies a signature against a pre-computed cryptographic digest.
    fn verify_prehashed(pk: &Self::PublicKey, digest: &[u8], signature: &Self::Signature) -> Result<()>;
}

/// Key Exchange (e.g., Diffie-Hellman).
pub trait KeyExchange {
    /// The public share.
    type PublicKey;
    /// The private secret.
    type PrivateKey;
    /// The computed shared secret.
    type SharedSecret;

    /// Generates a new key exchange pair.
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)>;
    /// Computes the shared secret using a local private key and peer's public
    /// key.
    fn exchange(sk: &Self::PrivateKey, pk: &Self::PublicKey) -> Result<Self::SharedSecret>;
}

/// Traditional Public Key Encryption (e.g., RSA).
pub trait PublicKeyEncryption {
    /// The public encryption key.
    type PublicKey;
    /// The private decryption key.
    type PrivateKey;

    /// Generates a new public/private key pair.
    fn keygen() -> Result<(Self::PublicKey, Self::PrivateKey)>;
    /// Encrypts the message.
    fn encrypt(pk: &Self::PublicKey, msg: &[u8]) -> Result<Vec<u8>>;
    /// Decrypts the ciphertext.
    fn decrypt(sk: &Self::PrivateKey, ct: &[u8]) -> Result<Vec<u8>>;
}

/// HMAC-based Key Derivation Function (HKDF).
pub trait Kdf {
    /// Extracts a fixed-length pseudo-random key (PRK) from input keying
    /// material (IKM) and a salt.
    fn extract(salt: &[u8], ikm: &[u8], prk: &mut [u8]) -> Result<()>;
    /// Expands the extracted PRK using protocol-specific info to generate the
    /// output keying material (OKM).
    fn expand(prk: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()>;
}

/// Password-Based Key Derivation Function (e.g., PBKDF2).
pub trait PasswordBasedKdf {
    /// Derives key material from a password, salt, and iteration count.
    fn derive(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<()>;
}

/// Single-step or Key-Based Key Derivation Function (SSKDF / KBKDF).
pub trait StepKdf {
    /// Derives key material from a secret and context info.
    fn derive(secret: &[u8], info: &[u8], output: &mut [u8]) -> Result<()>;
}

/// Pseudorandom Function (PRF).
pub trait Tls12Prf {
    /// Expands a secret using the PRF construction.
    fn expand(&self, secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) -> Result<()>;
}

/// Initializes a primitive from a variable-length secret key.
pub trait VariableKeyInit {
    /// Instantiates the primitive with arbitrary key material.
    fn new_from_slice(key: &[u8]) -> Result<Self>
    where
        Self: Sized;
}
