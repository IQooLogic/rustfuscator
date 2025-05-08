/*!
# Rustfuscator

A Rust library for obfuscating and unobfuscating text using AES-GCM encryption.

This library provides a way to protect sensitive data through obfuscation,
which is a form of lightweight encryption. It uses AES-GCM for encryption,
PBKDF2 for key derivation, and Base64 for string encoding.

## Example

```rust
use rustfuscator::Obfuscator;

fn main() {
    // Create a new obfuscator with a passphrase
    let obfuscator = Obfuscator::new("my-secure-passphrase".as_bytes());
    
    // Obfuscate a string
    let obfuscated = obfuscator.obfuscate("Hello, World!").unwrap();
    println!("Obfuscated: {}", obfuscated);
    
    // Unobfuscate the string
    let unobfuscated = obfuscator.unobfuscate(&obfuscated).unwrap();
    println!("Unobfuscated: {}", unobfuscated);
}
```
*/

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::Sha256;
use thiserror::Error;

/// Default salt length in bytes
const SALT_LENGTH: u8 = 8;
/// Default separator for obfuscated string parts
const DEFAULT_SEPARATOR: &str = "$";
/// Current version of the obfuscation format
const VERSION: &str = "o1";

/// Possible errors that can occur during obfuscation/unobfuscation
#[derive(Error, Debug)]
pub enum ObfuscatorError {
    /// The input string is not in a valid obfuscated format
    #[error("invalid obfuscated string")]
    InvalidObfuscatedString,

    /// The version of the obfuscation format is not supported
    #[error("unsupported obfuscator version")]
    UnsupportedVersion,

    /// An error occurred during encryption
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// An error occurred during decryption
    #[error("decryption error: {0}")]
    DecryptionError(String),

    /// An error occurred during base64 decoding
    #[error("base64 error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    /// An error occurred with the random number generator
    #[error("random generator error: {0}")]
    RandomError(String),
}

impl From<aes_gcm::Error> for ObfuscatorError {
    fn from(err: aes_gcm::Error) -> Self {
        ObfuscatorError::DecryptionError(err.to_string())
    }
}

/// Configuration for the Obfuscator
#[derive(Clone)]
pub struct Config {
    passphrase: Vec<u8>,
    salt_length: u8,
    separator: String,
}

/// The main obfuscator struct that provides text obfuscation functionality
pub struct Obfuscator {
    config: Config,
}

impl Obfuscator {
    /// Creates a new Obfuscator with the given passphrase
    ///
    /// # Arguments
    ///
    /// * `passphrase` - The passphrase used for encryption/decryption
    ///
    /// # Panics
    ///
    /// Panics if the passphrase is empty
    ///
    /// # Examples
    ///
    /// ```
    /// use rustfuscator::Obfuscator;
    ///
    /// let obfuscator = Obfuscator::new("my-secure-passphrase".as_bytes());
    /// ```
    pub fn new(passphrase: &[u8]) -> Self {
        if passphrase.is_empty() {
            panic!("passphrase must not be empty");
        }

        let config = Config {
            passphrase: passphrase.to_vec(),
            salt_length: SALT_LENGTH,
            separator: DEFAULT_SEPARATOR.to_string(),
        };

        Obfuscator { config }
    }

    /// Sets a custom salt length
    ///
    /// # Arguments
    ///
    /// * `length` - The salt length in bytes
    ///
    /// # Panics
    ///
    /// Panics if the salt length is 0
    ///
    /// # Examples
    ///
    /// ```
    /// use rustfuscator::Obfuscator;
    ///
    /// let obfuscator = Obfuscator::new("passphrase".as_bytes())
    ///     .with_salt_length(16);
    /// ```
    pub fn with_salt_length(mut self, length: u8) -> Self {
        if length == 0 {
            panic!("salt length must not be 0");
        }
        self.config.salt_length = length;
        self
    }

    /// Sets a custom separator for the obfuscated string parts
    ///
    /// # Arguments
    ///
    /// * `separator` - The separator string
    ///
    /// # Examples
    ///
    /// ```
    /// use rustfuscator::Obfuscator;
    ///
    /// let obfuscator = Obfuscator::new("passphrase".as_bytes())
    ///     .with_separator("#");
    /// ```
    pub fn with_separator(mut self, separator: &str) -> Self {
        self.config.separator = separator.to_string();
        self
    }

    /// Obfuscates the given text using the configured passphrase
    ///
    /// # Arguments
    ///
    /// * `text` - The text to obfuscate
    ///
    /// # Returns
    ///
    /// * `Result<String, ObfuscatorError>` - The obfuscated string or an error
    ///
    /// # Examples
    ///
    /// ```
    /// use rustfuscator::Obfuscator;
    ///
    /// let obfuscator = Obfuscator::new("passphrase".as_bytes());
    /// let obfuscated = obfuscator.obfuscate("Hello, World!").unwrap();
    /// println!("Obfuscated: {}", obfuscated);
    /// ```
    pub fn obfuscate(&self, text: &str) -> Result<String, ObfuscatorError> {
        let salt = self.generate_salt(self.config.salt_length)?;
        let key = self.derive_key(&self.config.passphrase, &salt);
        let iv = self.gen_crypto_key()?;
        let cipher_text = self.encrypt(text, &key, &iv)?;

        let encoded_salt = STANDARD.encode(&salt);
        let encoded_iv = STANDARD.encode(&iv);
        let encoded_cipher_text = STANDARD.encode(&cipher_text);

        Ok(format!(
            "{}{}{}{}{}{}{}{}",
            self.config.separator, VERSION,
            self.config.separator, encoded_salt,
            self.config.separator, encoded_iv,
            self.config.separator, encoded_cipher_text
        ))
    }

    /// Unobfuscates the given obfuscated text using the configured passphrase
    ///
    /// # Arguments
    ///
    /// * `obfuscated_text` - The obfuscated text to unobfuscate
    ///
    /// # Returns
    ///
    /// * `Result<String, ObfuscatorError>` - The original text or an error
    ///
    /// # Examples
    ///
    /// ```
    /// use rustfuscator::Obfuscator;
    ///
    /// let obfuscator = Obfuscator::new("passphrase".as_bytes());
    /// let obfuscated = obfuscator.obfuscate("Hello, World!").unwrap();
    /// let unobfuscated = obfuscator.unobfuscate(&obfuscated).unwrap();
    /// assert_eq!(unobfuscated, "Hello, World!");
    /// ```
    pub fn unobfuscate(&self, obfuscated_text: &str) -> Result<String, ObfuscatorError> {
        let parts: Vec<&str> = obfuscated_text.split(&self.config.separator).collect();
        let parts = if parts[0].is_empty() { &parts[1..] } else { &parts };

        if parts.len() != 4 {
            return Err(ObfuscatorError::InvalidObfuscatedString);
        }

        let version = parts[0];
        match version {
            "o1" => {
                let unobfuscated_bytes = self.decrypt(parts)?;
                Ok(String::from_utf8_lossy(&unobfuscated_bytes).to_string())
            }
            _ => Err(ObfuscatorError::UnsupportedVersion),
        }
    }

    fn decrypt(&self, parts: &[&str]) -> Result<Vec<u8>, ObfuscatorError> {
        let salt = STANDARD.decode(parts[1])?;
        let iv = STANDARD.decode(parts[2])?;
        let cipher_text = STANDARD.decode(parts[3])?;

        let key = self.derive_key(&self.config.passphrase, &salt);

        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| ObfuscatorError::EncryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(&iv);

        let obfuscated_bytes = cipher
            .decrypt(nonce, cipher_text.as_ref())
            .map_err(ObfuscatorError::from)?;

        Ok(obfuscated_bytes)
    }

    fn encrypt(&self, text: &str, key: &[u8], iv: &[u8]) -> Result<Vec<u8>, ObfuscatorError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| ObfuscatorError::EncryptionError(e.to_string()))?;

        let nonce = Nonce::from_slice(iv);

        let sealed = cipher
            .encrypt(nonce, text.as_bytes())
            .map_err(|e| ObfuscatorError::EncryptionError(e.to_string()))?;

        Ok(sealed)
    }

    fn generate_salt(&self, length: u8) -> Result<Vec<u8>, ObfuscatorError> {
        let mut salt = vec![0u8; length as usize];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| ObfuscatorError::RandomError(e.to_string()))?;
        Ok(salt)
    }

    fn derive_key(&self, passphrase: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut key = [0u8; 32]; // 32 bytes for AES-256
        pbkdf2_hmac::<Sha256>(passphrase, salt, 1000, &mut key);
        key.to_vec()
    }

    fn gen_crypto_key(&self) -> Result<Vec<u8>, ObfuscatorError> {
        let mut iv = vec![0u8; 12]; // 12 bytes for GCM nonce
        OsRng
            .try_fill_bytes(&mut iv)
            .map_err(|e| ObfuscatorError::RandomError(e.to_string()))?;
        Ok(iv)
    }
}

/// Default separator constant for usage in other modules
pub const DEFAULT_SEPARATOR_STR: &str = DEFAULT_SEPARATOR;