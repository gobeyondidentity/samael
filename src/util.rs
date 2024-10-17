use crate::service_provider::Error;
use data_encoding::{Encoding, Specification};
use openssl::pkey::{PKey, Private, Public};

/// Converts the PEM string representation into a Pkey.
pub fn pkey_from_public_key_pem_str(key_content: &str) -> Result<PKey<Public>, Error> {
    let rsa_public_key = openssl::rsa::Rsa::public_key_from_pem(key_content.as_bytes())?;
    PKey::from_rsa(rsa_public_key).map_err(Into::into)
}

/// Takes a string representation of a PEM private RSA key and converts it into
/// PKey.
pub fn pkey_from_private_key_pem_str(key_content: &str) -> Result<PKey<Private>, Error> {
    let rsa_private_key = openssl::rsa::Rsa::private_key_from_pem(key_content.as_bytes())?;
    PKey::from_rsa(rsa_private_key).map_err(Into::into)
}

pub fn base64_mime_encode_no_wrap() -> Result<Encoding, Error> {
    // Taken directly from data encoding and removing the wrap width from it.
    let mut spec = Specification::new();
    spec.symbols
        .push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
    spec.padding = Some('=');
    spec.encoding().map_err(Into::into)
}
