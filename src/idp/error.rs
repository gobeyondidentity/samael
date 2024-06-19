use std::str::Utf8Error;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Missing signature")]
    NoSignature,
    #[error("Missing KeyInfo")]
    NoKeyInfo,
    #[error("Missing certificate")]
    NoCertificate,
    #[error("Missing service provider SSO descriptors")]
    NoSPSsoDescriptors,
    #[error("Failed to generate signature")]
    SignatureFailed,
    #[error("certificate mismatch")]
    MismatchedCertificate,
    #[error("invalid certificate encoding")]
    InvalidCertificateEncoding,

    #[error("Missing audience from response.")]
    MissingAudience,
    #[error("Missing ACS url from response")]
    MissingAcsUrl,
    #[error("Non-http POST bindings are not supported")]
    NonHttpPostBindingUnsupported,

    #[error("Missing subject name ID")]
    MissingAuthnRequestSubjectNameID,
    #[error("Missing request issuer")]
    MissingAuthnRequestIssuer,

    #[error(transparent)]
    XmlGenerationError(Box<dyn std::error::Error>),
    // #[error(transparent)]
    // QuickXmlError(#[from] quick_xml::Error),

    // #[error(transparent)]
    // Utf8ConversionError(Utf8Error),
    #[error("Invalid AuthnRequest: {}", error)]
    InvalidAuthnRequest {
        #[from]
        error: crate::schema::authn_request::Error,
    },

    #[error("OpenSSL Error: {}", stack)]
    OpenSSLError {
        #[from]
        stack: openssl::error::ErrorStack,
    },

    #[error("Verification Error: {}", error)]
    VerificationError {
        #[from]
        error: crate::crypto::Error,
    },
}
