use thiserror::Error;

use crate::xmlsec::XmlSecError;

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

    #[error("Missing encryption algorithms")]
    MissingEncryptionAlgo,

    #[error("Missing encryption key")]
    MissingEncryptionKey,

    #[error("Missing encryption name")]
    MissingEncryptionKeyName,

    #[error("Unknown algorithm {0}")]
    UnknownAlgorithm(String),

    #[error("Mismatched algorithm key sizes")]
    AlgorithmKeySizesDontMatch,

    #[error("{0}")]
    XmlGenerationError(String),

    #[error("Encountered an error parsing generated XML document {error}")]
    XmlDocumentParsingError {
        #[from]
        error: libxml::parser::XmlParseError,
    },

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

    #[error("Missing Certificate")]
    MissingCert,

    #[error(transparent)]
    XmlSecError(#[from] XmlSecError),
}
