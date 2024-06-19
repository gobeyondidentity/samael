//!
//! XmlSec High Level Error handling
//!

/// Wrapper project-wide Result typealias.
pub type XmlSecResult<T> = Result<T, XmlSecError>;

/// Wrapper project-wide Errors enumeration.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum XmlSecError {
    XmlSecAbiMismatch,
    XmlSecInitError,
    ContextInitError,
    CryptoInitOpenSSLError,
    CryptoInitOpenSSLAppError,
    #[cfg(xmlsec_dynamic)]
    CryptoLoadLibraryError,

    InvalidInputString,

    SetKeyError,
    KeyNotLoaded,
    KeyLoadError,
    CertLoadError,

    RootNotFound,
    NodeNotFound,
    NotASignatureNode,

    SigningError,
    VerifyError,
    XPathNamespaceError,
    XPathContextError,
    XPathEvaluationError,
    EncMissingTemplateRootElement,
    EncWhileEncryptingXml,

    SecCreateBufferError,
    SecBufferAppendError,
    SecKeyReadBufferError,
    SecSetKeyNameError,

    KeyManagerCreateFailure,
    KeyManagerDefaultInitFailure,
    KeyManagerKeyAdoptionFailure,
    KeyInfoContextCreateFailure,
    KeyStoreCreateFailure,
    KeyDataStoreCreateFailure,
}

impl std::fmt::Display for XmlSecError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::XmlSecInitError => write!(fmt, "Internal XmlSec Init Error"),
            Self::XmlSecAbiMismatch => write!(fmt, "XmlSec ABI version mismatch"),
            Self::CryptoInitOpenSSLError => {
                write!(fmt, "Internal XmlSec Crypto OpenSSL Init Error")
            }
            Self::CryptoInitOpenSSLAppError => {
                write!(fmt, "Internal XmlSec Crypto OpenSSLApp Init Error")
            }
            #[cfg(xmlsec_dynamic)]
            Self::CryptoLoadLibraryError => {
                write!(fmt, "XmlSec failed to load default crypto backend")
            }
            Self::ContextInitError => write!(fmt, "Internal XmlSec Context Error"),

            Self::InvalidInputString => write!(fmt, "Input value is not a valid string"),

            Self::SetKeyError => write!(fmt, "Key could not be set"),
            Self::KeyNotLoaded => write!(fmt, "Key has not yet been loaded and is required"),
            Self::KeyLoadError => write!(fmt, "Failed to load key"),
            Self::CertLoadError => write!(fmt, "Failed to load certificate"),

            Self::RootNotFound => write!(fmt, "Failed to find document root"),
            Self::NodeNotFound => write!(fmt, "Failed to find node"),
            Self::NotASignatureNode => write!(fmt, "Node is not a signature node"),

            Self::SigningError => {
                write!(fmt, "An error has ocurred while attemting to sign document")
            }
            Self::VerifyError => write!(fmt, "Verification failed"),
            Self::XPathNamespaceError => write!(fmt, "Failed to register XPath namespace"),
            Self::XPathContextError => write!(fmt, "Failed to construct an XPath context"),
            Self::XPathEvaluationError => {
                write!(fmt, "An error occurred while parsing XPath expression")
            }
            Self::EncMissingTemplateRootElement => write!(fmt, "The template document is empty"),
            Self::EncWhileEncryptingXml => {
                write!(fmt, "An error occurred while encrypting XML with template")
            }
            Self::SecCreateBufferError => write!(fmt, "Failed to allocate memory for buffer"),
            Self::SecBufferAppendError => write!(fmt, "Failed to append to buffer"),
            Self::SecKeyReadBufferError => write!(fmt, "Failed to read key from buffer"),
            Self::SecSetKeyNameError => write!(fmt, "Failed to set key name"),

            Self::KeyManagerCreateFailure => write!(fmt, "Failed to create key manager"),
            Self::KeyManagerDefaultInitFailure => write!(
                fmt,
                "Failed to initialize key manager with default initialization"
            ),
            Self::KeyManagerKeyAdoptionFailure => write!(fmt, "Failed to adopt key"),
            Self::KeyInfoContextCreateFailure => write!(fmt, "Failed to create key info context"),
            Self::KeyStoreCreateFailure => write!(fmt, "Failed to create key store"),
            Self::KeyDataStoreCreateFailure => write!(fmt, "Failed to create a key data store"),
        }
    }
}

impl std::error::Error for XmlSecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
