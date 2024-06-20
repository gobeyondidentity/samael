//!
//! Wrapper for XmlSec Key and Certificate management Context
//!
use crate::bindings::{self, xmlSecKeySetName, xmlSecOpenSSLAppKeyLoadMemory};
use crate::bindings::{
    xmlSecKeyDataFormat_xmlSecKeyDataFormatDer, xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
};

use super::backend;
use super::error::XmlSecError;
use super::error::XmlSecResult;
use super::xmlsec_internal;

use std::ptr::null;
use std::ptr::null_mut;

/// x509 key format.
#[allow(dead_code)]
#[allow(missing_docs)]
#[repr(u32)]
pub enum XmlSecKeyFormat {
    Unknown = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatUnknown,
    Binary = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatBinary,
    Pem = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
    Der = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatDer,
    Pkcs8Pem = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPkcs8Pem,
    Pkcs8Der = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPkcs8Der,
    Pkcs12 = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatPkcs12,
    CertPem = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatCertPem,
    CertDer = bindings::xmlSecKeyDataFormat_xmlSecKeyDataFormatCertDer,
}

/// Key with which we sign/verify signatures or encrypt data. Used by [`XmlSecSignatureContext`][sigctx].
///
/// [sigctx]: struct.XmlSecSignatureContext.html
#[derive(Debug)]
pub struct XmlSecKey(*mut bindings::xmlSecKey);

impl XmlSecKey {
    /// Load key from buffer in memory, specifying format and optionally the password required to decrypt/unlock.
    pub fn from_memory(buffer: &[u8], format: XmlSecKeyFormat) -> XmlSecResult<Self> {
        xmlsec_internal::guarantee_xmlsec_init()?;

        // Load key from buffer
        let key = unsafe {
            backend::xmlSecCryptoAppKeyLoadMemory(
                buffer.as_ptr(),
                buffer.len().try_into().expect("Key buffer length overflow"),
                format as u32,
                null(),
                null_mut(),
                null_mut(),
            )
        };
        unsafe {
            if key.is_null() || (*key).value.is_null() || (*(*key).value).id.is_null() {
                return Err(XmlSecError::KeyLoadError);
            }
        }

        Ok(Self(key))
    }

    /// Create from raw pointer to an underlying xmlsec key structure. Henceforth its lifetime will be managed by this
    /// object.
    pub unsafe fn from_ptr(ptr: *mut bindings::xmlSecKey) -> Self {
        Self(ptr)
    }

    /// Leak the internal resource. This is needed by [`XmlSecSignatureContext`][sigctx], since xmlsec takes over the
    /// lifetime management of the underlying resource when setting it as the active key for signature signing or
    /// verification.
    ///
    /// [sigctx]: struct.XmlSecSignatureContext.html
    pub unsafe fn leak(key: Self) -> *mut bindings::xmlSecKey {
        let ptr = key.0;

        std::mem::forget(key);

        ptr
    }

    /// Attempts to load a key from rust native representation
    pub fn from_rsa_key_pem(name: &str, key: &[u8]) -> XmlSecResult<Self> {
        xmlsec_internal::guarantee_xmlsec_init()?;
        unsafe {
            let key_ptr = xmlSecOpenSSLAppKeyLoadMemory(
                key.as_ptr(),
                key.len() as u32,
                xmlSecKeyDataFormat_xmlSecKeyDataFormatPem,
                null(),
                null_mut(),
                null_mut(),
            );
            // CHecking all of the things that verify if a key was loaded
            // correctly this is based on the macro xmlSecKeyIsValid.
            if key_ptr.is_null() || (*key_ptr).value.is_null() || (*(*key_ptr).value).id.is_null() {
                return Err(XmlSecError::KeyLoadError);
            }

            // Setting the key name for later lookup

            if xmlSecKeySetName(
                key_ptr,
                std::ffi::CString::from_vec_unchecked(name.as_bytes().to_vec()).as_ptr()
                    as *const u8,
            ) != 0
            {
                return Err(XmlSecError::SecSetKeyNameError);
            }

            Ok(Self::from_ptr(key_ptr))
        }
    }

    /// Attempts to load a DER key from memory.
    pub fn from_rsa_key_der(name: &str, key: &[u8]) -> XmlSecResult<Self> {
        xmlsec_internal::guarantee_xmlsec_init()?;
        unsafe {
            let key_ptr = xmlSecOpenSSLAppKeyLoadMemory(
                key.as_ptr(),
                key.len() as u32,
                xmlSecKeyDataFormat_xmlSecKeyDataFormatDer,
                null(),
                null_mut(),
                null_mut(),
            );
            // CHecking all of the things that verify if a key was loaded
            // correctly this is based on the macro xmlSecKeyIsValid.
            if key_ptr.is_null() || (*key_ptr).value.is_null() || (*(*key_ptr).value).id.is_null() {
                return Err(XmlSecError::KeyLoadError);
            }

            // Setting the key name for later lookup

            if xmlSecKeySetName(
                key_ptr,
                std::ffi::CString::from_vec_unchecked(name.as_bytes().to_vec()).as_ptr()
                    as *const u8,
            ) != 0
            {
                return Err(XmlSecError::SecSetKeyNameError);
            }

            Ok(Self::from_ptr(key_ptr))
        }
    }

    // xmlSecOpenSSLAppKeyLoadMemory
}

impl PartialEq for XmlSecKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0 // compare pointer addresses
    }
}

impl Eq for XmlSecKey {}

impl Clone for XmlSecKey {
    fn clone(&self) -> Self {
        let new = unsafe { bindings::xmlSecKeyDuplicate(self.0) };

        Self(new)
    }
}

impl Drop for XmlSecKey {
    fn drop(&mut self) {
        unsafe { bindings::xmlSecKeyDestroy(self.0) };
    }
}
