use super::XmlSecError;
use super::XmlSecResult;
use crate::bindings::{
    xmlSecKeyStoreCreate, xmlSecKeyStoreDestroy, xmlSecKeyStoreId, xmlSecKeyStorePtr,
};

/// A pointer to a key store.
pub struct XmlSecKeyStore {
    ptr: xmlSecKeyStorePtr,
}

impl XmlSecKeyStore {
    /// Create a key store from a pointer
    pub fn from_ptr(ptr: xmlSecKeyStorePtr) -> Self {
        Self { ptr }
    }

    /// Create a new key store.
    pub fn new(id: xmlSecKeyStoreId) -> XmlSecResult<Self> {
        unsafe {
            let ptr = xmlSecKeyStoreCreate(id);
            if ptr.is_null() {
                return Err(XmlSecError::KeyStoreCreateFailure);
            }
            Ok(Self { ptr })
        }
    }
}

impl Drop for XmlSecKeyStore {
    fn drop(&mut self) {
        unsafe {
            xmlSecKeyStoreDestroy(self.ptr);
        }
    }
}
