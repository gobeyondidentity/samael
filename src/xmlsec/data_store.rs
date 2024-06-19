use super::XmlSecError;
use super::XmlSecResult;
use crate::bindings::{
    xmlSecKeyDataStoreCreate, xmlSecKeyDataStoreDestroy, xmlSecKeyDataStoreId,
    xmlSecKeyDataStorePtr,
};

/// A key data store.
pub struct XmlSecKeyDataStore {
    ptr: xmlSecKeyDataStorePtr,
}

impl XmlSecKeyDataStore {
    /// Construct a new data store from a pointer.
    pub fn from_ptr(ptr: xmlSecKeyDataStorePtr) -> Self {
        Self { ptr }
    }

    /// Allocate new instance of the xml data store.
    pub fn new(id: xmlSecKeyDataStoreId) -> XmlSecResult<Self> {
        unsafe {
            let ptr = xmlSecKeyDataStoreCreate(id);
            if ptr.is_null() {
                return Err(XmlSecError::KeyDataStoreCreateFailure);
            }
            Ok(Self { ptr })
        }
    }
}

impl Drop for XmlSecKeyDataStore {
    fn drop(&mut self) {
        unsafe { xmlSecKeyDataStoreDestroy(self.ptr) }
    }
}
// #define	xmlSecKeyDataStoreGetName()
// #define	xmlSecKeyDataStoreIsValid()
// #define	xmlSecKeyDataStoreCheckId()
// #define	xmlSecKeyDataStoreCheckSize()
