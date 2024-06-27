use super::XmlSecError;
use super::XmlSecKey;
use super::XmlSecResult;
use crate::bindings::{
    xmlSecKeysMngrCreate, xmlSecKeysMngrDestroy, xmlSecKeysMngrPtr,
    xmlSecOpenSSLAppDefaultKeysMngrAdoptKey, xmlSecOpenSSLAppDefaultKeysMngrInit,
};

/// The key manager type that's used for handling keys that are used to do
/// things like encrypt other keys.
pub struct XmlSecKeyManager {
    mngr: xmlSecKeysMngrPtr,
}

impl XmlSecKeyManager {
    /// Create and initialize a new key manager.
    pub fn new() -> XmlSecResult<Self> {
        unsafe {
            let mngr = xmlSecKeysMngrCreate();
            if mngr.is_null() {
                return Err(XmlSecError::KeyManagerCreateFailure);
            }
            if xmlSecOpenSSLAppDefaultKeysMngrInit(mngr) != 0 {
                return Err(XmlSecError::KeyManagerDefaultInitFailure);
            }
            Ok(Self { mngr })
        }
    }

    /// Returns the internal pointer to the type.
    pub fn as_ptr(&self) -> xmlSecKeysMngrPtr {
        self.mngr
    }

    /// add key to keys manager, from now on keys manager is responsible for
    /// destroying key.
    pub fn adopt_key(&self, key: XmlSecKey) -> XmlSecResult<()> {
        unsafe {
            let key = XmlSecKey::leak(key);
            if xmlSecOpenSSLAppDefaultKeysMngrAdoptKey(self.mngr, key) != 0 {
                return Err(XmlSecError::KeyManagerKeyAdoptionFailure);
            }
        }
        Ok(())
    }
}

impl Drop for XmlSecKeyManager {
    fn drop(&mut self) {
        unsafe { xmlSecKeysMngrDestroy(self.mngr) };
    }
}
