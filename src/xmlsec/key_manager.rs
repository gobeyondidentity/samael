use super::XmlSecError;
use super::XmlSecKey;
use super::XmlSecKeyDataStore;
use super::XmlSecKeyInfoContext;
use super::XmlSecKeyStore;
use super::XmlSecResult;
use crate::bindings::xmlSecKeyDataStoreId;
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

    // xmlSecKeyPtr	xmlSecKeysMngrFindKey ()
    /// Lookups key in the keys manager keys store. The caller is responsible
    /// for destroying the returned key using xmlSecKeyDestroy method.
    pub fn find_key(&self, _name: &str, _ctx: &XmlSecKeyInfoContext) -> XmlSecResult<XmlSecKey> {
        todo!()
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

    // xmlSecKeyPtr	xmlSecKeysMngrFindKeyFromX509Data ()
    // /// Lookups key in the keys manager keys store. The caller is responsible
    // /// for destroying the returned key using xmlSecKeyDestroy method.
    // fn find_key_from_x509(&self) -> XmlSecResult<XmlSecKey> {
    //     // TODO: Eventually add an implementation for an x509 certificate
    //     // that we can leverage from inside of xml sec.
    //     todo!()
    // }

    /// Adopts keys store in the keys manager.
    pub fn adopt_key_store(&self, _key_store: XmlSecKeyStore) -> XmlSecResult<()> {
        // int	xmlSecKeysMngrAdoptKeysStore ()
        todo!()
    }

    // xmlSecKeyStorePtr	xmlSecKeysMngrGetKeysStore ()
    /// Gets the keys store.
    pub fn get_key_store(&self) -> XmlSecResult<XmlSecKeyStore> {
        todo!()
    }

    // int	xmlSecKeysMngrAdoptDataStore ()
    /// Adopts data store in the keys manager.
    pub fn adopt_data_store(&self, _data_store: XmlSecKeyDataStore) -> XmlSecResult<()> {
        todo!()
    }

    // xmlSecKeyDataStorePtr	xmlSecKeysMngrGetDataStore ()
    /// Lookups the data store of given klass id in the keys manager.
    pub fn get_data_store(&self, _id: xmlSecKeyDataStoreId) -> XmlSecResult<()> {
        todo!()
    }

    /// Reads the <dsig:KeyInfo/> node keyInfoNode and extracts the key.
    pub fn get_key(&self, _key_info_context: XmlSecKeyInfoContext) -> XmlSecResult<XmlSecKey> {
        todo!()
    }

    // Other functions that we might want in the future.
    // xmlSecOpenSSLAppDefaultKeysMngrLoad
    // xmlSecOpenSSLAppDefaultKeysMngrSave
    // xmlSecOpenSSLAppKeysMngrCertLoad
    // xmlSecOpenSSLAppKeysMngrCertLoadMemory
    // xmlSecOpenSSLAppKeysMngrCertLoadBIO
    // xmlSecOpenSSLAppKeysMngrAddCertsPath
    // xmlSecOpenSSLAppKeysMngrAddCertsFile
}

impl Drop for XmlSecKeyManager {
    fn drop(&mut self) {
        unsafe { xmlSecKeysMngrDestroy(self.mngr) };
    }
}
