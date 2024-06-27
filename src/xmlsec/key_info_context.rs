use super::key_manager::XmlSecKeyManager;
use super::XmlSecError;
use super::XmlSecResult;
use crate::bindings::{xmlSecKeyInfoCtxCreate, xmlSecKeyInfoCtxDestroy, xmlSecKeyInfoCtxPtr};

/// The <dsig:KeyInfo /> reading or writing context.
#[derive(Debug)]
pub struct XmlSecKeyInfoContext {
    ctx: xmlSecKeyInfoCtxPtr,
}

impl XmlSecKeyInfoContext {
    /// Allocates and initializes <dsig:KeyInfo/> element processing context. Caller
    /// is responsible for freeing it by calling xmlSecKeyInfoCtxDestroy function.
    pub fn new(mngr: &XmlSecKeyManager) -> XmlSecResult<Self> {
        unsafe {
            let ctx = xmlSecKeyInfoCtxCreate(mngr.as_ptr());
            if ctx.is_null() {
                return Err(XmlSecError::KeyInfoContextCreateFailure);
            }
            Ok(Self { ctx })
        }
    }
}

impl Drop for XmlSecKeyInfoContext {
    fn drop(&mut self) {
        unsafe { xmlSecKeyInfoCtxDestroy(self.ctx) };
    }
}
