pub mod attribute;
mod bindings;
pub mod crypto;
pub mod idp;
pub mod key_info;
pub mod metadata;
pub mod schema;
pub mod service_provider;
pub mod signature;

pub mod xmlsec;

mod traits;

#[macro_use]
extern crate derive_builder;

pub fn init() -> xmlsec::XmlSecResult<xmlsec::XmlSecContext> {
    xmlsec::XmlSecContext::new()
}
