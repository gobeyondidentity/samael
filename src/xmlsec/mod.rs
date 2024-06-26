//
// Source of xmlsec adapted from a separate project: https://github.com/voipir/rust-xmlsec
// MIT Licence (Voipir Group): https://github.com/voipir/rust-xmlsec/blob/master/LICENSE

//!
//! Bindings for XmlSec1
//!
//! Modules reflect the header names of the bound xmlsec1 library
//!
#![deny(missing_docs)]

#[doc(hidden)]
pub use libxml::tree::document::Document as XmlDocument;
#[doc(hidden)]
pub use libxml::tree::node::Node as XmlNode;

mod add_id_attributes;
mod backend;
mod data_store;
mod error;
mod key_info_context;
mod key_manager;
mod key_store;
mod keys;
mod xmldsig;
mod xmlenc;
mod xmlsec_internal;

// exports
pub use self::add_id_attributes::*;
pub use self::data_store::*;
pub use self::error::XmlSecError;
pub use self::error::XmlSecResult;
pub use self::key_info_context::*;
pub use self::key_manager::*;
pub use self::key_store::*;
pub use self::keys::XmlSecKey;
pub use self::keys::XmlSecKeyFormat;
pub use self::xmldsig::XmlSecSignatureContext;
pub use self::xmlenc::*;
pub use self::xmlsec_internal::XmlSecContext;
