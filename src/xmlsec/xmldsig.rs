//!
//! Wrapper for XmlSec Signature Context
//!
use crate::bindings;

use super::XmlDocument;
use super::XmlSecError;
use super::XmlSecKey;
use super::XmlSecResult;

use std::os::raw::c_uchar;
use std::ptr::{null, null_mut};

/// Signature signing/verifying context
pub struct XmlSecSignatureContext {
    ctx: *mut bindings::xmlSecDSigCtx,
}

impl XmlSecSignatureContext {
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new() -> XmlSecResult<Self> {
        super::xmlsec_internal::guarantee_xmlsec_init()?;

        let ctx = unsafe { bindings::xmlSecDSigCtxCreate(null_mut()) };

        if ctx.is_null() {
            return Err(XmlSecError::ContextInitError);
        }

        Ok(Self { ctx })
    }

    /// Sets the key to use for signature or verification. In case a key had
    /// already been set, the latter one gets released in the optional return.
    pub fn insert_key(&mut self, key: XmlSecKey) -> Option<XmlSecKey> {
        let mut old = None;

        unsafe {
            if !(*self.ctx).signKey.is_null() {
                old = Some(XmlSecKey::from_ptr((*self.ctx).signKey));
            }

            (*self.ctx).signKey = XmlSecKey::leak(key);
        }

        old
    }

    /// Releases a currently set key returning `Some(key)` or None otherwise.
    #[allow(unused)]
    pub fn release_key(&mut self) -> Option<XmlSecKey> {
        unsafe {
            if (*self.ctx).signKey.is_null() {
                None
            } else {
                let key = XmlSecKey::from_ptr((*self.ctx).signKey);

                (*self.ctx).signKey = null_mut();

                Some(key)
            }
        }
    }

    /// Takes a [`XmlDocument`][xmldoc] and attempts to sign it. For this to
    /// work it has to have a properly structured `<dsig:Signature>` node
    /// within, and a XmlSecKey must have been previously set with
    /// [`insert_key`][inskey].
    ///
    /// if you previously called `update_document_id_hash` you don't need to
    /// provide `id_attr`.
    ///
    /// # Errors
    ///
    /// If key has not been previously set or document is malformed.
    ///
    /// [xmldoc]:
    ///     http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn sign_document(&self, doc: &XmlDocument, id_attr: Option<&str>) -> XmlSecResult<()> {
        self.key_is_set()?;

        let doc_ptr = doc.doc_ptr();
        let root = if let Some(root) = doc.get_root_element() {
            root
        } else {
            return Err(XmlSecError::RootNotFound);
        };

        let root_ptr = root.node_ptr() as *mut bindings::xmlNode;

        if let Some(id_attr) = id_attr {
            let cid =
                std::ffi::CString::new(id_attr).map_err(|_| XmlSecError::InvalidInputString)?;

            unsafe {
                let mut list = [cid.as_bytes().as_ptr(), null()];
                bindings::xmlSecAddIDs(
                    doc_ptr as *mut bindings::xmlDoc,
                    root_ptr,
                    list.as_mut_ptr(),
                );
            }
        }

        let signode = find_signode(root_ptr)?;
        self.sign_node_raw(signode)
    }

    /// Locates and explicitly signs only the document.
    pub fn sign_document_only(&self, doc: &XmlDocument) -> XmlSecResult<()> {
        self.key_is_set()?;
        // Creating an XPath to locate all of the
        let xpath_context =
            libxml::xpath::Context::new(doc).map_err(|_| XmlSecError::XPathContextError)?;
        xpath_context
            .register_namespace("dsig", "http://www.w3.org/2000/09/xmldsig#")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        xpath_context
            .register_namespace("saml2p", "urn:oasis:names:tc:SAML:2.0:protocol")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;

        let doc_signature_node = xpath_context
            .evaluate("//saml2p:Response/dsig:Signature")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;

        let signature_nodes = doc_signature_node.get_nodes_as_vec();
        if signature_nodes.is_empty() {
            return Err(XmlSecError::MissingDocumentSignature);
        }
        if signature_nodes.len() != 1 {
            return Err(XmlSecError::TooManySignatureNodesError);
        }
        // let mut node = signature_nodes[0];
        for mut to_sign in signature_nodes.into_iter() {
            self.sign_node_raw(
                to_sign
                    .node_ptr_mut()
                    .map_err(|msg| XmlSecError::XmlDocumentErr { msg })?
                    as *mut bindings::xmlNode,
            )?;
        }
        Ok(())
    }

    /// Signs the metadata envelope.
    pub fn sign_metadata_envelope(&self, doc: &XmlDocument) -> XmlSecResult<()> {
        self.key_is_set()?;
        // Creating an XPath to locate all of the
        let xpath_context =
            libxml::xpath::Context::new(doc).map_err(|_| XmlSecError::XPathContextError)?;
        xpath_context
            .register_namespace("dsig", "http://www.w3.org/2000/09/xmldsig#")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        xpath_context
            .register_namespace("md", "urn:oasis:names:tc:SAML:2.0:metadata")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;

        let doc_signature_node = xpath_context
            .evaluate("//md:EntityDescriptor/dsig:Signature")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;

        let signature_nodes = doc_signature_node.get_nodes_as_vec();
        if signature_nodes.is_empty() {
            return Err(XmlSecError::MissingDocumentSignature);
        }
        if signature_nodes.len() != 1 {
            return Err(XmlSecError::TooManySignatureNodesError);
        }
        // let mut node = signature_nodes[0];
        for mut to_sign in signature_nodes.into_iter() {
            self.sign_node_raw(
                to_sign
                    .node_ptr_mut()
                    .map_err(|msg| XmlSecError::XmlDocumentErr { msg })?
                    as *mut bindings::xmlNode,
            )?;
        }
        Ok(())
    }

    /// This should be called before everything else is so we don't update this
    /// multiple time, but all it does is walk all of the elements of the tree
    /// searching for ID's and adds all attributes from the ids list to the doc
    /// document IDs attributes hash.
    pub fn update_document_id_hash(&self, doc: &XmlDocument, id_attr: &str) -> XmlSecResult<()> {
        let doc_ptr = doc.doc_ptr();
        let root = if let Some(root) = doc.get_root_element() {
            root
        } else {
            return Err(XmlSecError::RootNotFound);
        };

        let root_ptr = root.node_ptr() as *mut bindings::xmlNode;
        let cid = std::ffi::CString::new(id_attr).map_err(|_| XmlSecError::InvalidInputString)?;

        unsafe {
            let mut list = [cid.as_bytes().as_ptr(), null()];
            bindings::xmlSecAddIDs(
                doc_ptr as *mut bindings::xmlDoc,
                root_ptr,
                list.as_mut_ptr(),
            );
        }
        Ok(())
    }

    /// Locates and signs all assertions within the document.
    pub fn sign_assertions(&self, doc: &XmlDocument) -> XmlSecResult<()> {
        self.key_is_set()?;
        // Creating an XPath to locate all of the
        let xpath_context =
            libxml::xpath::Context::new(doc).map_err(|_| XmlSecError::XPathContextError)?;
        xpath_context
            .register_namespace("dsig", "http://www.w3.org/2000/09/xmldsig#")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        xpath_context
            .register_namespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;

        xpath_context
            .register_namespace("saml1", "urn:oasis:names:tc:SAML:1.0:assertion")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;

        let assertion_signature_nodes = xpath_context
            .evaluate("//saml2:Assertion/dsig:Signature|//saml1:Assertion/dsig:Signature")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;

        let signature_nodes = assertion_signature_nodes.get_nodes_as_vec();
        // Attempting to sign all assertion nodes.
        for mut to_sign in signature_nodes.into_iter() {
            self.sign_node_raw(
                to_sign
                    .node_ptr_mut()
                    .map_err(|msg| XmlSecError::XmlDocumentErr { msg })?
                    as *mut bindings::xmlNode,
            )?;
        }
        Ok(())
    }

    /// Takes a [`XmlDocument`][xmldoc] and attempts to verify its signature. For this to work it has to have a properly
    /// structured and signed `<dsig:Signature>` node within, and a XmlSecKey must have been previously set with
    /// [`insert_key`][inskey].
    ///
    /// # Errors
    ///
    /// If key has not been previously set or document is malformed.
    ///
    /// [xmldoc]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Document.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn verify_document(&self, doc: &XmlDocument, id_attr: Option<&str>) -> XmlSecResult<bool> {
        self.key_is_set()?;

        let doc_ptr = doc.doc_ptr();
        let root = if let Some(root) = doc.get_root_element() {
            root
        } else {
            return Err(XmlSecError::RootNotFound);
        };

        let root_ptr = root.node_ptr() as *mut bindings::xmlNode;

        if let Some(id_attr) = id_attr {
            let cid =
                std::ffi::CString::new(id_attr).map_err(|_| XmlSecError::InvalidInputString)?;

            unsafe {
                let mut list = [cid.as_bytes().as_ptr(), null()];
                bindings::xmlSecAddIDs(
                    doc_ptr as *mut bindings::xmlDoc,
                    root_ptr,
                    list.as_mut_ptr(),
                );
            }
        }

        let signode = find_signode(root_ptr)?;
        self.verify_node_raw(signode)
    }

    /// This is to help with testing, but it attempts to verify all of the
    /// signatures within a document and returns the number of verified
    /// signatures.
    ///
    /// you should call `update_document_id_hash` before calling this if you
    /// need to verify the ID hash.
    ///
    /// WARNING ONLY WORKS WITH A SINGLE SIGNATURE WITHIN A DOCUMENT.
    pub fn verify_any_signatures(&self, doc: &XmlDocument) -> XmlSecResult<i32> {
        self.key_is_set()?;
        // Creating an XPath to locate all of the
        let xpath_context = libxml::xpath::Context::new(doc).expect("Failed to create XPath");
        xpath_context
            .register_namespace("dsig", "http://www.w3.org/2000/09/xmldsig#")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;

        let assertion_signature_nodes = xpath_context
            .evaluate("//dsig:Signature")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;

        let signature_nodes = assertion_signature_nodes.get_nodes_as_vec();
        // Attempting to sign all assertion nodes.
        for to_verify in signature_nodes.iter() {
            self.verify_node(to_verify)?;
        }
        Ok(signature_nodes.len() as i32)
    }

    /// Takes a `<dsig:Signature>` [`Node`][xmlnode] and attempts to verify it. For this to work, a XmlSecKey must have
    /// been previously set with [`insert_key`][inskey].
    ///
    /// # Errors
    ///
    /// If key has not been previously set, the node is not a signature node or the document is malformed.
    ///
    /// [xmlnode]: http://kwarc.github.io/rust-libxml/libxml/tree/document/struct.Node.html
    /// [inskey]: struct.XmlSecSignatureContext.html#method.insert_key
    pub fn verify_node(&self, sig_node: &libxml::tree::Node) -> XmlSecResult<bool> {
        self.key_is_set()?;
        if let Some(ns) = sig_node.get_namespace() {
            if ns.get_href() != "http://www.w3.org/2000/09/xmldsig#"
                || sig_node.get_name() != "Signature"
            {
                return Err(XmlSecError::NotASignatureNode);
            }
        } else {
            return Err(XmlSecError::NotASignatureNode);
        }

        let node_ptr = sig_node.node_ptr();
        self.verify_node_raw(node_ptr as *mut bindings::xmlNode)
    }
}

impl XmlSecSignatureContext {
    fn key_is_set(&self) -> XmlSecResult<()> {
        unsafe {
            if !(*self.ctx).signKey.is_null() {
                Ok(())
            } else {
                Err(XmlSecError::KeyNotLoaded)
            }
        }
    }

    fn sign_node_raw(&self, node: *mut bindings::xmlNode) -> XmlSecResult<()> {
        let rc = unsafe { bindings::xmlSecDSigCtxSign(self.ctx, node) };

        if rc < 0 {
            Err(XmlSecError::SigningError)
        } else {
            Ok(())
        }
    }

    fn verify_node_raw(&self, node: *mut bindings::xmlNode) -> XmlSecResult<bool> {
        let rc = unsafe { bindings::xmlSecDSigCtxVerify(self.ctx, node) };

        if rc < 0 {
            return Err(XmlSecError::VerifyError);
        }

        match unsafe { (*self.ctx).status } {
            bindings::xmlSecDSigStatus_xmlSecDSigStatusSucceeded => Ok(true),
            _ => Ok(false),
        }
    }
}

impl Drop for XmlSecSignatureContext {
    fn drop(&mut self) {
        unsafe { bindings::xmlSecDSigCtxDestroy(self.ctx) };
    }
}

fn find_signode(tree: *mut bindings::xmlNode) -> XmlSecResult<*mut bindings::xmlNode> {
    let signode = unsafe {
        bindings::xmlSecFindNode(
            tree,
            &bindings::xmlSecNodeSignature as *const c_uchar,
            &bindings::xmlSecDSigNs as *const c_uchar,
        )
    };

    if signode.is_null() {
        return Err(XmlSecError::NodeNotFound);
    }

    Ok(signode)
}
