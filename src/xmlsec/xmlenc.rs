use super::XmlDocument;
use super::XmlSecError;
use super::XmlSecKeyManager;
use super::XmlSecResult;
use crate::bindings::xmlSecOpenSSLKeyDataAesGetKlass;
use crate::bindings::{
    self, xmlSecEncCtxDecrypt, xmlSecEncCtxXmlEncrypt, xmlSecKeyReadMemory, xmlSecKeySetName,
};
use std::ptr::null_mut;

/// XmlSecEncryptionContext used for encrypting some or all of an XML document.
pub struct XmlSecEncryptionContext {
    ctx: bindings::xmlSecEncCtxPtr,
}

// The goal here is to eventually be able to call xmlSecEncCtxXmlEncrypt
// With a template we created natively.
impl XmlSecEncryptionContext {
    /// Creates a new instance of the encryption context.
    pub fn new() -> XmlSecResult<Self> {
        super::xmlsec_internal::guarantee_xmlsec_init()?;

        let ctx = unsafe { bindings::xmlSecEncCtxCreate(null_mut()) };

        if ctx.is_null() {
            return Err(XmlSecError::ContextInitError);
        }

        Ok(Self { ctx })
    }

    /// Creates an new XmlSecEncryptionContext and initialize it with a
    /// KeyManager.
    pub fn with_key_manager(manager: &XmlSecKeyManager) -> XmlSecResult<Self> {
        super::xmlsec_internal::guarantee_xmlsec_init()?;

        let ctx = unsafe { bindings::xmlSecEncCtxCreate(manager.as_ptr()) };

        if ctx.is_null() {
            return Err(XmlSecError::ContextInitError);
        }

        Ok(Self { ctx })
    }

    /// This assumes that a key is an AES key and we are using OpenSSL.
    pub fn set_key(&self, key_name: String, key_contents: &[u8]) -> XmlSecResult<()> {
        unsafe {
            let xml_sec_key = xmlSecKeyReadMemory(
                xmlSecOpenSSLKeyDataAesGetKlass(),
                key_contents.as_ptr(),
                key_contents.len() as u32,
            );
            if xml_sec_key.is_null() {
                return Err(XmlSecError::SecKeyReadBufferError);
            }
            // Setting key
            (*self.ctx).encKey = xml_sec_key;

            let name_ret = xmlSecKeySetName((*self.ctx).encKey, key_name.as_bytes().as_ptr());
            if name_ret != 0 {
                return Err(XmlSecError::SecSetKeyNameError);
            }
        }
        Ok(())
    }

    /// Encrypts all of the encrypted_assertion's assertion nodes within a
    /// document.
    pub fn encrypt_all_encrypted_assertions(&self, doc: &XmlDocument) -> XmlSecResult<()> {
        let xpath_context =
            libxml::xpath::Context::new(doc).map_err(|_| XmlSecError::XPathContextError)?;
        xpath_context
            .register_namespace("xenc", "http://www.w3.org/2001/04/xmlenc#")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        xpath_context
            .register_namespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;

        let to_transform = xpath_context
            .evaluate("//saml:EncryptedAssertion/saml:Assertion")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;

        let template_nodes = xpath_context
            .evaluate("//saml:EncryptedAssertion/xenc:EncryptedData")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;

        self.encrypt_all_node_pairs(to_transform, template_nodes)
    }

    /// Attempts to locate all of the encryption nodes within a document and use
    /// them in order to encrypt and transform them. ALl changes should be
    /// present within the provided document after evaluation.
    ///
    /// document - the document that owns the nodes.
    ///
    ///  nodes_to_encrypt - the result of an XPath object where all nodes that
    ///         need to be encrypted must be elements.
    ///
    /// encryption_template - The xml document that is applied to the node to
    ///     encrypt them.
    pub fn encrypt_all_node_pairs(
        &self,
        nodes_to_encrypt: libxml::xpath::Object,
        encryption_template_nodes: libxml::xpath::Object,
    ) -> XmlSecResult<()> {
        let nodes_to_encrypt_vec = nodes_to_encrypt.get_nodes_as_vec();
        let encryption_template_node = encryption_template_nodes.get_nodes_as_vec();
        if nodes_to_encrypt_vec.len() != encryption_template_node.len() {
            return Err(XmlSecError::MismatchedNumberOfNodesAndTemplates {
                node_count: nodes_to_encrypt_vec.len(),
                template_count: encryption_template_node.len(),
            });
        }
        for (node, template) in nodes_to_encrypt_vec
            .iter()
            .zip(encryption_template_node.iter())
        {
            unsafe {
                let res = xmlSecEncCtxXmlEncrypt(
                    self.ctx,
                    template.node_ptr() as crate::bindings::xmlNodePtr,
                    node.node_ptr() as crate::bindings::xmlNodePtr,
                );
                if res != 0 {
                    return Err(XmlSecError::EncWhileEncryptingXml);
                }
            }
        }
        Ok(())
    }

    /// Attempts to decrypt all encrypted nodes within a document.
    pub fn decrypt_document(&self, doc: &XmlDocument) -> XmlSecResult<()> {
        let xpath_context =
            libxml::xpath::Context::new(doc).map_err(|_| XmlSecError::XPathContextError)?;
        xpath_context
            .register_namespace("xenc", "http://www.w3.org/2001/04/xmlenc#")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        xpath_context
            .register_namespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        // xpath_context.regi
        let encrypted_nodes = xpath_context
            .evaluate("//saml:EncryptedAssertion/xenc:EncryptedData")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;
        let encrypted_nodes = encrypted_nodes.get_nodes_as_vec();
        for node in encrypted_nodes.iter() {
            unsafe {
                let rc =
                    xmlSecEncCtxDecrypt(self.ctx, node.node_ptr() as crate::bindings::xmlNodePtr);
                if rc != 0 || (*self.ctx).result.is_null() {
                    return Err(XmlSecError::EncDecryptionFailed);
                }
            }
        }
        Ok(())
    }
}

impl Drop for XmlSecEncryptionContext {
    fn drop(&mut self) {
        unsafe { bindings::xmlSecEncCtxDestroy(self.ctx) };
    }
}

#[cfg(test)]
mod test {
    use openssl::rand::rand_bytes;

    use super::super::*;
    use super::*;

    #[test]
    fn test_encryption_context() {
        let rsa_key = openssl::rsa::Rsa::generate(4096).expect("Failed to create rsa keys");

        // Setting up A key manager.
        let enc_key_manager = XmlSecKeyManager::new().expect("Failed to create key manager");
        let public_key_pem = rsa_key.public_key_to_pem().unwrap();
        let enc_sec_key = XmlSecKey::from_rsa_key_pem("test_name", &public_key_pem).unwrap();
        enc_key_manager.adopt_key(enc_sec_key).unwrap();

        let dec_key_manager = XmlSecKeyManager::new().expect("Failed to create key manager");
        let private_key_pem = rsa_key.private_key_to_pem().unwrap();
        let dec_sec_key = XmlSecKey::from_rsa_key_pem("test_name", &private_key_pem).unwrap();
        dec_key_manager.adopt_key(dec_sec_key).unwrap();

        let encryption_context: XmlSecEncryptionContext =
            XmlSecEncryptionContext::with_key_manager(&enc_key_manager).unwrap();

        let parser = libxml::parser::Parser::default();
        let saml_response = parser.parse_string(r#"
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#" Type="http://www.w3.org/2001/04/xmlenc#Element">
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
        <dsig:KeyInfo>
            <xenc:EncryptedKey>
                <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
                <dsig:KeyInfo>
                    <dsig:KeyName/>
                </dsig:KeyInfo>
                <xenc:CipherData>
                    <xenc:CipherValue/>
                </xenc:CipherData>
            </xenc:EncryptedKey>
        </dsig:KeyInfo>
        <xenc:CipherData>
            <xenc:CipherValue/>
        </xenc:CipherData>
    </xenc:EncryptedData>
    <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
        <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
        <saml:Subject>
        <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
        <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml:SubjectConfirmationData NotOnOrAfter="2024-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
        </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2024-01-18T06:21:48Z">
        <saml:AudienceRestriction>
            <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
        </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2024-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
        <saml:AuthnContext>
            <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
        </saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
        <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
        </saml:Attribute>
        <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
            <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
            <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
        </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
  </saml:EncryptedAssertion>
</samlp:Response>
        "#).unwrap();

        let xpath_context =
            libxml::xpath::Context::new(&saml_response).expect("Failed to create XPath");
        xpath_context
            .register_namespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion")
            .expect("Failed to register namespace");

        xpath_context
            .register_namespace("xenc", "http://www.w3.org/2001/04/xmlenc#")
            .expect("Failed to register namespace");

        let to_transform = xpath_context
            .evaluate("//saml:EncryptedAssertion/saml:Assertion")
            .expect("Failed to compile expression");

        let template_nodes = xpath_context
            .evaluate("//saml:EncryptedAssertion/xenc:EncryptedData")
            .expect("Failed to query for encrypted data nodes");

        let nodes = to_transform.get_nodes_as_vec();
        assert_eq!(nodes.len(), 1);
        let mut aes_key = [0; 256 / 8];
        rand_bytes(&mut aes_key).unwrap();

        encryption_context
            .set_key("test_key".to_string(), &aes_key)
            .expect("Failed to set key");
        encryption_context
            .encrypt_all_node_pairs(to_transform, template_nodes)
            .expect("Failed to visit all of the nodes");

        let decryption_context =
            XmlSecEncryptionContext::with_key_manager(&dec_key_manager).unwrap();
        decryption_context.decrypt_document(&saml_response).unwrap();
    }
}
