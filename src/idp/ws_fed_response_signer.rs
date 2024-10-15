use super::*;
use crate::schema::ws_fed::RequestSecurityTokenResponse;

pub(crate) struct WsFedResponseSigner {
    pub signing_certificate_der: Vec<u8>,
    pub signature_key_der: Vec<u8>,
}

impl WsFedResponseSigner {
    /// Creates a new MetadataSigner
    pub fn new(signing_certificate_der: Vec<u8>, signature_key_der: Vec<u8>) -> Self {
        Self {
            signing_certificate_der,
            signature_key_der,
        }
    }

    pub fn sign_request_security_token_response(
        &self,
        mut rstr: RequestSecurityTokenResponse,
    ) -> Result<String, Error> {
        // Updating all signature nodes
        update_x509_assertion_signatures(&mut rstr, &self.signing_certificate_der);

        let rstr_xml = rstr
            .to_xml()
            .map_err(|x| Error::XmlGenerationError(x.to_string()))?;

        let parser = libxml::parser::Parser::default();
        let xml_document = parser.parse_string(&rstr_xml)?;
        let mut context = XmlSecSignatureContext::new()?;
        let key = XmlSecKey::from_rsa_key_der("server_key", &self.signature_key_der)?;
        context.insert_key(key);
        // Updating the document with the correct hash value.
        context.update_document_id_hash(&xml_document, "AssertionID")?;
        context.sign_assertions(&xml_document)?;
        Ok(xml_document.to_string())
    }
}

fn update_x509_assertion_signatures(rstr: &mut RequestSecurityTokenResponse, x509_cert_der: &[u8]) {
    let encoded_cert = crate::crypto::mime_encode_x509_cert(x509_cert_der);
    if let Some(sig) = rstr.requested_security_token.assertion.signature.as_mut() {
        update_signature(&encoded_cert, sig)
    }
}
