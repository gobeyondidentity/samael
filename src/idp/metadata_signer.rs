use super::*;

/// This structure is responsible for handling all of the different signatures
/// that one could provide, then updating those signatures with the provided
/// certificate, followed by signing of said certificate. This exists because
/// I've seen examples of signed WS-Fed metadata, I haven't seen any examples of
/// singed metadata for SAML.
pub(crate) struct MetadataSigner {
    pub signing_certificate_der: Vec<u8>,
    pub signature_key_der: Vec<u8>,
}

impl MetadataSigner {
    /// Creates a new MetadataSigner
    pub fn new(signing_certificate_der: Vec<u8>, signature_key_der: Vec<u8>) -> Self {
        Self {
            signing_certificate_der,
            signature_key_der,
        }
    }

    pub fn sign_metadata(&self, mut metadata: EntityDescriptor) -> Result<String, Error> {
        // Updating all signature nodes
        update_x509_signatures(&mut metadata, &self.signing_certificate_der);

        let metadata_xml = metadata
            .to_xml()
            .map_err(|x| Error::XmlGenerationError(x.to_string()))?;

        let parser = libxml::parser::Parser::default();
        let xml_document = parser.parse_string(&metadata_xml)?;
        let mut context = XmlSecSignatureContext::new()?;
        let key = XmlSecKey::from_rsa_key_der("server_key", &self.signature_key_der)?;
        context.insert_key(key);
        // Updating the document with the correct hash value.
        context.update_document_id_hash(&xml_document, "ID")?;
        context.sign_metadata_envelope(&xml_document)?;
        Ok(xml_document.to_string())
    }
}

fn update_x509_signatures(metadata: &mut EntityDescriptor, x509_cert_der: &[u8]) {
    let encoded_cert = crate::crypto::mime_encode_x509_cert(x509_cert_der);
    // Updating signature.
    if let Some(sig) = metadata.signature.as_mut() {
        update_signature(&encoded_cert, sig)
    }

    // Updating all signature inside of all role descriptors.
    metadata.role_descriptors.iter_mut().for_each(|x| {
        x.iter_mut().for_each(|y| {
            y.signature
                .as_mut()
                .iter_mut()
                .for_each(|sig| update_signature(&encoded_cert, sig));
        })
    });

    // Updating all of the signatures inside of authn_authority_descriptors.
    metadata
        .authn_authority_descriptors
        .iter_mut()
        .for_each(|x| {
            x.iter_mut().for_each(|y| {
                y.signature
                    .as_mut()
                    .iter_mut()
                    .for_each(|sig| update_signature(&encoded_cert, sig));
            })
        });

    // Updating all of the signatures inside of attribute_authority_descriptors.
    metadata
        .attribute_authority_descriptors
        .iter_mut()
        .for_each(|x| {
            x.iter_mut().for_each(|y| {
                y.signature
                    .as_mut()
                    .iter_mut()
                    .for_each(|sig| update_signature(&encoded_cert, sig));
            })
        });
}
