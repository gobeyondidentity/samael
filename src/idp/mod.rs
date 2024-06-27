pub mod error;
pub mod response_builder;
pub mod sp_extractor;
#[cfg(test)]
mod tests;
pub mod verified_request;

use self::error::Error;
use crate::crypto;
use crate::idp::response_builder::{build_response_template, ResponseAttribute};
use crate::key_info::{KeyInfo, X509Data};
use crate::schema::Response;
use crate::signature::Signature;
use crate::traits::ToXml;
use crate::xmlsec::{
    XmlDocument, XmlSecEncryptionContext, XmlSecError, XmlSecKey, XmlSecKeyManager,
    XmlSecSignatureContext,
};
use lazy_static::lazy_static;
use openssl::bn::{BigNum, MsbOption};
use openssl::nid::Nid;
use openssl::pkey::{Private, Public};
use openssl::rand::rand_bytes;
use openssl::{asn1::Asn1Time, pkey, rsa::Rsa, x509};
use std::str::FromStr;

pub struct IdentityProvider {
    encryption_key_name: Option<String>,
    assertion_encryption_key: Option<pkey::PKey<Public>>,
    private_key: pkey::PKey<Private>,
}

pub enum KeyType {
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl KeyType {
    fn bit_length(&self) -> u32 {
        match &self {
            KeyType::Rsa2048 => 2048,
            KeyType::Rsa3072 => 3072,
            KeyType::Rsa4096 => 4096,
        }
    }
}

pub struct CertificateParams<'a> {
    pub common_name: &'a str,
    pub issuer_name: &'a str,
    pub days_until_expiration: u32,
}

impl IdentityProvider {
    pub fn new(
        encryption_key_name: Option<String>,
        encryption_key: Option<pkey::PKey<Public>>,
        private_key: pkey::PKey<Private>,
    ) -> Self {
        Self {
            encryption_key_name,
            assertion_encryption_key: encryption_key,
            private_key,
        }
    }

    pub fn generate_new(key_type: KeyType) -> Result<Self, Error> {
        let rsa = Rsa::generate(key_type.bit_length())?;
        let private_key = pkey::PKey::from_rsa(rsa)?;

        Ok(IdentityProvider {
            encryption_key_name: None,
            assertion_encryption_key: None,
            private_key,
        })
    }

    pub fn from_private_key_der(der_bytes: &[u8]) -> Result<Self, Error> {
        let rsa = Rsa::private_key_from_der(der_bytes)?;
        let private_key = pkey::PKey::from_rsa(rsa)?;

        Ok(IdentityProvider {
            encryption_key_name: None,
            assertion_encryption_key: None,
            private_key,
        })
    }

    pub fn from_private_key_pem(pem_bytes: &[u8]) -> Result<Self, Error> {
        let rsa = Rsa::private_key_from_pem(pem_bytes)?;
        let private_key = pkey::PKey::from_rsa(rsa)?;

        Ok(IdentityProvider {
            encryption_key_name: None,
            assertion_encryption_key: None,
            private_key,
        })
    }

    pub fn export_private_key_der(&self) -> Result<Vec<u8>, Error> {
        let rsa: Rsa<Private> = self.private_key.rsa()?;
        Ok(rsa.private_key_to_der()?)
    }
    // Response
    /// This function is responsible for taking the response object, and
    /// generating the correct Base64 encoded Response from it. This can than be
    /// used when we return the self submitting form. This handles all of the
    /// XML generating, encryption, and signing during XML generation.
    ///
    /// If an `assertion_encryption_key` is provided all assertions will be
    /// encrypted.
    ///
    /// if the `envelope_signature_params` parameter is set the envelope will be
    /// signed.
    ///
    /// If the parameter `sign_assertions` set to true the assertions will be
    /// signed.
    pub fn generate_response(
        &self,
        signature_params: Option<&CertificateParams>,
        saml_response: Response,
    ) -> Result<String, Error> {
        // Getting the certificate if one is asked for.
        let cert = if let Some(params) = signature_params {
            Some(self.create_certificate(params)?)
        } else {
            None
        };
        let signature_key = self.private_key.private_key_to_der()?;
        let generator = ResponseGenerator::new(
            self.encryption_key_name.clone(),
            self.assertion_encryption_key.clone(),
            cert,
            signature_key,
        );
        generator.generate_response(saml_response)
    }

    pub fn create_certificate(&self, params: &CertificateParams) -> Result<Vec<u8>, Error> {
        let mut name = x509::X509Name::builder()?;
        name.append_entry_by_nid(Nid::COMMONNAME, params.common_name)?;
        let name = name.build();

        let mut iss = x509::X509Name::builder()?;
        iss.append_entry_by_nid(Nid::COMMONNAME, params.issuer_name)?;
        let iss = iss.build();

        let mut builder = x509::X509::builder()?;

        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };

        builder.set_serial_number(&serial_number)?;
        builder.set_version(2)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&iss)?;
        builder.set_pubkey(&self.private_key)?;

        let starts = Asn1Time::days_from_now(0)?; // now
        builder.set_not_before(&starts)?;

        let expires = Asn1Time::days_from_now(params.days_until_expiration)?;
        builder.set_not_after(&expires)?;

        builder.sign(&self.private_key, openssl::hash::MessageDigest::sha256())?;

        let certificate: x509::X509 = builder.build();
        Ok(certificate.to_der()?)
    }

    pub fn create_template_response(
        &self,
        idp_x509_cert_der: &[u8],
        subject_name_id: &str,
        audience: &str,
        acs_url: &str,
        issuer: &str,
        in_response_to_id: &str,
        attributes: &[ResponseAttribute],
    ) -> Result<Response, Box<dyn std::error::Error>> {
        let response = build_response_template(
            idp_x509_cert_der,
            subject_name_id,
            audience,
            issuer,
            acs_url,
            in_response_to_id,
            attributes,
        );

        let response_xml_unsigned = response.to_xml()?;
        let signed_xml = crypto::sign_xml(
            response_xml_unsigned.as_str(),
            self.export_private_key_der()?.as_slice(),
        )?;
        let signed_response = Response::from_str(signed_xml.as_str())?;
        Ok(signed_response)
    }
}

/// This class is used to implement response generation instead of using
/// `try_into` for all of the code generation. This used by the
/// `IdentityProvider` to implement a transformation of a response into
/// something else.
struct ResponseGenerator {
    encryption_key_name: Option<String>,
    assertion_encryption_key: Option<pkey::PKey<Public>>,
    signing_certificate: Option<Vec<u8>>,
    signature_key_der: Vec<u8>,
}

impl ResponseGenerator {
    pub fn new(
        encryption_key_name: Option<String>,
        assertion_encryption_key: Option<pkey::PKey<Public>>,
        signing_certificate: Option<Vec<u8>>,
        signature_key_der: Vec<u8>,
    ) -> Self {
        Self {
            encryption_key_name,
            assertion_encryption_key,
            signing_certificate,
            signature_key_der,
        }
    }

    pub fn generate_response(&self, mut saml_response: Response) -> Result<String, Error> {
        // Step 1: Do some inspection of the saml_response before we convert it
        // into XML so we know what we need to do after we convert it into XML.

        // Checking if we have any assertions with a signature.
        let sign_assertions = check_sign_assertions(&saml_response);

        // Checking if we have any encrypted assertions.
        let need_to_encrypt_assertions = check_encrypt_assertions(&saml_response);

        // Checking if the response needs a signature.
        let sign_envelope = check_sign_envelope(&saml_response);

        if let Some(x509_cert) = self.signing_certificate.as_ref() {
            self.update_x509_signatures(&mut saml_response, x509_cert)?;
        } else if sign_assertions || sign_envelope {
            // If we are configured for this and we don't have certificate
            // parameters this is going to be problematic.
            return Err(Error::MissingCert);
        }

        // Step 2: Converting the response into a template that can be processed
        // more by xmlSec library.
        let xml_string = saml_response
            .to_xml()
            .map_err(|x| Error::XmlGenerationError(x.to_string()))?;

        let parser = libxml::parser::Parser::default();
        let xml_document = parser.parse_string(&xml_string)?;

        // Parse the xml into libxml2 format.
        if sign_assertions {
            let mut context = XmlSecSignatureContext::new()?;
            let key = XmlSecKey::from_rsa_key_der("server_key", &self.signature_key_der)?;
            context.insert_key(key);
            // Updating the document with the correct hash value.
            context.update_document_id_hash(&xml_document, "ID")?;

            // Checking for key and returning an error.
            context.sign_assertions(&xml_document)?;
        }

        // Handling assertion encryption.
        if need_to_encrypt_assertions {
            let encryption_key_name = self
                .encryption_key_name
                .as_ref()
                .ok_or(Error::MissingEncryptionKeyName)?;
            let assertion_encryption_key = self
                .assertion_encryption_key
                .as_ref()
                .ok_or(Error::MissingEncryptionKey)?;
            let key: Vec<u8> = assertion_encryption_key.rsa()?.public_key_to_pem()?;
            encrypt_assertions(&xml_document, encryption_key_name.as_str(), &key)?;
        }

        // Signing document envelope.
        if sign_envelope {
            let mut context = XmlSecSignatureContext::new()?;
            let key = XmlSecKey::from_rsa_key_der("server_key", &self.signature_key_der)?;
            context.insert_key(key);
            if !sign_assertions {
                context.update_document_id_hash(&xml_document, "ID")?;
            }
            context.sign_document_only(&xml_document)?;
        }

        Ok(xml_document.to_string())
    }

    fn update_x509_signatures(
        &self,
        saml_response: &mut Response,
        x509_cert_der: &[u8],
    ) -> Result<(), Error> {
        let encoded_cert = crate::crypto::mime_encode_x509_cert(x509_cert_der);
        saml_response
            .signature
            .as_mut()
            .iter_mut()
            .for_each(|sig| update_signature(&encoded_cert, sig));
        saml_response.encrypted_assertions.iter_mut().for_each(|x| {
            x.assertion
                .signature
                .as_mut()
                .iter_mut()
                .for_each(|sig| update_signature(&encoded_cert, sig));
        });
        saml_response.assertions.iter_mut().for_each(|x| {
            x.signature
                .as_mut()
                .iter_mut()
                .for_each(|sig| update_signature(&encoded_cert, sig));
        });
        Ok(())
    }
}

fn build_algo_to_key_map() -> std::collections::HashMap<String, usize> {
    let mut ret = std::collections::HashMap::<String, usize>::new();
    ret.insert(
        "http://www.w3.org/2001/04/xmlenc#tripledes-cbc".to_string(),
        168 / 8,
    ); // 168 bits
    ret.insert(
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc".to_string(),
        128 / 8,
    );
    ret.insert(
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc".to_string(),
        256 / 8,
    );
    ret.insert(
        "http://www.w3.org/2009/xmlenc11#aes128-gcm".to_string(),
        128 / 8,
    );
    ret.insert(
        "http://www.w3.org/2001/04/xmlenc#aes192-cbc".to_string(),
        192 / 8,
    );
    ret.insert(
        "http://www.w3.org/2009/xmlenc11#aes192-gcm".to_string(),
        192 / 8,
    );
    ret.insert(
        "http://www.w3.org/2009/xmlenc11#aes256-gcm".to_string(),
        256 / 8,
    );
    ret
}

lazy_static! {
    static ref ALGO_TO_KEY_LEN_IN_BYTES: std::collections::HashMap<String, usize> =
        build_algo_to_key_map();
}

/// Update the document with encrypted assertions.
fn encrypt_assertions(
    document: &XmlDocument,
    key_name: &str,
    public_encryption_key_pem: &[u8],
) -> Result<(), Error> {
    let key_manager = XmlSecKeyManager::new()?;
    let sec_key = XmlSecKey::from_rsa_key_pem(key_name, public_encryption_key_pem)?;
    key_manager.adopt_key(sec_key)?;
    let encryption_context: XmlSecEncryptionContext =
        XmlSecEncryptionContext::with_key_manager(&key_manager)?;

    let xpath_context =
        libxml::xpath::Context::new(document).map_err(|_| XmlSecError::XPathContextError)?;
    xpath_context
        .register_namespace("xenc", "http://www.w3.org/2001/04/xmlenc#")
        .map_err(|_| XmlSecError::XPathNamespaceError)?;
    xpath_context
        .register_namespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion")
        .map_err(|_| XmlSecError::XPathNamespaceError)?;

    let list_of_encryption_transformations = xpath_context
        .evaluate("//saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm")
        .map_err(|_| XmlSecError::XPathEvaluationError)?;
    let algorithms = list_of_encryption_transformations.get_nodes_as_str();
    if algorithms.is_empty() {
        return Err(Error::MissingEncryptionAlgo);
    }
    let key_length_in_bytes = if algorithms.len() == 1 {
        if let Some(bytes) = ALGO_TO_KEY_LEN_IN_BYTES.get(&algorithms[0]) {
            *bytes
        } else {
            return Err(Error::UnknownAlgorithm(algorithms[0].clone()));
        }
    } else {
        // NOTE: This isn't really a valid restriction because people don't use
        // multiple assertions, and they don't normally use encrypted assertions
        // for that matter, so if this every becomes an issue we can modify the
        // xmlEnc bindings in order to change key and length between
        // encryptions.
        let expected_bytes = if let Some(bytes) = ALGO_TO_KEY_LEN_IN_BYTES.get(&algorithms[0]) {
            bytes
        } else {
            return Err(Error::UnknownAlgorithm(algorithms[0].clone()));
        };
        for algo in algorithms.iter() {
            if let Some(bytes) = ALGO_TO_KEY_LEN_IN_BYTES.get(algo) {
                if bytes != expected_bytes {
                    return Err(Error::AlgorithmKeySizesDontMatch);
                }
            } else {
                return Err(Error::UnknownAlgorithm(algorithms[0].clone()));
            };
        }
        *expected_bytes
    };

    // Need to locate all of the `<xenc:EncryptedAssertion>` and figure out what
    // size key we need to use based on that and generate one of those instead?
    let mut aes_key = vec![0; key_length_in_bytes];
    rand_bytes(&mut aes_key)?;

    // Saving the encryption key that we are going to use.
    encryption_context.set_key("encryption_key".to_string(), &aes_key)?;
    encryption_context.encrypt_all_encrypted_assertions(document)?;

    Ok(())
}

fn update_signature(encoded_certificate: &str, sig: &mut Signature) {
    let key_info = if let Some(key_info) = sig.key_info.as_mut() {
        key_info
    } else {
        sig.key_info = Some(Vec::<KeyInfo>::new());
        // NOTE: Safe unwrap because I just set it on the line above.
        sig.key_info.as_mut().unwrap()
    };
    if key_info.is_empty() {
        return;
    }
    key_info.iter_mut().for_each(|ki| {
        if ki.x509_data.is_none() {
            ki.x509_data = Some(X509Data {
                certificates: vec![encoded_certificate.to_string()],
            })
        }
    });
}

// TODO: Consider refactoring this into a member functions of response.
fn check_sign_assertions(saml_response: &Response) -> bool {
    saml_response
        .assertions
        .iter()
        .any(|assertion| assertion.signature.is_some())
        || saml_response
            .encrypted_assertions
            .iter()
            .any(|enc_assertion| enc_assertion.assertion.signature.is_some())
}

fn check_encrypt_assertions(saml_response: &Response) -> bool {
    !saml_response.encrypted_assertions.is_empty()
}

fn check_sign_envelope(saml_response: &Response) -> bool {
    saml_response.signature.is_some()
}
