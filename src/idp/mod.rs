pub mod error;
use self::error::Error;

pub mod response_builder;
pub mod sp_extractor;
pub mod verified_request;

#[cfg(test)]
mod tests;

use crate::crypto::{self, sign_no_decl, sign_xml};
use openssl::bn::{BigNum, MsbOption};
use openssl::encrypt::Encrypter;
use openssl::nid::Nid;
use openssl::pkey::{Private, Public};
use openssl::{asn1::Asn1Time, pkey, rsa::Rsa, x509};
use std::str::FromStr;

use crate::idp::response_builder::{build_response_template, ResponseAttribute};
use crate::schema::{Assertion, EncryptedAssertion, Response};
use crate::signature::Signature;
use crate::traits::ToXml;

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
        sign_assertions: bool,
        encrypt_assertions: bool,
        sign_envelope: bool,
        saml_response: Response,
    ) -> Result<String, Error> {
        // Getting the certificate if one is asked for.
        let cert = if let Some(params) = signature_params {
            Some(self.create_certificate(params)?)
        } else {
            None
        };
        let signature_key = self.private_key.private_key_to_der()?;
        ResponseGenerator::new(
            self.encryption_key_name.clone(),
            self.assertion_encryption_key.clone(),
            sign_assertions,
            encrypt_assertions,
            sign_envelope,
            cert,
            signature_key,
        )
        .generate_response(saml_response)
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
    sign_assertions: bool,
    encrypt_assertions: bool,
    sign_envelope: bool,
    signing_certificate: Option<Vec<u8>>,
    signature_key: Vec<u8>,
}

impl ResponseGenerator {
    pub fn new(
        encryption_key_name: Option<String>,
        assertion_encryption_key: Option<pkey::PKey<Public>>,
        sign_assertions: bool,
        encrypt_assertions: bool,
        sign_envelope: bool,
        signing_certificate: Option<Vec<u8>>,
        signature_key: Vec<u8>,
    ) -> Self {
        Self {
            encryption_key_name,
            assertion_encryption_key,
            sign_assertions,
            encrypt_assertions,
            sign_envelope,
            signing_certificate,
            signature_key,
        }
    }

    pub fn generate_response(&self, mut saml_response: Response) -> Result<String, Error> {
        // Step one: sign assertions.
        if self.sign_assertions {
            if let Some(cert) = self.signing_certificate.as_ref() {
                if let Some(assertions) = saml_response.assertions.as_mut() {
                    for assertion in assertions.iter_mut() {
                        assertion.signature = Some(Signature::template(&assertion.id, cert));
                    }
                } else {
                    todo!("Create an error for missing assertions")
                }
            } else {
                todo!("Need to create an error for asking for an assertion signature without having a cert")
            }
        }

        // Step two: encrypt assertions
        if self.encrypt_assertions {
            if let Some(encryption_key) = self.assertion_encryption_key.as_ref() {
                let encrypted_assertions = if let Some(assertions) = saml_response.assertions.take()
                {
                    println!("Handling assertion encryption.");
                    assertions
                        .into_iter()
                        .map(|assertion| {
                            // TODO: Update the unwrap in order to enforce this as a precondition.
                            self.generate_encrypted_assertions(
                                self.encryption_key_name
                                    .as_ref()
                                    .map(|x| x.as_str())
                                    .unwrap(),
                                encryption_key,
                                assertion,
                            )
                        })
                        .collect::<Result<Vec<_>, Error>>()?
                } else {
                    todo!("Create an error for missing assertions")
                };
                saml_response.encrypted_assertions = Some(encrypted_assertions);
            } else {
                todo!("Make an error when asking for encrypted assertions without encryption key")
            }
        }

        // Step three: update the new response with assertion changes if there
        // are any.

        // Generate signature template for envelope?

        // Step four: sign the envelope.
        if self.sign_envelope {
            todo!("implement envelope signing")
        }
        // Step five: convert final Response XML into a Base64 encoded string
        // and return that result.

        todo!("generate response isn't implemented yet")
    }

    fn generate_encrypted_assertions(
        &self,
        encryption_key_name: &str,
        encryption_key: &pkey::PKey<Public>,
        assertion: Assertion,
    ) -> Result<EncryptedAssertion, Error> {
        // Step one: Check if we need to sign the assertion because that happens
        // first.
        let need_to_sign_assertions = assertion.signature.is_some();

        // Step one: Generate XML with template in in order to sign the
        // assertion.
        let body = assertion.to_xml().map_err(Error::XmlGenerationError)?;
        println!("What do we look like? {body}");
        let body = if need_to_sign_assertions {
            let ret = sign_no_decl(body.as_bytes(), &self.signature_key)?;
            ret
        } else {
            body
        };
        println!("What do we look like? {body}");
        // How to encrypt an AES key.
        let mut encrypter = Encrypter::new(&encryption_key)?;
        encrypter.set_rsa_padding(openssl::rsa::Padding::PKCS1_OAEP)?;
        let buffer_len = encrypter.encrypt_len(body.as_bytes())?;
        let mut encrypted = vec![0; buffer_len];
        let encrypted_len = encrypter.encrypt(body.as_bytes(), &mut encrypted)?;
        encrypted.truncate(encrypted_len);
        let encrypted_data = String::from_utf8(encrypted).unwrap();
        println!("Encrypted data: {encrypted_data}");
        // let mut out_buffer = String::with_capacity(encryption_key.rsa()?.size() as usize);
        // for _ in 0..encryption_key.rsa()?.size() {
        //     out_buffer.push('\0');
        // }
        // println!("KeySize = {}", encryption_key.rsa()?.size());
        // let encrypted_stuff_size = unsafe {
        //     // let aes_key = openssl::aes::AesKey::new_encrypt(encryption_key.rsa()?.public_key_to_der()?)?
        //     encryption_key.rsa()?.public_encrypt(
        //         body.as_bytes(),
        //         out_buffer.as_bytes_mut(),
        //         ,
        //     )?
        // };
        // out_buffer.shrink_to(encrypted_stuff_size);

        // let encrypted_body = encryption_key.
        // println!("Encrypted data = {}", out_buffer);

        todo!()
    }
}
