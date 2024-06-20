use super::*;
use crate::crypto::verify_signed_xml;
use crate::idp::sp_extractor::{RequiredAttribute, SPMetadataExtractor};
use crate::idp::verified_request::UnverifiedAuthnRequest;
use crate::schema::{
    Assertion, AudienceRestriction, AuthnContext, AuthnContextClassRef, AuthnStatement, Conditions,
    EncryptedAssertionBuilder, EncryptedCipherData, EncryptedCipherValue, EncryptedData,
    EncryptedKey, EncryptionKeyInfo, EncryptionMethod, Issuer, ResponseBuilder, StatusBuilder,
    StatusCode, Subject, SubjectConfirmation, SubjectConfirmationData, SubjectNameID,
};
use crate::service_provider::ServiceProvider;
use chrono::prelude::*;

#[test]
fn test_self_signed_authn_request() {
    let authn_request_xml = include_str!("../../test_vectors/authn_request.xml");
    let unverified = UnverifiedAuthnRequest::from_xml(authn_request_xml).expect("failed to parse");
    let _ = unverified
        .try_verify_self_signed()
        .expect("failed to verify self signed signature");
}

#[test]
fn test_extract_sp() {
    let sp_metadata = include_str!("../../test_vectors/sp_metadata.xml");
    let extractor = SPMetadataExtractor::try_from_xml(sp_metadata).expect("invalid entity");
    let x509cert = extractor
        .verification_cert()
        .expect("failed to get x509 cert");

    let authn_request_xml = include_str!("../../test_vectors/authn_request.xml");
    verify_signed_xml(authn_request_xml, x509cert.as_slice(), Some("ID"))
        .expect("failed to verify authn request");

    let issuer = extractor.issuer().expect("no issuer");
    let acs = extractor.acs().expect("invalid acs");

    assert_eq!(&issuer, "https://sp.example.com");
    assert_eq!(&acs.url, "https://sp.example.com/acs");
}

#[test]
fn test_signed_response() {
    // init our IdP
    let idp = IdentityProvider::from_private_key_der(include_bytes!(
        "../../test_vectors/idp_private_key.der"
    ))
    .expect("failed to create idp");

    let params = CertificateParams {
        common_name: "https://idp.example.com",
        issuer_name: "https://idp.example.com",
        days_until_expiration: 3650,
    };

    let idp_cert = idp.create_certificate(&params).expect("idp cert error");

    // init an AuthnRequest
    let authn_request_xml = include_str!("../../test_vectors/authn_request.xml");
    let unverified = UnverifiedAuthnRequest::from_xml(authn_request_xml).expect("failed to parse");
    let verified = unverified
        .try_verify_self_signed()
        .expect("failed to verify self signed signature");

    // create some attributes:
    let attrs = vec![
        (
            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "firstName",
            "",
        ),
        (
            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "lastName",
            "",
        ),
        (
            "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
            "firstName",
            "",
        ),
    ];

    let attrs = attrs
        .into_iter()
        .map(|attr| ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: attr.1.to_string(),
                format: Some(attr.0.to_string()),
            },
            value: attr.2,
        })
        .collect::<Vec<ResponseAttribute>>();

    // create and sign a response
    let out_response = idp
        .create_template_response(
            idp_cert.as_slice(),
            "testuser@example.com",
            "https://sp.example.com/audience",
            "https://sp.example.com/acs",
            "https://idp.example.com",
            verified.id.as_str(),
            &attrs,
        )
        .expect("failed to created and sign response");

    let out_xml = out_response
        .to_xml()
        .expect("failed to serialize response xml");

    verify_signed_xml(out_xml.as_bytes(), idp_cert.as_slice(), Some("ID"))
        .expect("verification failed");
}

#[test]
fn test_signed_response_threads() {
    let verify = move || {
        let authn_request_xml = include_str!("../../test_vectors/authn_request.xml");
        let cert_der = include_bytes!("../../test_vectors/sp_cert.der");
        let unverified =
            UnverifiedAuthnRequest::from_xml(authn_request_xml).expect("failed to parse");
        let _ = unverified
            .try_verify_self_signed()
            .expect("failed to verify self signed signature");
        verify_signed_xml(authn_request_xml, cert_der, Some("ID")).expect("failed verify");
    };

    let mut handles = vec![];
    for _ in 0..4 {
        handles.push(std::thread::spawn(test_self_signed_authn_request));
        handles.push(std::thread::spawn(test_extract_sp));
        handles.push(std::thread::spawn(verify));
    }

    handles
        .into_iter()
        .for_each(|h| h.join().expect("failed thread"));
}

#[test]
fn test_signed_response_fingerprint() {
    let idp = IdentityProvider::from_private_key_der(include_bytes!(
        "../../test_vectors/idp_private_key.der"
    ))
    .expect("failed to create idp");

    let params = CertificateParams {
        common_name: "https://idp.example.com",
        issuer_name: "https://idp.example.com",
        days_until_expiration: 3650,
    };

    let idp_cert = idp.create_certificate(&params).expect("idp cert error");
    let response = idp
        .create_template_response(
            idp_cert.as_slice(),
            "testuser@example.com",
            "https://sp.example.com/audience",
            "https://sp.example.com/acs",
            "https://idp.example.com",
            "",
            &[],
        )
        .expect("failed to created and sign response");
    let base64_cert = response
        .signature
        .unwrap()
        .key_info
        .unwrap()
        .first()
        .unwrap()
        .x509_data
        .clone()
        .unwrap()
        .certificates
        .first()
        .cloned()
        .unwrap();
    let der_cert = crate::crypto::decode_x509_cert(&base64_cert).expect("failed to decode cert ");
    assert_eq!(der_cert, idp_cert);
}

#[test]
fn test_do_not_accept_unsigned_response() {
    // If an IdP is configured with signing certs, do not accept unsigned
    // responses.
    let idp_metadata_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_metadata.xml"
    ));

    let sp = ServiceProvider {
        idp_metadata: idp_metadata_xml.parse().unwrap(),
        ..Default::default()
    };

    // Assert that this descriptor has a signing cert
    assert_eq!(
        sp.idp_metadata.idp_sso_descriptors.as_ref().unwrap()[0].key_descriptors[0]
            .key_use
            .as_ref()
            .unwrap(),
        "signing"
    );
    assert!(
        !sp.idp_metadata.idp_sso_descriptors.as_ref().unwrap()[0].key_descriptors[0]
            .key_info
            .x509_data
            .as_ref()
            .unwrap()
            .certificates
            .first()
            .unwrap()
            .is_empty()
    );

    let unsigned_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response.xml",
    ));

    let resp = sp.parse_xml_response(unsigned_response_xml, None);
    assert!(resp.is_err());

    let err = resp.err().unwrap();
    assert_eq!(
        err,
        crate::service_provider::Error::FailedToParseSamlResponse
    );
}

#[test]
fn test_do_not_accept_signed_with_wrong_key() {
    let idp_metadata_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_metadata.xml"
    ));

    let sp = ServiceProvider {
        idp_metadata: idp_metadata_xml.parse().unwrap(),
        ..Default::default()
    };

    let wrong_cert_signed_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed_by_idp_2.xml",
    ));

    let resp = sp.parse_xml_response(wrong_cert_signed_response_xml, None);
    assert!(resp.is_err());

    let err = resp.err().unwrap();

    assert_eq!(
        err,
        crate::service_provider::Error::FailedToValidateSignature
    );
}

#[test]
#[ignore]
fn test_accept_signed_with_correct_key_idp() {
    let idp_metadata_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_metadata.xml"
    ));

    let response_instant = "2014-07-17T01:01:48Z".parse::<DateTime<Utc>>().unwrap();
    let max_issue_delay =
        Utc::now() - response_instant + chrono::Duration::try_seconds(60).unwrap();

    let sp = ServiceProvider {
        metadata_url: Some("http://test_accept_signed_with_correct_key.test".into()),
        acs_url: Some("http://sp.example.com/demo1/index.php?acs".into()),
        idp_metadata: idp_metadata_xml.parse().unwrap(),
        max_issue_delay,
        ..Default::default()
    };

    let wrong_cert_signed_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed.xml",
    ));

    let resp = sp.parse_xml_response(
        wrong_cert_signed_response_xml,
        Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
    );

    assert!(resp.is_ok());
}

#[test]
fn test_accept_signed_with_correct_key_idp_2() {
    let idp_metadata_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/idp_2_metadata.xml"
    ));

    let response_instant = "2014-07-17T01:01:48Z".parse::<DateTime<Utc>>().unwrap();
    let max_issue_delay =
        Utc::now() - response_instant + chrono::Duration::try_seconds(60).unwrap();

    let sp = ServiceProvider {
        metadata_url: Some("http://test_accept_signed_with_correct_key.test".into()),
        acs_url: Some("http://sp.example.com/demo1/index.php?acs".into()),
        idp_metadata: idp_metadata_xml.parse().unwrap(),
        max_issue_delay,
        ..Default::default()
    };

    let wrong_cert_signed_response_xml = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test_vectors/response_signed_by_idp_2.xml",
    ));

    let resp = sp.parse_xml_response(
        wrong_cert_signed_response_xml,
        Some(&["ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"]),
    );

    assert!(resp.is_ok());
}

#[test]
fn test_signed_assertions() {
    let signature_keys = openssl::rsa::Rsa::generate(4096).unwrap();
    let encryption_keys = openssl::rsa::Rsa::generate(4096).unwrap();
    let public_key = encryption_keys.public_key_to_pem().unwrap();
    let public_encryption_key = openssl::rsa::Rsa::public_key_from_pem(&public_key).unwrap();
    let public_idp_signature_key = signature_keys.public_key_to_der().unwrap();

    let idp = IdentityProvider::new(
        Some("test_key_name".into()),
        Some(pkey::PKey::from_rsa(public_encryption_key).unwrap()),
        pkey::PKey::from_rsa(signature_keys).unwrap(),
    );

    let params = CertificateParams {
        common_name: "https://idp.example.com",
        issuer_name: "https://idp.example.com",
        days_until_expiration: 3650,
    };
    let assertion_id = crypto::gen_saml_assertion_id();
    // let idp_cert = idp.create_certificate(&params).expect("idp cert error");
    let issuer = Issuer {
        value: Some("http://its-a-me.com".to_string()),
        ..Default::default()
    };

    let response = ResponseBuilder::default()
        .id("123456789")
        .version("2.0")
        .issue_instant(Utc::now())
        .destination(Some("https://sp.example.com/acs".into()))
        .issuer(issuer.clone())
        .consent(None)
        .in_response_to("".to_string())
        .signature(None)
        .status(
            StatusBuilder::default()
                .status_code(StatusCode {
                    value: Some("urn:oasis:names:tc:SAML:2.0:status:Success".to_string()),
                })
                .status_message(None)
                .build()
                .unwrap(),
        )
        .encrypted_assertions(None)
        .assertions(vec![Assertion {
            id: assertion_id.clone(),
            issue_instant: Utc::now(),
            version: "2.0".to_string(),
            issuer: issuer.clone(),
            signature: Some(Signature::xmlsec_signature_template(
                None,
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "http://www.w3.org/2000/09/xmldsig#sha1",
            )),
            subject: Some(Subject {
                name_id: Some(SubjectNameID {
                    format: Some(
                        "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified".to_string(),
                    ),
                    value: "testuser@example.com".to_owned(),
                }),
                subject_confirmations: Some(vec![SubjectConfirmation {
                    method: Some("urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string()),
                    name_id: None,
                    subject_confirmation_data: Some(SubjectConfirmationData {
                        not_before: None,
                        not_on_or_after: None,
                        recipient: Some("https://sp.example.com/acs".to_owned()),
                        in_response_to: Some("123456789".to_owned()),
                        address: None,
                        content: None,
                    }),
                }]),
            }),
            conditions: Some(Conditions {
                not_before: None,
                not_on_or_after: None,
                audience_restrictions: Some(vec![AudienceRestriction {
                    audience: vec!["https://sp.example.com/audience".to_string()],
                }]),
                one_time_use: None,
                proxy_restriction: None,
            }),
            authn_statements: Some(vec![AuthnStatement {
                authn_instant: Some(Utc::now()),
                session_index: None,
                session_not_on_or_after: None,
                subject_locality: None,
                authn_context: Some(AuthnContext {
                    value: Some(AuthnContextClassRef {
                        value: Some(
                            "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".to_string(),
                        ),
                    }),
                }),
            }]),
            attribute_statements: None,
        }])
        .build()
        .unwrap();
    println!("Response XML:{} ", response.to_xml().unwrap());

    let xml_response = idp
        .generate_response(Some(&params), response)
        .expect("Code generation failed");
    println!("xml_response = {}", xml_response);

    let decoded_response: Response = xml_response.parse().expect("Failed to parse document");
    println!("Decoded Document: {decoded_response:?}");

    //Checking that we have have the assertion we were expecting.
    assert_eq!(decoded_response.assertions.as_ref().unwrap().len(), 1);

    // Attempting to get the signature from the assertion.
    let assertion = &decoded_response.assertions.as_ref().unwrap()[0];
    let signature = assertion
        .signature
        .as_ref()
        .expect("Failed to get signature");
    let key_info = signature.key_info.as_ref().expect("Missing key info");
    assert_eq!(key_info.len(), 1);
    let sig_content = signature
        .signature_value
        .base64_content
        .as_ref()
        .expect("Failed to get signature contents");
    assert_ne!(sig_content, "");
    println!("Signature value: {}", sig_content);
    assert_eq!(signature.signed_info.reference.len(), 1);
    let reference = &signature.signed_info.reference[0];
    let digest_value = reference
        .digest_value
        .as_ref()
        .expect("Failed to get digest value");
    let digest_contents = digest_value
        .base64_content
        .as_ref()
        .expect("Failed to get digest value contents");
    assert_ne!(digest_contents, "");

    let parser = libxml::parser::Parser::default();
    let document = parser
        .parse_string(xml_response)
        .expect("Failed to parse response");

    // Constructing a verifier, I hope this works.
    let mut verifier =
        XmlSecSignatureContext::new().expect("Failed to create xml XmlSecSignatureContext");
    let key = XmlSecKey::from_rsa_key_der("server_key", &public_idp_signature_key)
        .expect("Failed to create public key");
    verifier.insert_key(key);
    let verified_signature_nodes = verifier
        .verify_all_signatures(&document)
        .expect("Verification failed?");
    assert_eq!(verified_signature_nodes, 1);
}

#[test]
fn test_encrypted_assertions() {
    let signature_keys = openssl::rsa::Rsa::generate(4096).unwrap();
    let encryption_keys = openssl::rsa::Rsa::generate(4096).unwrap();
    let public_key = encryption_keys.public_key_to_pem().unwrap();
    let public_encryption_key = openssl::rsa::Rsa::public_key_from_pem(&public_key).unwrap();

    // Setting up a decryption context
    let dec_key_manager = XmlSecKeyManager::new().expect("Failed to create key manager");
    let private_key_pem = encryption_keys.private_key_to_pem().unwrap();
    let dec_sec_key = XmlSecKey::from_rsa_key_pem("test_name", &private_key_pem).unwrap();
    dec_key_manager.adopt_key(dec_sec_key).unwrap();

    let idp = IdentityProvider::new(
        Some("test_key_name".into()),
        Some(pkey::PKey::from_rsa(public_encryption_key).unwrap()),
        pkey::PKey::from_rsa(signature_keys).unwrap(),
    );

    let params = CertificateParams {
        common_name: "https://idp.example.com",
        issuer_name: "https://idp.example.com",
        days_until_expiration: 3650,
    };
    let assertion_id = crypto::gen_saml_assertion_id();
    // let idp_cert = idp.create_certificate(&params).expect("idp cert error");
    let issuer = Issuer {
        value: Some("http://its-a-me.com".to_string()),
        ..Default::default()
    };

    let response = ResponseBuilder::default()
        .id("123456789")
        .version("2.0")
        .issue_instant(Utc::now())
        .destination(Some("https://sp.example.com/acs".into()))
        .issuer(issuer.clone())
        .consent(None)
        .in_response_to("".to_string())
        .signature(None)
        .status(
            StatusBuilder::default()
                .status_code(StatusCode {
                    value: Some("urn:oasis:names:tc:SAML:2.0:status:Success".to_string()),
                })
                .status_message(None)
                .build()
                .unwrap(),
        )
        .encrypted_assertions(vec![EncryptedAssertionBuilder::default()
            .data(EncryptedData {
                method: EncryptionMethod {
                    algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc".to_string(),
                },
                encryption_cipher_data: EncryptedCipherData {
                    value: EncryptedCipherValue { value: None },
                },
                signature_key_info: vec![EncryptionKeyInfo {
                    encrypted_key: EncryptedKey {
                        method: EncryptionMethod {
                            algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-1_5".to_string(),
                        },
                        encryption_cipher_data: EncryptedCipherData {
                            value: EncryptedCipherValue { value: None },
                        },
                        key_info: None,
                    },
                }],
            })
            .assertion(Assertion {
                id: assertion_id.clone(),
                issue_instant: Utc::now(),
                version: "2.0".to_string(),
                issuer: issuer.clone(),
                signature: None,
                subject: Some(Subject {
                    name_id: Some(SubjectNameID {
                        format: Some(
                            "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified".to_string(),
                        ),
                        value: "testuser@example.com".to_owned(),
                    }),
                    subject_confirmations: Some(vec![SubjectConfirmation {
                        method: Some("urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string()),
                        name_id: None,
                        subject_confirmation_data: Some(SubjectConfirmationData {
                            not_before: None,
                            not_on_or_after: None,
                            recipient: Some("https://sp.example.com/acs".to_owned()),
                            in_response_to: Some("123456789".to_owned()),
                            address: None,
                            content: None,
                        }),
                    }]),
                }),
                conditions: Some(Conditions {
                    not_before: None,
                    not_on_or_after: None,
                    audience_restrictions: Some(vec![AudienceRestriction {
                        audience: vec!["https://sp.example.com/audience".to_string()],
                    }]),
                    one_time_use: None,
                    proxy_restriction: None,
                }),
                authn_statements: Some(vec![AuthnStatement {
                    authn_instant: Some(Utc::now()),
                    session_index: None,
                    session_not_on_or_after: None,
                    subject_locality: None,
                    authn_context: Some(AuthnContext {
                        value: Some(AuthnContextClassRef {
                            value: Some(
                                "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified".to_string(),
                            ),
                        }),
                    }),
                }]),
                attribute_statements: None,
            })
            .build()
            .unwrap()])
        .assertions(None)
        .build()
        .unwrap();
    println!("Response XML:{} ", response.to_xml().unwrap());

    let saml_response = idp
        .generate_response(Some(&params), response)
        .expect("Code generation failed");
    println!("saml_response = {}", saml_response);

    let parser = libxml::parser::Parser::default();
    let document = parser
        .parse_string(&saml_response)
        .expect("Failed to parse response");

    let decryption_context = XmlSecEncryptionContext::with_key_manager(&dec_key_manager).unwrap();
    decryption_context.decrypt_document(&document).unwrap();

    let decoded_response: Response = document
        .to_string()
        .parse()
        .expect("Failed to parse document");
    println!("Decoded Document: {decoded_response:?}");

    //Checking that we have have the assertion we were expecting.
    assert_eq!(
        decoded_response
            .encrypted_assertions
            .as_ref()
            .unwrap()
            .len(),
        1
    );

    // Attempting to get the signature from the assertion.
    // let enc_assertion = &decoded_response.encrypted_assertions.as_ref().unwrap()[0];
}
