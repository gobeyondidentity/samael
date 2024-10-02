use std::io::Read;

use super::Error;
use crate::{
    schema::{ws_fed::RequestSecurityTokenResponse, Response},
    xmlsec::{
        xml_sec_app_add_id_attr, XmlSecEncryptionContext, XmlSecError, XmlSecKey, XmlSecKeyManager,
        XmlSecSignatureContext,
    },
};
use flate2::read::DeflateDecoder;
use libxml::parser::Parser;
use openssl::pkey::{PKey, Private, Public};

#[derive(Clone, Builder)]
pub struct ResponseVerifier {
    #[builder(default)]
    pub idp_public_signature_key_name: Option<String>,
    #[builder(default)]
    pub idp_public_signature_key: Option<PKey<Public>>,
    #[builder(default)]
    pub sp_private_encryption_key_name: Option<String>,
    #[builder(default)]
    pub sp_private_encryption_key: Option<PKey<Private>>,

    #[builder(default)]
    pub enforce_at_least_one_signature: bool,
}

impl ResponseVerifier {
    /// Parses and verifies an HTML form. Returns both the response and
    /// optionally the relay state if present.
    pub fn verify_from_html_form(
        &self,
        html_form: &str,
    ) -> Result<(Response, Option<String>), Error> {
        let html_parser = Parser::default_html();
        let html_document = html_parser.parse_string(html_form)?;
        let xpath_context = libxml::xpath::Context::new(&html_document)
            .map_err(|_| XmlSecError::XPathContextError)?;
        // input type="hidden" name="SAMLResponse" value="
        let xpath_object = xpath_context
            .evaluate("//input[@type='hidden' and @name='SAMLResponse']/@value")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;
        let nodes = xpath_object.get_nodes_as_str();
        if nodes.is_empty() {
            return Err(Error::HtmlFormMissingSamlResponse);
        }
        if nodes.len() > 1 {
            return Err(Error::TooManySamlResponses);
        }
        let verified_response = self.verify_from_base64(nodes[0].as_str())?;
        let xpath_object = xpath_context
            .evaluate("//input[@type='hidden' and @name='RelayState']/@value")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;
        let nodes = xpath_object.get_nodes_as_str();
        if nodes.len() > 1 {
            return Err(Error::TooManySamlResponses);
        }
        Ok((verified_response, nodes.first().cloned()))
    }

    /// Parses and verifies an the redirect URI. Returns both the response and
    /// optionally the relay state if present.
    pub fn verify_from_url(&self, url: &url::Url) -> Result<(Response, Option<String>), Error> {
        let mut saml_response: Option<String> = None;
        let mut relay_state: Option<String> = None;
        for (name, value) in url.query_pairs().into_iter() {
            if name == "SAMLResponse" {
                if saml_response.is_some() {
                    return Err(Error::DuplicateSamlResponseInUrl);
                }
                saml_response = Some(value.to_string());
            }
            if name == "RelayState" {
                if relay_state.is_some() {
                    return Err(Error::DuplicateRelayStateInUrl);
                }
                relay_state = Some(value.to_string());
            }
        }

        let verified_response = if let Some(base64_encoded_response) = saml_response {
            let deflated_xml_document = openssl::base64::decode_block(&base64_encoded_response)?;
            let mut deflater = DeflateDecoder::new(deflated_xml_document.as_slice());
            let mut deflated_xml_vec = Vec::new();
            deflater.read_to_end(&mut deflated_xml_vec)?;
            let doc_str = String::from_utf8(deflated_xml_vec)?;
            self.verify_saml_response(&doc_str)?
        } else {
            return Err(Error::MissingSamlResponseInUrl);
        };
        Ok((verified_response, relay_state))
    }

    /// Verify a document starting from a base64 encoded Response object.
    pub fn verify_from_base64(&self, base64_encoded_xml: &str) -> Result<Response, Error> {
        let xml_document_str = openssl::base64::decode_block(base64_encoded_xml)?;
        let doc_str = String::from_utf8(xml_document_str)?;
        self.verify_saml_response(&doc_str)
    }

    /// Verifies an XML document string.
    pub fn verify_saml_response(&self, xml_doc_str: &str) -> Result<Response, Error> {
        let parser = Parser::default();
        let saml_response_document = parser.parse_string(xml_doc_str)?;

        // Verifying document only.
        let xpath_context = libxml::xpath::Context::new(&saml_response_document)
            .map_err(|_| XmlSecError::XPathContextError)?;
        xpath_context
            .register_namespace("dsig", "http://www.w3.org/2000/09/xmldsig#")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        xpath_context
            .register_namespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        xpath_context
            .register_namespace("samla", "urn:oasis:names:tc:SAML:2.0:assertion")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;

        if let Some(idp_signature_key) = self.idp_public_signature_key.as_ref() {
            let document_signature_node = xpath_context
                .evaluate("//samlp:Response/dsig:Signature")
                .map_err(|_| XmlSecError::XPathEvaluationError)?;
            unsafe {
                let node_name = std::ffi::CString::new("Response")?;
                let attr_name = std::ffi::CString::new("ID")?;
                let ns_href = std::ffi::CString::new("urn:oasis:names:tc:SAML:2.0:protocol")?;
                xml_sec_app_add_id_attr(
                    saml_response_document
                        .get_root_element()
                        .unwrap()
                        .node_ptr() as crate::bindings::xmlNodePtr,
                    &attr_name,
                    &node_name,
                    ns_href.as_ptr() as *const crate::bindings::xmlChar,
                )?;
            }
            let document_signature_node = document_signature_node.get_nodes_as_vec();
            if document_signature_node.len() > 1 {
                return Err(Error::TooManyDocumentSignatures);
            }
            for signature_node in document_signature_node.into_iter() {
                let mut verifier = XmlSecSignatureContext::new()?;

                let signature_key = idp_signature_key.rsa()?.public_key_to_pem()?;
                let key = XmlSecKey::from_rsa_key_pem("server_key", &signature_key)?;
                verifier.insert_key(key);

                if !verifier.verify_node(&signature_node)? {
                    return Err(Error::InvalidDocumentSignature);
                }
            }
        }

        // Step one: is to decrypt any encrypted assertions within the document.
        if let Some(decryption_key) = self.sp_private_encryption_key.as_ref() {
            let dec_key_manager = XmlSecKeyManager::new()?;
            let rsa_private_key = decryption_key.rsa()?.private_key_to_pem()?;
            let decryption_key = XmlSecKey::from_rsa_key_pem(
                self.sp_private_encryption_key_name
                    .as_ref()
                    .map(|x| x.as_str())
                    .unwrap_or("test_name"),
                &rsa_private_key,
            )?;
            dec_key_manager.adopt_key(decryption_key)?;
            // Constructing the decryption context and decrypting any
            // EncryptedAssertions for additional processing.
            let decryption_context = XmlSecEncryptionContext::with_key_manager(&dec_key_manager)?;
            decryption_context.decrypt_document(&saml_response_document)?;
        }

        // Step three: Validating all assertion signatures
        if let Some(idp_signature_key) = self.idp_public_signature_key.as_ref() {
            unsafe {
                let node_name = std::ffi::CString::new("Assertion")?;
                let attr_name = std::ffi::CString::new("ID")?;
                let ns_href = std::ffi::CString::new("urn:oasis:names:tc:SAML:2.0:assertion")?;
                xml_sec_app_add_id_attr(
                    saml_response_document
                        .get_root_element()
                        .unwrap()
                        .node_ptr() as crate::bindings::xmlNodePtr,
                    &attr_name,
                    &node_name,
                    ns_href.as_ptr() as *const crate::bindings::xmlChar,
                )?;
            }
            let assertions_signature_nodes = xpath_context
                .evaluate("//samla:Assertion/dsig:Signature")
                .map_err(|_| XmlSecError::XPathEvaluationError)?;
            let assertions_signature_nodes = assertions_signature_nodes.get_nodes_as_vec();
            for signature_node in assertions_signature_nodes.iter() {
                let mut verifier = XmlSecSignatureContext::new()?;
                let signature_key = idp_signature_key.rsa()?.public_key_to_pem()?;
                let key = XmlSecKey::from_rsa_key_pem("server_key", &signature_key)?;
                verifier.insert_key(key);

                if !verifier.verify_node(&signature_node)? {
                    return Err(Error::InvalidAssertionSignature);
                }
            }
        }
        // Parse the current document using serde, into a SAML response that we
        // can be assured that a document was processed correctly.
        Ok(saml_response_document.to_string().parse()?)
    }

    pub fn verify_from_url_encoded_ws_fed(
        &self,
        url_encoded_xml: &str,
    ) -> Result<RequestSecurityTokenResponse, Error> {
        let xml_document_str = urlencoding::decode(url_encoded_xml)?.to_string();
        self.verify_ws_fed_response(&xml_document_str)
    }

    pub fn verify_ws_fed_response(
        &self,
        xml_doc_str: &str,
    ) -> Result<RequestSecurityTokenResponse, Error> {
        let parser = Parser::default();
        let ws_fed_response_document = parser.parse_string(xml_doc_str)?;

        // Verifying document only.
        let xpath_context = libxml::xpath::Context::new(&ws_fed_response_document)
            .map_err(|_| XmlSecError::XPathContextError)?;
        xpath_context
            .register_namespace("dsig", "http://www.w3.org/2000/09/xmldsig#")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        xpath_context
            .register_namespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;
        xpath_context
            .register_namespace("samla", "urn:oasis:names:tc:SAML:2.0:assertion")
            .map_err(|_| XmlSecError::XPathNamespaceError)?;

        // Validating assertions signatures
        let Some(idp_signature_key) = self.idp_public_signature_key.as_ref() else {
            return Err(Error::MissingIdPPublicSignatureKey);
        };
        unsafe {
            let node_name = std::ffi::CString::new("Assertion")?;
            let attr_name = std::ffi::CString::new("ID")?;
            let ns_href = std::ffi::CString::new("urn:oasis:names:tc:SAML:2.0:assertion")?;
            xml_sec_app_add_id_attr(
                ws_fed_response_document
                    .get_root_element()
                    .unwrap()
                    .node_ptr() as crate::bindings::xmlNodePtr,
                &attr_name,
                &node_name,
                ns_href.as_ptr() as *const crate::bindings::xmlChar,
            )?;
        }
        let assertions_signature_nodes = xpath_context
            .evaluate("//samla:Assertion/dsig:Signature")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;
        let assertions_signature_nodes = assertions_signature_nodes.get_nodes_as_vec();
        for signature_node in assertions_signature_nodes.iter() {
            let mut verifier = XmlSecSignatureContext::new()?;
            let signature_key = idp_signature_key.rsa()?.public_key_to_pem()?;
            let key = XmlSecKey::from_rsa_key_pem("server_key", &signature_key)?;
            verifier.insert_key(key);

            if !verifier.verify_node(&signature_node)? {
                return Err(Error::InvalidAssertionSignature);
            }
        }
        // Parse the current document using serde, into a SAML response that we
        // can be assured that a document was processed correctly.
        Ok(ws_fed_response_document.to_string().parse()?)
    }

    /// Parses and verifies an HTML form. Returns both the response and
    /// optionally the relay state if present.
    pub fn verify_ws_fed_from_form_response(
        &self,
        html_form: &str,
    ) -> Result<(RequestSecurityTokenResponse, Option<String>), Error> {
        let html_parser = Parser::default_html();
        let html_document = html_parser.parse_string(html_form)?;
        let xpath_context = libxml::xpath::Context::new(&html_document)
            .map_err(|_| XmlSecError::XPathContextError)?;
        let xpath_object = xpath_context
            .evaluate("//input[@type='hidden' and @name='wresult']/@value")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;
        let nodes = xpath_object.get_nodes_as_str();
        if nodes.is_empty() {
            return Err(Error::HtmlFormMissingWResult);
        }
        if nodes.len() > 1 {
            return Err(Error::TooManyWResultResponses);
        }

        let verified_response = self.verify_from_url_encoded_ws_fed(nodes[0].as_str())?;
        let xpath_object = xpath_context
            .evaluate("//input[@type='hidden' and @name='ctx']/@value")
            .map_err(|_| XmlSecError::XPathEvaluationError)?;
        let nodes = xpath_object.get_nodes_as_str();
        if nodes.len() > 1 {
            return Err(Error::TooManyCtxResponses);
        }
        Ok((verified_response, nodes.first().cloned()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_verify_from_html_from() {
        // Basic form validation
        // TODO: replace this with something that is not signed and not encrypted.
        let test_form = r#"<html>
    <script>
    function on_load() {
        document.forms['selfsubmit'].submit();
    };
    </script>
    <body onload="on_load()">
        <form name="selfsubmit" action="http:&#x2F;&#x2F;example.com&#x2F;acs" method="POST">
        <input type="hidden" name="SAMLResponse" value="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHNhbWwycDpSZXNwb25zZSB4bWxuczpzYW1sMnA9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDpwcm90b2NvbCIgSUQ9ImlkMTBiMzFmNzAtYzQyMy00NTZiLWI3NDUtOTc0NTBjNDU5YzZjIiBWZXJzaW9uPSIiIElzc3VlSW5zdGFudD0iMTk3MC0wMS0wMVQwMDowMDowMC4wMDBaIiBEZXN0aW5hdGlvbj0iaHR0cDovL2V4YW1wbGUuY29tL2FjcyI+PGRzOlNpZ25hdHVyZSB4bWxuczpkcz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PGRzOlNpZ25lZEluZm8+PGRzOkNhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzEwL3htbC1leGMtYzE0biMiLz48ZHM6U2lnbmF0dXJlTWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxkc2lnLW1vcmUjcnNhLXNoYTI1NiIvPjxkczpSZWZlcmVuY2U+PGRzOlRyYW5zZm9ybXM+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PGRzOlRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMTAveG1sLWV4Yy1jMTRuIyIvPjwvZHM6VHJhbnNmb3Jtcz48ZHM6RGlnZXN0TWV0aG9kIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS8wNC94bWxlbmMjc2hhMjU2Ii8+PGRzOkRpZ2VzdFZhbHVlPlhmSm83UEc5dFlOSjFuYzkwT2R1aUR6enpjOXhZRHgyRGlydHRTczQyMjg9PC9kczpEaWdlc3RWYWx1ZT48L2RzOlJlZmVyZW5jZT48L2RzOlNpZ25lZEluZm8+PGRzOlNpZ25hdHVyZVZhbHVlPlBOdEIzQSt5OTZDNGlHU3VCVjNlZnhpeFZiWjdBVStMMzU2YnpmbWtqNHE1TzQ3T3RScVBodm13bFFYbk1xUnUKUm11SmVCRkREMEc0ZjZHWk5KS0RlSU44YnpoVTN5Q1V0ZjF0N3RHZDJOR1UxQ3RBWDRRL2dsblk3V1lIbUxqdQpjeEhDbUZDYzRaeTFQbnZ6dTYwb2xrYzF0MEdzcnJxTEpIOHU1U1N2eTljdWtram5jZzFDMHUrQzdSYTJiMjVYCkNCbUdsL0NDVkkwcWhtcU1lQkFlb1VjQ2dvcWZUbXZZcHM1NXB1Q3dWajNoOHA5Qy9XVUNwNmJZckxjVlA3VHEKdG9XZnJQakd5MUZGWFZHdTNwc08yNEt1UUVrV3QrSjQzOHRjTmQ3Z2hKNzE1QlV1dnFHME8vM3BCZWFQNEYrTgphYkhkemlxL3VWU0lqVGNDRTg2UDJaSTRQU1JRL3hVQzVFSU1jWlduRFptSG1rWnFNakpRV05TbkZ3Z2FDdUZICjRiQ1FQTnZjaUV6cEQ1Y0Q5UVR1SExPWmxzMVBPUXdQaEwvbUVVWXhUSmVMa2cwUTg2R3JVZExEZTB0N3E0Z2wKUkVRZ3JxaWFRdzE4c0I2TEFWQ053c2p2WEo3dW4rRExxd3UrdXdkWHI5QVQxekxpMTdsbkRKaC9oNlVYVTJHOQpuNTJmRjU1QVQrcVc1b1VzalNxeFZiTFFqeHQxSWdxcy9SSFFvNEFIUE5EU2ExWFExbjV1M2RuNnlYY1BOSzdaCkszdGFUVDFEY0ZVRjZtR1p6NDB1Ym0wajErL0dEM2dUdzdwN1duNmxNL2JKaTMyU21mZEc0Ujh1RmM5NU9sdWYKbW1XdEJ3OVlxRjJxMnVlVis2RHZ4aTNVM2FoYW53cEJEaktoMHRMSFF3ND08L2RzOlNpZ25hdHVyZVZhbHVlPjxkczpLZXlJbmZvPjxkczpYNTA5RGF0YT48ZHM6WDUwOUNlcnRpZmljYXRlPk1JSUUwRENDQXJpZ0F3SUJBZ0lVUUJ2OVJkZDRmVGVGOWNOOUdEMkRmeDVVNFZrd0RRWUpLb1pJaHZjTkFRRUxCUUF3SWpFZ01CNEcKQTFVRUF3d1hhSFIwY0hNNkx5OXBaSEF1WlhoaGJYQnNaUzVqYjIwd0hoY05NalF3TmpJMU1URTFPVFV6V2hjTk16UXdOakl6TVRFMQpPVFV6V2pBaU1TQXdIZ1lEVlFRRERCZG9kSFJ3Y3pvdkwybGtjQzVsZUdGdGNHeGxMbU52YlRDQ0FpSXdEUVlKS29aSWh2Y05BUUVCCkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQU9xb2VyNzhjUmlmRVF3dWFJVTUwanF0TU4rVkFYY3VJaGpOV3BZN0xMOGtLV2hzK0d2U2h5T0MKWjNVSlJpQkdJSUJoN3JYZXY5TmZlcU5Ud0hRYjdyMk9MbzBUenlFZkhGalRVZy94R0g2eEZnNTZQQ0RsNHZ5TDdscGZIbTJTN2VHegpsRnBQRTBTQjlLZzM0MnlXOTZ6eGVJWExWWG41OEhrNTBId0c1T244OHJBWmpjN0xyN1JLbWNpTGgvR1E4ZlNnK1ByZHZuVWxNdkFiCmh1dlVqVGNPa0dLVjcyS1VQbURZVmZBNGpXZEdlOVZnVktUenNhci81dGNZU2g5b0hjR053UmFtY0ltRHBTTXNyY3ZrdHNHeHQ0NXcKU0lFdEoxZzhRaFk4MEY4OTJzT2FOMDRqT3pyeCtYWWdja2d2aFVqTTQ4cjdQSE1sdmVPTnhyRWd4VXA2S3I5RTZPWW1aWlUrZnlMZQp2SlZCcCt6U0U1c3lFSEI0SEZNSUEvOTJUcDd4UllMeWcwd2VRM3hWRlRPdHUxK0RIcjFhTHJ0a1laMUNRUmk2bDM5NytrMmg4cnQxCmNpZzYwcjV2cm5iRUQzWlp6YUZydXNjTVlIeVZUb3ZheGpFWVBDWnpMMWV0UmdlY0d6MzRjUVdpZC9PWHJ5b1RBSThsZldmRmp1VCsKUHFJNHI4bDErOEFkNHBFUFZPbSsyRkwvL3lLNkhKZGVheUpBUGp2QnNqZFArYzl5djB6L21zNDh5b1F4YkdXRWxwcnc5WWFER3lZWQpxakxtaEE3MzY0dVIxRjRQZVJIdk1FNWROVm9zajJEVFl4c3FMaEVSdTVsZGs2V1pUa2l1VlVtVmJvL1QvT2c3YTU5L3VzbW4ybTFSCktPZVhJRXBlQWtuTjhLSGYvU1hiQWdNQkFBRXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnSUJBS2hsdTQ4WFpXK05pSWswcU1JZ3kxWWUKU01Tam9hY3dQZFZVNGxOb0dISW84SWZMZUFxS1BCUHg3eVkxdCs3dHNuTWh5SkhybnhmemN6Qy9RbFIydDhnU3VrN3Z2SHBNU1VsbgpUTUFZZ0gzRFBDSmlja3hzK2VPMXMvVTVrZVRHT1drYTdVQk5YNW9vTWQyMVU5RE1oUlFGNTlCWHNmMXBUWk5hNXdrRXMvZEIvMUo2Clc4K3Evb2tqSHFPTzBWa2lQWStmSGdTS3JRUXhITkpJR2s4b0FTRkgzdWRYTm5MajdQcCsyZVkxa2tVemNIbUYyU3U5bGtGajJVZnEKSlhwUFJiVDJKWXlMaWUyWHpTWFduYUJpOHJCdzRPNDBTNjZFVWhpamlxekNyZ05TL0hLRnBycTM2YitTNUpNSEVTQzIrQnN2WitpMApUcTNMWll2NVFoMUtDdVlsRkhqaVlMVXh2cExKek1nZ0NMQjA1Vm8yenJVOWxYS3Rhcno1aFpIK2ZHdDNxcC9mbW9WV1pNUVVUYU1wCm1nQ29BWGk0RDBCaWhJYVBJTndRQXZoUU53bXlqdHNQSFd6cnMvMWd0RHlBOCtoVGszekxkbUk0ZDhUc1dNcTRJL3crWEM5MWgyMVYKSWFjNDg0czl3R3pTamg4bzRERUh5dUNCNnJxYk9GL0w0N2dvcklJWEtZVm5EanE2dlVvRzdZc0RyMVVBamFVWk96S1RTMnh0UTU0YQpwa3J5QU9EZk5PZ2FQMXNmbVFZdnRpOXAyWjUwUTBXWGJxekdqSVRtL1RkYi9IWVExVkNPc3A2Z3pWNDM4UHlYODNFOHpTWWZLeTNDCjk2bmFQNWsxbmgvUG0rYjlvK2N5bUpzaGhnMkNkaWtwRWVxYkxDL2tjeEtQQTVqNGdKSWMKPC9kczpYNTA5Q2VydGlmaWNhdGU+PC9kczpYNTA5RGF0YT48L2RzOktleUluZm8+PC9kczpTaWduYXR1cmU+PHNhbWwycDpTdGF0dXM+PHNhbWwycDpTdGF0dXNDb2RlIFZhbHVlPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6c3RhdHVzOlN1Y2Nlc3MiLz48L3NhbWwycDpTdGF0dXM+PHNhbWwyOkFzc2VydGlvbiB4bWxuczpzYW1sMj0idXJuOm9hc2lzOm5hbWVzOnRjOlNBTUw6Mi4wOmFzc2VydGlvbiIgeG1sbnM6eHNkPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgSUQ9Il81N2Q4MWI1MS04ZGJjLTQ0ZGYtYTc0Ni05OTEyZjhhMzkzNjgiIFZlcnNpb249IjIuMCIgSXNzdWVJbnN0YW50PSIyMDI0LTA2LTI1VDExOjU5OjUzLjYwM1oiPjxzYW1sMjpJc3N1ZXIgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPmh0dHA6Ly9sb2NhbGhvc3Q6OTAxMy92MS90ZW5hbnRzL1hRaERXV2xyZGl6dGNTeEk2Y3hXbi9yZWFsbXMvSEdzTkxyakpwUVR6U2FDM2dmNkdSb0haZUt6RWNodUEvYXBwbGljYXRpb25zL2IyZWRkZGNlLWM4YjctNDUyYS04YzI5LWJiNDI2ODg0OTNlYy9zYW1sL21ldGFkYXRhPC9zYW1sMjpJc3N1ZXI+PHNhbWwyOlN1YmplY3QgeG1sbnM6c2FtbDI9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxzYW1sMjpOYW1lSUQgRm9ybWF0PSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjE6bmFtZWlkLWZvcm1hdDp1bnNwZWNpZmllZCI+bW9jayB1c2VyPC9zYW1sMjpOYW1lSUQ+PHNhbWwyOlN1YmplY3RDb25maXJtYXRpb24gTWV0aG9kPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoxLjA6Y206YmVhcmVyIj48c2FtbDI6U3ViamVjdENvbmZpcm1hdGlvbkRhdGEgTm90QmVmb3JlPSIyMDI0LTA2LTI1VDExOjU5OjUzLjYwM1oiIE5vdE9uT3JBZnRlcj0iMjAyNC0wNi0yNVQxMjo1OTo1My42MDNaIiBSZWNpcGllbnQ9Imh0dHA6Ly9leGFtcGxlLmNvbS9hY3MiLz48L3NhbWwyOlN1YmplY3RDb25maXJtYXRpb24+PC9zYW1sMjpTdWJqZWN0PjxzYW1sMjpDb25kaXRpb25zIE5vdEJlZm9yZT0iMjAyNC0wNi0yNVQxMTo1OTo1M1oiIE5vdE9uT3JBZnRlcj0iMjAyNC0wNi0yNVQxMjo1OTo1M1oiPjxzYW1sMjpBdWRpZW5jZVJlc3RyaWN0aW9uPjxzYW1sMjpBdWRpZW5jZT5odHRwOi8vZXhhbXBsZS5jb20vYXVkaWVuY2U8L3NhbWwyOkF1ZGllbmNlPjwvc2FtbDI6QXVkaWVuY2VSZXN0cmljdGlvbj48L3NhbWwyOkNvbmRpdGlvbnM+PHNhbWwyOkF1dGhuU3RhdGVtZW50IEF1dGhuSW5zdGFudD0iMjAyNC0wNi0yNVQxMTo1OTo1My42MDNaIj48c2FtbDI6QXV0aG5Db250ZXh0PjxzYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj51cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YWM6Y2xhc3NlczpYNTA5PC9zYW1sMjpBdXRobkNvbnRleHRDbGFzc1JlZj48L3NhbWwyOkF1dGhuQ29udGV4dD48L3NhbWwyOkF1dGhuU3RhdGVtZW50Pjwvc2FtbDI6QXNzZXJ0aW9uPjwvc2FtbDJwOlJlc3BvbnNlPgo=" />
        </form>
    </body>"#;
        let builder = ResponseVerifierBuilder::default();
        let verifier = builder.build().unwrap();
        let _response = verifier.verify_from_html_form(test_form).unwrap();
    }
}
