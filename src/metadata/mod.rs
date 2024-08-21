mod affiliation_descriptor;
mod attribute_consuming_service;
mod contact_person;
mod encryption_method;
mod endpoint;
mod entity_descriptor;
mod helpers;
mod key_descriptor;
mod localized;
mod organization;
mod sp_sso_descriptor;
pub mod ws_fed;

pub use affiliation_descriptor::*;
pub use attribute_consuming_service::AttributeConsumingService;
pub use contact_person::*;
pub use encryption_method::EncryptionMethod;
pub use endpoint::*;
pub use entity_descriptor::*;
pub use key_descriptor::KeyDescriptor;
pub use localized::*;
pub use organization::Organization;
pub use sp_sso_descriptor::SpSsoDescriptor;
pub mod de {
    pub use quick_xml::de::*;
}
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::io::Cursor;

use serde::Deserialize;

use crate::attribute::Attribute;
use crate::metadata::helpers::write_plain_element;
use crate::signature::Signature;
use chrono::prelude::*;

// HTTP_POST_BINDING is the official URN for the HTTP-POST binding (transport)
pub const HTTP_POST_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

// HTTP_REDIRECT_BINDING is the official URN for the HTTP-Redirect binding (transport)
pub const HTTP_REDIRECT_BINDING: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum NameIdFormat {
    UnspecifiedNameIDFormat,
    TransientNameIDFormat,
    EmailAddressNameIDFormat,
    PersistentNameIDFormat,
}

impl NameIdFormat {
    pub fn value(&self) -> &'static str {
        match self {
            NameIdFormat::UnspecifiedNameIDFormat => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
            }
            NameIdFormat::TransientNameIDFormat => {
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
            }
            NameIdFormat::EmailAddressNameIDFormat => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            }
            NameIdFormat::PersistentNameIDFormat => {
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
            }
        }
    }
}

pub const ROLE_DESCRIPTOR_XML_NAME: &str = "md:RoleDescriptor";
pub const NS_XSI_SCHEMA_INSTANCE: (&str, &str) =
    ("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");

pub const NS_WS_FED: (&str, &str) = (
    "xmlns:fed",
    "http://docs.oasis-open.org/wsfed/federation/200706",
);
pub const XSI_TYPE_ATTR_NAME: &str = "xsi:type";

/// This should be the base class of role descriptions.
///
/// The <RoleDescriptor> element is an abstract extension point that contains
/// common descriptive information intended to provide processing commonality
/// across different roles. New roles can be defined by extending its abstract
/// RoleDescriptorType complex type.
#[derive(Clone, Debug, Deserialize, Default, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RoleDescriptor {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "@protocolSupportEnumeration")]
    pub protocol_support_enumeration: String,
    #[serde(rename = "@errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    #[serde(rename = "@xsi:type", default)]
    #[serde(alias = "@type")]
    pub r#type: Option<String>,
    #[serde(rename = "PassiveRequestorEndpoint", default)]
    pub passive_requestor_endpoint: Vec<ws_fed::PassiveRequestorEndpoint>,
}

impl TryFrom<RoleDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: RoleDescriptor) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&RoleDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &RoleDescriptor) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(ROLE_DESCRIPTOR_XML_NAME);
        if !value.passive_requestor_endpoint.is_empty() {
            root.push_attribute(NS_WS_FED);
        }

        if let Some(ty) = value.r#type.as_ref() {
            root.push_attribute(NS_XSI_SCHEMA_INSTANCE);
            root.push_attribute((XSI_TYPE_ATTR_NAME, ty.as_str()));
        }

        if let Some(id) = &value.id {
            root.push_attribute(("ID", id.as_ref()));
        }

        if let Some(valid_until) = &value.valid_until {
            root.push_attribute((
                "validUntil",
                valid_until
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ));
        }

        if let Some(cache_duration) = &value.cache_duration {
            root.push_attribute(("cacheDuration", cache_duration.to_string().as_ref()));
        }

        root.push_attribute((
            "protocolSupportEnumeration",
            value.protocol_support_enumeration.as_str(),
        ));

        if let Some(error_url) = &value.error_url {
            root.push_attribute(("errorURL", error_url.as_ref()));
        }

        // Writing the actual event starting from here.
        writer.write_event(Event::Start(root))?;

        for descriptor in &value.key_descriptors {
            let event: Event<'_> = descriptor.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(signature) = value.signature.as_ref() {
            let event: Event<'_> = signature.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(organization) = &value.organization {
            let event: Event<'_> = organization.try_into()?;
            writer.write_event(event)?;
        }

        for contact in &value.contact_people {
            let event: Event<'_> = contact.try_into()?;
            writer.write_event(event)?;
        }

        for requestor in &value.passive_requestor_endpoint {
            let event: Event<'_> = requestor.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(ROLE_DESCRIPTOR_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SSODescriptor {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "@protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "@errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    // ^- RoleDescriptor
    #[serde(rename = "ArtifactResolutionService", default)]
    pub artifact_resolution_service: Vec<IndexedEndpoint>,
    #[serde(rename = "SingleLogoutService", default)]
    pub single_logout_services: Vec<Endpoint>,
    #[serde(rename = "ManageNameIDService", default)]
    pub manage_name_id_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct IdpSsoDescriptor {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "@protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "@errorURL")]
    pub error_url: Option<String>,
    pub signature: Option<String>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    #[serde(rename = "ArtifactResolutionService", default)]
    pub artifact_resolution_service: Vec<IndexedEndpoint>,
    #[serde(rename = "SingleLogoutService", default)]
    pub single_logout_services: Vec<Endpoint>,
    #[serde(rename = "ManageNameIDService", default)]
    pub manage_name_id_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
    // ^-SSODescriptor
    #[serde(rename = "@WantAuthnRequestsSigned")]
    pub want_authn_requests_signed: Option<bool>,
    #[serde(rename = "SingleSignOnService", default)]
    pub single_sign_on_services: Vec<Endpoint>,
    #[serde(rename = "NameIDMappingService", default)]
    pub name_id_mapping_services: Vec<Endpoint>,
    #[serde(rename = "AssertionIDRequestService", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[serde(rename = "AttributeProfile", default)]
    pub attribute_profiles: Vec<String>,
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<Attribute>,
}

const NAME: &str = "md:IDPSSODescriptor";

impl TryFrom<IdpSsoDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: IdpSsoDescriptor) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&IdpSsoDescriptor> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &IdpSsoDescriptor) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);

        if let Some(id) = &value.id {
            root.push_attribute(("ID", id.as_ref()));
        }
        if let Some(what_signed_requests) = value.want_authn_requests_signed.as_ref() {
            root.push_attribute((
                "WantAuthnRequestsSigned",
                what_signed_requests.to_string().as_str(),
            ));
        }

        if let Some(valid_until) = &value.valid_until {
            root.push_attribute((
                "validUntil",
                valid_until
                    .to_rfc3339_opts(SecondsFormat::Secs, true)
                    .as_ref(),
            ));
        }

        if let Some(cache_duration) = &value.cache_duration {
            root.push_attribute(("cacheDuration", cache_duration.to_string().as_ref()));
        }

        if let Some(protocol_support_enumeration) = &value.protocol_support_enumeration {
            root.push_attribute((
                "protocolSupportEnumeration",
                protocol_support_enumeration.as_ref(),
            ));
        }

        if let Some(error_url) = &value.error_url {
            root.push_attribute(("errorURL", error_url.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        for descriptor in &value.key_descriptors {
            let event: Event<'_> = descriptor.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(organization) = &value.organization {
            let event: Event<'_> = organization.try_into()?;
            writer.write_event(event)?;
        }

        for contact in &value.contact_people {
            let event: Event<'_> = contact.try_into()?;
            writer.write_event(event)?;
        }

        for service in &value.artifact_resolution_service {
            writer.write_event(service.to_xml("md:ArtifactResolutionService")?)?;
        }

        for service in &value.single_logout_services {
            writer.write_event(service.to_xml("md:SingleLogoutService")?)?;
        }

        for service in &value.single_sign_on_services {
            writer.write_event(service.to_xml("md:SingleSignOnService")?)?;
        }

        for service in &value.manage_name_id_services {
            writer.write_event(service.to_xml("md:ManageNameIDService")?)?;
        }

        for format in &value.name_id_formats {
            write_plain_element(&mut writer, "md:NameIDFormat", format.as_ref())?;
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthnAuthorityDescriptors {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "@protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "@errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    // ^- RoleDescriptor
    #[serde(rename = "AuthnQueryService", default)]
    pub authn_query_services: Vec<Endpoint>,
    #[serde(rename = "AssertionIDRequestService", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeAuthorityDescriptors {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "@protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "@errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    // ^- RoleDescriptor
    #[serde(rename = "AttributeService", default)]
    pub attribute_services: Vec<Endpoint>,
    #[serde(rename = "AssertionIDRequestService", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
    #[serde(rename = "AttributeProfile", default)]
    pub attribute_profiles: Vec<String>,
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<Attribute>,
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct PdpDescriptors {
    #[serde(rename = "@ID")]
    pub id: Option<String>,
    #[serde(rename = "@validUntil")]
    pub valid_until: Option<chrono::DateTime<Utc>>,
    #[serde(rename = "@cacheDuration")]
    pub cache_duration: Option<usize>,
    #[serde(rename = "@protocolSupportEnumeration")]
    pub protocol_support_enumeration: Option<String>,
    #[serde(rename = "@errorURL")]
    pub error_url: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "KeyDescriptor", default)]
    pub key_descriptors: Vec<KeyDescriptor>,
    #[serde(rename = "Organization")]
    pub organization: Option<Organization>,
    #[serde(rename = "ContactPerson", default)]
    pub contact_people: Vec<ContactPerson>,
    // ^- RoleDescriptor
    #[serde(rename = "AuthzService", default)]
    pub authz_services: Vec<Endpoint>,
    #[serde(rename = "AssertionIDRequestService", default)]
    pub assertion_id_request_services: Vec<Endpoint>,
    #[serde(rename = "NameIDFormat", default)]
    pub name_id_formats: Vec<String>,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::schema::ws_fed::{Address, EndpointReference};
    use std::str::FromStr;
    use ws_fed::PassiveRequestorEndpoint;

    #[test]
    fn entity_descriptor_rt_with_ws_fed() {
        let input = EntityDescriptor {
            entity_id: None,
            id: None,
            valid_until: None,
            cache_duration: None,
            signature: None,
            affiliation_descriptors: None,
            role_descriptors: Some(vec![RoleDescriptor {
                id: Some("My id".to_string()),
                valid_until: None,
                cache_duration: None,
                protocol_support_enumeration: "protocol_support_enumeration".to_string(),
                error_url: None,
                signature: None,
                key_descriptors: Vec::new(),
                organization: None,
                contact_people: Vec::new(),
                r#type: Some("Something".to_string()),
                passive_requestor_endpoint: vec![PassiveRequestorEndpoint {
                    endpoint_reference: EndpointReference {
                        address: Address {
                            value: "My Address".to_string(),
                        },
                    },
                }],
            }]),
            idp_sso_descriptors: None,
            sp_sso_descriptors: None,
            authn_authority_descriptors: None,
            attribute_authority_descriptors: None,
            pdp_descriptors: None,
            organization: None,
            contact_person: None,
        };
        let xml_body = input.to_xml().unwrap();
        println!("XML body = {xml_body}");
        let deserialized = EntityDescriptor::from_str(&xml_body).unwrap();
        assert_eq!(deserialized, input);
    }
}
