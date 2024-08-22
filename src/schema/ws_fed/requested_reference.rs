use super::*;

pub const REQUESTED_ATTACHED_REFERENCE_XML_NAME: &str = "wst:RequestedAttachedReference";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestedAttachedReference {
    #[serde(rename = "SecurityTokenReference")]
    pub security_token_reference: SecurityTokenReference,
}

impl TryFrom<&RequestedAttachedReference> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &RequestedAttachedReference) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(REQUESTED_ATTACHED_REFERENCE_XML_NAME);
        writer.write_event(Event::Start(root))?;

        let event: Event<'_> = (&value.security_token_reference).try_into()?;
        writer.write_event(event)?;

        writer.write_event(Event::End(BytesEnd::new(
            REQUESTED_ATTACHED_REFERENCE_XML_NAME,
        )))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

pub const REQUESTED_UNATTACHED_REFERENCE_XML_NAME: &str = "wst:RequestedUnattachedReference";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestedUnattachedReference {
    #[serde(rename = "SecurityTokenReference")]
    pub security_token_reference: SecurityTokenReference,
}

impl TryFrom<&RequestedUnattachedReference> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &RequestedUnattachedReference) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(REQUESTED_UNATTACHED_REFERENCE_XML_NAME);
        writer.write_event(Event::Start(root))?;

        let event: Event<'_> = (&value.security_token_reference).try_into()?;
        writer.write_event(event)?;

        writer.write_event(Event::End(BytesEnd::new(
            REQUESTED_UNATTACHED_REFERENCE_XML_NAME,
        )))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

pub const SECURITY_TOKEN_REFERENCE_XML_NAME: &str = "wssext1:SecurityTokenReference";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct SecurityTokenReference {
    #[serde(rename = "KeyIdentifier")]
    pub key_identifier: KeyIdentifier,
}

impl TryFrom<&SecurityTokenReference> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SecurityTokenReference) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(SECURITY_TOKEN_REFERENCE_XML_NAME);
        // Adding namespace for this element.
        root.push_attribute(NS_WS_SEC_EXT_1_0);
        // Adding namespace for an attribute attached here.
        root.push_attribute(NS_WS_SECURITY_SEC_EXT);
        // Adding the attribute with namespace and value.
        root.push_attribute(SECURITY_TOKEN_REFERENCE_SAML_TOKEN_TYPE_ATTR);
        writer.write_event(Event::Start(root))?;

        let event: Event<'_> = (&value.key_identifier).try_into()?;
        writer.write_event(event)?;

        writer.write_event(Event::End(BytesEnd::new(SECURITY_TOKEN_REFERENCE_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

pub const KEY_IDENTIFIER_XML_NAME: &str = "wssext1:KeyIdentifier";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct KeyIdentifier {
    #[serde(rename = "$value")]
    pub value: String,
}

impl TryFrom<&KeyIdentifier> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &KeyIdentifier) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(KEY_IDENTIFIER_XML_NAME);
        root.push_attribute(KEY_IDENTIFIER_VALUE_TYPE_SAML_ATTR);
        writer.write_event(Event::Start(root))?;

        writer.write_event(Event::Text(BytesText::from_escaped(value.value.as_str())))?;

        writer.write_event(Event::End(BytesEnd::new(KEY_IDENTIFIER_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
