//

use super::*;

pub const CLAIM_TYPES_OFFERED_XML_NAME: &str = "fed:ClaimTypesOffered";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct ClaimTypesOffered {
    #[serde(rename = "ClaimType", default)]
    pub claim_types: Vec<ClaimType>,
}

impl TryFrom<&ClaimTypesOffered> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &ClaimTypesOffered) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(CLAIM_TYPES_OFFERED_XML_NAME);
        writer.write_event(Event::Start(root))?;

        // Writing all of the offered token types.
        for token in value.claim_types.iter() {
            let event: Event<'_> = token.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(CLAIM_TYPES_OFFERED_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

pub const WS_FED_AUTH_NAMESPACE: (&str, &str) = (
    "xmlns:auth",
    "http://docs.oasis-open.org/wsfed/authorization/200706",
);
pub const CLAIM_TYPE_XML_NAME: &str = "auth:ClaimType";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct ClaimType {
    #[serde(rename = "@Uri", default)]
    pub uri: String,
    #[serde(rename = "DisplayName", default)]
    pub display_name: Option<AuthDisplayName>,
    #[serde(rename = "Description", default)]
    pub description: Option<AuthDescription>,
}

impl TryFrom<&ClaimType> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &ClaimType) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(CLAIM_TYPE_XML_NAME);
        root.push_attribute(WS_FED_AUTH_NAMESPACE);
        root.push_attribute(("Uri", value.uri.as_ref()));
        writer.write_event(Event::Start(root))?;

        if let Some(display_name) = value.display_name.as_ref() {
            let event: Event<'_> = display_name.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(description) = value.description.as_ref() {
            let event: Event<'_> = description.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(CLAIM_TYPE_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

pub const AUTH_DISPLAY_NAME_XML_NAME: &str = "auth:DisplayName";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthDisplayName {
    #[serde(rename = "$value", default)]
    pub value: Option<String>,
}

impl TryFrom<&AuthDisplayName> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AuthDisplayName) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(AUTH_DISPLAY_NAME_XML_NAME);
        writer.write_event(Event::Start(root))?;

        if let Some(value) = &value.value {
            writer.write_event(Event::Text(BytesText::from_escaped(value)))?;
        }

        writer.write_event(Event::End(BytesEnd::new(AUTH_DISPLAY_NAME_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

pub const AUTH_DESCRIPTION_XML_NAME: &str = "auth:Description";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AuthDescription {
    #[serde(rename = "$value", default)]
    pub value: Option<String>,
}

impl TryFrom<&AuthDescription> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AuthDescription) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(AUTH_DESCRIPTION_XML_NAME);
        writer.write_event(Event::Start(root))?;

        if let Some(value) = &value.value {
            writer.write_event(Event::Text(BytesText::from_escaped(value)))?;
        }

        writer.write_event(Event::End(BytesEnd::new(AUTH_DESCRIPTION_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
