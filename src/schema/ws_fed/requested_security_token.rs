use saml_1_1::Assertion11;

use super::*;

pub const RST_XML_NAME: &str = "wst:RequestedSecurityToken";

/// This olds the "token", which in this case is a signed assertion.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestedSecurityToken {
    /// This is required to be a SAML assertion by section 13.6.3.
    #[serde(rename = "Assertion")]
    pub assertion: Assertion11,
}

impl TryFrom<&RequestedSecurityToken> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &RequestedSecurityToken) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(RST_XML_NAME);
        writer.write_event(Event::Start(root))?;

        // Writing assertion
        let event: Event<'_> = (&value.assertion).try_into()?;
        writer.write_event(event)?;

        writer.write_event(Event::End(BytesEnd::new(RST_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
