use super::*;

pub const ADDRESS_XML_NAME: &str = "wsa:Address";

/// Required by section 13.6.3.
///
/// The <t:RequestSecurityTokenResponse> element MAY include a wsp:AppliesTo /
/// wsa:EndpointReference / wsa:Address element that specifies the Resource
/// Realm URI.  Note that this data MUST be consistent with similar data present
/// in security tokens (if any is present) – for example it must duplicate the
/// information in the signed token’s saml:Audience element when SAML security
/// tokens are returned.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Address {
    #[serde(rename = "$value")]
    pub value: String,
}

impl TryFrom<&Address> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Address) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(ADDRESS_XML_NAME);
        writer.write_event(Event::Start(root))?;

        writer.write_event(Event::Text(BytesText::from_escaped(value.value.as_str())))?;

        writer.write_event(Event::End(BytesEnd::new(ADDRESS_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
