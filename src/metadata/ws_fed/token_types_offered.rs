use super::*;

pub const TOKEN_TYPES_OFFERED_XML_NAME: &str = "fed:TokenTypesOffered";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct TokenTypesOffered {
    #[serde(rename = "TokenType")]
    pub token_types: Vec<WsFedTokenType>,
}

impl TryFrom<&TokenTypesOffered> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &TokenTypesOffered) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(TOKEN_TYPES_OFFERED_XML_NAME);
        writer.write_event(Event::Start(root))?;

        // Writing all of the offered token types.
        for token in value.token_types.iter() {
            let event: Event<'_> = token.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(TOKEN_TYPES_OFFERED_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

pub const TOKEN_TYPE_XML_NAME: &str = "fed:TokenType";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct WsFedTokenType {
    #[serde(rename = "@Uri", default)]
    pub uri: String,
}

impl TryFrom<&WsFedTokenType> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &WsFedTokenType) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(TOKEN_TYPE_XML_NAME);
        root.push_attribute(("Uri", value.uri.as_ref()));
        writer.write_event(Event::Empty(root))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
