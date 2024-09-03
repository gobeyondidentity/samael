use super::*;

pub const TOKEN_TYPE_XML_NAME: &str = "wst:TokenType";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct TokenType {
    #[serde(rename = "$value")]
    pub value: String,
}

impl TryFrom<&TokenType> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &TokenType) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(TOKEN_TYPE_XML_NAME);
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(value.value.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new(TOKEN_TYPE_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
