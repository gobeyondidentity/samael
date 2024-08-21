use super::*;

pub const ENDPOINT_REFERENCE_XML_NAME: &str = "wsa:EndpointReference";

/// Required by section 13.6.3.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct EndpointReference {
    #[serde(rename = "Address")]
    pub address: Address,
}

impl TryFrom<&EndpointReference> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EndpointReference) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(ENDPOINT_REFERENCE_XML_NAME);
        root.push_attribute(NS_WS_ADDRESS);
        writer.write_event(Event::Start(root))?;

        // Writing assertion
        let event: Event<'_> = (&value.address).try_into()?;
        writer.write_event(event)?;

        writer.write_event(Event::End(BytesEnd::new(ENDPOINT_REFERENCE_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
