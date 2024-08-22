use super::*;
use crate::schema::ws_fed::EndpointReference;

pub const ENDPOINT_REFERENCE_XML_NAME: &str = "fed:PassiveRequestorEndpoint";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct PassiveRequestorEndpoint {
    #[serde(rename = "EndpointReference")]
    pub endpoint_reference: EndpointReference,
}

impl TryFrom<&PassiveRequestorEndpoint> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &PassiveRequestorEndpoint) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(ENDPOINT_REFERENCE_XML_NAME);
        writer.write_event(Event::Start(root))?;

        // Writing assertion
        let event: Event<'_> = (&value.endpoint_reference).try_into()?;
        writer.write_event(event)?;

        writer.write_event(Event::End(BytesEnd::new(ENDPOINT_REFERENCE_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
