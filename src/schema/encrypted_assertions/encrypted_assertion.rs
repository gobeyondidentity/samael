use crate::schema::Assertion;

use super::*;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct EncryptedAssertion {
    #[serde(rename = "EncryptedData")]
    pub data: Option<EncryptedData>,

    #[serde(rename = "Assertion")]
    pub assertion: Assertion,
}

impl EncryptedAssertion {
    fn name() -> &'static str {
        "saml2:EncryptedAssertion"
    }
}

impl TryFrom<&EncryptedAssertion> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &EncryptedAssertion) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(EncryptedAssertion::name());
        //
        root.push_attribute(("xmlns:saml2", "urn:oasis:names:tc:SAML:2.0:assertion"));

        writer.write_event(Event::Start(root))?;
        if let Some(encrypted_data) = value.data.as_ref() {
            let event: Event<'_> = encrypted_data.try_into()?;
            writer.write_event(event)?;
        } else {
            return Err(Box::new(
                crate::schema::error::SchemaError::MissingEncryptionTemplate(
                    "EncryptedAssertion".to_string(),
                ),
            ));
        }
        let event: Event<'_> = (&value.assertion).try_into()?;
        writer.write_event(event)?;
        writer.write_event(Event::End(BytesEnd::new(EncryptedAssertion::name())))?;

        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
