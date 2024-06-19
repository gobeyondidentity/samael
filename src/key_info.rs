use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "ds:KeyInfo";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Default)]
pub struct KeyInfo {
    #[serde(rename = "@Id")]
    pub id: Option<String>,
    #[serde(rename = "X509Data")]
    pub x509_data: Option<X509Data>,
    #[serde(rename = "KeyName")]
    pub key_name: Option<KeyName>,
}

impl TryFrom<KeyInfo> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: KeyInfo) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&KeyInfo> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &KeyInfo) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);
        if let Some(id) = &value.id {
            root.push_attribute(("Id", id.as_ref()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(x509_data) = &value.x509_data {
            let event: Event<'_> = x509_data.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(key_name) = value.key_name.as_ref() {
            let event: Event<'_> = key_name.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const X509_DATA_NAME: &str = "ds:X509Data";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct X509Data {
    #[serde(rename = "X509Certificate")]
    pub certificates: Vec<String>,
}

impl TryFrom<X509Data> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: X509Data) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&X509Data> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &X509Data) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(X509_DATA_NAME);
        writer.write_event(Event::Start(root))?;

        for certificate in &value.certificates {
            let name = "ds:X509Certificate";
            writer.write_event(Event::Start(BytesStart::new(name)))?;
            writer.write_event(Event::Text(BytesText::from_escaped(certificate.as_str())))?;
            writer.write_event(Event::End(BytesEnd::new(name)))?;
        }

        writer.write_event(Event::End(BytesEnd::new(X509_DATA_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const KEY_NAME: &str = "ds:KeyName";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Default)]
pub struct KeyName {
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

impl TryFrom<KeyName> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: KeyName) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&KeyName> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &KeyName) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(KEY_NAME);
        match value.value.as_ref() {
            Some(value) => {
                writer.write_event(Event::Start(root))?;
                writer.write_event(Event::Text(BytesText::from_escaped(value.as_str())))?;
                writer.write_event(Event::End(BytesEnd::new(KEY_NAME)))?;
            }
            None => {
                writer.write_event(Event::Empty(root))?;
            }
        }
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
