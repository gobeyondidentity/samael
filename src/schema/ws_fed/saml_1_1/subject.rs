use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use serde::Deserialize;
use std::io::Cursor;

const NAME: &str = "saml:Subject";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct Subject11 {
    #[serde(rename = "NameIdentifier")]
    #[builder(default)]
    pub name_id: Option<SubjectNameID11>,
    #[serde(rename = "SubjectConfirmation")]
    #[builder(default)]
    pub subject_confirmations: Option<Vec<SubjectConfirmation11>>,
}

impl TryFrom<Subject11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Subject11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Subject11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Subject11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(NAME);

        writer.write_event(Event::Start(root))?;
        if let Some(name_id) = &value.name_id {
            let event: Event<'_> = name_id.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(subject_confirmations) = &value.subject_confirmations {
            for confirmation in subject_confirmations {
                let event: Event<'_> = confirmation.try_into()?;
                writer.write_event(event)?;
            }
        }
        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct SubjectNameID11 {
    #[serde(rename = "@Format")]
    #[builder(default)]
    pub format: Option<String>,

    #[serde(rename = "$value")]
    #[builder(default)]
    pub value: String,
}

impl SubjectNameID11 {
    fn name() -> &'static str {
        "saml:NameIdentifier"
    }
}

impl TryFrom<SubjectNameID11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SubjectNameID11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SubjectNameID11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SubjectNameID11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(SubjectNameID11::name());

        if let Some(format) = &value.format {
            root.push_attribute(("Format", format.as_ref()));
        }

        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(value.value.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new(SubjectNameID11::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const SUBJECT_CONFIRMATION_NAME: &str = "saml:SubjectConfirmation";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct SubjectConfirmation11 {
    #[serde(rename = "ConfirmationMethod", default)]
    #[builder(default)]
    pub methods: Vec<ConfirmationMethod11>,
}

impl TryFrom<SubjectConfirmation11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: SubjectConfirmation11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&SubjectConfirmation11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &SubjectConfirmation11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(SUBJECT_CONFIRMATION_NAME);
        writer.write_event(Event::Start(root))?;
        for method in value.methods.iter() {
            let event: Event<'_> = method.try_into()?;
            writer.write_event(event)?;
        }
        writer.write_event(Event::End(BytesEnd::new(SUBJECT_CONFIRMATION_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const CONFIRMATION_METHOD_NAME: &str = "saml:ConfirmationMethod";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct ConfirmationMethod11 {
    #[serde(rename = "$value", default)]
    #[builder(default)]
    pub value: Option<String>,
}

impl TryFrom<ConfirmationMethod11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: ConfirmationMethod11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&ConfirmationMethod11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &ConfirmationMethod11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(CONFIRMATION_METHOD_NAME);
        match value.value.as_ref() {
            Some(value) => {
                writer.write_event(Event::Start(root))?;
                writer.write_event(Event::Text(BytesText::from_escaped(value.as_str())))?;
                writer.write_event(Event::End(BytesEnd::new(CONFIRMATION_METHOD_NAME)))?;
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
