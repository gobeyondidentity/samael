use super::*;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct AttributeStatement11 {
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<Attribute11>,

    #[serde(rename = "Subject")]
    pub subject: Option<Subject11>,
}

impl AttributeStatement11 {
    fn name() -> &'static str {
        "saml:AttributeStatement"
    }
}

impl TryFrom<AttributeStatement11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AttributeStatement11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AttributeStatement11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AttributeStatement11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(AttributeStatement11::name());

        writer.write_event(Event::Start(root))?;

        for attr in &value.attributes {
            let event: Event<'_> = attr.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(subject) = value.subject.as_ref() {
            let event: Event<'_> = subject.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(AttributeStatement11::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const ATTRIBUTE_VALUE_NAME: &str = "saml:AttributeValue";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AttributeValue11 {
    #[serde(rename = "$value")]
    pub value: Option<String>,
}

impl TryFrom<AttributeValue11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AttributeValue11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AttributeValue11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AttributeValue11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(ATTRIBUTE_VALUE_NAME);

        writer.write_event(Event::Start(root))?;

        if let Some(value) = &value.value {
            writer.write_event(Event::Text(BytesText::from_escaped(value)))?;
        }

        writer.write_event(Event::End(BytesEnd::new(ATTRIBUTE_VALUE_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Attribute11 {
    #[serde(rename = "@AttributeName")]
    pub name: Option<String>,
    #[serde(rename = "@AttributeNamespace", default)]
    pub namespace: Option<String>,
    #[serde(rename = "AttributeValue", default)]
    pub values: Vec<AttributeValue11>,
}

impl Attribute11 {
    fn name() -> &'static str {
        "saml:Attribute"
    }
}

impl TryFrom<Attribute11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Attribute11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Attribute11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Attribute11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(Attribute11::name());

        if let Some(name) = &value.name {
            root.push_attribute(("AttributeName", name.as_ref()));
        }
        if let Some(ns) = value.namespace.as_ref() {
            root.push_attribute(("AttributeNamespace", ns.as_ref()));
        }

        writer.write_event(Event::Start(root))?;

        for val in &value.values {
            let event: Event<'_> = val.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(Attribute11::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
