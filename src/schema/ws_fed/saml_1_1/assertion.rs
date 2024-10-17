use super::*;

/// This represents an assertion in SAML 1.1. This is to support the WS-Fed
/// Protocol.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct Assertion11 {
    #[serde(rename = "@AssertionID")]
    pub id: String,
    #[serde(rename = "@Issuer")]
    pub issuer: String,
    #[serde(rename = "@IssueInstant")]
    pub issue_instant: DateTime<Utc>,
    #[serde(rename = "Signature")]
    pub signature: Option<Signature>,
    #[serde(rename = "Conditions")]
    #[builder(default)]
    pub conditions: Option<Conditions11>,
    #[serde(rename = "AuthenticationStatement")]
    #[builder(default)]
    pub authn_statements: Option<Vec<AuthenticationStatement11>>,
    #[serde(rename = "AttributeStatement")]
    #[builder(default)]
    pub attribute_statements: Option<Vec<AttributeStatement11>>,
}

impl Assertion11 {
    fn name() -> &'static str {
        "saml:Assertion"
    }

    fn schema() -> &'static [(&'static str, &'static str)] {
        &[("xmlns:saml", "urn:oasis:names:tc:SAML:1.0:assertion")]
    }
}

impl TryFrom<Assertion11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Assertion11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Assertion11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Assertion11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(Assertion11::name());

        for attr in Assertion11::schema() {
            root.push_attribute((attr.0, attr.1));
        }

        root.push_attribute(("AssertionID", value.id.as_ref()));
        root.push_attribute(("Issuer", value.issuer.as_ref()));
        root.push_attribute((
            "IssueInstant",
            value
                .issue_instant
                .to_rfc3339_opts(SecondsFormat::Millis, true)
                .as_ref(),
        ));
        root.push_attribute(("MajorVersion", "1"));
        root.push_attribute(("MinorVersion", "1"));

        writer.write_event(Event::Start(root))?;

        if let Some(conditions) = &value.conditions {
            let event: Event<'_> = conditions.try_into()?;
            writer.write_event(event)?;
        }


        if let Some(statements) = &value.attribute_statements {
            for statement in statements {
                let event: Event<'_> = statement.try_into()?;
                writer.write_event(event)?;
            }
        }

        if let Some(statements) = &value.authn_statements {
            for statement in statements {
                let event: Event<'_> = statement.try_into()?;
                writer.write_event(event)?;
            }
        }
        
        if let Some(signature) = &value.signature {
            let event: Event<'_> = signature.try_into()?;
            writer.write_event(event)?;
        }


        writer.write_event(Event::End(BytesEnd::new(Assertion11::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
