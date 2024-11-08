use super::*;

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct AuthenticationStatement11 {
    #[serde(rename = "@AuthenticationInstant")]
    #[builder(default)]
    pub authn_instant: Option<String>,
    #[serde(rename = "@AuthenticationMethod")]
    #[builder(default)]
    pub authn_method: Option<String>,
    #[serde(rename = "Subject")]
    #[builder(default)]
    pub subject: Option<Subject11>,
}

impl AuthenticationStatement11 {
    fn name() -> &'static str {
        "saml:AuthenticationStatement"
    }
}

impl TryFrom<AuthenticationStatement11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AuthenticationStatement11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AuthenticationStatement11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AuthenticationStatement11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(AuthenticationStatement11::name());

        if let Some(session) = &value.authn_method {
            root.push_attribute(("AuthenticationMethod", session.as_ref()));
        }

        if let Some(instant) = &value.authn_instant {
            root.push_attribute(("AuthenticationInstant", instant.as_str()));
        }
        writer.write_event(Event::Start(root))?;

        if let Some(context) = &value.subject {
            let event: Event<'_> = context.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(AuthenticationStatement11::name())))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
