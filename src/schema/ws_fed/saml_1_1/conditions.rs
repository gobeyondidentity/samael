use super::super::*;

const NAME: &str = "saml:Conditions";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct Conditions11 {
    #[serde(rename = "@NotBefore")]
    #[builder(default)]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(rename = "@NotOnOrAfter")]
    #[builder(default)]
    pub not_on_or_after: Option<DateTime<Utc>>,
    #[serde(rename = "AudienceRestrictionCondition", default)]
    #[builder(default)]
    pub audience_restrictions: Option<Vec<AudienceRestriction11>>,
}

impl TryFrom<Conditions11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: Conditions11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Conditions11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &Conditions11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(NAME);
        if let Some(not_before) = &value.not_before {
            root.push_attribute((
                "NotBefore",
                not_before
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }
        if let Some(not_on_or_after) = &value.not_on_or_after {
            root.push_attribute((
                "NotOnOrAfter",
                not_on_or_after
                    .to_rfc3339_opts(SecondsFormat::Millis, true)
                    .as_ref(),
            ));
        }
        writer.write_event(Event::Start(root))?;
        if let Some(audience_restrictions) = &value.audience_restrictions {
            for restriction in audience_restrictions {
                let event: Event<'_> = restriction.try_into()?;
                writer.write_event(event)?;
            }
        }
        writer.write_event(Event::End(BytesEnd::new(NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

const AUDIENCE_RESTRICTION_NAME: &str = "saml:AudienceRestrictionCondition";
const AUDIENCE_NAME: &str = "saml:Audience";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd, Builder)]
#[builder(setter(into))]
pub struct AudienceRestriction11 {
    #[serde(rename = "Audience")]
    pub audience: Vec<String>,
}

impl TryFrom<AudienceRestriction11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: AudienceRestriction11) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&AudienceRestriction11> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AudienceRestriction11) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(AUDIENCE_RESTRICTION_NAME);
        writer.write_event(Event::Start(root))?;
        for aud in &value.audience {
            writer.write_event(Event::Start(BytesStart::new(AUDIENCE_NAME)))?;
            writer.write_event(Event::Text(BytesText::from_escaped(aud)))?;
            writer.write_event(Event::End(BytesEnd::new(AUDIENCE_NAME)))?;
        }
        writer.write_event(Event::End(BytesEnd::new(AUDIENCE_RESTRICTION_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
