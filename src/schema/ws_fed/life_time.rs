use super::*;

pub const LIFE_TIME_XML_NAME: &str = "t:LifeTime";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LifeTime {
    /// This OPTIONAL element represents the creation time of the security
    /// token. Within the SOAP processing model, creation is the instant that
    /// the infoset is serialized for transmission. The creation time of the
    /// token SHOULD NOT differ substantially from its transmission time. The
    /// difference in time SHOULD be minimized. If this time occurs in the
    /// future then this is a request for a postdated token. If this attribute
    /// isn't specified, then the current time is used as an initial period.
    #[serde(rename = "Created")]
    pub created: Option<LifeTimeCreated>,

    /// This OPTIONAL element specifies an absolute time representing the upper
    /// bound on the validity time period of the requested token. If this
    /// attribute isn't specified, then the service chooses the lifetime of the
    /// security token. A Fault code (wsu:MessageExpired) is provided if the
    /// recipient wants to inform the requestor that its security semantics were
    /// expired. A service MAY issue a Fault indicating the security semantics
    /// have expired.
    #[serde(rename = "Expires")]
    pub expires: Option<LifeTimeExpires>,
}

impl TryFrom<&LifeTime> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &LifeTime) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let root = BytesStart::new(LIFE_TIME_XML_NAME);
        writer.write_event(Event::Start(root))?;

        if let Some(created) = value.created.as_ref() {
            let event: Event<'_> = created.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(expires) = value.expires.as_ref() {
            let event: Event<'_> = expires.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(LIFE_TIME_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

pub const LIFE_TIME_CREATED_XML_NAME: &str = "wsu:Created";

/// This OPTIONAL element represents the creation time of the security token.
/// Within the SOAP processing model, creation is the instant that the infoset
/// is serialized for transmission. The creation time of the token SHOULD NOT
/// differ substantially from its transmission time. The difference in time
/// SHOULD be minimized. If this time occurs in the future then this is a
/// request for a postdated token. If this attribute isn't specified, then the
/// current time is used as an initial period.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LifeTimeCreated {
    #[serde(rename = "$value")]
    pub value: String,
}

impl TryFrom<&LifeTimeCreated> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &LifeTimeCreated) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(LIFE_TIME_CREATED_XML_NAME);
        root.push_attribute(NS_WS_SECURITY_UTILITY);
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(value.value.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new(LIFE_TIME_CREATED_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

pub const LIFE_TIME_EXPIRES_XML_NAME: &str = "wsu:Expires";

#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct LifeTimeExpires {
    #[serde(rename = "$value")]
    pub value: String,
}

impl TryFrom<&LifeTimeExpires> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &LifeTimeExpires) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(LIFE_TIME_EXPIRES_XML_NAME);
        root.push_attribute(NS_WS_SECURITY_UTILITY);
        writer.write_event(Event::Start(root))?;
        writer.write_event(Event::Text(BytesText::from_escaped(value.value.as_str())))?;
        writer.write_event(Event::End(BytesEnd::new(LIFE_TIME_EXPIRES_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
