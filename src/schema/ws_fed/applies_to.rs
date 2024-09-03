use super::*;

pub const APPLIES_TO_XML_NAME: &str = "wsp:AppliesTo";

/// Section 4.4.1 wsp:AppliesTo in RST and RSTR
///
/// Both the requestor and the issuer can specify a scope for the issued token
/// using the <wsp:AppliesTo> element. If a token issuer cannot provide a token
/// with a scope that is at least as broad as that requested by the requestor
/// then it SHOULD generate a fault. This section defines some rules for
/// interpreting the various combinations of provided scope:
///
///     - If neither the requestor nor the issuer specifies a scope then the
///     scope of the issued token is implied.
///
///     - If the requestor specifies a scope and the issuer does not then the
///       scope of the token is assumed to be that specified by the requestor.
///
///     - If the requestor does not specify a scope and the issuer does specify
///     a scope then the scope of the token is as defined by the issuers scope
///
///     - If both requestor and issuer specify a scope then there are two
///     possible outcomes:
///
///         - If both the issuer and requestor specify the same scope then the
///         issued token has that scope.
///
///         - If the issuer specifies a wider scope than the requestor then the
///         issued token has the scope specified by the issuer.
///
/// The requestor and issuer MUST agree on the version of [WS-Policy] used to
/// specify the scope of the issued token. The Trust13 assertion in
/// [WS-SecurityPolicy] provides a mechanism to communicate which version of
/// [WS-Policy] is to be used.
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct AppliesTo {
    /// Required by Section 13.6.3:
    #[serde(rename = "EndpointReference")]
    pub endpoint_reference: EndpointReference,
}

impl TryFrom<&AppliesTo> for Event<'_> {
    type Error = Box<dyn std::error::Error>;

    fn try_from(value: &AppliesTo) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(APPLIES_TO_XML_NAME);
        root.push_attribute(NS_WS_POLICY);
        writer.write_event(Event::Start(root))?;

        // Writing assertion
        let event: Event<'_> = (&value.endpoint_reference).try_into()?;
        writer.write_event(event)?;

        writer.write_event(Event::End(BytesEnd::new(APPLIES_TO_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}
