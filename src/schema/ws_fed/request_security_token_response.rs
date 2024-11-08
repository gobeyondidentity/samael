use super::*;

pub const RSTR_XML_NAME: &str = "t:RequestSecurityTokenResponse";
pub const RSTR_CONTEXT_ATTR_NAME: &str = "Context";

/// Definition available inside of WS-Trust 1.4 standard
/// https://docs.oasis-open.org/ws-sx/ws-trust/v1.4/ws-trust.html
/// Section 3.2
#[derive(Clone, Debug, Deserialize, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct RequestSecurityTokenResponse {
    /// This OPTIONAL URI specifies the identifier from the original request.
    /// That is, if a context URI is specified on a RST, then it MUST be echoed
    /// on the corresponding RSTRs.  For unsolicited RSTRs (RSTRs that aren't
    /// the result of an explicit RST), this represents a hint as to how the
    /// recipient is expected to use this token.  No values are pre-defined for
    /// this usage; this is for use by specifications that leverage the WS-Trust
    /// mechanisms.
    #[serde(rename = "@Context")]
    pub context: Option<String>,

    /// This OPTIONAL element specifies the type of security token returned.
    ///
    /// This has the following value: http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0
    #[serde(rename = "TokenType")]
    pub token_type: Option<TokenType>,

    /// This OPTIONAL element is used to return the requested security token.
    /// Normally the requested security token is the contents of this element
    /// but a security token reference MAY be used instead. For example, if the
    /// requested security token is used in securing the message, then the
    /// security token is placed into the <wsse:Security> header (as described
    /// in [WS-Security]) and a <wsse:SecurityTokenReference> element is placed
    /// inside of the <t:RequestedSecurityToken> element to reference the
    /// token in the <wsse:Security> header. The response MAY contain a token
    /// reference where the token is located at a URI outside of the message. In
    /// such cases the recipient is assumed to know how to fetch the token from
    /// the URI address or specified endpoint reference. It should be noted that
    /// when the token is not returned as part of the message it cannot be
    /// secured, so a secure communication mechanism SHOULD be used to obtain
    /// the token.
    ///
    /// Not optional as required by section 13.6.3 WS-Fed
    ///
    /// The <t:RequestSecurityTokenResponse> element that is included as the
    /// wresult field in the SignIn response MUST contain a
    /// <t:RequestedSecurityToken> element.  Support for SAML assertions MUST
    /// be provided but another token format MAY be used (depending on policy).
    #[serde(rename = "RequestedSecurityToken")]
    pub requested_security_token: RequestedSecurityToken,

    /// This OPTIONAL element specifies the scope to which this security token
    /// applies. Refer to [WS-PolicyAttachment] for more information. Note that
    /// if an <wsp:AppliesTo> was specified in the request, the same scope
    /// SHOULD be returned in the response (if a <wsp:AppliesTo> is returned).
    ///
    /// Required in our context for section 13.6.3 ws-fed
    ///
    /// The <t:RequestSecurityTokenResponse> element MAY include a
    /// wsp:AppliesTo / wsa:EndpointReference / wsa:Address element that
    /// specifies the Resource Realm URI.  Note that this data MUST be
    /// consistent with similar data present in security tokens (if any is
    /// present) – for example it must duplicate the information in the signed
    /// token’s saml:Audience element when SAML security tokens are returned.
    #[serde(rename = "AppliesTo")]
    pub applies_to: AppliesTo,

    /// Should have the value: http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey
    #[serde(rename = "KeyType")]
    pub key_type: Option<KeyType>,

    /// This is not listed within the spec for WS-Trust or WS-Fed. Should have
    /// the value: http://schemas.xmlsoap.org/ws/2005/02/trust/Issue
    ///
    /// This isn't present within the standard but it exists within Microsoft
    /// examples on their website:
    /// https://learn.microsoft.com/en-us/entra/identity-platform/reference-saml-tokens
    #[serde(rename = "RequestType")]
    pub request_type: Option<RequestType>,

    /// This OPTIONAL element specifies the lifetime of the issued security
    /// token. If omitted the lifetime is unspecified (not necessarily
    /// unlimited). It is RECOMMENDED that if a lifetime exists for a token that
    /// this element be included in the response.
    #[serde(rename = "LifeTime")]
    pub life_time: Option<LifeTime>,

    /// Since returned tokens are considered opaque to the requestor, this
    /// OPTIONAL element is specified to indicate how to reference the returned
    /// token when that token doesn't support references using URI fragments
    /// (XML ID). This element contains a <wsse:SecurityTokenReference> element
    /// that can be used verbatim to reference the token (when the token is
    /// placed inside a message). Typically tokens allow the use of wsu:Id so
    /// this element isn't required. Note that a token MAY support multiple
    /// reference mechanisms; this indicates the issuer’s preferred mechanism.
    /// When encrypted tokens are returned, this element is not needed since the
    /// <xenc:EncryptedData> element supports an ID reference. If this element
    /// is not present in the RSTR then the recipient can assume that the
    /// returned token (when present in a message) supports references using URI
    /// fragments.
    ///
    /// See section `4.4.2 Requested References` within WS-Trust for more
    /// information.
    #[serde(rename = "RequestedAttachedReference")]
    pub requested_attached_reference: Option<RequestedAttachedReference>,

    /// In some cases tokens need not be present in the message. This OPTIONAL
    /// element is specified to indicate how to reference the token when it is
    /// not placed inside the message. This element contains a
    /// <wsse:SecurityTokenReference> element that can be used verbatim to
    /// reference the token (when the token is not placed inside a message) for
    /// replies. Note that a token MAY support multiple external reference
    /// mechanisms; this indicates the issuer’s preferred mechanism.
    ///
    /// See section `4.4.2 Requested References` within WS-Trust for more
    /// information.
    #[serde(rename = "RequestedUnattachedReference")]
    pub requested_unattached_reference: Option<RequestedUnattachedReference>,
    // Not supported: <t:RequestedProofToken> <t:Entropy><t:BinarySecret>...</t:BinarySecret>
}
impl RequestSecurityTokenResponse {
    pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let event: Event<'_> = self.try_into()?;
        writer.write_event(event)?;
        Ok(String::from_utf8(write_buf)?)
    }
}

impl FromStr for RequestSecurityTokenResponse {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(quick_xml::de::from_str(s)?)
    }
}

impl TryFrom<&RequestSecurityTokenResponse> for Event<'_> {
    type Error = Box<dyn std::error::Error>;
    // pub fn to_xml(&self) -> Result<String, Box<dyn std::error::Error>> {
    fn try_from(value: &RequestSecurityTokenResponse) -> Result<Self, Self::Error> {
        let mut write_buf = Vec::new();
        let mut writer = Writer::new(Cursor::new(&mut write_buf));
        let mut root = BytesStart::new(RSTR_XML_NAME);

        // Writing namespaces here
        root.push_attribute(NS_WS_TRUST);
        if let Some(context) = value.context.as_ref() {
            root.push_attribute((RSTR_CONTEXT_ATTR_NAME, context.as_str()))
        }
        writer.write_event(Event::Start(root))?;

        let event: Event<'_> = (&value.applies_to).try_into()?;
        writer.write_event(event)?;

        let event: Event<'_> = (&value.requested_security_token).try_into()?;
        writer.write_event(event)?;

        if let Some(token_type) = value.token_type.as_ref() {
            let event: Event<'_> = token_type.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(request_type) = value.request_type.as_ref() {
            let event: Event<'_> = request_type.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(key_type) = value.key_type.as_ref() {
            let event: Event<'_> = key_type.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(life_time) = value.life_time.as_ref() {
            let event: Event<'_> = life_time.try_into()?;
            writer.write_event(event)?;
        }
        if let Some(requested_attached_reference) = value.requested_attached_reference.as_ref() {
            let event: Event<'_> = requested_attached_reference.try_into()?;
            writer.write_event(event)?;
        }

        if let Some(requested_unattached_reference) = value.requested_unattached_reference.as_ref()
        {
            let event: Event<'_> = requested_unattached_reference.try_into()?;
            writer.write_event(event)?;
        }

        writer.write_event(Event::End(BytesEnd::new(RSTR_XML_NAME)))?;
        Ok(Event::Text(BytesText::from_escaped(String::from_utf8(
            write_buf,
        )?)))
    }
}

#[cfg(test)]
mod test {
    use libxml::parser::Parser;
    use saml_1_1::{
        Assertion11, Attribute11, AttributeStatement11, AttributeValue11, AudienceRestriction11,
        AuthenticationStatement11, Conditions11, ConfirmationMethod11, Subject11,
        SubjectConfirmation11, SubjectNameID11,
    };

    use super::*;

    #[test]
    fn rstr_serdes_rt() {
        let rstr = RequestSecurityTokenResponse {
            context: Some("Something".to_string()),
            token_type: Some(TokenType {
                value: "token_type".to_string(),
            }),
            requested_security_token: RequestedSecurityToken {
                assertion: Assertion11 {
                    id: "assertion".to_string(),
                    issue_instant: chrono::Utc::now(),
                    signature: None,
                    conditions: Some(Conditions11 {
                        not_before: Some(chrono::Utc::now()),
                        not_on_or_after: Some(chrono::Utc::now()),
                        audience_restrictions: Some(vec![AudienceRestriction11 {
                            audience: vec!["1".to_string(), "2".to_string()],
                        }]),
                    }),
                    authn_statements: Some(vec![AuthenticationStatement11 {
                        authn_instant: Some(chrono::Utc::now()),
                        authn_method: Some("something".to_string()),
                        subject: Some(Subject11 {
                            name_id: Some(SubjectNameID11 {
                                format: Some("subject name id format".to_string()),
                                value: "subject name id value".to_string(),
                            }),
                            subject_confirmations: Some(vec![SubjectConfirmation11 {
                                methods: vec![ConfirmationMethod11 {
                                    value: Some("Subject confirmation Method".to_string()),
                                }],
                            }]),
                        }),
                    }]),
                    attribute_statements: Some(vec![AttributeStatement11 {
                        attributes: vec![Attribute11 {
                            name: Some("Name".to_string()),
                            namespace: Some("Namespace".to_string()),
                            values: vec![AttributeValue11 {
                                value: Some("AttributeValue".to_string()),
                            }],
                        }],
                        subject: Some(Subject11 {
                            name_id: Some(SubjectNameID11 {
                                format: Some("subject name id format".to_string()),
                                value: "subject name id value".to_string(),
                            }),
                            subject_confirmations: Some(vec![SubjectConfirmation11 {
                                methods: vec![ConfirmationMethod11 {
                                    value: Some("Subject confirmation Method".to_string()),
                                }],
                            }]),
                        }),
                    }]),
                    issuer: "Something".to_string(),
                },
            },
            applies_to: AppliesTo {
                endpoint_reference: EndpointReference {
                    address: Address {
                        value: "waffles.com".to_string(),
                    },
                },
            },
            key_type: Some(KeyType {
                value: "a key_type".to_string(),
            }),
            request_type: Some(RequestType {
                value: "request_type".to_string(),
            }),
            life_time: Some(LifeTime {
                created: Some(LifeTimeCreated {
                    value: "creation_time".to_string(),
                }),
                expires: Some(LifeTimeExpires {
                    value: "expiration_time".to_string(),
                }),
            }),
            requested_attached_reference: Some(RequestedAttachedReference {
                security_token_reference: SecurityTokenReference {
                    key_identifier: KeyIdentifier {
                        value: "My attached key".to_string(),
                    },
                },
            }),
            requested_unattached_reference: Some(RequestedUnattachedReference {
                security_token_reference: SecurityTokenReference {
                    key_identifier: KeyIdentifier {
                        value: "My unattached key".to_string(),
                    },
                },
            }),
        };
        let xml_body = rstr.to_xml().expect("Failed to produce XML");
        println!("{}", xml_body);
        let deserialized = RequestSecurityTokenResponse::from_str(&xml_body).unwrap();
        let parser = Parser::default();
        let _ = parser
            .parse_string(xml_body)
            .expect("Failed to parse XML document");

        assert_eq!(deserialized.context, rstr.context);
        assert_eq!(deserialized.token_type, rstr.token_type);
        // Skipping this because of a clock skew issue with issue instant cause
        // by parsing.

        // assert_eq!(deserialized.requested_security_token, rstr.requested_security_token);
        assert_eq!(deserialized.applies_to, rstr.applies_to);
        assert_eq!(deserialized.key_type, rstr.key_type);
        assert_eq!(deserialized.request_type, rstr.request_type);
        assert_eq!(deserialized.life_time, rstr.life_time);
        assert_eq!(
            deserialized.requested_attached_reference,
            rstr.requested_attached_reference
        );
        assert_eq!(
            deserialized.requested_unattached_reference,
            rstr.requested_unattached_reference
        );
        // Checking assertion for validity.
        let actual_assertion = &deserialized.requested_security_token.assertion;
        let expected_assertion = &rstr.requested_security_token.assertion;
        assert_eq!(actual_assertion.id, expected_assertion.id);
        assert_eq!(actual_assertion.issuer, expected_assertion.issuer);
        // assert_eq!()
        let actual_conditions = actual_assertion
            .conditions
            .as_ref()
            .expect("Missing actual conditions");
        assert!(actual_conditions.not_before.is_some());
        assert!(actual_conditions.not_on_or_after.is_some());
        let expected_conditions = expected_assertion
            .conditions
            .as_ref()
            .expect("Missing expected conditions");
        assert_eq!(
            actual_conditions.audience_restrictions,
            expected_conditions.audience_restrictions
        );
        // assert_eq!( expected_assertion.conditions.len());
        // assert_eq!(actual_assertion.conditions[0]., )

        let actual_authn_statements = actual_assertion
            .authn_statements
            .as_ref()
            .expect("Missing actual authn_statements");
        assert_eq!(actual_authn_statements.len(), 1);
        let actual_authn_statement = &actual_authn_statements[0];
        let expected_authn_statement = &expected_assertion
            .authn_statements
            .as_ref()
            .expect("Missing expected authn_statements")[0];

        assert!(actual_authn_statement.authn_instant.is_some());
        assert_eq!(
            actual_authn_statement.authn_method,
            expected_authn_statement.authn_method
        );
        assert_eq!(
            actual_authn_statement.subject,
            expected_authn_statement.subject
        );

        assert_eq!(
            actual_assertion.attribute_statements,
            expected_assertion.attribute_statements
        );
    }
}
