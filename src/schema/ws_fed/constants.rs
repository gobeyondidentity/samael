/// Namespace for WS-Trust.
pub(crate) const NS_WS_TRUST: (&'static str, &'static str) =
    ("xmlns:wst", "http://schemas.xmlsoap.org/ws/2005/02/trust");

/// Namespace for SOAP policy
pub(crate) const NS_WS_POLICY: (&'static str, &'static str) =
    ("xmlns:wsp", "http://schemas.xmlsoap.org/ws/2004/09/policy");

/// Namespace for WS address
pub(crate) const NS_WS_ADDRESS: (&'static str, &'static str) =
    ("xmlns:wsa", "http://www.w3.org/2005/08/addressing");

/// Namespace for WS-Security Utilities.
pub(crate) const NS_WS_SECURITY_UTILITY: (&'static str, &'static str) = (
    "xmlns:wsu",
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
);

/// Namespace for WS-Security SecExt
pub(crate) const NS_WS_SECURITY_SEC_EXT: (&'static str, &'static str) = (
    "xmlns:d3p1",
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
);

/// This is the namespace for the security token reference.
pub(crate) const NS_WS_SEC_EXT_1_0: (&'static str, &'static str) = (
    "xmlns:wssext1",
    "https://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
);

/// This is used to indicate that the provided attribute value is a SAML id.
pub(crate) const KEY_IDENTIFIER_VALUE_TYPE_SAML_ATTR: (&'static str, &'static str) = (
    "ValueType",
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID",
);

/// THis is used to indicate that, inside of a reference to a token.
pub(crate) const SECURITY_TOKEN_REFERENCE_SAML_TOKEN_TYPE_ATTR: (&'static str, &'static str) = (
    "d3p1:TokenType",
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0",
);

/// This is the default value we should have for the token type inside of an
/// RSTR,
pub const RSTR_TOKEN_TYPE_SAML: &str =
    "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

/// This is the default value for the key_type field inside of an RSTR.
pub const RSTR_KEY_TYPE_NO_PROOF: &str =
    "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey";

/// This is the default value for the reference_type field inside of an RSTR.
pub const RSTR_REFERENCE_TYPE_WS_TRUST: &str = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
