//! ATProto OAuth discovery metadata and endpoint constants.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use thiserror::Error;
use url::Url;

pub const OAUTH_PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";
pub const OAUTH_AUTHORIZATION_SERVER_PATH: &str = "/.well-known/oauth-authorization-server";
pub const OAUTH_AUTHORIZE_PATH: &str = "/oauth/authorize";
pub const OAUTH_PAR_PATH: &str = "/oauth/par";
pub const OAUTH_TOKEN_PATH: &str = "/oauth/token";
pub const OAUTH_REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
pub const OAUTH_PAR_EXPIRES_IN_SECONDS: i64 = 300;
pub const OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PushedAuthorizationRequest {
    pub client_id: String,
    pub response_type: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: String,
    pub redirect_uri: String,
    pub scope: String,
    pub login_hint: Option<String>,
    pub client_assertion_type: Option<String>,
    pub client_assertion: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub request_uri: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenRequest {
    AuthorizationCode {
        client_id: String,
        code: String,
        redirect_uri: String,
        code_verifier: String,
    },
    RefreshToken {
        client_id: String,
        refresh_token: String,
    },
}

impl PushedAuthorizationRequest {
    pub fn requested_scopes(&self) -> BTreeSet<&str> {
        self.scope.split_whitespace().collect()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "client_id": self.client_id,
            "response_type": self.response_type,
            "code_challenge": self.code_challenge,
            "code_challenge_method": self.code_challenge_method,
            "state": self.state,
            "redirect_uri": self.redirect_uri,
            "scope": self.scope,
            "login_hint": self.login_hint,
            "client_assertion_type": self.client_assertion_type,
            "client_assertion": self.client_assertion,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum OAuthRequestError {
    #[error("missing required OAuth parameter `{parameter}`")]
    MissingParameter { parameter: &'static str },

    #[error("duplicate OAuth parameter `{parameter}`")]
    DuplicateParameter { parameter: String },

    #[error("invalid OAuth parameter `{parameter}`: {message}")]
    InvalidParameter {
        parameter: &'static str,
        message: String,
    },

    #[error("unsupported OAuth parameter `{parameter}`")]
    UnsupportedParameter { parameter: &'static str },

    #[error("confidential OAuth client authentication is not implemented yet")]
    UnsupportedClientAuthentication,

    #[error("unsupported OAuth grant type `{grant_type}`")]
    UnsupportedGrantType { grant_type: String },

    #[error("malformed form body: {0}")]
    MalformedForm(String),
}

impl OAuthRequestError {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidParameter {
                parameter: "client_id",
                ..
            } => "invalid_client",
            Self::UnsupportedClientAuthentication => "invalid_client",
            Self::UnsupportedGrantType { .. } => "unsupported_grant_type",
            _ => "invalid_request",
        }
    }
}

pub fn is_oauth_well_known_path(path: &str) -> bool {
    matches!(
        path,
        OAUTH_PROTECTED_RESOURCE_PATH | OAUTH_AUTHORIZATION_SERVER_PATH
    )
}

pub fn is_oauth_endpoint_path(path: &str) -> bool {
    matches!(
        path,
        OAUTH_AUTHORIZE_PATH | OAUTH_PAR_PATH | OAUTH_TOKEN_PATH
    )
}

pub fn protected_resource_metadata(origin: &str) -> Value {
    json!({
        "resource": origin,
        "authorization_servers": [origin],
        "scopes_supported": oauth_scopes(),
    })
}

pub fn authorization_server_metadata(origin: &str) -> Value {
    json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}{OAUTH_AUTHORIZE_PATH}"),
        "token_endpoint": format!("{origin}{OAUTH_TOKEN_PATH}"),
        "pushed_authorization_request_endpoint": format!("{origin}{OAUTH_PAR_PATH}"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "scopes_supported": oauth_scopes(),
        "subject_types_supported": ["public"],
        "authorization_response_iss_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "require_request_uri_registration": true,
        "require_pushed_authorization_requests": true,
        "dpop_signing_alg_values_supported": ["ES256"],
        "client_id_metadata_document_supported": true,
    })
}

fn oauth_scopes() -> Vec<&'static str> {
    vec!["atproto", "transition:generic", "transition:email"]
}

pub fn is_localhost_client_id(client_id: &str) -> bool {
    Url::parse(client_id).is_ok_and(|url| {
        url.scheme() == "http"
            && url.host_str() == Some("localhost")
            && url.port().is_none()
            && url.path() == "/"
    })
}

pub fn validate_client_metadata(
    client_id: &str,
    metadata: Option<&Value>,
    redirect_uri: &str,
    scope: &str,
) -> Result<(), OAuthRequestError> {
    if is_localhost_client_id(client_id) {
        return validate_localhost_client_metadata(client_id, redirect_uri, scope);
    }

    let metadata = metadata.ok_or_else(|| {
        invalid_param(
            "client_id",
            "client metadata document is required".to_string(),
        )
    })?;
    if metadata.get("client_id").and_then(Value::as_str) != Some(client_id) {
        return Err(invalid_param(
            "client_id",
            "client metadata client_id did not match".to_string(),
        ));
    }
    if !json_array_contains(metadata.get("grant_types"), "authorization_code") {
        return Err(invalid_param(
            "client_id",
            "client metadata must include authorization_code grant".to_string(),
        ));
    }
    if !json_array_contains(metadata.get("response_types"), "code") {
        return Err(invalid_param(
            "client_id",
            "client metadata must include code response type".to_string(),
        ));
    }
    if metadata
        .get("dpop_bound_access_tokens")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_param(
            "client_id",
            "client metadata must require DPoP-bound access tokens".to_string(),
        ));
    }
    if metadata
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or("none")
        != "none"
    {
        return Err(OAuthRequestError::UnsupportedClientAuthentication);
    }
    if !metadata
        .get("redirect_uris")
        .and_then(Value::as_array)
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(redirect_uri))
        })
    {
        return Err(invalid_param(
            "redirect_uri",
            "redirect_uri is not declared by client metadata".to_string(),
        ));
    }
    let declared_scope = metadata
        .get("scope")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_param("scope", "client metadata must declare scope".to_string()))?;
    validate_requested_scope_subset(declared_scope, scope)
}

pub fn parse_authorization_request(
    params: &[(String, String)],
) -> Result<AuthorizationRequest, OAuthRequestError> {
    let fields = params_to_fields(params);
    let client_id = required_single(&fields, "client_id")?;
    validate_client_id(&client_id)?;
    let request_uri = required_single(&fields, "request_uri")?;
    validate_request_uri(&request_uri)?;

    Ok(AuthorizationRequest {
        client_id,
        request_uri,
    })
}

pub fn parse_pushed_authorization_request(
    body: &str,
) -> Result<PushedAuthorizationRequest, OAuthRequestError> {
    let fields = parse_form_urlencoded(body)?;

    if fields.contains_key("client_secret") {
        return Err(OAuthRequestError::UnsupportedParameter {
            parameter: "client_secret",
        });
    }

    let client_id = required_single(&fields, "client_id")?;
    validate_client_id(&client_id)?;
    let response_type = required_single(&fields, "response_type")?;
    if response_type != "code" {
        return Err(invalid_param(
            "response_type",
            "expected `code`".to_string(),
        ));
    }

    let code_challenge = required_single(&fields, "code_challenge")?;
    validate_code_challenge(&code_challenge)?;
    let code_challenge_method = required_single(&fields, "code_challenge_method")?;
    if code_challenge_method != "S256" {
        return Err(invalid_param(
            "code_challenge_method",
            "only `S256` is supported".to_string(),
        ));
    }

    let state = required_single(&fields, "state")?;
    validate_nonempty_length("state", &state, 2048)?;
    let redirect_uri = required_single(&fields, "redirect_uri")?;
    validate_redirect_uri(&redirect_uri)?;
    let scope = required_single(&fields, "scope")?;
    validate_scope(&scope)?;
    let login_hint = optional_single(&fields, "login_hint")?;
    if let Some(login_hint) = &login_hint {
        validate_nonempty_length("login_hint", login_hint, 2048)?;
    }

    let client_assertion_type = optional_single(&fields, "client_assertion_type")?;
    let client_assertion = optional_single(&fields, "client_assertion")?;
    match (&client_assertion_type, &client_assertion) {
        (None, None) => {}
        (Some(kind), Some(assertion)) if kind == OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER => {
            validate_nonempty_length("client_assertion", assertion, 100_000)?;
            return Err(OAuthRequestError::UnsupportedClientAuthentication);
        }
        (Some(_), Some(_)) => {
            return Err(invalid_param(
                "client_assertion_type",
                "expected JWT bearer client assertion type".to_string(),
            ));
        }
        (Some(_), None) => {
            return Err(OAuthRequestError::MissingParameter {
                parameter: "client_assertion",
            });
        }
        (None, Some(_)) => {
            return Err(OAuthRequestError::MissingParameter {
                parameter: "client_assertion_type",
            });
        }
    }

    Ok(PushedAuthorizationRequest {
        client_id,
        response_type,
        code_challenge,
        code_challenge_method,
        state,
        redirect_uri,
        scope,
        login_hint,
        client_assertion_type,
        client_assertion,
    })
}

pub fn parse_token_request(body: &str) -> Result<TokenRequest, OAuthRequestError> {
    let fields = parse_form_urlencoded(body)?;
    reject_unsupported_client_secret(&fields)?;
    reject_unsupported_client_assertion(&fields)?;

    let grant_type = required_single(&fields, "grant_type")?;
    match grant_type.as_str() {
        "authorization_code" => {
            let client_id = required_single(&fields, "client_id")?;
            validate_client_id(&client_id)?;
            let code = required_single(&fields, "code")?;
            validate_nonempty_length("code", &code, 2048)?;
            let redirect_uri = required_single(&fields, "redirect_uri")?;
            validate_redirect_uri(&redirect_uri)?;
            let code_verifier = required_single(&fields, "code_verifier")?;
            validate_code_verifier(&code_verifier)?;
            Ok(TokenRequest::AuthorizationCode {
                client_id,
                code,
                redirect_uri,
                code_verifier,
            })
        }
        "refresh_token" => {
            let client_id = required_single(&fields, "client_id")?;
            validate_client_id(&client_id)?;
            let refresh_token = required_single(&fields, "refresh_token")?;
            validate_nonempty_length("refresh_token", &refresh_token, 100_000)?;
            Ok(TokenRequest::RefreshToken {
                client_id,
                refresh_token,
            })
        }
        _ => Err(OAuthRequestError::UnsupportedGrantType { grant_type }),
    }
}

fn parse_form_urlencoded(body: &str) -> Result<BTreeMap<String, Vec<String>>, OAuthRequestError> {
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    if body.is_empty() {
        return Ok(fields);
    }

    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_form(key)?;
        let value = percent_decode_form(value)?;
        fields.entry(key).or_default().push(value);
    }
    Ok(fields)
}

fn reject_unsupported_client_secret(
    fields: &BTreeMap<String, Vec<String>>,
) -> Result<(), OAuthRequestError> {
    if fields.contains_key("client_secret") {
        Err(OAuthRequestError::UnsupportedParameter {
            parameter: "client_secret",
        })
    } else {
        Ok(())
    }
}

fn reject_unsupported_client_assertion(
    fields: &BTreeMap<String, Vec<String>>,
) -> Result<(), OAuthRequestError> {
    let client_assertion_type = optional_single(fields, "client_assertion_type")?;
    let client_assertion = optional_single(fields, "client_assertion")?;
    match (&client_assertion_type, &client_assertion) {
        (None, None) => Ok(()),
        (Some(kind), Some(assertion)) if kind == OAUTH_CLIENT_ASSERTION_TYPE_JWT_BEARER => {
            validate_nonempty_length("client_assertion", assertion, 100_000)?;
            Err(OAuthRequestError::UnsupportedClientAuthentication)
        }
        (Some(_), Some(_)) => Err(invalid_param(
            "client_assertion_type",
            "expected JWT bearer client assertion type".to_string(),
        )),
        (Some(_), None) => Err(OAuthRequestError::MissingParameter {
            parameter: "client_assertion",
        }),
        (None, Some(_)) => Err(OAuthRequestError::MissingParameter {
            parameter: "client_assertion_type",
        }),
    }
}

fn params_to_fields(params: &[(String, String)]) -> BTreeMap<String, Vec<String>> {
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    for (key, value) in params {
        fields.entry(key.clone()).or_default().push(value.clone());
    }
    fields
}

fn percent_decode_form(value: &str) -> Result<String, OAuthRequestError> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(OAuthRequestError::MalformedForm(
                        "incomplete percent escape".to_string(),
                    ));
                }
                let high = hex_value(bytes[index + 1]).ok_or_else(|| {
                    OAuthRequestError::MalformedForm("invalid percent escape".to_string())
                })?;
                let low = hex_value(bytes[index + 2]).ok_or_else(|| {
                    OAuthRequestError::MalformedForm("invalid percent escape".to_string())
                })?;
                out.push((high << 4) | low);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out)
        .map_err(|_| OAuthRequestError::MalformedForm("invalid utf-8".to_string()))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn required_single(
    fields: &BTreeMap<String, Vec<String>>,
    parameter: &'static str,
) -> Result<String, OAuthRequestError> {
    let value = optional_single(fields, parameter)?
        .ok_or(OAuthRequestError::MissingParameter { parameter })?;
    validate_nonempty_length(parameter, &value, 8192)?;
    Ok(value)
}

fn optional_single(
    fields: &BTreeMap<String, Vec<String>>,
    parameter: &'static str,
) -> Result<Option<String>, OAuthRequestError> {
    let Some(values) = fields.get(parameter) else {
        return Ok(None);
    };
    if values.len() > 1 {
        return Err(OAuthRequestError::DuplicateParameter {
            parameter: parameter.to_string(),
        });
    }
    Ok(values.first().cloned())
}

fn validate_client_id(value: &str) -> Result<(), OAuthRequestError> {
    let url = Url::parse(value).map_err(|error| invalid_param("client_id", error.to_string()))?;
    if url.username() != "" || url.password().is_some() || url.fragment().is_some() {
        return Err(invalid_param(
            "client_id",
            "must not contain credentials or fragment".to_string(),
        ));
    }
    match url.scheme() {
        "https" => {
            if url.host_str().is_none() {
                return Err(invalid_param("client_id", "missing hostname".to_string()));
            }
            if url.port().is_some() {
                return Err(invalid_param(
                    "client_id",
                    "https client_id must not include a port".to_string(),
                ));
            }
        }
        "http" => {
            if url.host_str() != Some("localhost") || url.port().is_some() || url.path() != "/" {
                return Err(invalid_param(
                    "client_id",
                    "http client_id is only allowed for exact localhost development clients"
                        .to_string(),
                ));
            }
        }
        _ => {
            return Err(invalid_param(
                "client_id",
                "expected https URL or exact http://localhost".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_redirect_uri(value: &str) -> Result<(), OAuthRequestError> {
    let url =
        Url::parse(value).map_err(|error| invalid_param("redirect_uri", error.to_string()))?;
    if url.fragment().is_some() {
        return Err(invalid_param(
            "redirect_uri",
            "must not include a fragment".to_string(),
        ));
    }
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(url.host_str()) => Ok(()),
        scheme if scheme.contains('.') && url.path().starts_with('/') => Ok(()),
        _ => Err(invalid_param(
            "redirect_uri",
            "expected https, loopback http, or reverse-domain native URI".to_string(),
        )),
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("127.0.0.1") | Some("::1") | Some("[::1]"))
}

fn validate_scope(value: &str) -> Result<(), OAuthRequestError> {
    let scopes = value.split_whitespace().collect::<BTreeSet<_>>();
    if !scopes.contains("atproto") {
        return Err(invalid_param("scope", "must include `atproto`".to_string()));
    }
    if scopes.is_empty() {
        return Err(invalid_param("scope", "must not be empty".to_string()));
    }
    Ok(())
}

fn validate_localhost_client_metadata(
    client_id: &str,
    redirect_uri: &str,
    scope: &str,
) -> Result<(), OAuthRequestError> {
    let url =
        Url::parse(client_id).map_err(|error| invalid_param("client_id", error.to_string()))?;
    let declared_redirects = url
        .query_pairs()
        .filter(|(key, _)| key == "redirect_uri")
        .map(|(_, value)| value.to_string())
        .collect::<Vec<_>>();
    let declared_redirects = if declared_redirects.is_empty() {
        vec!["http://127.0.0.1/".to_string(), "http://[::1]/".to_string()]
    } else {
        declared_redirects
    };
    if !declared_redirects
        .iter()
        .any(|declared| localhost_redirect_matches(declared, redirect_uri))
    {
        return Err(invalid_param(
            "redirect_uri",
            "redirect_uri is not declared by localhost client metadata".to_string(),
        ));
    }

    let declared_scope = url
        .query_pairs()
        .find(|(key, _)| key == "scope")
        .map(|(_, value)| value.to_string())
        .unwrap_or_else(|| "atproto".to_string());
    validate_requested_scope_subset(&declared_scope, scope)
}

fn localhost_redirect_matches(declared: &str, requested: &str) -> bool {
    let Ok(declared) = Url::parse(declared) else {
        return false;
    };
    let Ok(requested) = Url::parse(requested) else {
        return false;
    };
    declared.scheme() == "http"
        && requested.scheme() == "http"
        && is_loopback_host(declared.host_str())
        && is_loopback_host(requested.host_str())
        && declared.host_str() == requested.host_str()
        && declared.path() == requested.path()
}

fn validate_requested_scope_subset(
    declared_scope: &str,
    requested_scope: &str,
) -> Result<(), OAuthRequestError> {
    let declared = declared_scope.split_whitespace().collect::<BTreeSet<_>>();
    for requested in requested_scope.split_whitespace() {
        if !declared.contains(requested) {
            return Err(invalid_param(
                "scope",
                format!("scope `{requested}` is not declared by client metadata"),
            ));
        }
    }
    Ok(())
}

fn json_array_contains(value: Option<&Value>, needle: &str) -> bool {
    value
        .and_then(Value::as_array)
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(needle)))
}

fn validate_request_uri(value: &str) -> Result<(), OAuthRequestError> {
    validate_nonempty_length("request_uri", value, 2048)?;
    if value
        .strip_prefix(OAUTH_REQUEST_URI_PREFIX)
        .is_some_and(|token| !token.is_empty())
    {
        Ok(())
    } else {
        Err(invalid_param(
            "request_uri",
            "expected pushed authorization request URI".to_string(),
        ))
    }
}

fn validate_code_challenge(value: &str) -> Result<(), OAuthRequestError> {
    if !(43..=128).contains(&value.len()) {
        return Err(invalid_param(
            "code_challenge",
            "must be 43 to 128 characters".to_string(),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(invalid_param(
            "code_challenge",
            "contains characters outside the PKCE unreserved set".to_string(),
        ));
    }
    Ok(())
}

fn validate_code_verifier(value: &str) -> Result<(), OAuthRequestError> {
    if !(43..=128).contains(&value.len()) {
        return Err(invalid_param(
            "code_verifier",
            "must be 43 to 128 characters".to_string(),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return Err(invalid_param(
            "code_verifier",
            "contains characters outside the PKCE unreserved set".to_string(),
        ));
    }
    Ok(())
}

fn validate_nonempty_length(
    parameter: &'static str,
    value: &str,
    max_len: usize,
) -> Result<(), OAuthRequestError> {
    if value.is_empty() {
        return Err(invalid_param(parameter, "must not be empty".to_string()));
    }
    if value.len() > max_len {
        return Err(invalid_param(
            parameter,
            format!("must be at most {max_len} bytes"),
        ));
    }
    Ok(())
}

fn invalid_param(parameter: &'static str, message: String) -> OAuthRequestError {
    OAuthRequestError::InvalidParameter { parameter, message }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE_CHALLENGE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";

    fn array_strings<'a>(metadata: &'a Value, field: &str) -> Vec<&'a str> {
        metadata[field]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect()
    }

    #[test]
    fn protected_resource_metadata_points_to_authorization_server() {
        let metadata = protected_resource_metadata("https://pds.example.com");

        assert_eq!(metadata["resource"], "https://pds.example.com");
        assert_eq!(
            array_strings(&metadata, "authorization_servers"),
            vec!["https://pds.example.com"]
        );
        assert!(array_strings(&metadata, "scopes_supported").contains(&"atproto"));
    }

    #[test]
    fn authorization_server_metadata_has_required_atproto_oauth_fields() {
        let metadata = authorization_server_metadata("https://pds.example.com");

        assert_eq!(metadata["issuer"], "https://pds.example.com");
        assert_eq!(
            metadata["authorization_endpoint"],
            "https://pds.example.com/oauth/authorize"
        );
        assert_eq!(
            metadata["token_endpoint"],
            "https://pds.example.com/oauth/token"
        );
        assert_eq!(
            metadata["pushed_authorization_request_endpoint"],
            "https://pds.example.com/oauth/par"
        );
        assert!(array_strings(&metadata, "response_types_supported").contains(&"code"));
        assert!(array_strings(&metadata, "grant_types_supported").contains(&"authorization_code"));
        assert!(array_strings(&metadata, "grant_types_supported").contains(&"refresh_token"));
        assert!(array_strings(&metadata, "code_challenge_methods_supported").contains(&"S256"));
        assert!(array_strings(&metadata, "scopes_supported").contains(&"atproto"));
        assert_eq!(
            metadata["authorization_response_iss_parameter_supported"],
            true
        );
        assert_eq!(metadata["require_pushed_authorization_requests"], true);
        assert!(array_strings(&metadata, "dpop_signing_alg_values_supported").contains(&"ES256"));
        assert_eq!(metadata["client_id_metadata_document_supported"], true);
    }

    #[test]
    fn recognizes_oauth_paths() {
        assert!(is_oauth_well_known_path(OAUTH_PROTECTED_RESOURCE_PATH));
        assert!(is_oauth_well_known_path(OAUTH_AUTHORIZATION_SERVER_PATH));
        assert!(is_oauth_endpoint_path(OAUTH_AUTHORIZE_PATH));
        assert!(is_oauth_endpoint_path(OAUTH_PAR_PATH));
        assert!(is_oauth_endpoint_path(OAUTH_TOKEN_PATH));
        assert!(!is_oauth_endpoint_path("/oauth/revoke"));
    }

    #[test]
    fn parses_valid_public_localhost_par_request() {
        let request = parse_pushed_authorization_request(&format!(
            "client_id=http%3A%2F%2Flocalhost&response_type=code&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256&state=abc123&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=atproto+transition%3Ageneric&login_hint=alice.example"
        ))
        .unwrap();

        assert_eq!(request.client_id, "http://localhost");
        assert_eq!(request.response_type, "code");
        assert_eq!(request.code_challenge, CODE_CHALLENGE);
        assert_eq!(request.code_challenge_method, "S256");
        assert_eq!(request.state, "abc123");
        assert_eq!(request.redirect_uri, "http://127.0.0.1/callback");
        assert_eq!(request.scope, "atproto transition:generic");
        assert_eq!(request.login_hint.as_deref(), Some("alice.example"));
        assert!(request.requested_scopes().contains("atproto"));
    }

    #[test]
    fn parses_authorization_request_from_par_reference() {
        let request = parse_authorization_request(&[
            ("client_id".to_string(), "http://localhost".to_string()),
            (
                "request_uri".to_string(),
                format!("{OAUTH_REQUEST_URI_PREFIX}abc123"),
            ),
        ])
        .unwrap();

        assert_eq!(request.client_id, "http://localhost");
        assert_eq!(
            request.request_uri,
            format!("{OAUTH_REQUEST_URI_PREFIX}abc123")
        );
    }

    #[test]
    fn rejects_authorization_request_without_par_reference() {
        let error = parse_authorization_request(&[
            ("client_id".to_string(), "http://localhost".to_string()),
            (
                "request_uri".to_string(),
                "https://client.example/request".to_string(),
            ),
        ])
        .unwrap_err();

        assert!(matches!(
            error,
            OAuthRequestError::InvalidParameter {
                parameter: "request_uri",
                ..
            }
        ));
    }

    #[test]
    fn validates_localhost_client_metadata_from_query_params() {
        validate_client_metadata(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=atproto%20transition%3Ageneric",
            None,
            "http://127.0.0.1:4321/callback",
            "atproto transition:generic",
        )
        .unwrap();
    }

    #[test]
    fn rejects_scope_not_declared_by_client_metadata() {
        let error = validate_client_metadata(
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=atproto",
            None,
            "http://127.0.0.1/callback",
            "atproto transition:generic",
        )
        .unwrap_err();

        assert!(matches!(
            error,
            OAuthRequestError::InvalidParameter {
                parameter: "scope",
                ..
            }
        ));
    }

    #[test]
    fn validates_public_client_metadata_document() {
        let metadata = json!({
            "client_id": "https://client.example.com/oauth.json",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "redirect_uris": ["https://client.example.com/callback"],
            "scope": "atproto transition:generic",
            "dpop_bound_access_tokens": true,
            "token_endpoint_auth_method": "none",
        });

        validate_client_metadata(
            "https://client.example.com/oauth.json",
            Some(&metadata),
            "https://client.example.com/callback",
            "atproto",
        )
        .unwrap();
    }

    #[test]
    fn rejects_missing_atproto_scope() {
        let error = parse_pushed_authorization_request(&format!(
            "client_id=http%3A%2F%2Flocalhost&response_type=code&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256&state=abc123&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=transition%3Ageneric"
        ))
        .unwrap_err();

        assert!(matches!(
            error,
            OAuthRequestError::InvalidParameter {
                parameter: "scope",
                ..
            }
        ));
    }

    #[test]
    fn rejects_duplicate_single_value_fields() {
        let error = parse_pushed_authorization_request(&format!(
            "client_id=http%3A%2F%2Flocalhost&client_id=http%3A%2F%2Flocalhost&response_type=code&code_challenge={CODE_CHALLENGE}&code_challenge_method=S256&state=abc123&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=atproto"
        ))
        .unwrap_err();

        assert_eq!(
            error,
            OAuthRequestError::DuplicateParameter {
                parameter: "client_id".to_string()
            }
        );
    }

    #[test]
    fn rejects_plain_pkce() {
        let error = parse_pushed_authorization_request(&format!(
            "client_id=http%3A%2F%2Flocalhost&response_type=code&code_challenge={CODE_CHALLENGE}&code_challenge_method=plain&state=abc123&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&scope=atproto"
        ))
        .unwrap_err();

        assert!(matches!(
            error,
            OAuthRequestError::InvalidParameter {
                parameter: "code_challenge_method",
                ..
            }
        ));
    }

    #[test]
    fn rejects_malformed_form_encoding() {
        assert!(matches!(
            parse_pushed_authorization_request("client_id=%zz"),
            Err(OAuthRequestError::MalformedForm(_))
        ));
    }

    #[test]
    fn parses_authorization_code_token_request() {
        let request = parse_token_request(
            "grant_type=authorization_code&client_id=http%3A%2F%2Flocalhost&code=abc&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&code_verifier=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ",
        )
        .unwrap();

        assert_eq!(
            request,
            TokenRequest::AuthorizationCode {
                client_id: "http://localhost".to_string(),
                code: "abc".to_string(),
                redirect_uri: "http://127.0.0.1/callback".to_string(),
                code_verifier: CODE_CHALLENGE.to_string(),
            }
        );
    }

    #[test]
    fn parses_refresh_token_request() {
        let request = parse_token_request(
            "grant_type=refresh_token&client_id=http%3A%2F%2Flocalhost&refresh_token=token",
        )
        .unwrap();

        assert_eq!(
            request,
            TokenRequest::RefreshToken {
                client_id: "http://localhost".to_string(),
                refresh_token: "token".to_string(),
            }
        );
    }

    #[test]
    fn rejects_short_pkce_verifier() {
        let error = parse_token_request(
            "grant_type=authorization_code&client_id=http%3A%2F%2Flocalhost&code=abc&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&code_verifier=short",
        )
        .unwrap_err();

        assert!(matches!(
            error,
            OAuthRequestError::InvalidParameter {
                parameter: "code_verifier",
                ..
            }
        ));
    }
}
