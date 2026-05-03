//! ATProto OAuth discovery metadata and endpoint constants.

use serde_json::{json, Value};

pub const OAUTH_PROTECTED_RESOURCE_PATH: &str = "/.well-known/oauth-protected-resource";
pub const OAUTH_AUTHORIZATION_SERVER_PATH: &str = "/.well-known/oauth-authorization-server";
pub const OAUTH_AUTHORIZE_PATH: &str = "/oauth/authorize";
pub const OAUTH_PAR_PATH: &str = "/oauth/par";
pub const OAUTH_TOKEN_PATH: &str = "/oauth/token";

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
