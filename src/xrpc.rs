//! XRPC routing and query parameter helpers.

use thiserror::Error;

pub const SERVER_DESCRIBE_SERVER: &str = "com.atproto.server.describeServer";
pub const SERVER_CREATE_ACCOUNT: &str = "com.atproto.server.createAccount";
pub const SERVER_CREATE_SESSION: &str = "com.atproto.server.createSession";
pub const SERVER_GET_SESSION: &str = "com.atproto.server.getSession";
pub const SERVER_REFRESH_SESSION: &str = "com.atproto.server.refreshSession";
pub const SERVER_DELETE_SESSION: &str = "com.atproto.server.deleteSession";
pub const REPO_DESCRIBE_REPO: &str = "com.atproto.repo.describeRepo";
pub const REPO_GET_RECORD: &str = "com.atproto.repo.getRecord";
pub const REPO_LIST_RECORDS: &str = "com.atproto.repo.listRecords";
pub const REPO_CREATE_RECORD: &str = "com.atproto.repo.createRecord";
pub const REPO_PUT_RECORD: &str = "com.atproto.repo.putRecord";
pub const REPO_DELETE_RECORD: &str = "com.atproto.repo.deleteRecord";
pub const REPO_APPLY_WRITES: &str = "com.atproto.repo.applyWrites";
pub const REPO_UPLOAD_BLOB: &str = "com.atproto.repo.uploadBlob";
pub const REPO_LIST_MISSING_BLOBS: &str = "com.atproto.repo.listMissingBlobs";
pub const SYNC_GET_LATEST_COMMIT: &str = "com.atproto.sync.getLatestCommit";
pub const SYNC_GET_REPO_STATUS: &str = "com.atproto.sync.getRepoStatus";
pub const SYNC_LIST_REPOS: &str = "com.atproto.sync.listRepos";
pub const SYNC_SUBSCRIBE_REPOS: &str = "com.atproto.sync.subscribeRepos";
pub const SYNC_LIST_BLOBS: &str = "com.atproto.sync.listBlobs";
pub const SYNC_GET_BLOB: &str = "com.atproto.sync.getBlob";
pub const SYNC_GET_RECORD: &str = "com.atproto.sync.getRecord";
pub const SYNC_GET_REPO: &str = "com.atproto.sync.getRepo";

const DEFAULT_LIST_LIMIT: usize = 50;
const MAX_LIST_LIMIT: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XrpcRoute {
    Worker,
    DirectoryObject,
    HostRepoObject,
    RepoObject { name: String },
    Unsupported,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListRecordsParams {
    pub collection: String,
    pub limit: usize,
    pub cursor: Option<String>,
    pub reverse: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum XrpcError {
    #[error("missing required query parameter `{param}`")]
    MissingParam { param: &'static str },

    #[error("empty query parameter `{param}`")]
    EmptyParam { param: &'static str },

    #[error("invalid limit `{value}`: expected an integer from 1 to {max}")]
    InvalidLimit { value: String, max: usize },

    #[error("invalid boolean `{param}` value `{value}`: expected `true` or `false`")]
    InvalidBoolean { param: &'static str, value: String },
}

pub fn route_xrpc_method(method: &str, query: &[(String, String)]) -> Result<XrpcRoute, XrpcError> {
    match method {
        SERVER_DESCRIBE_SERVER => Ok(XrpcRoute::Worker),
        SERVER_CREATE_ACCOUNT
        | SERVER_CREATE_SESSION
        | SERVER_GET_SESSION
        | SERVER_REFRESH_SESSION
        | SERVER_DELETE_SESSION
        | SYNC_LIST_REPOS
        | SYNC_SUBSCRIBE_REPOS => Ok(XrpcRoute::DirectoryObject),
        REPO_CREATE_RECORD
        | REPO_PUT_RECORD
        | REPO_DELETE_RECORD
        | REPO_APPLY_WRITES
        | REPO_UPLOAD_BLOB
        | REPO_LIST_MISSING_BLOBS => Ok(XrpcRoute::HostRepoObject),
        REPO_DESCRIBE_REPO | REPO_GET_RECORD | REPO_LIST_RECORDS => {
            let repo = required_param(query, "repo")?;
            Ok(XrpcRoute::RepoObject {
                name: repo_object_name_from_identifier(&repo),
            })
        }
        SYNC_GET_LATEST_COMMIT
        | SYNC_GET_REPO_STATUS
        | SYNC_LIST_BLOBS
        | SYNC_GET_BLOB
        | SYNC_GET_RECORD
        | SYNC_GET_REPO => {
            let did = required_param(query, "did")?;
            Ok(XrpcRoute::RepoObject {
                name: repo_object_name_from_identifier(&did),
            })
        }
        _ => Ok(XrpcRoute::Unsupported),
    }
}

pub fn parse_list_records_params(
    query: &[(String, String)],
) -> Result<ListRecordsParams, XrpcError> {
    Ok(ListRecordsParams {
        collection: required_param(query, "collection")?,
        limit: parse_limit(optional_param(query, "limit").as_deref())?,
        cursor: optional_param(query, "cursor").filter(|value| !value.is_empty()),
        reverse: parse_bool_param(query, "reverse")?,
    })
}

pub fn required_param(
    query: &[(String, String)],
    param: &'static str,
) -> Result<String, XrpcError> {
    let value = query
        .iter()
        .find(|(key, _)| key == param)
        .map(|(_, value)| value.trim().to_string())
        .ok_or(XrpcError::MissingParam { param })?;
    if value.is_empty() {
        return Err(XrpcError::EmptyParam { param });
    }
    Ok(value)
}

pub fn optional_param(query: &[(String, String)], param: &str) -> Option<String> {
    query
        .iter()
        .find(|(key, _)| key == param)
        .map(|(_, value)| value.to_string())
}

pub fn repo_object_name_from_identifier(identifier: &str) -> String {
    identifier
        .strip_prefix("did:gsv:")
        .or_else(|| identifier.strip_prefix("did:web:"))
        .unwrap_or(identifier)
        .to_string()
}

pub fn at_uri(did: &str, collection: &str, rkey: &str) -> String {
    format!("at://{did}/{collection}/{rkey}")
}

fn parse_limit(value: Option<&str>) -> Result<usize, XrpcError> {
    let Some(value) = value else {
        return Ok(DEFAULT_LIST_LIMIT);
    };

    let limit = value
        .parse::<usize>()
        .map_err(|_| XrpcError::InvalidLimit {
            value: value.to_string(),
            max: MAX_LIST_LIMIT,
        })?;
    if !(1..=MAX_LIST_LIMIT).contains(&limit) {
        return Err(XrpcError::InvalidLimit {
            value: value.to_string(),
            max: MAX_LIST_LIMIT,
        });
    }
    Ok(limit)
}

fn parse_bool_param(query: &[(String, String)], param: &'static str) -> Result<bool, XrpcError> {
    match optional_param(query, param).as_deref() {
        None | Some("") | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(value) => Err(XrpcError::InvalidBoolean {
            param,
            value: value.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(params: &[(&str, &str)]) -> Vec<(String, String)> {
        params
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    #[test]
    fn routes_server_describe_to_worker() {
        assert_eq!(
            route_xrpc_method(SERVER_DESCRIBE_SERVER, &[]).unwrap(),
            XrpcRoute::Worker
        );
    }

    #[test]
    fn routes_directory_methods_to_directory_object() {
        for method in [
            SERVER_CREATE_ACCOUNT,
            SERVER_CREATE_SESSION,
            SERVER_GET_SESSION,
            SERVER_REFRESH_SESSION,
            SERVER_DELETE_SESSION,
            SYNC_LIST_REPOS,
            SYNC_SUBSCRIBE_REPOS,
        ] {
            assert_eq!(
                route_xrpc_method(method, &[]).unwrap(),
                XrpcRoute::DirectoryObject
            );
        }
    }

    #[test]
    fn routes_write_methods_to_host_repo_object() {
        for method in [
            REPO_CREATE_RECORD,
            REPO_PUT_RECORD,
            REPO_DELETE_RECORD,
            REPO_APPLY_WRITES,
            REPO_UPLOAD_BLOB,
            REPO_LIST_MISSING_BLOBS,
        ] {
            assert_eq!(
                route_xrpc_method(method, &[]).unwrap(),
                XrpcRoute::HostRepoObject
            );
        }
    }

    #[test]
    fn routes_repo_methods_to_repo_object_by_repo() {
        assert_eq!(
            route_xrpc_method(REPO_GET_RECORD, &query(&[("repo", "alice")])).unwrap(),
            XrpcRoute::RepoObject {
                name: "alice".to_string()
            }
        );
    }

    #[test]
    fn routes_gsv_dids_to_their_local_repo_name() {
        assert_eq!(
            route_xrpc_method(SYNC_GET_LATEST_COMMIT, &query(&[("did", "did:gsv:alice")])).unwrap(),
            XrpcRoute::RepoObject {
                name: "alice".to_string()
            }
        );
    }

    #[test]
    fn routes_hostname_did_web_to_their_local_repo_name() {
        assert_eq!(
            route_xrpc_method(
                SYNC_GET_LATEST_COMMIT,
                &query(&[("did", "did:web:pds.example.com")])
            )
            .unwrap(),
            XrpcRoute::RepoObject {
                name: "pds.example.com".to_string()
            }
        );
    }

    #[test]
    fn routes_sync_car_methods_to_repo_object_by_did() {
        assert_eq!(
            route_xrpc_method(SYNC_GET_REPO, &query(&[("did", "did:gsv:alice")])).unwrap(),
            XrpcRoute::RepoObject {
                name: "alice".to_string()
            }
        );
        assert_eq!(
            route_xrpc_method(SYNC_GET_RECORD, &query(&[("did", "did:gsv:alice")])).unwrap(),
            XrpcRoute::RepoObject {
                name: "alice".to_string()
            }
        );
    }

    #[test]
    fn routes_sync_blob_methods_to_repo_object_by_did() {
        assert_eq!(
            route_xrpc_method(SYNC_LIST_BLOBS, &query(&[("did", "did:gsv:alice")])).unwrap(),
            XrpcRoute::RepoObject {
                name: "alice".to_string()
            }
        );
        assert_eq!(
            route_xrpc_method(SYNC_GET_BLOB, &query(&[("did", "did:gsv:alice")])).unwrap(),
            XrpcRoute::RepoObject {
                name: "alice".to_string()
            }
        );
    }

    #[test]
    fn routes_repo_status_to_repo_object_by_did() {
        assert_eq!(
            route_xrpc_method(
                SYNC_GET_REPO_STATUS,
                &query(&[("did", "did:web:pds.example.com")])
            )
            .unwrap(),
            XrpcRoute::RepoObject {
                name: "pds.example.com".to_string()
            }
        );
    }

    #[test]
    fn requires_repo_identifier_for_repo_methods() {
        assert_eq!(
            route_xrpc_method(REPO_LIST_RECORDS, &[]).unwrap_err(),
            XrpcError::MissingParam { param: "repo" }
        );
    }

    #[test]
    fn parses_list_records_defaults() {
        assert_eq!(
            parse_list_records_params(&query(&[("collection", "app.gsv.feed.post")])).unwrap(),
            ListRecordsParams {
                collection: "app.gsv.feed.post".to_string(),
                limit: 50,
                cursor: None,
                reverse: false,
            }
        );
    }

    #[test]
    fn parses_list_records_cursor_limit_and_reverse() {
        assert_eq!(
            parse_list_records_params(&query(&[
                ("collection", "app.gsv.feed.post"),
                ("cursor", "app.gsv.feed.post/1"),
                ("limit", "2"),
                ("reverse", "true"),
            ]))
            .unwrap(),
            ListRecordsParams {
                collection: "app.gsv.feed.post".to_string(),
                limit: 2,
                cursor: Some("app.gsv.feed.post/1".to_string()),
                reverse: true,
            }
        );
    }

    #[test]
    fn rejects_out_of_range_list_limits() {
        assert_eq!(
            parse_list_records_params(&query(&[
                ("collection", "app.gsv.feed.post"),
                ("limit", "101"),
            ]))
            .unwrap_err(),
            XrpcError::InvalidLimit {
                value: "101".to_string(),
                max: 100,
            }
        );
    }

    #[test]
    fn builds_at_uris() {
        assert_eq!(
            at_uri("did:gsv:alice", "app.gsv.feed.post", "one"),
            "at://did:gsv:alice/app.gsv.feed.post/one"
        );
    }
}
