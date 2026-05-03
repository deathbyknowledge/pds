use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use futures_util::StreamExt;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, json, to_string, Value};
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue};
use worker::{
    durable_object, event, Context, DurableObject, Env, FixedLengthStream, Headers, HttpMetadata,
    Method, Request, RequestInit, Response, ResponseBody, SqlStorage, State, WebSocket,
    WebSocketIncomingMessage, WebSocketPair,
};

use crate::auth::{
    hash_password, session_claims, sign_token, verify_password, verify_token, ACCESS_SCOPE,
    REFRESH_SCOPE,
};
use crate::car::{decode_car, encode_car, encode_car_from_store, CarBlock, CarError};
use crate::cbor::encode_dag_cbor;
use crate::cid::{parse_cid, raw_cid, raw_cid_from_sha256_digest};
use crate::commit::{Did, RepoRev};
use crate::data_model::{Nsid, RecordKey, RepoPath};
use crate::do_store::{
    DirectoryAccountRow, DirectoryCommitEventInput, DirectoryEventRow, DirectoryRepoRow,
    DirectorySessionRow, RepoBlobRow, RepoCommitEventInput, RepoIdentityRow, RepoStateRow,
    SqlDirectoryStore, SqlRepoStore,
};
use crate::identity::{IdentityError, RepoSigningKey};
use crate::oauth::{
    authorization_server_metadata, is_oauth_well_known_path, protected_resource_metadata,
    OAUTH_AUTHORIZATION_SERVER_PATH, OAUTH_AUTHORIZE_PATH, OAUTH_PAR_PATH,
    OAUTH_PROTECTED_RESOURCE_PATH, OAUTH_TOKEN_PATH,
};
use crate::repo::{
    RepoError, RepoMutation, RepoOperation, RepoOperationAction, RepoWrite, SignedRepository,
};
use crate::repo_import::{
    diff_imported_records, extract_record_blob_refs as extract_import_record_blob_refs,
    validate_imported_repo, ImportRepoOp, RepoImportError,
};
use crate::storage::{RepoBlockStore, RepoRecordIndex, StorageError};
use crate::xrpc::{
    at_uri, optional_param, parse_get_blocks_params, parse_list_records_params, required_param,
    route_xrpc_method, REPO_APPLY_WRITES, REPO_CREATE_RECORD, REPO_DELETE_RECORD,
    REPO_DESCRIBE_REPO, REPO_GET_RECORD, REPO_IMPORT_REPO, REPO_LIST_MISSING_BLOBS,
    REPO_LIST_RECORDS, REPO_PUT_RECORD, REPO_UPLOAD_BLOB, SERVER_CREATE_ACCOUNT,
    SERVER_CREATE_SESSION, SERVER_DELETE_SESSION, SERVER_DESCRIBE_SERVER, SERVER_GET_SESSION,
    SERVER_REFRESH_SESSION, SYNC_GET_BLOB, SYNC_GET_BLOCKS, SYNC_GET_CHECKOUT, SYNC_GET_HEAD,
    SYNC_GET_HOST_STATUS, SYNC_GET_LATEST_COMMIT, SYNC_GET_RECORD, SYNC_GET_REPO,
    SYNC_GET_REPO_STATUS, SYNC_LIST_BLOBS, SYNC_LIST_REPOS, SYNC_LIST_REPOS_BY_COLLECTION,
    SYNC_SUBSCRIBE_REPOS,
};
use crate::xrpc::{XrpcError, XrpcRoute};

const DID_DOCUMENT_PATH: &str = "/.well-known/did.json";
const ATPROTO_DID_PATH: &str = "/.well-known/atproto-did";
const BLOB_BUCKET_BINDING: &str = "BLOB_BUCKET";
const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;
const MAX_IMPORT_REPO_BYTES: usize = 25 * 1024 * 1024;
const MAX_APPLY_WRITES: usize = 200;
const PASSWORD_SALT_BYTES: usize = 16;
const SESSION_ID_BYTES: usize = 24;
const REPO_SIGNING_KEY_BYTES: usize = 32;
const ACCESS_TOKEN_TTL_SECONDS: i64 = 15 * 60;
const REFRESH_TOKEN_TTL_SECONDS: i64 = 60 * 60 * 24 * 30;

#[event(fetch)]
async fn fetch(req: Request, env: worker::Env, _ctx: Context) -> worker::Result<Response> {
    let url = req.url()?;
    let parts = url
        .path()
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();

    if req.method() == Method::Options {
        return empty_response(204);
    }

    if req.method() == Method::Get && url.path() == "/xrpc/_health" {
        return health_response();
    }

    if req.method() == Method::Get && is_oauth_well_known_path(url.path()) {
        return oauth_metadata_response(&url);
    }

    if parts.len() >= 2 && parts[0] == "oauth" {
        let Some(host) = url.host_str() else {
            return json_response(
                400,
                &json!({
                    "error": "InvalidRequest",
                    "message": "request host is required",
                }),
            );
        };
        let namespace = env.durable_object("DIRECTORY_OBJECTS")?;
        let id = namespace.id_from_name(host)?;
        let stub = id.get_stub()?;
        return stub.fetch_with_request(req).await;
    }

    if req.method() == Method::Get && is_host_identity_path(url.path()) {
        let Some(host) = url.host_str() else {
            return json_response(
                400,
                &json!({
                    "error": "InvalidRequest",
                    "message": "request host is required",
                }),
            );
        };
        let namespace = env.durable_object("REPO_OBJECTS")?;
        let id = namespace.id_from_name(host)?;
        let stub = id.get_stub()?;
        return stub.fetch_with_request(req).await;
    }

    if parts.len() >= 2 && parts[0] == "xrpc" && !parts[1].is_empty() {
        let query = query_pairs(&url);
        return match route_xrpc_method(parts[1], &query) {
            Ok(XrpcRoute::Worker) => describe_server(&url),
            Ok(XrpcRoute::DirectoryObject) => {
                let Some(host) = url.host_str() else {
                    return json_response(
                        400,
                        &json!({
                            "error": "InvalidRequest",
                            "message": "request host is required",
                        }),
                    );
                };
                let namespace = env.durable_object("DIRECTORY_OBJECTS")?;
                let id = namespace.id_from_name(host)?;
                let stub = id.get_stub()?;
                stub.fetch_with_request(req).await
            }
            Ok(XrpcRoute::HostRepoObject) => {
                let Some(host) = url.host_str() else {
                    return json_response(
                        400,
                        &json!({
                            "error": "InvalidRequest",
                            "message": "request host is required",
                        }),
                    );
                };
                let namespace = env.durable_object("REPO_OBJECTS")?;
                let id = namespace.id_from_name(host)?;
                let stub = id.get_stub()?;
                stub.fetch_with_request(req).await
            }
            Ok(XrpcRoute::RepoObject { name }) => {
                let namespace = env.durable_object("REPO_OBJECTS")?;
                let id = namespace.id_from_name(&name)?;
                let stub = id.get_stub()?;
                stub.fetch_with_request(req).await
            }
            Ok(XrpcRoute::Unsupported) => json_response(
                404,
                &json!({
                    "error": "MethodNotFound",
                    "message": format!("unsupported XRPC method `{}`", parts[1]),
                }),
            ),
            Err(error) => json_response(
                400,
                &json!({
                    "error": "InvalidRequest",
                    "message": error.to_string(),
                }),
            ),
        };
    }

    if parts.len() >= 2 && parts[0] == "repos" && !parts[1].is_empty() {
        let namespace = env.durable_object("REPO_OBJECTS")?;
        let id = namespace.id_from_name(parts[1])?;
        let stub = id.get_stub()?;
        return stub.fetch_with_request(req).await;
    }

    json_response(
        200,
        &json!({
            "name": "gsv-pds",
            "version": env!("CARGO_PKG_VERSION"),
            "status": "ready",
            "routes": {
                "repoStatus": "GET /repos/:name/status",
                "repoInit": "POST /repos/:name/init",
                "repoDirectorySync": "POST /repos/:name/directory-sync",
                "recordCreate": "POST /repos/:name/records",
                "recordUpdate": "PUT /repos/:name/records",
                "recordDelete": "DELETE /repos/:name/records",
                "recordRead": "GET /repos/:name/records?path=collection/rkey",
                "recordList": "GET /repos/:name/records?collection=nsid",
                "oauthProtectedResource": "GET /.well-known/oauth-protected-resource",
                "oauthAuthorizationServer": "GET /.well-known/oauth-authorization-server",
                "oauthPar": "POST /oauth/par",
                "oauthAuthorize": "GET /oauth/authorize",
                "oauthToken": "POST /oauth/token",
                "xrpcDescribeServer": "GET /xrpc/com.atproto.server.describeServer",
                "xrpcCreateAccount": "POST /xrpc/com.atproto.server.createAccount",
                "xrpcCreateSession": "POST /xrpc/com.atproto.server.createSession",
                "xrpcGetSession": "GET /xrpc/com.atproto.server.getSession",
                "xrpcRefreshSession": "POST /xrpc/com.atproto.server.refreshSession",
                "xrpcDeleteSession": "POST /xrpc/com.atproto.server.deleteSession",
                "xrpcDescribeRepo": "GET /xrpc/com.atproto.repo.describeRepo?repo=:repo",
                "xrpcGetRecord": "GET /xrpc/com.atproto.repo.getRecord?repo=:repo&collection=:nsid&rkey=:rkey",
                "xrpcListRecords": "GET /xrpc/com.atproto.repo.listRecords?repo=:repo&collection=:nsid",
                "xrpcCreateRecord": "POST /xrpc/com.atproto.repo.createRecord",
                "xrpcPutRecord": "POST /xrpc/com.atproto.repo.putRecord",
                "xrpcDeleteRecord": "POST /xrpc/com.atproto.repo.deleteRecord",
                "xrpcApplyWrites": "POST /xrpc/com.atproto.repo.applyWrites",
                "xrpcImportRepo": "POST /xrpc/com.atproto.repo.importRepo",
                "xrpcUploadBlob": "POST /xrpc/com.atproto.repo.uploadBlob",
                "xrpcListMissingBlobs": "GET /xrpc/com.atproto.repo.listMissingBlobs",
                "xrpcGetLatestCommit": "GET /xrpc/com.atproto.sync.getLatestCommit?did=:did",
                "xrpcGetHead": "GET /xrpc/com.atproto.sync.getHead?did=:did",
                "xrpcGetRepoStatus": "GET /xrpc/com.atproto.sync.getRepoStatus?did=:did",
                "xrpcListRepos": "GET /xrpc/com.atproto.sync.listRepos",
                "xrpcListReposByCollection": "GET /xrpc/com.atproto.sync.listReposByCollection?collection=:nsid",
                "xrpcSubscribeRepos": "GET /xrpc/com.atproto.sync.subscribeRepos",
                "xrpcGetHostStatus": "GET /xrpc/com.atproto.sync.getHostStatus?hostname=:hostname",
                "xrpcListBlobs": "GET /xrpc/com.atproto.sync.listBlobs?did=:did",
                "xrpcGetBlob": "GET /xrpc/com.atproto.sync.getBlob?did=:did&cid=:cid",
                "xrpcGetBlocks": "GET /xrpc/com.atproto.sync.getBlocks?did=:did&cids=:cid",
                "xrpcSyncGetRecord": "GET /xrpc/com.atproto.sync.getRecord?did=:did&collection=:nsid&rkey=:rkey",
                "xrpcGetCheckout": "GET /xrpc/com.atproto.sync.getCheckout?did=:did",
                "xrpcSyncGetRepo": "GET /xrpc/com.atproto.sync.getRepo?did=:did",
                "didWeb": "GET /.well-known/did.json",
                "handleDid": "GET /.well-known/atproto-did"
            }
        }),
    )
}

#[durable_object]
pub struct RepoObject {
    sql: SqlStorage,
    #[allow(dead_code)]
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for RepoObject {
    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
        SqlRepoStore::new(sql.clone())
            .init_schema()
            .expect("initialize repo durable object schema");
        Self { sql, state, env }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        match self.handle(&mut req).await {
            Ok(response) => Ok(response),
            Err(error) => json_response(
                error.status,
                &json!({
                    "error": error.message,
                }),
            ),
        }
    }
}

#[durable_object]
pub struct PdsDirectoryObject {
    sql: SqlStorage,
    #[allow(dead_code)]
    state: State,
    #[allow(dead_code)]
    env: Env,
}

impl DurableObject for PdsDirectoryObject {
    fn new(state: State, env: Env) -> Self {
        let sql = state.storage().sql();
        SqlDirectoryStore::new(sql.clone())
            .init_schema()
            .expect("initialize PDS directory durable object schema");
        Self { sql, state, env }
    }

    async fn fetch(&self, mut req: Request) -> worker::Result<Response> {
        match self.handle(&mut req).await {
            Ok(response) => Ok(response),
            Err(error) => json_response(
                error.status,
                &json!({
                    "error": error.message,
                }),
            ),
        }
    }

    async fn websocket_message(
        &self,
        _ws: WebSocket,
        _message: WebSocketIncomingMessage,
    ) -> worker::Result<()> {
        Ok(())
    }

    async fn websocket_close(
        &self,
        _ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> worker::Result<()> {
        Ok(())
    }

    async fn websocket_error(&self, _ws: WebSocket, _error: worker::Error) -> worker::Result<()> {
        Ok(())
    }
}

impl PdsDirectoryObject {
    async fn handle(&self, req: &mut Request) -> Result<Response, HttpError> {
        if req.method() == Method::Options {
            return empty_response(204).map_err(HttpError::worker);
        }

        let url = req.url().map_err(HttpError::worker)?;
        let parts = url
            .path()
            .trim_start_matches('/')
            .split('/')
            .collect::<Vec<_>>();

        if req.method() == Method::Get
            && parts.len() >= 2
            && parts[0] == "xrpc"
            && parts[1] == SYNC_LIST_REPOS
        {
            return self.xrpc_list_repos(&url);
        }
        if req.method() == Method::Get
            && parts.len() >= 2
            && parts[0] == "xrpc"
            && parts[1] == SYNC_LIST_REPOS_BY_COLLECTION
        {
            return self.xrpc_list_repos_by_collection(&url);
        }
        if req.method() == Method::Get
            && parts.len() >= 2
            && parts[0] == "xrpc"
            && parts[1] == SYNC_GET_HOST_STATUS
        {
            return self.xrpc_get_host_status(req, &url);
        }
        if req.method() == Method::Get
            && parts.len() >= 2
            && parts[0] == "xrpc"
            && parts[1] == SYNC_SUBSCRIBE_REPOS
        {
            return self.xrpc_subscribe_repos(req, &url);
        }
        if parts.len() >= 2 && parts[0] == "oauth" {
            return match (req.method(), url.path()) {
                (Method::Get, OAUTH_AUTHORIZE_PATH) => self.oauth_authorize(),
                (Method::Post, OAUTH_PAR_PATH) => {
                    self.oauth_pushed_authorization_request(req).await
                }
                (Method::Post, OAUTH_TOKEN_PATH) => self.oauth_token(req).await,
                (_, OAUTH_AUTHORIZE_PATH | OAUTH_PAR_PATH | OAUTH_TOKEN_PATH) => {
                    Err(HttpError::new(405, "method not allowed"))
                }
                _ => Err(HttpError::new(404, "unsupported OAuth endpoint")),
            };
        }
        if parts.len() >= 2 && parts[0] == "xrpc" {
            return match (req.method(), parts[1]) {
                (Method::Post, SERVER_CREATE_ACCOUNT) => self.xrpc_create_account(req, &url).await,
                (Method::Post, SERVER_CREATE_SESSION) => self.xrpc_create_session(req, &url).await,
                (Method::Get, SERVER_GET_SESSION) => self.xrpc_get_session(req, &url),
                (Method::Post, SERVER_REFRESH_SESSION) => {
                    self.xrpc_refresh_session(req, &url).await
                }
                (Method::Post, SERVER_DELETE_SESSION) => self.xrpc_delete_session(req),
                (
                    _,
                    SERVER_CREATE_ACCOUNT
                    | SERVER_CREATE_SESSION
                    | SERVER_GET_SESSION
                    | SERVER_REFRESH_SESSION
                    | SERVER_DELETE_SESSION
                    | SYNC_LIST_REPOS
                    | SYNC_LIST_REPOS_BY_COLLECTION
                    | SYNC_GET_HOST_STATUS
                    | SYNC_SUBSCRIBE_REPOS,
                ) => Err(HttpError::new(405, "method not allowed")),
                _ => Err(HttpError::new(404, "unsupported XRPC method")),
            };
        }

        match (req.method(), url.path()) {
            (Method::Get, "/directory/status") => self.status(),
            (Method::Post, "/directory/repos/upsert") => self.upsert_repo(req).await,
            _ => Err(HttpError::new(404, "not found")),
        }
    }

    fn store(&self) -> SqlDirectoryStore {
        SqlDirectoryStore::new(self.sql.clone())
    }

    fn status(&self) -> Result<Response, HttpError> {
        let store = self.store();
        json_response(
            200,
            &json!({
                "repos": store.repo_count().map_err(HttpError::worker)?,
                "accounts": store.account_count().map_err(HttpError::worker)?,
                "events": store.event_count().map_err(HttpError::worker)?,
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn xrpc_create_account(
        &self,
        req: &mut Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcCreateAccountRequest = req.json().await.map_err(HttpError::worker)?;
        let request_host = request_host(req)?;
        ensure_supported_account_handle(&body.handle, &request_host)?;
        if body.did.is_some() || body.plc_op.is_some() {
            return Err(HttpError::new(
                400,
                "importing existing DIDs is not implemented",
            ));
        }
        let password = body
            .password
            .as_deref()
            .ok_or_else(|| HttpError::new(400, "InvalidPassword: password is required"))?;
        ensure_password_strength(password)?;
        let store = self.store();
        if store
            .get_account_by_identifier(&body.handle)
            .map_err(HttpError::worker)?
            .is_some()
        {
            return Err(HttpError::new(400, "HandleNotAvailable"));
        }

        let did = Did::new(format!("did:web:{}", body.handle)).map_err(HttpError::bad_request)?;
        let repo_name = body.handle.clone();
        let signing_key_hex = generate_repo_signing_key_hex()?;
        let init = self
            .initialize_account_repo(
                url,
                &repo_name,
                did.as_str(),
                &body.handle,
                &signing_key_hex,
            )
            .await?;

        let salt = random_bytes::<PASSWORD_SALT_BYTES>()?;
        let account = DirectoryAccountRow {
            did: did.clone(),
            handle: body.handle.clone(),
            email: body.email.clone(),
            password_hash: hash_password(password, &salt),
            repo_name: repo_name.clone(),
            public_key_multibase: init.public_key_multibase.clone(),
            active: true,
            status: None,
        };
        store.insert_account(&account).map_err(HttpError::worker)?;
        let repo = DirectoryRepoRow {
            did: did.clone(),
            handle: body.handle.clone(),
            repo_name,
            head: parse_cid(&init.latest_commit).map_err(HttpError::bad_request)?,
            rev: RepoRev::new(init.latest_rev).map_err(HttpError::bad_request)?,
            active: true,
        };
        store.upsert_repo(&repo).map_err(HttpError::worker)?;
        let event = store
            .append_account_event(&did, true, None)
            .map_err(HttpError::worker)?;
        self.broadcast_repo_event(&event)?;

        let session = self.create_session_for_account(&account)?;
        store
            .insert_session(&session.row)
            .map_err(HttpError::worker)?;
        json_response(200, &session_response(url, &account, Some(session.tokens)))
            .map_err(HttpError::worker)
    }

    async fn xrpc_create_session(
        &self,
        req: &mut Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let body: XrpcCreateSessionRequest = req.json().await.map_err(HttpError::worker)?;
        let Some(account) = self
            .store()
            .get_account_by_identifier(&body.identifier)
            .map_err(HttpError::worker)?
        else {
            return Err(HttpError::new(401, "invalid identifier or password"));
        };
        if !verify_password(&body.password, &account.password_hash).map_err(HttpError::auth)? {
            return Err(HttpError::new(401, "invalid identifier or password"));
        }
        if !account.active {
            return Err(HttpError::new(403, "AccountTakedown"));
        }

        let session = self.create_session_for_account(&account)?;
        self.store()
            .insert_session(&session.row)
            .map_err(HttpError::worker)?;
        json_response(200, &session_response(url, &account, Some(session.tokens)))
            .map_err(HttpError::worker)
    }

    fn xrpc_get_session(&self, req: &Request, url: &worker::Url) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        json_response(200, &session_response(url, &account, None)).map_err(HttpError::worker)
    }

    async fn xrpc_refresh_session(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, REFRESH_SCOPE)?;
        let Some(session) = self
            .store()
            .get_session_by_refresh_jti(&claims.jti)
            .map_err(HttpError::worker)?
        else {
            return Err(HttpError::new(401, "InvalidToken"));
        };
        if !session.active || session.refresh_jti != claims.jti {
            return Err(HttpError::new(401, "InvalidToken"));
        }
        let account = self.account_for_claims(&claims)?;
        let refreshed = self.create_session_for_account(&account)?;
        self.store()
            .rotate_session_refresh(&session.session_id, &refreshed.row.refresh_jti)
            .map_err(HttpError::worker)?;
        json_response(
            200,
            &session_response(url, &account, Some(refreshed.tokens)),
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_delete_session(&self, req: &Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, REFRESH_SCOPE)?;
        self.store()
            .delete_session_by_refresh_jti(&claims.jti)
            .map_err(HttpError::worker)?;
        empty_response(200).map_err(HttpError::worker)
    }

    fn xrpc_list_repos(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let limit = parse_xrpc_limit(optional_param(&params, "limit").as_deref(), 500, 1000)?;
        let cursor = optional_param(&params, "cursor").filter(|value| !value.is_empty());
        let (repos, next_cursor) = self
            .store()
            .list_repos(limit, cursor.as_deref())
            .map_err(HttpError::worker)?;

        let mut body = json!({
            "repos": repos
                .into_iter()
                .map(directory_repo_json)
                .collect::<Vec<_>>()
        });
        if let Some(cursor) = next_cursor {
            body["cursor"] = json!(cursor);
        }

        json_response(200, &body).map_err(HttpError::worker)
    }

    fn xrpc_list_repos_by_collection(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let collection = Nsid::new(required_param(&params, "collection").map_err(HttpError::xrpc)?)
            .map_err(HttpError::bad_request)?;
        let limit = parse_xrpc_limit(optional_param(&params, "limit").as_deref(), 500, 2000)?;
        let cursor = optional_param(&params, "cursor").filter(|value| !value.is_empty());
        let (repos, next_cursor) = self
            .store()
            .list_repos_by_collection(&collection, limit, cursor.as_deref())
            .map_err(HttpError::worker)?;

        let mut body = json!({
            "repos": repos
                .into_iter()
                .map(|did| json!({ "did": did.to_string() }))
                .collect::<Vec<_>>(),
        });
        if let Some(cursor) = next_cursor {
            body["cursor"] = json!(cursor);
        }

        json_response(200, &body).map_err(HttpError::worker)
    }

    fn xrpc_get_host_status(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let hostname = required_param(&params, "hostname").map_err(HttpError::xrpc)?;
        let request_host = request_host(req)?;
        if hostname != request_host {
            return Err(HttpError::new(404, "HostNotFound"));
        }
        let store = self.store();
        json_response(
            200,
            &json!({
                "hostname": hostname,
                "seq": store.max_event_seq().map_err(HttpError::worker)?,
                "accountCount": store.account_count().map_err(HttpError::worker)?,
                "status": "active",
            }),
        )
        .map_err(HttpError::worker)
    }

    fn oauth_authorize(&self) -> Result<Response, HttpError> {
        oauth_error_response(
            501,
            "temporarily_unavailable",
            "OAuth authorization UI is not implemented yet",
        )
        .map_err(HttpError::worker)
    }

    async fn oauth_pushed_authorization_request(
        &self,
        req: &mut Request,
    ) -> Result<Response, HttpError> {
        ensure_form_urlencoded(req)?;
        let _ = req.text().await.map_err(HttpError::worker)?;
        oauth_error_response(
            501,
            "temporarily_unavailable",
            "OAuth pushed authorization requests are not implemented yet",
        )
        .map_err(HttpError::worker)
    }

    async fn oauth_token(&self, req: &mut Request) -> Result<Response, HttpError> {
        ensure_form_urlencoded(req)?;
        let _ = req.text().await.map_err(HttpError::worker)?;
        oauth_error_response(
            501,
            "temporarily_unavailable",
            "OAuth token exchange is not implemented yet",
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_subscribe_repos(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let upgrade = req
            .headers()
            .get("upgrade")
            .map_err(HttpError::worker)?
            .unwrap_or_default();
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return json_response(
                426,
                &json!({
                    "error": "UpgradeRequired",
                    "message": "com.atproto.sync.subscribeRepos requires a WebSocket upgrade",
                }),
            )
            .map_err(HttpError::worker);
        }

        let params = query_pairs(url);
        let cursor = optional_param(&params, "cursor")
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.parse::<i64>().map_err(|_| {
                    HttpError::new(
                        400,
                        format!("invalid cursor `{value}`: expected integer seq"),
                    )
                })
            })
            .transpose()?
            .unwrap_or(self.store().max_event_seq().map_err(HttpError::worker)?);

        let pair = WebSocketPair::new().map_err(HttpError::worker)?;
        self.state.accept_web_socket(&pair.server);

        let events = self
            .store()
            .list_events_after(cursor, 500)
            .map_err(HttpError::worker)?;
        for event in events {
            let frame = subscribe_event_frame(&event)?;
            pair.server
                .send_with_bytes(frame)
                .map_err(HttpError::worker)?;
        }

        Response::from_websocket(pair.client).map_err(HttpError::worker)
    }

    async fn upsert_repo(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: DirectoryUpsertRepoRequest = req.json().await.map_err(HttpError::worker)?;
        let records = body.records.map(validate_repo_paths).transpose()?;
        let row = DirectoryRepoRow {
            did: Did::new(body.did).map_err(HttpError::bad_request)?,
            handle: body.handle,
            repo_name: body.repo_name,
            head: parse_cid(&body.head).map_err(HttpError::bad_request)?,
            rev: RepoRev::new(body.rev).map_err(HttpError::bad_request)?,
            active: body.active.unwrap_or(true),
        };
        let store = self.store();
        store.upsert_repo(&row).map_err(HttpError::worker)?;
        if let Some(records) = &records {
            store
                .replace_repo_record_paths(&row.did, records)
                .map_err(HttpError::worker)?;
        }
        let stored_event = if let Some(event) = body.event {
            let blocks = BASE64_STANDARD
                .decode(event.blocks_base64)
                .map_err(HttpError::bad_request)?;
            let event_record_paths = repo_record_path_ops_from_commit_ops(&event.ops)?;
            let event = DirectoryCommitEventInput {
                did: row.did.clone(),
                commit_cid: row.head,
                rev: row.rev.clone(),
                since: event
                    .since
                    .map(RepoRev::new)
                    .transpose()
                    .map_err(HttpError::bad_request)?,
                blocks,
                ops_json: to_string(&event.ops).map_err(HttpError::worker)?,
                blobs_json: to_string(&event.blobs.unwrap_or_default())
                    .map_err(HttpError::worker)?,
            };
            let stored = store
                .append_commit_event(&event)
                .map_err(HttpError::worker)?;
            if records.is_none() {
                store
                    .upsert_repo_record_paths(&row.did, &event_record_paths.upserts)
                    .map_err(HttpError::worker)?;
                store
                    .delete_repo_record_paths(&row.did, &event_record_paths.deletes)
                    .map_err(HttpError::worker)?;
            }
            Some(stored)
        } else {
            None
        };
        if let Some(event) = &stored_event {
            self.broadcast_repo_event(event)?;
        }

        json_response(
            200,
            &json!({
                "ok": true,
                "repo": directory_repo_json(row),
                "seq": stored_event.as_ref().map(|event| event.seq),
            }),
        )
        .map_err(HttpError::worker)
    }

    fn broadcast_repo_event(&self, event: &DirectoryEventRow) -> Result<(), HttpError> {
        let frame = subscribe_event_frame(event)?;
        for socket in self.state.get_websockets() {
            let _ = socket.send_with_bytes(&frame);
        }
        Ok(())
    }

    async fn initialize_account_repo(
        &self,
        url: &worker::Url,
        repo_name: &str,
        did: &str,
        handle: &str,
        signing_key_p256_hex: &str,
    ) -> Result<InternalInitRepoResponse, HttpError> {
        let namespace = self
            .env
            .durable_object("REPO_OBJECTS")
            .map_err(HttpError::worker)?;
        let id = namespace
            .id_from_name(repo_name)
            .map_err(HttpError::worker)?;
        let stub = id.get_stub().map_err(HttpError::worker)?;
        let body = json!({
            "did": did,
            "handle": handle,
            "rev": generated_initial_repo_rev()?.to_string(),
            "signingKeyP256Hex": signing_key_p256_hex,
            "reset": false,
            "notifyDirectory": false,
        });
        let headers = Headers::new();
        headers
            .set("content-type", "application/json")
            .map_err(HttpError::worker)?;
        headers
            .set("x-pds-admin-token", &admin_token_from_env(&self.env)?)
            .map_err(HttpError::worker)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(JsValue::from_str(&body.to_string())));
        let request = Request::new_with_init(
            &format!("{}/repos/{}/init", request_origin(url), repo_name),
            &init,
        )
        .map_err(HttpError::worker)?;
        let mut response = stub
            .fetch_with_request(request)
            .await
            .map_err(HttpError::worker)?;
        if !(200..=299).contains(&response.status_code()) {
            let text = response.text().await.unwrap_or_else(|_| String::new());
            return Err(HttpError::new(
                response.status_code(),
                format!("failed to initialize repo: {text}"),
            ));
        }
        response.json().await.map_err(HttpError::worker)
    }

    fn create_session_for_account(
        &self,
        account: &DirectoryAccountRow,
    ) -> Result<CreatedSession, HttpError> {
        let now = current_unix_time();
        let session_id = random_token_id()?;
        let refresh_jti = random_token_id()?;
        let secret = token_secret_from_env(&self.env)?;
        let access_jwt = sign_token(
            &secret,
            &session_claims(
                account.did.as_str(),
                &account.handle,
                &session_id,
                ACCESS_SCOPE,
                now,
                ACCESS_TOKEN_TTL_SECONDS,
            ),
        )
        .map_err(HttpError::auth)?;
        let refresh_jwt = sign_token(
            &secret,
            &session_claims(
                account.did.as_str(),
                &account.handle,
                &refresh_jti,
                REFRESH_SCOPE,
                now,
                REFRESH_TOKEN_TTL_SECONDS,
            ),
        )
        .map_err(HttpError::auth)?;
        Ok(CreatedSession {
            row: DirectorySessionRow {
                session_id,
                did: account.did.clone(),
                refresh_jti,
                active: true,
            },
            tokens: SessionTokens {
                access_jwt,
                refresh_jwt,
            },
        })
    }

    fn require_bearer_claims(
        &self,
        req: &Request,
        scope: &str,
    ) -> Result<crate::auth::TokenClaims, HttpError> {
        let token = bearer_token(req)?;
        verify_token(
            &token_secret_from_env(&self.env)?,
            &token,
            scope,
            current_unix_time(),
        )
        .map_err(HttpError::auth)
    }

    fn account_for_claims(
        &self,
        claims: &crate::auth::TokenClaims,
    ) -> Result<DirectoryAccountRow, HttpError> {
        let did = Did::new(claims.sub.clone()).map_err(HttpError::bad_request)?;
        let Some(account) = self
            .store()
            .get_account_by_did(&did)
            .map_err(HttpError::worker)?
        else {
            return Err(HttpError::new(401, "InvalidToken"));
        };
        if !account.active {
            return Err(HttpError::new(403, "AccountTakedown"));
        }
        Ok(account)
    }
}

impl RepoObject {
    async fn handle(&self, req: &mut Request) -> Result<Response, HttpError> {
        if req.method() == Method::Options {
            return empty_response(204).map_err(HttpError::worker);
        }

        let url = req.url().map_err(HttpError::worker)?;
        let parts = url
            .path()
            .trim_start_matches('/')
            .split('/')
            .collect::<Vec<_>>();
        if req.method() == Method::Get {
            match url.path() {
                DID_DOCUMENT_PATH => return self.did_document_response(&url),
                ATPROTO_DID_PATH => return self.handle_did_response(),
                _ => {}
            }
        }

        if parts.len() >= 2 && parts[0] == "xrpc" && !parts[1].is_empty() {
            return self.handle_xrpc(req, parts[1], &url).await;
        }

        let repo_name = parts.get(1).copied().unwrap_or("").to_string();
        let action = parts.get(2).copied().unwrap_or("");

        match (req.method(), action) {
            (Method::Get, "status") => self.status(),
            (Method::Post, "init") => self.init(req, &repo_name).await,
            (Method::Post, "directory-sync") => self.sync_directory(req, &repo_name).await,
            (Method::Post, "records") => self.create_record(req, &repo_name).await,
            (Method::Put, "records") => self.update_record(req, &repo_name).await,
            (Method::Delete, "records") => self.delete_record(req, &repo_name).await,
            (Method::Get, "records") => self.read_records(&url).await,
            _ => Err(HttpError::new(404, "not found")),
        }
    }

    fn store(&self) -> SqlRepoStore {
        SqlRepoStore::new(self.sql.clone())
    }

    async fn handle_xrpc(
        &self,
        req: &mut Request,
        xrpc_method: &str,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        match (req.method(), xrpc_method) {
            (Method::Get, REPO_DESCRIBE_REPO) => self.xrpc_describe_repo(url).await,
            (Method::Get, REPO_GET_RECORD) => self.xrpc_get_record(url).await,
            (Method::Get, REPO_LIST_RECORDS) => self.xrpc_list_records(url).await,
            (Method::Get, SYNC_GET_LATEST_COMMIT) => self.xrpc_get_latest_commit(url),
            (Method::Get, SYNC_GET_HEAD) => self.xrpc_get_head(url),
            (Method::Get, SYNC_GET_REPO_STATUS) => self.xrpc_get_repo_status(url),
            (Method::Get, SYNC_LIST_BLOBS) => self.xrpc_list_blobs(url),
            (Method::Get, SYNC_GET_BLOB) => self.xrpc_get_blob(url).await,
            (Method::Get, SYNC_GET_BLOCKS) => self.xrpc_get_blocks(url),
            (Method::Get, SYNC_GET_RECORD) => self.xrpc_get_sync_record(url).await,
            (Method::Get, SYNC_GET_CHECKOUT) => self.xrpc_get_checkout(url).await,
            (Method::Get, SYNC_GET_REPO) => self.xrpc_get_repo(url).await,
            (Method::Get, REPO_LIST_MISSING_BLOBS) => self.xrpc_list_missing_blobs(req, url),
            (Method::Get, SERVER_DESCRIBE_SERVER) => {
                describe_server(url).map_err(HttpError::worker)
            }
            (Method::Post, REPO_CREATE_RECORD) => self.xrpc_create_record(req).await,
            (Method::Post, REPO_PUT_RECORD) => self.xrpc_put_record(req).await,
            (Method::Post, REPO_DELETE_RECORD) => self.xrpc_delete_record(req).await,
            (Method::Post, REPO_APPLY_WRITES) => self.xrpc_apply_writes(req).await,
            (Method::Post, REPO_IMPORT_REPO) => self.xrpc_import_repo(req).await,
            (Method::Post, REPO_UPLOAD_BLOB) => self.xrpc_upload_blob(req).await,
            (
                _,
                REPO_DESCRIBE_REPO
                | REPO_GET_RECORD
                | REPO_LIST_RECORDS
                | SYNC_GET_LATEST_COMMIT
                | SYNC_GET_HEAD
                | SYNC_GET_REPO_STATUS
                | SYNC_LIST_BLOBS
                | SYNC_GET_BLOB
                | SYNC_GET_BLOCKS
                | SYNC_GET_RECORD
                | SYNC_GET_CHECKOUT
                | SYNC_GET_REPO
                | SERVER_DESCRIBE_SERVER
                | REPO_CREATE_RECORD
                | REPO_PUT_RECORD
                | REPO_DELETE_RECORD
                | REPO_APPLY_WRITES
                | REPO_IMPORT_REPO
                | REPO_UPLOAD_BLOB
                | REPO_LIST_MISSING_BLOBS,
            ) => Err(HttpError::new(405, "method not allowed")),
            _ => Err(HttpError::new(404, "unsupported XRPC method")),
        }
    }

    fn status(&self) -> Result<Response, HttpError> {
        let store = self.store();
        let state = store.get_repo_state().map_err(HttpError::worker)?;
        let identity = store.get_repo_identity().map_err(HttpError::worker)?;
        let blocks = store.block_count().map_err(HttpError::worker)?;
        let records = store.record_count().map_err(HttpError::worker)?;

        json_response(
            200,
            &json!({
                "initialized": state.is_some(),
                "did": state.as_ref().map(|row| row.did.to_string()),
                "handle": identity.as_ref().map(|row| row.handle.clone()),
                "publicKeyMultibase": identity.as_ref().map(|row| row.public_key_multibase.clone()),
                "latestCommit": state.as_ref().map(|row| row.latest_commit.to_string()),
                "latestRev": state.as_ref().map(|row| row.latest_rev.to_string()),
                "blocks": blocks,
                "records": records,
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn xrpc_describe_repo(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let repo_param = required_param(&params, "repo").map_err(HttpError::xrpc)?;
        let (state, identity, mut repo) = self.open_repo_with_identity()?;
        let entries = repo.entries().await.map_err(HttpError::repo)?;
        let collections = entries
            .into_iter()
            .map(|entry| entry.path.collection.to_string())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();

        json_response(
            200,
            &json!({
                "handle": identity.handle.clone(),
                "did": state.did.to_string(),
                "didDoc": did_document(
                    state.did.as_str(),
                    &identity.handle,
                    &identity.public_key_multibase,
                    &request_origin(url),
                ),
                "collections": collections,
                "handleIsCorrect": handle_is_correct(&repo_param, &identity.handle, state.did.as_str()),
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn xrpc_get_record(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        required_param(&params, "repo").map_err(HttpError::xrpc)?;
        let collection = Nsid::new(required_param(&params, "collection").map_err(HttpError::xrpc)?)
            .map_err(HttpError::bad_request)?;
        let rkey = RecordKey::new(required_param(&params, "rkey").map_err(HttpError::xrpc)?)
            .map_err(HttpError::bad_request)?;
        let expected_cid = optional_param(&params, "cid")
            .filter(|value| !value.is_empty())
            .map(|value| parse_cid(&value).map_err(HttpError::bad_request))
            .transpose()?;
        let path = RepoPath::new(collection, rkey);

        let (state, mut repo) = self.open_repo_with_state()?;
        let Some(stored) = repo
            .get_record::<Value>(&path)
            .await
            .map_err(HttpError::repo)?
        else {
            return Err(HttpError::new(404, "record not found"));
        };
        if expected_cid.is_some_and(|cid| cid != stored.cid) {
            return Err(HttpError::new(404, "record not found"));
        }

        json_response(
            200,
            &json!({
                "uri": at_uri(
                    state.did.as_str(),
                    stored.path.collection.as_str(),
                    stored.path.rkey.as_str()
                ),
                "cid": stored.cid.to_string(),
                "value": stored.record,
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn xrpc_list_records(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        required_param(&params, "repo").map_err(HttpError::xrpc)?;
        let list_params = parse_list_records_params(&params).map_err(HttpError::xrpc)?;
        let collection = Nsid::new(list_params.collection).map_err(HttpError::bad_request)?;
        let (state, mut repo) = self.open_repo_with_state()?;
        let mut entries = repo
            .entries_for_collection(&collection)
            .await
            .map_err(HttpError::repo)?;
        if list_params.reverse {
            entries.reverse();
        }

        let start = list_params
            .cursor
            .as_deref()
            .and_then(|cursor| {
                entries
                    .iter()
                    .position(|entry| entry.path.as_mst_key() == cursor)
            })
            .map(|index| index + 1)
            .unwrap_or(0);
        let entry_count = entries.len();
        let selected = entries
            .into_iter()
            .skip(start)
            .take(list_params.limit)
            .collect::<Vec<_>>();
        let next_cursor = if entry_count > start + selected.len() {
            selected.last().map(|entry| entry.path.as_mst_key())
        } else {
            None
        };

        let mut records = Vec::with_capacity(selected.len());
        for entry in &selected {
            let Some(stored) = repo
                .get_record::<Value>(&entry.path)
                .await
                .map_err(HttpError::repo)?
            else {
                return Err(HttpError::new(
                    500,
                    "record index points to a missing MST entry",
                ));
            };
            records.push(json!({
                "uri": at_uri(
                    state.did.as_str(),
                    stored.path.collection.as_str(),
                    stored.path.rkey.as_str()
                ),
                "cid": stored.cid.to_string(),
                "value": stored.record,
            }));
        }

        json_response(
            200,
            &json!({
                "records": records,
                "cursor": next_cursor,
            }),
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_get_latest_commit(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let state = self.repo_state()?;
        ensure_repo_did(&state, &did)?;

        json_response(
            200,
            &json!({
                "cid": state.latest_commit.to_string(),
                "rev": state.latest_rev.to_string(),
            }),
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_get_head(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let state = self.repo_state()?;
        ensure_repo_did(&state, &did)?;

        json_response(
            200,
            &json!({
                "root": state.latest_commit.to_string(),
            }),
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_get_repo_status(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let state = self.repo_state()?;
        ensure_repo_did(&state, &did)?;

        json_response(
            200,
            &json!({
                "did": state.did.to_string(),
                "active": true,
                "rev": state.latest_rev.to_string(),
            }),
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_list_blobs(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let state = self.repo_state()?;
        ensure_repo_did(&state, &did)?;
        let limit = parse_xrpc_limit(optional_param(&params, "limit").as_deref(), 500, 1000)?;
        let cursor = optional_param(&params, "cursor").filter(|value| !value.is_empty());
        let (cids, next_cursor) = self
            .store()
            .list_blob_cids(limit, cursor.as_deref())
            .map_err(HttpError::worker)?;

        let mut body = json!({
            "cids": cids
                .into_iter()
                .map(|cid| cid.to_string())
                .collect::<Vec<_>>(),
        });
        if let Some(cursor) = next_cursor {
            body["cursor"] = json!(cursor);
        }

        json_response(200, &body).map_err(HttpError::worker)
    }

    fn xrpc_list_missing_blobs(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let limit = parse_xrpc_limit(optional_param(&params, "limit").as_deref(), 500, 1000)?;
        let cursor = optional_param(&params, "cursor").filter(|value| !value.is_empty());
        let state = self.repo_state()?;
        self.require_repo_write_auth(req, &state.did)?;
        let (refs, next_cursor) = self
            .store()
            .list_missing_blob_refs(limit, cursor.as_deref())
            .map_err(HttpError::worker)?;

        let mut body = json!({
            "blobs": refs
                .into_iter()
                .map(|row| json!({
                    "cid": row.cid.to_string(),
                    "recordUri": at_uri(
                        state.did.as_str(),
                        row.path.collection.as_str(),
                        row.path.rkey.as_str()
                    ),
                }))
                .collect::<Vec<_>>(),
        });
        if let Some(cursor) = next_cursor {
            body["cursor"] = json!(cursor);
        }

        json_response(200, &body).map_err(HttpError::worker)
    }

    async fn xrpc_get_blob(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let cid = required_param(&params, "cid").map_err(HttpError::xrpc)?;
        let state = self.repo_state()?;
        ensure_repo_did(&state, &did)?;
        let cid = parse_cid(&cid).map_err(HttpError::bad_request)?;
        let Some(blob) = self.store().get_blob(&cid).map_err(HttpError::worker)? else {
            return Err(HttpError::new(404, "blob not found"));
        };

        self.blob_response_for_row(blob).await
    }

    fn xrpc_get_blocks(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = parse_get_blocks_params(&query_pairs(url)).map_err(HttpError::xrpc)?;
        let state = self.repo_state()?;
        ensure_repo_did(&state, &params.did)?;
        let cids = params
            .cids
            .iter()
            .map(|cid| parse_cid(cid).map_err(HttpError::bad_request))
            .collect::<Result<Vec<_>, _>>()?;
        let store = self.store();
        let car = encode_car_from_store(&[], cids, &store).map_err(|error| match error {
            CarError::MissingBlock { cid } => {
                HttpError::new(404, format!("BlockNotFound: block `{cid}` not found"))
            }
            other => HttpError::car(other),
        })?;
        car_response(car).map_err(HttpError::worker)
    }

    async fn xrpc_get_sync_record(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let collection = Nsid::new(required_param(&params, "collection").map_err(HttpError::xrpc)?)
            .map_err(HttpError::bad_request)?;
        let rkey = RecordKey::new(required_param(&params, "rkey").map_err(HttpError::xrpc)?)
            .map_err(HttpError::bad_request)?;
        let path = RepoPath::new(collection, rkey);
        let (state, mut repo) = self.open_repo_with_state()?;
        ensure_repo_did(&state, &did)?;

        let cids = repo
            .extract_record_cids(&path)
            .await
            .map_err(HttpError::repo)?;
        let car = encode_car_from_store(&[state.latest_commit], cids, repo.storage())
            .map_err(HttpError::car)?;
        car_response(car).map_err(HttpError::worker)
    }

    async fn xrpc_get_checkout(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let (state, mut repo) = self.open_repo_with_state()?;
        ensure_repo_did(&state, &did)?;
        let cids = repo.export_cids().await.map_err(HttpError::repo)?;
        let car = encode_car_from_store(&[state.latest_commit], cids, repo.storage())
            .map_err(HttpError::car)?;
        car_response(car).map_err(HttpError::worker)
    }

    async fn xrpc_get_repo(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let (state, mut repo) = self.open_repo_with_state()?;
        ensure_repo_did(&state, &did)?;
        let car = if let Some(since) =
            optional_param(&params, "since").filter(|value| !value.is_empty())
        {
            self.repo_diff_car_since(&state, &since)?
        } else {
            let cids = repo.export_cids().await.map_err(HttpError::repo)?;
            encode_car_from_store(&[state.latest_commit], cids, repo.storage())
                .map_err(HttpError::car)?
        };
        car_response(car).map_err(HttpError::worker)
    }

    async fn init(&self, req: &mut Request, repo_name: &str) -> Result<Response, HttpError> {
        let body: InitRepoRequest = req.json().await.map_err(HttpError::worker)?;
        self.require_admin(req)?;
        let request_host = request_host(req)?;
        let store = self.store();
        let existing = store.get_repo_state().map_err(HttpError::worker)?;
        if existing.is_some() && !body.reset.unwrap_or(false) {
            return Err(HttpError::new(409, "repo already initialized"));
        }
        if body.reset.unwrap_or(false) {
            store.clear_all().map_err(HttpError::worker)?;
        }

        let did = Did::new(body.did).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let signing_key = RepoSigningKey::from_p256_hex(&body.signing_key_p256_hex)
            .map_err(HttpError::identity)?;
        let identity = RepoIdentityRow {
            handle: body.handle,
            signing_key_p256_hex: signing_key.to_p256_hex(),
            public_key_multibase: signing_key
                .public_key_multibase()
                .map_err(HttpError::identity)?,
        };
        let mut repo = SignedRepository::create(store, did.clone(), rev.clone(), &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let state = RepoStateRow {
            did,
            latest_commit: repo.latest_commit_cid(),
            latest_rev: rev,
        };
        let event = self
            .repo_commit_event_payload(&mut repo, state.latest_commit, None, Vec::new())
            .await?;
        repo.storage()
            .put_repo_state(&state)
            .map_err(HttpError::worker)?;
        repo.storage()
            .put_repo_identity(&identity)
            .map_err(HttpError::worker)?;
        self.persist_commit_event(repo.storage(), &state, &event)
            .map_err(HttpError::worker)?;
        if body.notify_directory.unwrap_or(true) {
            self.notify_directory(
                &request_host,
                repo_name,
                &identity,
                &state,
                None,
                Some(&event),
            )
            .await?;
        }

        json_response(
            201,
            &json!({
                "did": state.did.to_string(),
                "handle": identity.handle,
                "publicKeyMultibase": identity.public_key_multibase,
                "latestCommit": state.latest_commit.to_string(),
                "latestRev": state.latest_rev.to_string(),
                "mstRoot": repo.mst_root().to_string(),
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn create_record(
        &self,
        req: &mut Request,
        repo_name: &str,
    ) -> Result<Response, HttpError> {
        let body: WriteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        self.require_admin(req)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let blob_cids = extract_record_blob_refs(&body.record)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .create_record(path.clone(), &body.record, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let event = self
            .commit_event_payload(
                &mut repo,
                &mutation,
                Some(previous_state.latest_rev.clone()),
                blob_cids.clone(),
            )
            .await?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.persist_commit_event(repo.storage(), &state, &event)
            .map_err(HttpError::worker)?;
        if let Some(record_cid) = mutation.record_cid {
            repo.storage()
                .replace_blob_refs(&path, record_cid, &blob_cids)
                .map_err(HttpError::worker)?;
        }
        self.notify_directory(
            &request_host,
            repo_name,
            &identity,
            &state,
            None,
            Some(&event),
        )
        .await?;
        json_response(201, &mutation_response(&path, &mutation)).map_err(HttpError::worker)
    }

    async fn update_record(
        &self,
        req: &mut Request,
        repo_name: &str,
    ) -> Result<Response, HttpError> {
        let body: WriteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        self.require_admin(req)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let blob_cids = extract_record_blob_refs(&body.record)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .update_record(path.clone(), &body.record, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let event = self
            .commit_event_payload(
                &mut repo,
                &mutation,
                Some(previous_state.latest_rev.clone()),
                blob_cids.clone(),
            )
            .await?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.persist_commit_event(repo.storage(), &state, &event)
            .map_err(HttpError::worker)?;
        if let Some(record_cid) = mutation.record_cid {
            repo.storage()
                .replace_blob_refs(&path, record_cid, &blob_cids)
                .map_err(HttpError::worker)?;
        }
        self.notify_directory(
            &request_host,
            repo_name,
            &identity,
            &state,
            None,
            Some(&event),
        )
        .await?;
        json_response(200, &mutation_response(&path, &mutation)).map_err(HttpError::worker)
    }

    async fn delete_record(
        &self,
        req: &mut Request,
        repo_name: &str,
    ) -> Result<Response, HttpError> {
        let body: DeleteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        self.require_admin(req)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .delete_record(&path, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let event = self
            .commit_event_payload(
                &mut repo,
                &mutation,
                Some(previous_state.latest_rev.clone()),
                Vec::new(),
            )
            .await?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.persist_commit_event(repo.storage(), &state, &event)
            .map_err(HttpError::worker)?;
        repo.storage()
            .delete_blob_refs(&path)
            .map_err(HttpError::worker)?;
        self.notify_directory(
            &request_host,
            repo_name,
            &identity,
            &state,
            None,
            Some(&event),
        )
        .await?;
        json_response(200, &mutation_response(&path, &mutation)).map_err(HttpError::worker)
    }

    async fn sync_directory(
        &self,
        req: &mut Request,
        repo_name: &str,
    ) -> Result<Response, HttpError> {
        self.require_admin(req)?;
        let request_host = request_host(req)?;
        let (state, identity, mut repo) = self.open_repo_with_identity()?;
        let records = repo_record_paths(&mut repo).await?;
        self.notify_directory(
            &request_host,
            repo_name,
            &identity,
            &state,
            Some(&records),
            None,
        )
        .await?;

        json_response(
            200,
            &json!({
                "ok": true,
                "did": state.did.to_string(),
                "latestCommit": state.latest_commit.to_string(),
                "latestRev": state.latest_rev.to_string(),
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn xrpc_create_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcCreateRecordRequest = req.json().await.map_err(HttpError::worker)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        ensure_repo_identifier(&previous_state, &identity, &body.repo)?;
        self.require_repo_write_auth(req, &previous_state.did)?;
        ensure_swap_commit(&previous_state, body.swap_commit.as_deref())?;

        let collection = Nsid::new(body.collection).map_err(HttpError::bad_request)?;
        let rkey = if let Some(rkey) = body.rkey {
            RecordKey::new(rkey).map_err(HttpError::bad_request)?
        } else {
            generated_record_key(&previous_state.latest_commit)?
        };
        let path = RepoPath::new(collection, rkey);
        let blob_cids = extract_record_blob_refs(&body.record)?;
        let rev = generated_repo_rev(&previous_state.latest_commit)?;
        let mutation = repo
            .create_record(path.clone(), &body.record, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let event = self
            .commit_event_payload(
                &mut repo,
                &mutation,
                Some(previous_state.latest_rev.clone()),
                blob_cids.clone(),
            )
            .await?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.persist_commit_event(repo.storage(), &state, &event)
            .map_err(HttpError::worker)?;
        if let Some(record_cid) = mutation.record_cid {
            repo.storage()
                .replace_blob_refs(&path, record_cid, &blob_cids)
                .map_err(HttpError::worker)?;
        }
        self.notify_directory(
            &request_host,
            &identity.handle,
            &identity,
            &state,
            None,
            Some(&event),
        )
        .await?;

        json_response(
            200,
            &xrpc_record_mutation_response(&state.did, &path, &mutation),
        )
        .map_err(HttpError::worker)
    }

    async fn xrpc_put_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcPutRecordRequest = req.json().await.map_err(HttpError::worker)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        ensure_repo_identifier(&previous_state, &identity, &body.repo)?;
        self.require_repo_write_auth(req, &previous_state.did)?;
        ensure_swap_commit(&previous_state, body.swap_commit.as_deref())?;

        let path = RepoPath::new(
            Nsid::new(body.collection).map_err(HttpError::bad_request)?,
            RecordKey::new(body.rkey).map_err(HttpError::bad_request)?,
        );
        let existing = repo
            .get_record::<Value>(&path)
            .await
            .map_err(HttpError::repo)?;
        ensure_swap_record_field(
            existing.as_ref().map(|record| record.cid),
            &body.swap_record,
        )?;
        let blob_cids = extract_record_blob_refs(&body.record)?;
        let rev = generated_repo_rev(&previous_state.latest_commit)?;
        let mutation = if existing.is_some() {
            repo.update_record(path.clone(), &body.record, rev, &signing_key)
                .await
        } else {
            repo.create_record(path.clone(), &body.record, rev, &signing_key)
                .await
        }
        .map_err(HttpError::repo)?;
        let event = self
            .commit_event_payload(
                &mut repo,
                &mutation,
                Some(previous_state.latest_rev.clone()),
                blob_cids.clone(),
            )
            .await?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.persist_commit_event(repo.storage(), &state, &event)
            .map_err(HttpError::worker)?;
        if let Some(record_cid) = mutation.record_cid {
            repo.storage()
                .replace_blob_refs(&path, record_cid, &blob_cids)
                .map_err(HttpError::worker)?;
        }
        self.notify_directory(
            &request_host,
            &identity.handle,
            &identity,
            &state,
            None,
            Some(&event),
        )
        .await?;

        json_response(
            200,
            &xrpc_record_mutation_response(&state.did, &path, &mutation),
        )
        .map_err(HttpError::worker)
    }

    async fn xrpc_delete_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcDeleteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        ensure_repo_identifier(&previous_state, &identity, &body.repo)?;
        self.require_repo_write_auth(req, &previous_state.did)?;
        ensure_swap_commit(&previous_state, body.swap_commit.as_deref())?;

        let path = RepoPath::new(
            Nsid::new(body.collection).map_err(HttpError::bad_request)?,
            RecordKey::new(body.rkey).map_err(HttpError::bad_request)?,
        );
        let existing = repo
            .get_record::<Value>(&path)
            .await
            .map_err(HttpError::repo)?;
        ensure_optional_swap_record(
            existing.as_ref().map(|record| record.cid),
            body.swap_record.as_deref(),
        )?;
        if existing.is_none() {
            return json_response(200, &xrpc_noop_delete_response(&previous_state))
                .map_err(HttpError::worker);
        }
        let rev = generated_repo_rev(&previous_state.latest_commit)?;
        let mutation = repo
            .delete_record(&path, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let event = self
            .commit_event_payload(
                &mut repo,
                &mutation,
                Some(previous_state.latest_rev.clone()),
                Vec::new(),
            )
            .await?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.persist_commit_event(repo.storage(), &state, &event)
            .map_err(HttpError::worker)?;
        repo.storage()
            .delete_blob_refs(&path)
            .map_err(HttpError::worker)?;
        self.notify_directory(
            &request_host,
            &identity.handle,
            &identity,
            &state,
            None,
            Some(&event),
        )
        .await?;

        json_response(200, &xrpc_delete_mutation_response(&mutation)).map_err(HttpError::worker)
    }

    async fn xrpc_apply_writes(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcApplyWritesRequest = req.json().await.map_err(HttpError::worker)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        ensure_repo_identifier(&previous_state, &identity, &body.repo)?;
        self.require_repo_write_auth(req, &previous_state.did)?;
        ensure_swap_commit(&previous_state, body.swap_commit.as_deref())?;
        if body.writes.is_empty() {
            return Err(HttpError::new(
                400,
                "applyWrites requires at least one write",
            ));
        }
        if body.writes.len() > MAX_APPLY_WRITES {
            return Err(HttpError::new(
                400,
                format!("applyWrites supports at most {MAX_APPLY_WRITES} writes"),
            ));
        }

        let mut writes = Vec::new();
        let mut blob_ref_updates = Vec::new();
        let mut event_blobs = BTreeSet::new();
        for (write_index, raw_write) in body.writes.into_iter().enumerate() {
            let kind = parse_apply_write_kind(&raw_write.write_type)?;
            let collection = Nsid::new(raw_write.collection).map_err(HttpError::bad_request)?;
            match kind {
                RepoOperationAction::Create => {
                    let record = raw_write.value.ok_or_else(|| {
                        HttpError::new(400, "applyWrites create requires `value`")
                    })?;
                    let rkey = if let Some(rkey) = raw_write.rkey {
                        RecordKey::new(rkey).map_err(HttpError::bad_request)?
                    } else {
                        generated_record_key_with_offset(
                            &previous_state.latest_commit,
                            write_index,
                        )?
                    };
                    let path = RepoPath::new(collection, rkey);
                    let blobs = extract_record_blob_refs(&record)?;
                    event_blobs.extend(blobs.iter().copied());
                    blob_ref_updates.push((path.clone(), Some(blobs)));
                    writes.push(RepoWrite::Create { path, record });
                }
                RepoOperationAction::Update => {
                    let record = raw_write.value.ok_or_else(|| {
                        HttpError::new(400, "applyWrites update requires `value`")
                    })?;
                    let rkey = raw_write
                        .rkey
                        .ok_or_else(|| HttpError::new(400, "applyWrites update requires `rkey`"))?;
                    let path = RepoPath::new(
                        collection,
                        RecordKey::new(rkey).map_err(HttpError::bad_request)?,
                    );
                    let blobs = extract_record_blob_refs(&record)?;
                    event_blobs.extend(blobs.iter().copied());
                    blob_ref_updates.push((path.clone(), Some(blobs)));
                    writes.push(RepoWrite::Update { path, record });
                }
                RepoOperationAction::Delete => {
                    let rkey = raw_write
                        .rkey
                        .ok_or_else(|| HttpError::new(400, "applyWrites delete requires `rkey`"))?;
                    let path = RepoPath::new(
                        collection,
                        RecordKey::new(rkey).map_err(HttpError::bad_request)?,
                    );
                    blob_ref_updates.push((path.clone(), None));
                    writes.push(RepoWrite::Delete { path });
                }
            }
        }

        let rev = generated_repo_rev(&previous_state.latest_commit)?;
        let mutation = repo
            .apply_writes(writes, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let event = self
            .commit_event_payload(
                &mut repo,
                &mutation,
                Some(previous_state.latest_rev.clone()),
                event_blobs.into_iter().collect(),
            )
            .await?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.persist_commit_event(repo.storage(), &state, &event)
            .map_err(HttpError::worker)?;
        for (path, blobs) in blob_ref_updates {
            match blobs {
                Some(blobs) => {
                    if let Some(record_cid) = mutation
                        .ops
                        .iter()
                        .rev()
                        .find(|op| op.path == path)
                        .and_then(|op| op.cid)
                    {
                        repo.storage()
                            .replace_blob_refs(&path, record_cid, &blobs)
                            .map_err(HttpError::worker)?;
                    }
                }
                None => {
                    repo.storage()
                        .delete_blob_refs(&path)
                        .map_err(HttpError::worker)?;
                }
            }
        }
        self.notify_directory(
            &request_host,
            &identity.handle,
            &identity,
            &state,
            None,
            Some(&event),
        )
        .await?;

        json_response(200, &xrpc_apply_writes_response(&state.did, &mutation))
            .map_err(HttpError::worker)
    }

    async fn xrpc_import_repo(&self, req: &mut Request) -> Result<Response, HttpError> {
        let request_host = request_host(req)?;
        let (previous_state, identity, mut existing_repo) = self.open_repo_with_identity()?;
        self.require_repo_write_auth(req, &previous_state.did)?;
        ensure_import_repo_content_type(req)?;
        let content_length = request_content_length(req)?
            .ok_or_else(|| HttpError::new(411, "importRepo requires a content-length header"))?;
        ensure_import_repo_size_limit(content_length)?;

        let existing_records = existing_repo
            .entries()
            .await
            .map_err(HttpError::repo)?
            .into_iter()
            .map(|entry| (entry.path, entry.cid))
            .collect::<Vec<_>>();
        let bytes = req.bytes().await.map_err(HttpError::worker)?;
        ensure_import_repo_size_limit(bytes.len() as u64)?;
        let decoded = decode_car(&bytes).map_err(|error| HttpError::new(400, error.to_string()))?;
        let imported = validate_imported_repo(decoded, &previous_state.did)
            .await
            .map_err(HttpError::import)?;
        let ops = diff_imported_records(existing_records, &imported.records);
        let event = DirectoryCommitEventPayload {
            since: Some(previous_state.latest_rev.clone()),
            blocks: imported.current_car.clone(),
            ops: directory_import_ops(&ops),
            blobs: imported_blob_strings(&imported.records),
        };
        let state = RepoStateRow {
            did: previous_state.did.clone(),
            latest_commit: imported.root,
            latest_rev: imported.rev.clone(),
        };
        let record_paths = imported
            .records
            .iter()
            .map(|record| record.path.clone())
            .collect::<Vec<_>>();

        let mut store = self.store();
        store
            .clear_repo_data_for_import()
            .map_err(HttpError::worker)?;
        for block in &imported.blocks {
            store
                .put_block_with_cid(block.cid, block.bytes.clone())
                .map_err(HttpError::storage)?;
        }
        store.put_repo_state(&state).map_err(HttpError::worker)?;
        for record in &imported.records {
            store
                .put_record_pointer(record.path.clone(), record.cid)
                .map_err(HttpError::storage)?;
            store
                .replace_blob_refs(&record.path, record.cid, &record.blob_cids)
                .map_err(HttpError::worker)?;
        }
        self.persist_commit_event(&store, &state, &event)
            .map_err(HttpError::worker)?;
        self.notify_directory(
            &request_host,
            &identity.handle,
            &identity,
            &state,
            Some(&record_paths),
            Some(&event),
        )
        .await?;

        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_upload_blob(&self, req: &mut Request) -> Result<Response, HttpError> {
        let state = self.repo_state()?;
        self.require_repo_write_auth(req, &state.did)?;
        let mime_type = req
            .headers()
            .get("content-type")
            .map_err(HttpError::worker)?
            .and_then(|value| value.split(';').next().map(|part| part.trim().to_string()))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "application/octet-stream".to_string());
        let blob = self.put_blob_request_body(&mime_type, req).await?;

        json_response(
            200,
            &json!({
                "blob": {
                    "$type": "blob",
                    "ref": {"$link": blob.cid.to_string()},
                    "mimeType": blob.mime_type,
                    "size": blob.byte_len,
                },
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn read_records(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let mut repo = self.open_repo()?;
        let params = url.query_pairs().collect::<Vec<_>>();
        let path = params
            .iter()
            .find(|(key, _)| key == "path")
            .map(|(_, value)| value.to_string());
        if let Some(path) = path {
            let path = RepoPath::parse(&path).map_err(HttpError::bad_request)?;
            let stored = repo
                .get_record::<Value>(&path)
                .await
                .map_err(HttpError::repo)?;
            let Some(stored) = stored else {
                return Err(HttpError::new(404, "record not found"));
            };
            return json_response(
                200,
                &json!({
                    "path": stored.path.to_string(),
                    "cid": stored.cid.to_string(),
                    "record": stored.record,
                }),
            )
            .map_err(HttpError::worker);
        }

        let collection = params
            .iter()
            .find(|(key, _)| key == "collection")
            .map(|(_, value)| value.to_string());
        let entries = if let Some(collection) = collection {
            let collection = Nsid::new(collection).map_err(HttpError::bad_request)?;
            repo.entries_for_collection(&collection)
                .await
                .map_err(HttpError::repo)?
        } else {
            repo.entries().await.map_err(HttpError::repo)?
        };

        json_response(
            200,
            &json!({
                "records": entries
                    .into_iter()
                    .map(|entry| json!({
                        "path": entry.path.to_string(),
                        "cid": entry.cid.to_string(),
                    }))
                    .collect::<Vec<_>>()
            }),
        )
        .map_err(HttpError::worker)
    }

    fn open_repo(&self) -> Result<SignedRepository<SqlRepoStore>, HttpError> {
        let (_, repo) = self.open_repo_with_state()?;
        Ok(repo)
    }

    fn open_repo_for_write_with_state(
        &self,
    ) -> Result<
        (
            RepoStateRow,
            RepoIdentityRow,
            RepoSigningKey,
            SignedRepository<SqlRepoStore>,
        ),
        HttpError,
    > {
        let (state, identity, repo) = self.open_repo_with_identity()?;
        let signing_key = identity.signing_key().map_err(HttpError::identity)?;
        Ok((state, identity, signing_key, repo))
    }

    fn open_repo_with_state(
        &self,
    ) -> Result<(RepoStateRow, SignedRepository<SqlRepoStore>), HttpError> {
        let store = self.store();
        let state = self.repo_state_from(&store)?;
        let repo = SignedRepository::open(store, state.latest_commit).map_err(HttpError::repo)?;
        Ok((state, repo))
    }

    fn open_repo_with_identity(
        &self,
    ) -> Result<
        (
            RepoStateRow,
            RepoIdentityRow,
            SignedRepository<SqlRepoStore>,
        ),
        HttpError,
    > {
        let store = self.store();
        let state = self.repo_state_from(&store)?;
        let identity = self.repo_identity_from(&store)?;
        let repo = SignedRepository::open(store, state.latest_commit).map_err(HttpError::repo)?;
        Ok((state, identity, repo))
    }

    fn repo_state(&self) -> Result<RepoStateRow, HttpError> {
        let store = self.store();
        self.repo_state_from(&store)
    }

    fn repo_identity(&self) -> Result<RepoIdentityRow, HttpError> {
        let store = self.store();
        self.repo_identity_from(&store)
    }

    fn repo_state_from(&self, store: &SqlRepoStore) -> Result<RepoStateRow, HttpError> {
        store
            .get_repo_state()
            .map_err(HttpError::worker)?
            .ok_or_else(|| HttpError::new(404, "repo not initialized"))
    }

    fn repo_identity_from(&self, store: &SqlRepoStore) -> Result<RepoIdentityRow, HttpError> {
        store
            .get_repo_identity()
            .map_err(HttpError::worker)?
            .ok_or_else(|| HttpError::new(404, "repo identity not initialized"))
    }

    fn did_document_response(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let state = self.repo_state()?;
        let identity = self.repo_identity()?;
        json_response(
            200,
            &did_document(
                state.did.as_str(),
                &identity.handle,
                &identity.public_key_multibase,
                &request_origin(url),
            ),
        )
        .map_err(HttpError::worker)
    }

    fn handle_did_response(&self) -> Result<Response, HttpError> {
        let state = self.repo_state()?;
        text_response(200, state.did.as_str()).map_err(HttpError::worker)
    }

    fn require_admin(&self, req: &Request) -> Result<(), HttpError> {
        require_admin_with_env(&self.env, req)
    }

    fn require_repo_write_auth(&self, req: &Request, did: &Did) -> Result<(), HttpError> {
        if is_admin_authorized(&self.env, req)? {
            return Ok(());
        }
        let token = bearer_token(req)?;
        let claims = verify_token(
            &token_secret_from_env(&self.env)?,
            &token,
            ACCESS_SCOPE,
            current_unix_time(),
        )
        .map_err(HttpError::auth)?;
        if claims.sub == did.as_str() {
            Ok(())
        } else {
            Err(HttpError::new(403, "token does not match repo DID"))
        }
    }

    async fn notify_directory(
        &self,
        request_host: &str,
        repo_name: &str,
        identity: &RepoIdentityRow,
        state: &RepoStateRow,
        records: Option<&[RepoPath]>,
        event: Option<&DirectoryCommitEventPayload>,
    ) -> Result<(), HttpError> {
        let mut body = json!({
            "did": state.did.to_string(),
            "handle": identity.handle.clone(),
            "repoName": repo_name,
            "head": state.latest_commit.to_string(),
            "rev": state.latest_rev.to_string(),
            "active": true,
        });
        if let Some(records) = records {
            body["records"] = json!(records
                .iter()
                .map(|path| path.to_string())
                .collect::<Vec<_>>());
        }
        if let Some(event) = event {
            body["event"] = json!({
                "since": event.since.as_ref().map(|rev| rev.to_string()),
                "blocksBase64": BASE64_STANDARD.encode(&event.blocks),
                "ops": event.ops,
                "blobs": event.blobs,
            });
        }
        let mut response = fetch_directory_json(
            &self.env,
            request_host,
            Method::Post,
            "/directory/repos/upsert",
            &body,
        )
        .await?;
        let status = response.status_code();
        if !(200..300).contains(&status) {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read directory response".to_string());
            return Err(HttpError::new(
                500,
                format!("directory update failed with status {status}: {message}"),
            ));
        }
        Ok(())
    }

    async fn commit_event_payload(
        &self,
        repo: &mut SignedRepository<SqlRepoStore>,
        mutation: &RepoMutation,
        since: Option<RepoRev>,
        blobs: Vec<crate::cid::Cid>,
    ) -> Result<DirectoryCommitEventPayload, HttpError> {
        let cids = mutation_diff_cids(repo, mutation).await?;
        self.repo_commit_event_payload_from_cids(
            repo,
            mutation.commit_cid,
            since,
            directory_commit_ops(&mutation.ops),
            blobs,
            cids,
        )
        .await
    }

    async fn repo_commit_event_payload(
        &self,
        repo: &mut SignedRepository<SqlRepoStore>,
        commit_cid: crate::cid::Cid,
        since: Option<RepoRev>,
        ops: Vec<DirectoryCommitOp>,
    ) -> Result<DirectoryCommitEventPayload, HttpError> {
        let cids = repo.export_cids().await.map_err(HttpError::repo)?;
        self.repo_commit_event_payload_from_cids(repo, commit_cid, since, ops, Vec::new(), cids)
            .await
    }

    async fn repo_commit_event_payload_from_cids(
        &self,
        repo: &mut SignedRepository<SqlRepoStore>,
        commit_cid: crate::cid::Cid,
        since: Option<RepoRev>,
        ops: Vec<DirectoryCommitOp>,
        blobs: Vec<crate::cid::Cid>,
        cids: Vec<crate::cid::Cid>,
    ) -> Result<DirectoryCommitEventPayload, HttpError> {
        let blocks =
            encode_car_from_store(&[commit_cid], cids, repo.storage()).map_err(HttpError::car)?;
        Ok(DirectoryCommitEventPayload {
            since,
            blocks,
            ops,
            blobs: blobs.into_iter().map(|cid| cid.to_string()).collect(),
        })
    }

    fn persist_commit_event(
        &self,
        store: &SqlRepoStore,
        state: &RepoStateRow,
        event: &DirectoryCommitEventPayload,
    ) -> worker::Result<()> {
        store.append_commit_event(&RepoCommitEventInput {
            rev: state.latest_rev.clone(),
            since: event.since.clone(),
            commit_cid: state.latest_commit,
            blocks: event.blocks.clone(),
            ops_json: to_string(&event.ops)?,
            blobs_json: to_string(&event.blobs)?,
        })
    }

    async fn blob_response_for_row(&self, blob: RepoBlobRow) -> Result<Response, HttpError> {
        if blob.storage_kind == "r2" {
            let key = blob
                .storage_key
                .clone()
                .unwrap_or_else(|| blob_storage_key(&blob.cid));
            let bucket = self.env.bucket(BLOB_BUCKET_BINDING).map_err(|_| {
                HttpError::new(500, "BLOB_BUCKET binding is required to read this blob")
            })?;
            let Some(object) = bucket.get(key).execute().await.map_err(HttpError::worker)? else {
                return Err(HttpError::new(404, "blob not found"));
            };
            let Some(body) = object.body() else {
                return Err(HttpError::new(
                    500,
                    "R2 blob object returned without a body",
                ));
            };
            let response_body = body.response_body().map_err(HttpError::worker)?;
            blob_stream_response(response_body, &blob.mime_type, blob.byte_len)
                .map_err(HttpError::worker)
        } else {
            blob_response(blob.bytes, &blob.mime_type).map_err(HttpError::worker)
        }
    }

    async fn put_blob_request_body(
        &self,
        mime_type: &str,
        req: &mut Request,
    ) -> Result<RepoBlobRow, HttpError> {
        let content_length = request_content_length(req)?;
        if let Some(content_length) = content_length {
            ensure_blob_size_limit(content_length)?;
        }

        if let (Ok(bucket), Some(content_length)) =
            (self.env.bucket(BLOB_BUCKET_BINDING), content_length)
        {
            let key = temporary_blob_storage_key();
            let hasher = Rc::new(RefCell::new(Sha256::new()));
            let byte_len = Rc::new(Cell::new(0_u64));
            let stream_hasher = Rc::clone(&hasher);
            let stream_byte_len = Rc::clone(&byte_len);
            let metered_stream = req.stream().map_err(HttpError::worker)?.map(
                move |chunk| -> worker::Result<Vec<u8>> {
                    let chunk = chunk?;
                    let next_len = stream_byte_len
                        .get()
                        .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
                    if next_len > MAX_BLOB_BYTES as u64 {
                        return Err(worker::Error::RustError(format!(
                            "blob too large: max {MAX_BLOB_BYTES} bytes"
                        )));
                    }
                    stream_byte_len.set(next_len);
                    stream_hasher.borrow_mut().update(&chunk);
                    Ok(chunk)
                },
            );

            bucket
                .put(
                    key.clone(),
                    FixedLengthStream::wrap(metered_stream, content_length),
                )
                .http_metadata(blob_http_metadata(mime_type))
                .execute()
                .await
                .map_err(HttpError::worker)?;

            let digest = hasher.borrow().clone().finalize();
            let cid = raw_cid_from_sha256_digest(&digest);
            let byte_len = byte_len.get();
            if let Some(existing) = self.store().get_blob(&cid).map_err(HttpError::worker)? {
                let _ = bucket.delete(key).await;
                return Ok(existing);
            }
            return self
                .store()
                .put_blob_metadata(
                    cid,
                    mime_type,
                    usize::try_from(byte_len).unwrap_or(MAX_BLOB_BYTES),
                    "r2",
                    Some(&key),
                )
                .map_err(HttpError::worker);
        }

        let bytes = req.bytes().await.map_err(HttpError::worker)?;
        ensure_blob_size_limit(bytes.len() as u64)?;
        self.put_blob_bytes(mime_type, bytes).await
    }

    async fn put_blob_bytes(
        &self,
        mime_type: &str,
        bytes: Vec<u8>,
    ) -> Result<RepoBlobRow, HttpError> {
        let cid = raw_cid(&bytes);
        let byte_len = bytes.len();
        if let Ok(bucket) = self.env.bucket(BLOB_BUCKET_BINDING) {
            let key = blob_storage_key(&cid);
            bucket
                .put(key.clone(), bytes)
                .http_metadata(blob_http_metadata(mime_type))
                .execute()
                .await
                .map_err(HttpError::worker)?;
            self.store()
                .put_blob_metadata(cid, mime_type, byte_len, "r2", Some(&key))
                .map_err(HttpError::worker)
        } else {
            self.store()
                .put_blob_bytes(mime_type, bytes)
                .map_err(HttpError::worker)
        }
    }

    fn repo_diff_car_since(&self, state: &RepoStateRow, since: &str) -> Result<Vec<u8>, HttpError> {
        let since = RepoRev::new(since.to_string()).map_err(HttpError::bad_request)?;
        if since == state.latest_rev {
            return encode_car(&[state.latest_commit], Vec::<CarBlock>::new())
                .map_err(HttpError::car);
        }
        let store = self.store();
        if !store
            .has_commit_event_rev(&since)
            .map_err(HttpError::worker)?
        {
            return Err(HttpError::new(
                400,
                format!("unknown since revision `{since}`"),
            ));
        }
        let events = store
            .list_commit_events_after_rev(&since)
            .map_err(HttpError::worker)?;
        if events.is_empty() {
            return encode_car(&[state.latest_commit], Vec::<CarBlock>::new())
                .map_err(HttpError::car);
        }

        let mut seen = BTreeSet::new();
        let mut blocks = Vec::new();
        for event in events {
            let decoded = decode_car(&event.blocks).map_err(HttpError::car)?;
            for block in decoded.blocks {
                if seen.insert(block.cid) {
                    blocks.push(block);
                }
            }
        }

        encode_car(&[state.latest_commit], blocks).map_err(HttpError::car)
    }

    fn persist_mutation(
        &self,
        store: &SqlRepoStore,
        mutation: &RepoMutation,
    ) -> worker::Result<RepoStateRow> {
        let state = RepoStateRow {
            did: mutation.commit.did.clone(),
            latest_commit: mutation.commit_cid,
            latest_rev: mutation.commit.rev.clone(),
        };
        store.put_repo_state(&state)?;
        Ok(state)
    }
}

#[derive(Debug, Deserialize)]
struct InitRepoRequest {
    did: String,
    handle: String,
    rev: String,
    #[serde(rename = "signingKeyP256Hex", alias = "signing_key_p256_hex")]
    signing_key_p256_hex: String,
    #[serde(default)]
    reset: Option<bool>,
    #[serde(default, rename = "notifyDirectory")]
    notify_directory: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct XrpcCreateAccountRequest {
    handle: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    did: Option<String>,
    #[serde(default, rename = "plcOp")]
    plc_op: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct XrpcCreateSessionRequest {
    identifier: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct InternalInitRepoResponse {
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: String,
    #[serde(rename = "latestCommit")]
    latest_commit: String,
    #[serde(rename = "latestRev")]
    latest_rev: String,
}

struct CreatedSession {
    row: DirectorySessionRow,
    tokens: SessionTokens,
}

struct SessionTokens {
    access_jwt: String,
    refresh_jwt: String,
}

#[derive(Debug, Deserialize)]
struct WriteRecordRequest {
    path: String,
    rev: String,
    record: Value,
}

#[derive(Debug, Deserialize)]
struct XrpcCreateRecordRequest {
    repo: String,
    collection: String,
    #[serde(default)]
    rkey: Option<String>,
    record: Value,
    #[serde(default, rename = "validate")]
    _validate: Option<bool>,
    #[serde(default, rename = "swapCommit")]
    swap_commit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrpcPutRecordRequest {
    repo: String,
    collection: String,
    rkey: String,
    record: Value,
    #[serde(default, rename = "validate")]
    _validate: Option<bool>,
    #[serde(default, rename = "swapRecord")]
    swap_record: SwapRecordField,
    #[serde(default, rename = "swapCommit")]
    swap_commit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrpcDeleteRecordRequest {
    repo: String,
    collection: String,
    rkey: String,
    #[serde(default, rename = "swapRecord")]
    swap_record: Option<String>,
    #[serde(default, rename = "swapCommit")]
    swap_commit: Option<String>,
}

#[derive(Debug, Default)]
enum SwapRecordField {
    #[default]
    Missing,
    Absent,
    Cid(String),
}

impl<'de> Deserialize<'de> for SwapRecordField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(Self::Cid)
            .map_or(Ok(Self::Absent), Ok)
    }
}

#[derive(Debug, Deserialize)]
struct XrpcApplyWritesRequest {
    repo: String,
    #[serde(default, rename = "validate")]
    _validate: Option<bool>,
    writes: Vec<XrpcApplyWriteRequest>,
    #[serde(default, rename = "swapCommit")]
    swap_commit: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrpcApplyWriteRequest {
    #[serde(rename = "$type")]
    write_type: String,
    collection: String,
    #[serde(default)]
    rkey: Option<String>,
    #[serde(default)]
    value: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct DeleteRecordRequest {
    path: String,
    rev: String,
}

#[derive(Debug, Deserialize)]
struct DirectoryUpsertRepoRequest {
    did: String,
    handle: String,
    #[serde(rename = "repoName", alias = "repo_name")]
    repo_name: String,
    head: String,
    rev: String,
    #[serde(default)]
    active: Option<bool>,
    #[serde(default)]
    records: Option<Vec<String>>,
    #[serde(default)]
    event: Option<DirectoryCommitEventRequest>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DirectoryCommitEventRequest {
    #[serde(default)]
    since: Option<String>,
    #[serde(rename = "blocksBase64")]
    blocks_base64: String,
    #[serde(default)]
    ops: Vec<DirectoryCommitOp>,
    #[serde(default)]
    blobs: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize)]
struct DirectoryCommitEventPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<RepoRev>,
    blocks: Vec<u8>,
    ops: Vec<DirectoryCommitOp>,
    blobs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct DirectoryCommitOp {
    action: String,
    path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prev: Option<String>,
}

#[derive(Debug)]
struct HttpError {
    status: u16,
    message: String,
}

impl HttpError {
    fn new(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(error: impl std::error::Error) -> Self {
        Self::new(400, error.to_string())
    }

    fn worker(error: impl std::fmt::Display) -> Self {
        Self::new(500, error.to_string())
    }

    fn xrpc(error: XrpcError) -> Self {
        Self::new(400, error.to_string())
    }

    fn identity(error: IdentityError) -> Self {
        Self::new(400, error.to_string())
    }

    fn auth(error: crate::auth::AuthError) -> Self {
        Self::new(401, error.to_string())
    }

    fn storage(error: StorageError) -> Self {
        Self::new(500, error.to_string())
    }

    fn import(error: RepoImportError) -> Self {
        Self::new(400, error.to_string())
    }

    fn car(error: CarError) -> Self {
        match error {
            CarError::MissingBlock { .. } => Self::new(500, error.to_string()),
            _ => Self::worker(error),
        }
    }

    fn repo(error: RepoError) -> Self {
        match error {
            RepoError::RecordAlreadyExists { .. } => Self::new(409, error.to_string()),
            RepoError::RecordNotFound { .. }
            | RepoError::MissingRecordBlock { .. }
            | RepoError::MissingCommit { .. } => Self::new(404, error.to_string()),
            RepoError::Commit(crate::commit::CommitError::InvalidDid { .. })
            | RepoError::Commit(crate::commit::CommitError::InvalidRev { .. }) => {
                Self::new(400, error.to_string())
            }
            _ => Self::worker(error),
        }
    }
}

fn mutation_response(path: &RepoPath, mutation: &RepoMutation) -> Value {
    json!({
        "path": path.to_string(),
        "recordCid": mutation.record_cid.map(|cid| cid.to_string()),
        "latestCommit": mutation.commit_cid.to_string(),
        "latestRev": mutation.commit.rev.to_string(),
        "mstRoot": mutation.mst_root.to_string(),
        "prev": mutation.commit.prev.map(|cid| cid.to_string()),
    })
}

fn xrpc_record_mutation_response(did: &Did, path: &RepoPath, mutation: &RepoMutation) -> Value {
    json!({
        "uri": at_uri(did.as_str(), path.collection.as_str(), path.rkey.as_str()),
        "cid": mutation.record_cid.map(|cid| cid.to_string()),
        "commit": {
            "cid": mutation.commit_cid.to_string(),
            "rev": mutation.commit.rev.to_string(),
        },
    })
}

fn xrpc_delete_mutation_response(mutation: &RepoMutation) -> Value {
    json!({
        "commit": {
            "cid": mutation.commit_cid.to_string(),
            "rev": mutation.commit.rev.to_string(),
        },
    })
}

fn xrpc_noop_delete_response(state: &RepoStateRow) -> Value {
    json!({
        "commit": {
            "cid": state.latest_commit.to_string(),
            "rev": state.latest_rev.to_string(),
        },
    })
}

fn xrpc_apply_writes_response(did: &Did, mutation: &RepoMutation) -> Value {
    json!({
        "commit": {
            "cid": mutation.commit_cid.to_string(),
            "rev": mutation.commit.rev.to_string(),
        },
        "results": mutation.ops
            .iter()
            .map(|op| match op.action {
                RepoOperationAction::Create => json!({
                    "$type": "com.atproto.repo.applyWrites#createResult",
                    "uri": at_uri(did.as_str(), op.path.collection.as_str(), op.path.rkey.as_str()),
                    "cid": op.cid.map(|cid| cid.to_string()),
                    "validationStatus": "unknown",
                }),
                RepoOperationAction::Update => json!({
                    "$type": "com.atproto.repo.applyWrites#updateResult",
                    "uri": at_uri(did.as_str(), op.path.collection.as_str(), op.path.rkey.as_str()),
                    "cid": op.cid.map(|cid| cid.to_string()),
                    "validationStatus": "unknown",
                }),
                RepoOperationAction::Delete => json!({
                    "$type": "com.atproto.repo.applyWrites#deleteResult",
                }),
            })
            .collect::<Vec<_>>(),
    })
}

fn directory_commit_ops(ops: &[RepoOperation]) -> Vec<DirectoryCommitOp> {
    ops.iter()
        .map(|op| DirectoryCommitOp {
            action: op.action.as_str().to_string(),
            path: op.path.to_string(),
            cid: op.cid.map(|cid| cid.to_string()),
            prev: op.prev.map(|cid| cid.to_string()),
        })
        .collect()
}

fn directory_import_ops(ops: &[ImportRepoOp]) -> Vec<DirectoryCommitOp> {
    ops.iter()
        .map(|op| DirectoryCommitOp {
            action: op.action.as_str().to_string(),
            path: op.path.to_string(),
            cid: op.cid.map(|cid| cid.to_string()),
            prev: op.prev.map(|cid| cid.to_string()),
        })
        .collect()
}

fn imported_blob_strings(records: &[crate::repo_import::ImportedRecord]) -> Vec<String> {
    records
        .iter()
        .flat_map(|record| record.blob_cids.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|cid| cid.to_string())
        .collect()
}

async fn repo_record_paths(
    repo: &mut SignedRepository<SqlRepoStore>,
) -> Result<Vec<RepoPath>, HttpError> {
    Ok(repo
        .entries()
        .await
        .map_err(HttpError::repo)?
        .into_iter()
        .map(|entry| entry.path)
        .collect())
}

fn validate_repo_paths(paths: Vec<String>) -> Result<Vec<RepoPath>, HttpError> {
    paths
        .into_iter()
        .map(|path| RepoPath::parse(&path).map_err(HttpError::bad_request))
        .collect::<Result<BTreeSet<_>, _>>()
        .map(|paths| paths.into_iter().collect())
}

#[derive(Debug, Default)]
struct RepoRecordPathOps {
    upserts: Vec<RepoPath>,
    deletes: Vec<RepoPath>,
}

fn repo_record_path_ops_from_commit_ops(
    ops: &[DirectoryCommitOp],
) -> Result<RepoRecordPathOps, HttpError> {
    let mut paths = BTreeMap::new();
    for op in ops {
        let path = RepoPath::parse(&op.path).map_err(HttpError::bad_request)?;
        paths.insert(path, op.action != "delete");
    }
    let (upserts, deletes): (Vec<_>, Vec<_>) = paths.into_iter().partition(|(_, active)| *active);
    Ok(RepoRecordPathOps {
        upserts: upserts.into_iter().map(|(path, _)| path).collect(),
        deletes: deletes.into_iter().map(|(path, _)| path).collect(),
    })
}

async fn mutation_diff_cids(
    repo: &mut SignedRepository<SqlRepoStore>,
    mutation: &RepoMutation,
) -> Result<Vec<crate::cid::Cid>, HttpError> {
    let mut seen = BTreeSet::new();
    let mut cids = Vec::new();
    for op in &mutation.ops {
        for cid in repo
            .extract_record_cids(&op.path)
            .await
            .map_err(HttpError::repo)?
        {
            if seen.insert(cid) {
                cids.push(cid);
            }
        }
    }
    if seen.insert(mutation.commit_cid) {
        cids.insert(0, mutation.commit_cid);
    }
    Ok(cids)
}

fn extract_record_blob_refs(record: &Value) -> Result<Vec<crate::cid::Cid>, HttpError> {
    extract_import_record_blob_refs(record).map_err(HttpError::import)
}

fn ensure_swap_commit(state: &RepoStateRow, swap_commit: Option<&str>) -> Result<(), HttpError> {
    let Some(swap_commit) = swap_commit else {
        return Ok(());
    };
    let cid = parse_cid(swap_commit).map_err(HttpError::bad_request)?;
    if cid == state.latest_commit {
        Ok(())
    } else {
        Err(invalid_swap("swapCommit did not match current repo commit"))
    }
}

fn ensure_optional_swap_record(
    current: Option<crate::cid::Cid>,
    swap_record: Option<&str>,
) -> Result<(), HttpError> {
    let Some(swap_record) = swap_record else {
        return Ok(());
    };
    let expected = parse_cid(swap_record).map_err(HttpError::bad_request)?;
    if current == Some(expected) {
        Ok(())
    } else {
        Err(invalid_swap("swapRecord did not match current record"))
    }
}

fn ensure_swap_record_field(
    current: Option<crate::cid::Cid>,
    swap_record: &SwapRecordField,
) -> Result<(), HttpError> {
    match swap_record {
        SwapRecordField::Missing => Ok(()),
        SwapRecordField::Absent if current.is_none() => Ok(()),
        SwapRecordField::Absent => Err(invalid_swap("swapRecord expected the record to be absent")),
        SwapRecordField::Cid(expected) => ensure_optional_swap_record(current, Some(expected)),
    }
}

fn invalid_swap(message: &str) -> HttpError {
    HttpError::new(400, format!("InvalidSwap: {message}"))
}

fn parse_apply_write_kind(value: &str) -> Result<RepoOperationAction, HttpError> {
    if value.ends_with("#create") || value == "create" {
        Ok(RepoOperationAction::Create)
    } else if value.ends_with("#update") || value == "update" {
        Ok(RepoOperationAction::Update)
    } else if value.ends_with("#delete") || value == "delete" {
        Ok(RepoOperationAction::Delete)
    } else {
        Err(HttpError::new(
            400,
            format!("unsupported applyWrites op type `{value}`"),
        ))
    }
}

fn blob_storage_key(cid: &crate::cid::Cid) -> String {
    format!("blobs/{cid}")
}

fn temporary_blob_storage_key() -> String {
    let random = (js_sys::Math::random() * u64::MAX as f64) as u64;
    format!(
        "blob-uploads/{}-{random:016x}",
        worker::Date::now().as_millis()
    )
}

fn blob_http_metadata(mime_type: &str) -> HttpMetadata {
    HttpMetadata {
        content_type: Some(mime_type.to_string()),
        content_language: None,
        content_disposition: None,
        content_encoding: None,
        cache_control: None,
        cache_expiry: None,
    }
}

fn request_content_length(req: &Request) -> Result<Option<u64>, HttpError> {
    let Some(value) = req
        .headers()
        .get("content-length")
        .map_err(HttpError::worker)?
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|error| HttpError::new(400, format!("invalid content-length header: {error}")))
}

fn ensure_import_repo_content_type(req: &Request) -> Result<(), HttpError> {
    let content_type = req
        .headers()
        .get("content-type")
        .map_err(HttpError::worker)?
        .and_then(|value| value.split(';').next().map(|part| part.trim().to_string()))
        .unwrap_or_default();
    if content_type == "application/vnd.ipld.car" {
        Ok(())
    } else {
        Err(HttpError::new(
            415,
            "importRepo requires content-type application/vnd.ipld.car",
        ))
    }
}

fn ensure_form_urlencoded(req: &Request) -> Result<(), HttpError> {
    let content_type = req
        .headers()
        .get("content-type")
        .map_err(HttpError::worker)?
        .and_then(|value| value.split(';').next().map(|part| part.trim().to_string()))
        .unwrap_or_default();
    if content_type == "application/x-www-form-urlencoded" {
        Ok(())
    } else {
        Err(HttpError::new(
            415,
            "OAuth endpoint requires content-type application/x-www-form-urlencoded",
        ))
    }
}

fn ensure_import_repo_size_limit(byte_len: u64) -> Result<(), HttpError> {
    if byte_len > MAX_IMPORT_REPO_BYTES as u64 {
        Err(HttpError::new(
            413,
            format!("repo import too large: max {MAX_IMPORT_REPO_BYTES} bytes"),
        ))
    } else {
        Ok(())
    }
}

fn ensure_blob_size_limit(byte_len: u64) -> Result<(), HttpError> {
    if byte_len > MAX_BLOB_BYTES as u64 {
        Err(HttpError::new(
            413,
            format!("blob too large: max {MAX_BLOB_BYTES} bytes"),
        ))
    } else {
        Ok(())
    }
}

fn require_admin_with_env(env: &Env, req: &Request) -> Result<(), HttpError> {
    if is_admin_authorized(env, req)? {
        Ok(())
    } else {
        Err(HttpError::new(401, "admin token required"))
    }
}

fn is_admin_authorized(env: &Env, req: &Request) -> Result<bool, HttpError> {
    let token = admin_token_from_env(env)?;
    let authorization = req
        .headers()
        .get("authorization")
        .map_err(HttpError::worker)?;
    let admin_header = req
        .headers()
        .get("x-pds-admin-token")
        .map_err(HttpError::worker)?;
    let expected_authorization = format!("Bearer {token}");
    Ok(
        authorization.as_deref() == Some(expected_authorization.as_str())
            || admin_header.as_deref() == Some(token.as_str()),
    )
}

fn admin_token_from_env(env: &Env) -> Result<String, HttpError> {
    let token = env
        .secret("PDS_ADMIN_TOKEN")
        .or_else(|_| env.var("PDS_ADMIN_TOKEN"))
        .map_err(|_| HttpError::new(500, "PDS_ADMIN_TOKEN binding is required"))?
        .to_string();
    if token.is_empty() {
        Err(HttpError::new(500, "PDS_ADMIN_TOKEN must not be empty"))
    } else {
        Ok(token)
    }
}

fn token_secret_from_env(env: &Env) -> Result<String, HttpError> {
    let token = match env
        .secret("PDS_JWT_SECRET")
        .or_else(|_| env.var("PDS_JWT_SECRET"))
    {
        Ok(value) => value.to_string(),
        Err(_) => admin_token_from_env(env)?,
    };
    if token.is_empty() {
        Err(HttpError::new(500, "PDS_JWT_SECRET must not be empty"))
    } else {
        Ok(token)
    }
}

fn bearer_token(req: &Request) -> Result<String, HttpError> {
    let authorization = req
        .headers()
        .get("authorization")
        .map_err(HttpError::worker)?
        .ok_or_else(|| HttpError::new(401, "authorization bearer token required"))?;
    authorization
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .map(|token| token.to_string())
        .ok_or_else(|| HttpError::new(401, "authorization bearer token required"))
}

fn ensure_supported_account_handle(handle: &str, request_host: &str) -> Result<(), HttpError> {
    if handle == request_host {
        Ok(())
    } else {
        Err(HttpError::new(
            400,
            format!("UnsupportedDomain: this PDS currently supports only `{request_host}`"),
        ))
    }
}

fn ensure_password_strength(password: &str) -> Result<(), HttpError> {
    if password.len() < 8 {
        Err(HttpError::new(
            400,
            "InvalidPassword: password must be at least 8 characters",
        ))
    } else {
        Ok(())
    }
}

fn session_response(
    url: &worker::Url,
    account: &DirectoryAccountRow,
    tokens: Option<SessionTokens>,
) -> Value {
    let mut body = json!({
        "did": account.did.to_string(),
        "handle": account.handle.clone(),
        "active": account.active,
        "didDoc": did_document(
            account.did.as_str(),
            &account.handle,
            &account.public_key_multibase,
            &request_origin(url),
        ),
    });
    if let Some(status) = &account.status {
        body["status"] = json!(status);
    }
    if let Some(email) = &account.email {
        body["email"] = json!(email);
        body["emailConfirmed"] = json!(false);
        body["emailAuthFactor"] = json!(false);
    }
    if let Some(tokens) = tokens {
        body["accessJwt"] = json!(tokens.access_jwt);
        body["refreshJwt"] = json!(tokens.refresh_jwt);
    }
    body
}

fn generate_repo_signing_key_hex() -> Result<String, HttpError> {
    for _ in 0..16 {
        let bytes = random_bytes::<REPO_SIGNING_KEY_BYTES>()?;
        let hex = hex_encode(&bytes);
        if RepoSigningKey::from_p256_hex(&hex).is_ok() {
            return Ok(hex);
        }
    }
    Err(HttpError::new(500, "failed to generate repo signing key"))
}

fn random_token_id() -> Result<String, HttpError> {
    Ok(BASE64_STANDARD.encode(random_bytes::<SESSION_ID_BYTES>()?))
}

fn random_bytes<const N: usize>() -> Result<[u8; N], HttpError> {
    let mut bytes = [0_u8; N];
    fill_random_bytes(&mut bytes)?;
    Ok(bytes)
}

#[cfg(target_arch = "wasm32")]
fn fill_random_bytes(bytes: &mut [u8]) -> Result<(), HttpError> {
    let array = js_sys::Uint8Array::new_with_length(bytes.len() as u32);
    let crypto = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))
        .map_err(js_value_error)?;
    let get_random_values = js_sys::Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
        .map_err(js_value_error)?
        .dyn_into::<js_sys::Function>()
        .map_err(js_value_error)?;
    get_random_values
        .call1(&crypto, &array)
        .map_err(js_value_error)?;
    array.copy_to(bytes);
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn fill_random_bytes(bytes: &mut [u8]) -> Result<(), HttpError> {
    getrandom::fill(bytes).map_err(|error| HttpError::new(500, error.to_string()))
}

#[cfg(target_arch = "wasm32")]
fn js_value_error(value: JsValue) -> HttpError {
    HttpError::new(
        500,
        value
            .as_string()
            .unwrap_or_else(|| "JavaScript error".to_string()),
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(HEX[(byte >> 4) as usize] as char);
        result.push(HEX[(byte & 0x0f) as usize] as char);
    }
    result
}

fn current_unix_time() -> i64 {
    (worker::Date::now().as_millis() / 1000) as i64
}

fn generated_initial_repo_rev() -> Result<RepoRev, HttpError> {
    let entropy = u64::from_le_bytes(random_bytes::<8>()?);
    RepoRev::new(generated_tid_from_entropy(entropy, 0)).map_err(HttpError::bad_request)
}

fn generated_record_key(seed: &crate::cid::Cid) -> Result<RecordKey, HttpError> {
    RecordKey::new(generated_tid(seed)).map_err(HttpError::bad_request)
}

fn generated_record_key_with_offset(
    seed: &crate::cid::Cid,
    offset: usize,
) -> Result<RecordKey, HttpError> {
    RecordKey::new(generated_tid_with_offset(seed, offset as u64)).map_err(HttpError::bad_request)
}

fn generated_repo_rev(seed: &crate::cid::Cid) -> Result<RepoRev, HttpError> {
    RepoRev::new(generated_tid(seed)).map_err(HttpError::bad_request)
}

fn generated_tid(seed: &crate::cid::Cid) -> String {
    generated_tid_with_offset(seed, 0)
}

fn generated_tid_with_offset(seed: &crate::cid::Cid, offset: u64) -> String {
    let entropy = seed.hash().digest().last().copied().unwrap_or_default() as u64;
    generated_tid_from_entropy(entropy, offset)
}

fn generated_tid_from_entropy(entropy: u64, offset: u64) -> String {
    const TID_ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";
    let mut value = worker::Date::now()
        .as_millis()
        .saturating_mul(1000)
        .saturating_add(entropy)
        .saturating_add(offset);
    let mut bytes = [b'2'; 13];
    for byte in bytes.iter_mut().rev() {
        *byte = TID_ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(bytes.to_vec()).expect("TID alphabet is ASCII")
}

fn ensure_repo_identifier(
    state: &RepoStateRow,
    identity: &RepoIdentityRow,
    repo: &str,
) -> Result<(), HttpError> {
    if repo == state.did.as_str() || repo == identity.handle {
        Ok(())
    } else {
        Err(HttpError::new(404, "repo not found"))
    }
}

fn subscribe_event_frame(event: &DirectoryEventRow) -> Result<Vec<u8>, HttpError> {
    if event.event_type == "account" {
        return subscribe_account_event_frame(event);
    }

    let commit = event
        .commit_cid
        .ok_or_else(|| HttpError::new(500, "directory commit event is missing commit cid"))?;
    let rev = event
        .rev
        .as_ref()
        .ok_or_else(|| HttpError::new(500, "directory commit event is missing rev"))?;
    let ops = from_str::<Vec<DirectoryCommitOp>>(&event.ops_json).map_err(HttpError::worker)?;
    let blobs = from_str::<Vec<String>>(&event.blobs_json).map_err(HttpError::worker)?;
    let frame_ops = ops
        .into_iter()
        .map(|op| {
            Ok(SubscribeReposOp {
                action: op.action,
                path: op.path,
                cid: op
                    .cid
                    .map(|cid| parse_cid(&cid).map_err(HttpError::bad_request))
                    .transpose()?,
                prev: op
                    .prev
                    .map(|cid| parse_cid(&cid).map_err(HttpError::bad_request))
                    .transpose()?,
            })
        })
        .collect::<Result<Vec<_>, HttpError>>()?;
    let frame_blobs = blobs
        .into_iter()
        .map(|cid| parse_cid(&cid).map_err(HttpError::bad_request))
        .collect::<Result<Vec<_>, HttpError>>()?;

    let header = SubscribeReposHeader {
        op: 1,
        kind: "#commit",
    };
    let body = SubscribeReposCommit {
        seq: event.seq,
        rebase: false,
        too_big: false,
        repo: event.did.to_string(),
        commit,
        rev: rev.to_string(),
        since: event.since.as_ref().map(|rev| rev.to_string()),
        blocks: event.blocks.clone().unwrap_or_default(),
        ops: frame_ops,
        blobs: frame_blobs,
        time: event.created_at.clone(),
    };

    let mut frame = encode_dag_cbor(&header).map_err(HttpError::worker)?;
    frame.extend(encode_dag_cbor(&body).map_err(HttpError::worker)?);
    Ok(frame)
}

fn subscribe_account_event_frame(event: &DirectoryEventRow) -> Result<Vec<u8>, HttpError> {
    let payload =
        from_str::<DirectoryAccountEventPayload>(&event.blobs_json).map_err(HttpError::worker)?;
    let header = SubscribeReposHeader {
        op: 1,
        kind: "#account",
    };
    let body = SubscribeReposAccount {
        seq: event.seq,
        did: event.did.to_string(),
        active: payload.active,
        status: payload.status,
        time: event.created_at.clone(),
    };

    let mut frame = encode_dag_cbor(&header).map_err(HttpError::worker)?;
    frame.extend(encode_dag_cbor(&body).map_err(HttpError::worker)?);
    Ok(frame)
}

#[derive(Serialize)]
struct SubscribeReposHeader<'a> {
    op: i64,
    #[serde(rename = "t")]
    kind: &'a str,
}

#[derive(Serialize)]
struct SubscribeReposCommit {
    seq: i64,
    rebase: bool,
    #[serde(rename = "tooBig")]
    too_big: bool,
    repo: String,
    commit: crate::cid::Cid,
    rev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    since: Option<String>,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
    ops: Vec<SubscribeReposOp>,
    blobs: Vec<crate::cid::Cid>,
    time: String,
}

#[derive(Deserialize)]
struct DirectoryAccountEventPayload {
    active: bool,
    status: Option<String>,
}

#[derive(Serialize)]
struct SubscribeReposAccount {
    seq: i64,
    did: String,
    active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    time: String,
}

#[derive(Serialize)]
struct SubscribeReposOp {
    action: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cid: Option<crate::cid::Cid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prev: Option<crate::cid::Cid>,
}

fn health_response() -> worker::Result<Response> {
    json_response(
        200,
        &json!({
            "version": env!("CARGO_PKG_VERSION"),
            "status": "ok",
        }),
    )
}

fn describe_server(url: &worker::Url) -> worker::Result<Response> {
    let domains = url
        .host_str()
        .map(|host| vec![host.to_string()])
        .unwrap_or_default();
    json_response(
        200,
        &json!({
            "did": "did:gsv:pds",
            "availableUserDomains": domains,
            "inviteCodeRequired": true,
            "phoneVerificationRequired": false,
            "links": {},
            "contact": {},
        }),
    )
}

fn oauth_metadata_response(url: &worker::Url) -> worker::Result<Response> {
    let origin = request_origin(url);
    let metadata = match url.path() {
        OAUTH_PROTECTED_RESOURCE_PATH => protected_resource_metadata(&origin),
        OAUTH_AUTHORIZATION_SERVER_PATH => authorization_server_metadata(&origin),
        _ => json!({}),
    };
    let mut response = Response::from_json(&metadata)?.with_status(200);
    response
        .headers_mut()
        .set("cache-control", "public, max-age=300")?;
    set_cors(&mut response)?;
    Ok(response)
}

fn did_document(
    did: &str,
    handle: &str,
    public_key_multibase: &str,
    service_endpoint: &str,
) -> Value {
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": did,
        "alsoKnownAs": [format!("at://{handle}")],
        "verificationMethod": [{
            "id": "#atproto",
            "type": "Multikey",
            "controller": did,
            "publicKeyMultibase": public_key_multibase,
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": service_endpoint,
        }],
    })
}

async fn fetch_directory_json(
    env: &Env,
    directory_name: &str,
    method: Method,
    path: &str,
    body: &Value,
) -> Result<Response, HttpError> {
    let namespace = env
        .durable_object("DIRECTORY_OBJECTS")
        .map_err(HttpError::worker)?;
    let id = namespace
        .id_from_name(directory_name)
        .map_err(HttpError::worker)?;
    let stub = id.get_stub().map_err(HttpError::worker)?;

    let headers = Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(HttpError::worker)?;
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(
            &to_string(body).map_err(HttpError::worker)?,
        )));
    let request = Request::new_with_init(&format!("https://pds.internal{path}"), &init)
        .map_err(HttpError::worker)?;

    stub.fetch_with_request(request)
        .await
        .map_err(HttpError::worker)
}

fn directory_repo_json(row: DirectoryRepoRow) -> Value {
    json!({
        "did": row.did.to_string(),
        "head": row.head.to_string(),
        "rev": row.rev.to_string(),
        "active": row.active,
        "handle": row.handle,
        "repoName": row.repo_name,
    })
}

fn query_pairs(url: &worker::Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn request_host(req: &Request) -> Result<String, HttpError> {
    req.url()
        .map_err(HttpError::worker)?
        .host_str()
        .map(|host| host.to_string())
        .ok_or_else(|| HttpError::new(400, "request host is required"))
}

fn is_host_identity_path(path: &str) -> bool {
    matches!(path, DID_DOCUMENT_PATH | ATPROTO_DID_PATH)
}

fn parse_xrpc_limit(value: Option<&str>, default: usize, max: usize) -> Result<usize, HttpError> {
    let Some(value) = value else {
        return Ok(default);
    };
    if value.is_empty() {
        return Ok(default);
    }
    let limit = value
        .parse::<usize>()
        .map_err(|_| HttpError::new(400, format!("invalid limit `{value}`")))?;
    if !(1..=max).contains(&limit) {
        return Err(HttpError::new(
            400,
            format!("invalid limit `{value}`: expected an integer from 1 to {max}"),
        ));
    }
    Ok(limit)
}

fn request_origin(url: &worker::Url) -> String {
    let mut origin = format!(
        "{}://{}",
        url.scheme(),
        url.host_str().unwrap_or("localhost")
    );
    if let Some(port) = url.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    origin
}

fn handle_is_correct(repo_param: &str, handle: &str, did: &str) -> bool {
    (repo_param == handle || repo_param == did)
        && did
            .strip_prefix("did:web:")
            .is_some_and(|host| host == handle)
}

fn ensure_repo_did(state: &RepoStateRow, did: &str) -> Result<(), HttpError> {
    if state.did.as_str() == did {
        Ok(())
    } else {
        Err(HttpError::new(404, "repo not found"))
    }
}

fn car_response(bytes: Vec<u8>) -> worker::Result<Response> {
    let mut response = Response::from_bytes(bytes)?;
    response
        .headers_mut()
        .set("content-type", "application/vnd.ipld.car")?;
    set_cors(&mut response)?;
    Ok(response)
}

fn blob_response(bytes: Vec<u8>, mime_type: &str) -> worker::Result<Response> {
    let mut response = Response::from_bytes(bytes)?;
    response.headers_mut().set("content-type", mime_type)?;
    set_cors(&mut response)?;
    Ok(response)
}

fn blob_stream_response(
    body: ResponseBody,
    mime_type: &str,
    byte_len: i64,
) -> worker::Result<Response> {
    let mut response = Response::from_body(body)?;
    response.headers_mut().set("content-type", mime_type)?;
    if byte_len >= 0 {
        response
            .headers_mut()
            .set("content-length", &byte_len.to_string())?;
    }
    set_cors(&mut response)?;
    Ok(response)
}

fn json_response(status: u16, value: &impl Serialize) -> worker::Result<Response> {
    let mut response = Response::from_json(value)?.with_status(status);
    set_cors(&mut response)?;
    Ok(response)
}

fn oauth_error_response(
    status: u16,
    error: &str,
    error_description: &str,
) -> worker::Result<Response> {
    let mut response = Response::from_json(&json!({
        "error": error,
        "error_description": error_description,
    }))?
    .with_status(status);
    response.headers_mut().set("cache-control", "no-store")?;
    set_cors(&mut response)?;
    Ok(response)
}

fn text_response(status: u16, value: &str) -> worker::Result<Response> {
    let mut response = Response::from_bytes(value.as_bytes().to_vec())?.with_status(status);
    response.headers_mut().set("content-type", "text/plain")?;
    set_cors(&mut response)?;
    Ok(response)
}

fn empty_response(status: u16) -> worker::Result<Response> {
    let mut response = Response::empty()?.with_status(status);
    set_cors(&mut response)?;
    Ok(response)
}

fn set_cors(response: &mut Response) -> worker::Result<()> {
    let headers = response.headers_mut();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, OPTIONS",
    )?;
    headers.set(
        "Access-Control-Allow-Headers",
        "authorization, content-type, dpop, x-pds-admin-token",
    )?;
    headers.set("Access-Control-Expose-Headers", "dpop-nonce")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_host_identity_well_known_paths() {
        assert!(is_host_identity_path("/.well-known/did.json"));
        assert!(is_host_identity_path("/.well-known/atproto-did"));
        assert!(!is_host_identity_path("/.well-known"));
        assert!(!is_host_identity_path("/.well-known/other"));
    }
}
