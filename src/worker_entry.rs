use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use base64::engine::general_purpose::{
    STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD,
};
use base64::Engine as _;
use futures_util::StreamExt;
use serde::de::{DeserializeOwned, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, json, to_string, to_vec, Value};
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue};
use worker::{
    durable_object, event, Context, DurableObject, Env, Fetch, FixedLengthStream, Headers,
    HttpMetadata, Method, Request, RequestInit, Response, ResponseBody, SqlStorage, State,
    WebSocket, WebSocketIncomingMessage, WebSocketPair,
};

use crate::atproto_resolver::{
    did_document_claims_handle, did_document_pds_endpoint, did_web_document_url,
    ensure_did_document_id, handle_did_txt_name, lexicon_authority_did_override,
    lexicon_authority_domain, lexicon_txt_name, prefixed_txt_values, validate_handle_syntax,
};
use crate::auth::{
    hash_password, oauth_session_claims, session_claims, sign_token, verify_password, verify_token,
    ACCESS_SCOPE, REFRESH_SCOPE,
};
use crate::car::{decode_car, encode_car, encode_car_from_store, CarBlock, CarError};
use crate::cbor::encode_dag_cbor;
use crate::cid::{parse_cid, raw_cid, raw_cid_from_sha256_digest};
use crate::commit::{CommitBlock, Did, RepoRev};
use crate::data_model::{Nsid, RecordKey, RepoPath};
use crate::do_store::{
    DirectoryAccountRow, DirectoryActionTokenInput, DirectoryActionTokenRow,
    DirectoryCommitEventInput, DirectoryEventRow, DirectoryInviteCodeInput, DirectoryInviteCodeRow,
    DirectoryInviteCodeUseRow, DirectoryOauthAuthorizationCodeInput, DirectoryOauthParRequestInput,
    DirectoryOauthParRequestRow, DirectoryRepoRow, DirectoryReservedSigningKeyInput,
    DirectoryReservedSigningKeyRow, DirectorySessionRow, RepoBlobRow, RepoCommitEventInput,
    RepoIdentityRow, RepoStateRow, SqlDirectoryStore, SqlRepoStore,
};
use crate::dpop::{dpop_htu, verify_dpop_proof, DpopError, VerifiedDpopProof};
use crate::identity::{IdentityError, RepoSigningKey};
use crate::lexicon::{self, RecordValidationStatus};
use crate::oauth::{
    authorization_server_metadata, client_auth_method_from_metadata, client_jwks_from_metadata,
    client_jwks_uri, is_localhost_client_id, is_oauth_well_known_path, parse_authorization_form,
    parse_authorization_request, parse_pushed_authorization_request, parse_token_request,
    protected_resource_metadata, validate_client_metadata, verify_private_key_jwt, OAuthClientAuth,
    OAuthClientAuthMethod, OAuthRequestError, TokenRequest, OAUTH_AUTHORIZATION_SERVER_PATH,
    OAUTH_AUTHORIZE_PATH, OAUTH_PAR_EXPIRES_IN_SECONDS, OAUTH_PAR_PATH,
    OAUTH_PROTECTED_RESOURCE_PATH, OAUTH_REQUEST_URI_PREFIX, OAUTH_TOKEN_PATH,
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
    at_uri, optional_param, parse_get_blocks_params, parse_list_records_params,
    repo_object_name_from_identifier, required_param, route_xrpc_method, strong_ref,
    ADMIN_DELETE_ACCOUNT, ADMIN_DISABLE_ACCOUNT_INVITES, ADMIN_DISABLE_INVITE_CODES,
    ADMIN_ENABLE_ACCOUNT_INVITES, ADMIN_GET_ACCOUNT_INFO, ADMIN_GET_ACCOUNT_INFOS,
    ADMIN_GET_INVITE_CODES, ADMIN_GET_SUBJECT_STATUS, ADMIN_SEARCH_ACCOUNTS, ADMIN_SEND_EMAIL,
    ADMIN_UPDATE_ACCOUNT_EMAIL, ADMIN_UPDATE_ACCOUNT_HANDLE, ADMIN_UPDATE_ACCOUNT_PASSWORD,
    ADMIN_UPDATE_ACCOUNT_SIGNING_KEY, ADMIN_UPDATE_SUBJECT_STATUS, IDENTITY_REFRESH_IDENTITY,
    IDENTITY_RESOLVE_DID, IDENTITY_RESOLVE_HANDLE, IDENTITY_RESOLVE_IDENTITY,
    IDENTITY_UPDATE_HANDLE, REPO_APPLY_WRITES, REPO_CREATE_RECORD, REPO_DELETE_RECORD,
    REPO_DESCRIBE_REPO, REPO_GET_RECORD, REPO_IMPORT_REPO, REPO_LIST_MISSING_BLOBS,
    REPO_LIST_RECORDS, REPO_PUT_RECORD, REPO_UPLOAD_BLOB, SERVER_ACTIVATE_ACCOUNT,
    SERVER_CHANGE_PASSWORD, SERVER_CHECK_ACCOUNT_STATUS, SERVER_CONFIRM_EMAIL,
    SERVER_CREATE_ACCOUNT, SERVER_CREATE_APP_PASSWORD, SERVER_CREATE_INVITE_CODE,
    SERVER_CREATE_INVITE_CODES, SERVER_CREATE_SESSION, SERVER_DEACTIVATE_ACCOUNT,
    SERVER_DELETE_ACCOUNT, SERVER_DELETE_SESSION, SERVER_DESCRIBE_SERVER,
    SERVER_GET_ACCOUNT_INVITE_CODES, SERVER_GET_SERVICE_AUTH, SERVER_GET_SESSION,
    SERVER_LIST_APP_PASSWORDS, SERVER_REFRESH_SESSION, SERVER_REQUEST_ACCOUNT_DELETE,
    SERVER_REQUEST_EMAIL_CONFIRMATION, SERVER_REQUEST_EMAIL_UPDATE, SERVER_REQUEST_PASSWORD_RESET,
    SERVER_RESERVE_SIGNING_KEY, SERVER_RESET_PASSWORD, SERVER_REVOKE_APP_PASSWORD,
    SERVER_UPDATE_EMAIL, SYNC_GET_BLOB, SYNC_GET_BLOCKS, SYNC_GET_CHECKOUT, SYNC_GET_HEAD,
    SYNC_GET_HOST_STATUS, SYNC_GET_LATEST_COMMIT, SYNC_GET_RECORD, SYNC_GET_REPO,
    SYNC_GET_REPO_STATUS, SYNC_LIST_BLOBS, SYNC_LIST_REPOS, SYNC_LIST_REPOS_BY_COLLECTION,
    SYNC_SUBSCRIBE_REPOS,
};
use crate::xrpc::{XrpcError, XrpcRoute};

const DID_DOCUMENT_PATH: &str = "/.well-known/did.json";
const ATPROTO_DID_PATH: &str = "/.well-known/atproto-did";
const BLOB_BUCKET_BINDING: &str = "BLOB_BUCKET";
const MAX_BLOB_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_MAX_ACCOUNT_BLOB_BYTES: i64 = 1024 * 1024 * 1024;
const TEMP_BLOB_TTL_SECONDS: i64 = 24 * 60 * 60;
const BLOB_GC_BATCH_LIMIT: usize = 200;
const MAX_IMPORT_REPO_BYTES: usize = 25 * 1024 * 1024;
const MAX_APPLY_WRITES: usize = 200;
const MAX_DYNAMIC_LEXICON_FETCHES: usize = 32;
const PASSWORD_SALT_BYTES: usize = 16;
const SESSION_ID_BYTES: usize = 24;
const APP_PASSWORD_BYTES: usize = 18;
const ACTION_TOKEN_BYTES: usize = 24;
const INVITE_CODE_BYTES: usize = 12;
const REPO_SIGNING_KEY_BYTES: usize = 32;
const OAUTH_REQUEST_URI_BYTES: usize = 32;
const OAUTH_DPOP_NONCE_BYTES: usize = 32;
const OAUTH_AUTHORIZATION_CODE_BYTES: usize = 32;
const ACCESS_TOKEN_TTL_SECONDS: i64 = 15 * 60;
const REFRESH_TOKEN_TTL_SECONDS: i64 = 60 * 60 * 24 * 30;
const ACTION_TOKEN_TTL_SECONDS: i64 = 60 * 60;
const OAUTH_AUTHORIZATION_CODE_TTL_SECONDS: i64 = 5 * 60;
const ACTION_ACCOUNT_DELETE: &str = "account_delete";
const ACTION_PASSWORD_RESET: &str = "password_reset";
const ACTION_EMAIL_CONFIRMATION: &str = "email_confirmation";
const ACTION_EMAIL_UPDATE: &str = "email_update";
const INTERNAL_REPO_CONTROL_ROOT: &str = "_pds_internal";
const INTERNAL_REPO_CONTROL_REPOS: &str = "repos";
const INTERNAL_REPO_CONTROL_STATUS: &str = "status";
const INTERNAL_REPO_CONTROL_INIT: &str = "init";
const INTERNAL_REPO_CONTROL_IDENTITY: &str = "identity";
const INTERNAL_REPO_CONTROL_SIGNING_KEY: &str = "signing-key";
const INTERNAL_REPO_CONTROL_SERVICE_AUTH: &str = "service-auth";
const INTERNAL_REPO_CONTROL_LEXICONS: &str = "lexicons";
const INTERNAL_DIRECTORY_CONTROL_DIRECTORY: &str = "directory";
const INTERNAL_DIRECTORY_CONTROL_STATUS: &str = "status";
const INTERNAL_DIRECTORY_CONTROL_ACCOUNTS: &str = "accounts";
const INTERNAL_DIRECTORY_CONTROL_REPOS: &str = "repos";
const INTERNAL_DIRECTORY_CONTROL_UPSERT: &str = "upsert";

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
            Ok(XrpcRoute::Worker) => handle_worker_xrpc(req.method(), parts[1], &url),
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
            Ok(XrpcRoute::RepoObjectByJsonBodyRepo) => forward_xrpc_json_body_repo(req, &env).await,
            Ok(XrpcRoute::RepoObjectByBearerSubject) => {
                forward_xrpc_bearer_subject(req, &env).await
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

    if url.path() != "/" {
        return json_response(
            404,
            &json!({
                "error": "not found",
            }),
        );
    }

    json_response(
        200,
        &json!({
            "name": "gsv-pds",
            "version": env!("CARGO_PKG_VERSION"),
            "status": "ready",
            "routes": {
                "oauthProtectedResource": "GET /.well-known/oauth-protected-resource",
                "oauthAuthorizationServer": "GET /.well-known/oauth-authorization-server",
                "oauthPar": "POST /oauth/par",
                "oauthAuthorize": "GET /oauth/authorize",
                "oauthToken": "POST /oauth/token",
                "xrpcDescribeServer": "GET /xrpc/com.atproto.server.describeServer",
                "xrpcResolveHandle": "GET /xrpc/com.atproto.identity.resolveHandle?handle=:handle",
                "xrpcResolveDid": "GET /xrpc/com.atproto.identity.resolveDid?did=:did",
                "xrpcResolveIdentity": "GET /xrpc/com.atproto.identity.resolveIdentity?identifier=:handle_or_did",
                "xrpcCreateAccount": "POST /xrpc/com.atproto.server.createAccount",
                "xrpcCreateSession": "POST /xrpc/com.atproto.server.createSession",
                "xrpcGetSession": "GET /xrpc/com.atproto.server.getSession",
                "xrpcRefreshSession": "POST /xrpc/com.atproto.server.refreshSession",
                "xrpcDeleteSession": "POST /xrpc/com.atproto.server.deleteSession",
                "xrpcChangePassword": "POST /xrpc/com.atproto.server.changePassword",
                "xrpcRequestPasswordReset": "POST /xrpc/com.atproto.server.requestPasswordReset",
                "xrpcResetPassword": "POST /xrpc/com.atproto.server.resetPassword",
                "xrpcRequestEmailConfirmation": "POST /xrpc/com.atproto.server.requestEmailConfirmation",
                "xrpcConfirmEmail": "POST /xrpc/com.atproto.server.confirmEmail",
                "xrpcRequestEmailUpdate": "POST /xrpc/com.atproto.server.requestEmailUpdate",
                "xrpcUpdateEmail": "POST /xrpc/com.atproto.server.updateEmail",
                "xrpcRequestAccountDelete": "POST /xrpc/com.atproto.server.requestAccountDelete",
                "xrpcDeleteAccount": "POST /xrpc/com.atproto.server.deleteAccount",
                "xrpcDeactivateAccount": "POST /xrpc/com.atproto.server.deactivateAccount",
                "xrpcActivateAccount": "POST /xrpc/com.atproto.server.activateAccount",
                "xrpcCheckAccountStatus": "GET /xrpc/com.atproto.server.checkAccountStatus",
                "xrpcGetServiceAuth": "GET /xrpc/com.atproto.server.getServiceAuth?aud=:did",
                "xrpcReserveSigningKey": "POST /xrpc/com.atproto.server.reserveSigningKey",
                "xrpcCreateInviteCode": "POST /xrpc/com.atproto.server.createInviteCode",
                "xrpcCreateInviteCodes": "POST /xrpc/com.atproto.server.createInviteCodes",
                "xrpcGetAccountInviteCodes": "GET /xrpc/com.atproto.server.getAccountInviteCodes",
                "xrpcCreateAppPassword": "POST /xrpc/com.atproto.server.createAppPassword",
                "xrpcListAppPasswords": "GET /xrpc/com.atproto.server.listAppPasswords",
                "xrpcRevokeAppPassword": "POST /xrpc/com.atproto.server.revokeAppPassword",
                "xrpcAdminDeleteAccount": "POST /xrpc/com.atproto.admin.deleteAccount",
                "xrpcAdminDisableAccountInvites": "POST /xrpc/com.atproto.admin.disableAccountInvites",
                "xrpcAdminDisableInviteCodes": "POST /xrpc/com.atproto.admin.disableInviteCodes",
                "xrpcAdminEnableAccountInvites": "POST /xrpc/com.atproto.admin.enableAccountInvites",
                "xrpcAdminGetAccountInfo": "GET /xrpc/com.atproto.admin.getAccountInfo?did=:did",
                "xrpcAdminGetAccountInfos": "GET /xrpc/com.atproto.admin.getAccountInfos?dids=:did",
                "xrpcAdminGetInviteCodes": "GET /xrpc/com.atproto.admin.getInviteCodes",
                "xrpcAdminGetSubjectStatus": "GET /xrpc/com.atproto.admin.getSubjectStatus?did=:did",
                "xrpcAdminSearchAccounts": "GET /xrpc/com.atproto.admin.searchAccounts",
                "xrpcAdminSendEmail": "POST /xrpc/com.atproto.admin.sendEmail",
                "xrpcAdminUpdateAccountEmail": "POST /xrpc/com.atproto.admin.updateAccountEmail",
                "xrpcAdminUpdateAccountHandle": "POST /xrpc/com.atproto.admin.updateAccountHandle",
                "xrpcAdminUpdateAccountPassword": "POST /xrpc/com.atproto.admin.updateAccountPassword",
                "xrpcAdminUpdateAccountSigningKey": "POST /xrpc/com.atproto.admin.updateAccountSigningKey",
                "xrpcAdminUpdateSubjectStatus": "POST /xrpc/com.atproto.admin.updateSubjectStatus",
                "xrpcDescribeRepo": "GET /xrpc/com.atproto.repo.describeRepo?repo=:repo",
                "xrpcGetRecord": "GET /xrpc/com.atproto.repo.getRecord?repo=:repo&collection=:nsid&rkey=:rkey",
                "xrpcListRecords": "GET /xrpc/com.atproto.repo.listRecords?repo=:repo&collection=:nsid",
                "xrpcCreateRecord": "POST /xrpc/com.atproto.repo.createRecord",
                "xrpcPutRecord": "POST /xrpc/com.atproto.repo.putRecord",
                "xrpcDeleteRecord": "POST /xrpc/com.atproto.repo.deleteRecord",
                "xrpcApplyWrites": "POST /xrpc/com.atproto.repo.applyWrites",
                "xrpcImportRepo": "POST /xrpc/com.atproto.repo.importRepo",
                "xrpcUploadBlob": "POST /xrpc/com.atproto.repo.uploadBlob",
                "xrpcListMissingBlobs": "GET /xrpc/com.atproto.repo.listMissingBlobs?repo=:repo",
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

async fn forward_xrpc_json_body_repo(req: Request, env: &Env) -> worker::Result<Response> {
    match try_forward_xrpc_json_body_repo(req, env).await {
        Ok(response) => Ok(response),
        Err(error) => json_response(
            error.status,
            &xrpc_error_body(&error.message, Some(error.message.as_str())),
        ),
    }
}

async fn try_forward_xrpc_json_body_repo(
    mut req: Request,
    env: &Env,
) -> Result<Response, HttpError> {
    let url = req.url().map_err(HttpError::worker)?.to_string();
    let method = req.method().clone();
    let headers = req.headers().clone();
    let body = req.text().await.map_err(HttpError::worker)?;
    let repo = xrpc_body_repo(&body)?;
    let request = request_with_text_body(&url, method, headers, &body)?;
    forward_request_to_repo_name(env, &repo_object_name_from_identifier(&repo), request).await
}

async fn forward_xrpc_bearer_subject(req: Request, env: &Env) -> worker::Result<Response> {
    match try_forward_xrpc_bearer_subject(req, env).await {
        Ok(response) => Ok(response),
        Err(error) => json_response(
            error.status,
            &xrpc_error_body(&error.message, Some(error.message.as_str())),
        ),
    }
}

async fn try_forward_xrpc_bearer_subject(req: Request, env: &Env) -> Result<Response, HttpError> {
    let presented = authorization_token(&req)?;
    let claims = verify_token(
        &token_secret_from_env(env)?,
        &presented.token,
        ACCESS_SCOPE,
        current_unix_time(),
    )
    .map_err(HttpError::auth)?;
    let did = Did::new(claims.sub).map_err(HttpError::bad_request)?;
    forward_request_to_repo_name(env, &repo_object_name_from_identifier(did.as_str()), req).await
}

async fn forward_request_to_repo_name(
    env: &Env,
    repo_name: &str,
    req: Request,
) -> Result<Response, HttpError> {
    let namespace = env
        .durable_object("REPO_OBJECTS")
        .map_err(HttpError::worker)?;
    let id = namespace
        .id_from_name(repo_name)
        .map_err(HttpError::worker)?;
    let stub = id.get_stub().map_err(HttpError::worker)?;
    stub.fetch_with_request(req)
        .await
        .map_err(HttpError::worker)
}

fn request_with_text_body(
    url: &str,
    method: Method,
    headers: Headers,
    body: &str,
) -> Result<Request, HttpError> {
    let mut init = RequestInit::new();
    init.with_method(method)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(body)));
    Request::new_with_init(url, &init).map_err(HttpError::worker)
}

fn xrpc_body_repo(body: &str) -> Result<String, HttpError> {
    let value: Value = from_str(body).map_err(HttpError::bad_request)?;
    value
        .get("repo")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|repo| !repo.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| HttpError::new(400, "MissingRepo"))
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
                &xrpc_error_body(&error.message, Some(error.message.as_str())),
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
                &xrpc_error_body(&error.message, Some(error.message.as_str())),
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
                (Method::Get, OAUTH_AUTHORIZE_PATH) => self.oauth_authorize(req, &url),
                (Method::Post, OAUTH_AUTHORIZE_PATH) => {
                    self.oauth_authorize_submit(req, &url).await
                }
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
                (Method::Post, SERVER_CHANGE_PASSWORD) => self.xrpc_change_password(req).await,
                (Method::Post, SERVER_REQUEST_PASSWORD_RESET) => {
                    self.xrpc_request_password_reset(req).await
                }
                (Method::Post, SERVER_RESET_PASSWORD) => self.xrpc_reset_password(req).await,
                (Method::Post, SERVER_REQUEST_EMAIL_CONFIRMATION) => {
                    self.xrpc_request_email_confirmation(req).await
                }
                (Method::Post, SERVER_CONFIRM_EMAIL) => self.xrpc_confirm_email(req).await,
                (Method::Post, SERVER_REQUEST_EMAIL_UPDATE) => {
                    self.xrpc_request_email_update(req).await
                }
                (Method::Post, SERVER_UPDATE_EMAIL) => self.xrpc_update_email(req, &url).await,
                (Method::Post, SERVER_REQUEST_ACCOUNT_DELETE) => {
                    self.xrpc_request_account_delete(req).await
                }
                (Method::Post, SERVER_DELETE_ACCOUNT) => self.xrpc_delete_account(req).await,
                (Method::Post, SERVER_DEACTIVATE_ACCOUNT) => {
                    self.xrpc_deactivate_account(req).await
                }
                (Method::Post, SERVER_ACTIVATE_ACCOUNT) => self.xrpc_activate_account(req, &url),
                (Method::Get, SERVER_CHECK_ACCOUNT_STATUS) => {
                    self.xrpc_check_account_status(req, &url).await
                }
                (Method::Get, SERVER_GET_SERVICE_AUTH) => {
                    self.xrpc_get_service_auth(req, &url).await
                }
                (Method::Post, SERVER_RESERVE_SIGNING_KEY) => {
                    self.xrpc_reserve_signing_key(req).await
                }
                (Method::Post, SERVER_CREATE_INVITE_CODE) => {
                    self.xrpc_create_invite_code(req).await
                }
                (Method::Post, SERVER_CREATE_INVITE_CODES) => {
                    self.xrpc_create_invite_codes(req).await
                }
                (Method::Get, SERVER_GET_ACCOUNT_INVITE_CODES) => {
                    self.xrpc_get_account_invite_codes(req, &url)
                }
                (Method::Post, SERVER_CREATE_APP_PASSWORD) => {
                    self.xrpc_create_app_password(req).await
                }
                (Method::Get, SERVER_LIST_APP_PASSWORDS) => self.xrpc_list_app_passwords(req),
                (Method::Post, SERVER_REVOKE_APP_PASSWORD) => {
                    self.xrpc_revoke_app_password(req).await
                }
                (Method::Get, IDENTITY_RESOLVE_HANDLE) => self.xrpc_resolve_handle(&url),
                (Method::Get, IDENTITY_RESOLVE_IDENTITY) => self.xrpc_resolve_identity(&url),
                (Method::Post, IDENTITY_UPDATE_HANDLE) => self.xrpc_update_handle(req, &url).await,
                (Method::Post, IDENTITY_REFRESH_IDENTITY) => {
                    self.xrpc_refresh_identity(req, &url).await
                }
                (Method::Post, ADMIN_DELETE_ACCOUNT) => self.xrpc_admin_delete_account(req).await,
                (Method::Post, ADMIN_DISABLE_ACCOUNT_INVITES) => {
                    self.xrpc_admin_disable_account_invites(req).await
                }
                (Method::Post, ADMIN_DISABLE_INVITE_CODES) => {
                    self.xrpc_admin_disable_invite_codes(req).await
                }
                (Method::Post, ADMIN_ENABLE_ACCOUNT_INVITES) => {
                    self.xrpc_admin_enable_account_invites(req).await
                }
                (Method::Get, ADMIN_GET_ACCOUNT_INFO) => {
                    self.xrpc_admin_get_account_info(req, &url)
                }
                (Method::Get, ADMIN_GET_ACCOUNT_INFOS) => {
                    self.xrpc_admin_get_account_infos(req, &url)
                }
                (Method::Get, ADMIN_GET_INVITE_CODES) => {
                    self.xrpc_admin_get_invite_codes(req, &url)
                }
                (Method::Get, ADMIN_GET_SUBJECT_STATUS) => {
                    self.xrpc_admin_get_subject_status(req, &url)
                }
                (Method::Get, ADMIN_SEARCH_ACCOUNTS) => self.xrpc_admin_search_accounts(req, &url),
                (Method::Post, ADMIN_SEND_EMAIL) => self.xrpc_admin_send_email(req).await,
                (Method::Post, ADMIN_UPDATE_ACCOUNT_EMAIL) => {
                    self.xrpc_admin_update_account_email(req).await
                }
                (Method::Post, ADMIN_UPDATE_ACCOUNT_HANDLE) => {
                    self.xrpc_admin_update_account_handle(req, &url).await
                }
                (Method::Post, ADMIN_UPDATE_ACCOUNT_PASSWORD) => {
                    self.xrpc_admin_update_account_password(req).await
                }
                (Method::Post, ADMIN_UPDATE_ACCOUNT_SIGNING_KEY) => {
                    self.xrpc_admin_update_account_signing_key(req, &url).await
                }
                (Method::Post, ADMIN_UPDATE_SUBJECT_STATUS) => {
                    self.xrpc_admin_update_subject_status(req).await
                }
                (
                    _,
                    SERVER_CREATE_ACCOUNT
                    | SERVER_CREATE_SESSION
                    | SERVER_GET_SESSION
                    | SERVER_REFRESH_SESSION
                    | SERVER_DELETE_SESSION
                    | SERVER_CHANGE_PASSWORD
                    | SERVER_REQUEST_PASSWORD_RESET
                    | SERVER_RESET_PASSWORD
                    | SERVER_REQUEST_EMAIL_CONFIRMATION
                    | SERVER_CONFIRM_EMAIL
                    | SERVER_REQUEST_EMAIL_UPDATE
                    | SERVER_UPDATE_EMAIL
                    | SERVER_REQUEST_ACCOUNT_DELETE
                    | SERVER_DELETE_ACCOUNT
                    | SERVER_DEACTIVATE_ACCOUNT
                    | SERVER_ACTIVATE_ACCOUNT
                    | SERVER_CHECK_ACCOUNT_STATUS
                    | SERVER_GET_SERVICE_AUTH
                    | SERVER_RESERVE_SIGNING_KEY
                    | SERVER_CREATE_INVITE_CODE
                    | SERVER_CREATE_INVITE_CODES
                    | SERVER_GET_ACCOUNT_INVITE_CODES
                    | SERVER_CREATE_APP_PASSWORD
                    | SERVER_LIST_APP_PASSWORDS
                    | SERVER_REVOKE_APP_PASSWORD
                    | IDENTITY_RESOLVE_HANDLE
                    | IDENTITY_RESOLVE_IDENTITY
                    | IDENTITY_UPDATE_HANDLE
                    | IDENTITY_REFRESH_IDENTITY
                    | ADMIN_DELETE_ACCOUNT
                    | ADMIN_DISABLE_ACCOUNT_INVITES
                    | ADMIN_DISABLE_INVITE_CODES
                    | ADMIN_ENABLE_ACCOUNT_INVITES
                    | ADMIN_GET_ACCOUNT_INFO
                    | ADMIN_GET_ACCOUNT_INFOS
                    | ADMIN_GET_INVITE_CODES
                    | ADMIN_GET_SUBJECT_STATUS
                    | ADMIN_SEARCH_ACCOUNTS
                    | ADMIN_SEND_EMAIL
                    | ADMIN_UPDATE_ACCOUNT_EMAIL
                    | ADMIN_UPDATE_ACCOUNT_HANDLE
                    | ADMIN_UPDATE_ACCOUNT_PASSWORD
                    | ADMIN_UPDATE_ACCOUNT_SIGNING_KEY
                    | ADMIN_UPDATE_SUBJECT_STATUS
                    | SYNC_LIST_REPOS
                    | SYNC_LIST_REPOS_BY_COLLECTION
                    | SYNC_GET_HOST_STATUS
                    | SYNC_SUBSCRIBE_REPOS,
                ) => Err(HttpError::new(405, "method not allowed")),
                _ => Err(HttpError::new(404, "unsupported XRPC method")),
            };
        }

        let parts = url
            .path()
            .trim_start_matches('/')
            .split('/')
            .collect::<Vec<_>>();
        if let Some(action) = internal_directory_control_action(&parts) {
            return match (req.method(), action) {
                (Method::Get, InternalDirectoryControlAction::Status) => self.internal_status(),
                (Method::Get, InternalDirectoryControlAction::AccountStatus) => {
                    self.internal_account_status(&url)
                }
                (Method::Post, InternalDirectoryControlAction::RepoUpsert) => {
                    self.internal_upsert_repo(req).await
                }
                _ => Err(HttpError::new(404, "not found")),
            };
        }

        Err(HttpError::new(404, "not found"))
    }

    fn store(&self) -> SqlDirectoryStore {
        SqlDirectoryStore::new(self.sql.clone())
    }

    fn internal_status(&self) -> Result<Response, HttpError> {
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

    fn internal_account_status(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = Did::new(required_param(&params, "did").map_err(HttpError::xrpc)?)
            .map_err(HttpError::bad_request)?;
        let Some(account) = self
            .store()
            .get_account_by_did(&did)
            .map_err(HttpError::worker)?
        else {
            return Err(HttpError::new(404, "account not found"));
        };
        json_response(
            200,
            &json!({
                "did": account.did.to_string(),
                "handle": account.handle,
                "active": account.active,
                "status": account.status,
            }),
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_resolve_identity(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let identifier = required_param(&params, "identifier").map_err(HttpError::xrpc)?;
        let Some(account) = self
            .store()
            .get_account_by_identifier(&identifier)
            .map_err(HttpError::worker)?
        else {
            let error = if identifier.starts_with("did:") {
                "DidNotFound"
            } else {
                "HandleNotFound"
            };
            return Err(HttpError::new(404, error));
        };
        if !account.active {
            return Err(HttpError::new(404, "DidDeactivated"));
        }

        json_response(
            200,
            &identity_info_response_body(&request_origin(url), &account),
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_resolve_handle(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let handle = required_param(&params, "handle")
            .map_err(HttpError::xrpc)?
            .to_ascii_lowercase();
        let Some(account) = self
            .store()
            .get_account_by_identifier(&handle)
            .map_err(HttpError::worker)?
        else {
            return Err(HttpError::new(404, "HandleNotFound"));
        };
        if account.handle != handle || !account.active {
            return Err(HttpError::new(404, "HandleNotFound"));
        }
        json_response(
            200,
            &json!({
                "did": account.did.to_string(),
            }),
        )
        .map_err(HttpError::worker)
    }

    fn set_account_active(
        &self,
        did: &Did,
        active: bool,
        status: Option<&str>,
    ) -> Result<(), HttpError> {
        let store = self.store();
        store
            .set_account_active(did, active, status)
            .map_err(HttpError::worker)?;
        store
            .set_repo_active(did, active)
            .map_err(HttpError::worker)?;
        let event = store
            .append_account_event(did, active, status)
            .map_err(HttpError::worker)?;
        self.broadcast_repo_event(&event)
    }

    async fn xrpc_create_account(
        &self,
        req: &mut Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let admin_authorized = is_admin_authorized(&self.env, req)?;
        let mut body: XrpcCreateAccountRequest = req.json().await.map_err(HttpError::worker)?;
        body.handle = body.handle.to_ascii_lowercase();
        body.email = normalize_account_email(body.email);
        body.invite_code = body
            .invite_code
            .map(|code| code.trim().to_string())
            .filter(|code| !code.is_empty());
        let request_host = request_host(req)?;
        if body.plc_op.is_some() {
            return Err(HttpError::new(400, "PLC operations are not implemented"));
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
        if !admin_authorized && body.invite_code.is_none() {
            return Err(HttpError::new(400, "InvalidInviteCode"));
        }
        if let Some(invite_code) = body.invite_code.as_deref() {
            self.ensure_invite_code_usable(&store, invite_code)?;
        }

        let (did, repo_name, validate_did_document) = account_identity_for_creation(
            &self.env,
            &body.handle,
            body.did.as_deref(),
            &request_host,
        )
        .await?;
        if store
            .get_account_by_did(&did)
            .map_err(HttpError::worker)?
            .is_some()
        {
            return Err(HttpError::new(400, "DidNotAvailable"));
        }
        let signing_key_hex = generate_repo_signing_key_hex()?;
        let init = match self
            .internal_initialize_account_repo(
                url,
                &repo_name,
                did.as_str(),
                &body.handle,
                &signing_key_hex,
            )
            .await
        {
            Ok(init) => init,
            Err(error) if is_repo_already_initialized_error(&error) => {
                self.recover_initialized_account_repo(url, &repo_name, did.as_str(), &body.handle)
                    .await?
            }
            Err(error) => return Err(error),
        };
        if validate_did_document {
            validate_account_did_document(&body.handle, did.as_str()).await?;
        }

        let salt = random_bytes::<PASSWORD_SALT_BYTES>()?;
        let account = DirectoryAccountRow {
            did: did.clone(),
            handle: body.handle.clone(),
            email: body.email.clone(),
            email_confirmed: false,
            invites_disabled: false,
            invite_note: None,
            password_hash: hash_password(password, &salt),
            repo_name: repo_name.clone(),
            public_key_multibase: init.public_key_multibase.clone(),
            active: true,
            status: None,
            created_at: current_datetime_string(),
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
        let identity_event = store
            .append_identity_event(&did, &body.handle)
            .map_err(HttpError::worker)?;
        self.broadcast_repo_event(&identity_event)?;
        let account_event = store
            .append_account_event(&did, true, None)
            .map_err(HttpError::worker)?;
        self.broadcast_repo_event(&account_event)?;
        if let Some(invite_code) = body.invite_code.as_deref() {
            self.consume_invite_code(&store, invite_code, &did)?;
        }

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
        let mut body: XrpcCreateSessionRequest = req.json().await.map_err(HttpError::worker)?;
        if !body.identifier.starts_with("did:") {
            body.identifier = body.identifier.to_ascii_lowercase();
        }
        let Some(account) = self
            .store()
            .get_account_by_identifier(&body.identifier)
            .map_err(HttpError::worker)?
        else {
            return Err(HttpError::new(401, "invalid identifier or password"));
        };
        if !self.verify_account_or_app_password(&account, &body.password)? {
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

    async fn xrpc_change_password(&self, req: &mut Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let body: XrpcChangePasswordRequest = req.json().await.map_err(HttpError::worker)?;
        if !verify_password(&body.old_password, &account.password_hash).map_err(HttpError::auth)? {
            return Err(HttpError::new(401, "invalid password"));
        }
        ensure_password_strength(&body.new_password)?;
        let salt = random_bytes::<PASSWORD_SALT_BYTES>()?;
        self.store()
            .update_account_password(&account.did, &hash_password(&body.new_password, &salt))
            .map_err(HttpError::worker)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_request_password_reset(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcRequestPasswordResetRequest = req.json().await.map_err(HttpError::worker)?;
        let email = normalize_required_email(&body.email)?;
        let account = self
            .store()
            .get_account_by_email(&email)
            .map_err(HttpError::worker)?;
        let token = if let Some(account) = account.filter(|account| account.active) {
            Some(self.issue_action_token(&account.did, ACTION_PASSWORD_RESET, Some(&email))?)
        } else {
            None
        };
        action_token_response(&self.env, req, token.as_deref()).map_err(HttpError::worker)
    }

    async fn xrpc_reset_password(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcResetPasswordRequest = req.json().await.map_err(HttpError::worker)?;
        ensure_password_strength(&body.password)?;
        let token = self.validate_action_token(ACTION_PASSWORD_RESET, &body.token)?;
        let account = self
            .store()
            .get_account_by_did(&token.did)
            .map_err(HttpError::worker)?
            .ok_or_else(|| HttpError::new(400, "InvalidToken"))?;
        if !account.active {
            return Err(HttpError::new(403, "AccountTakedown"));
        }
        let salt = random_bytes::<PASSWORD_SALT_BYTES>()?;
        let store = self.store();
        store
            .update_account_password(&account.did, &hash_password(&body.password, &salt))
            .map_err(HttpError::worker)?;
        store
            .delete_sessions_for_did(&account.did)
            .map_err(HttpError::worker)?;
        store
            .delete_app_passwords_for_did(&account.did)
            .map_err(HttpError::worker)?;
        self.consume_validated_action_token(&token)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_request_email_confirmation(&self, req: &Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let Some(email) = account.email.as_deref() else {
            return Err(HttpError::new(400, "InvalidEmail"));
        };
        let token =
            self.issue_action_token(&account.did, ACTION_EMAIL_CONFIRMATION, Some(email))?;
        action_token_response(&self.env, req, Some(&token)).map_err(HttpError::worker)
    }

    async fn xrpc_confirm_email(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcConfirmEmailRequest = req.json().await.map_err(HttpError::worker)?;
        let email = normalize_required_email(&body.email)?;
        let token = self.validate_action_token(ACTION_EMAIL_CONFIRMATION, &body.token)?;
        if token.email.as_deref() != Some(email.as_str()) {
            return Err(HttpError::new(400, "InvalidToken"));
        }
        let account = self
            .store()
            .get_account_by_did(&token.did)
            .map_err(HttpError::worker)?
            .ok_or_else(|| HttpError::new(400, "AccountNotFound"))?;
        if account.email.as_deref() != Some(email.as_str()) {
            return Err(HttpError::new(400, "InvalidEmail"));
        }
        self.store()
            .set_account_email_confirmed(&account.did, &email, true)
            .map_err(HttpError::worker)?;
        self.consume_validated_action_token(&token)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_request_email_update(&self, req: &Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let token = if account.email_confirmed {
            Some(self.issue_action_token(
                &account.did,
                ACTION_EMAIL_UPDATE,
                account.email.as_deref(),
            )?)
        } else {
            None
        };
        let mut body = json!({ "tokenRequired": account.email_confirmed });
        if is_admin_authorized(&self.env, req)? {
            if let Some(token) = token {
                body["token"] = json!(token);
            }
        }
        json_response(200, &body).map_err(HttpError::worker)
    }

    async fn xrpc_update_email(
        &self,
        req: &mut Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let mut account = self.account_for_claims(&claims)?;
        let body: XrpcUpdateEmailRequest = req.json().await.map_err(HttpError::worker)?;
        let email = normalize_required_email(&body.email)?;
        let mut email_update_token = None;
        if account.email_confirmed {
            let Some(token) = body.token.as_deref() else {
                return Err(HttpError::new(400, "TokenRequired"));
            };
            let token = self.validate_action_token(ACTION_EMAIL_UPDATE, token)?;
            if token.did != account.did {
                return Err(HttpError::new(400, "InvalidToken"));
            }
            email_update_token = Some(token);
        }
        account.email = Some(email);
        account.email_confirmed = false;
        self.store()
            .update_account_email(&account.did, account.email.as_deref(), false)
            .map_err(HttpError::worker)?;
        if let Some(token) = email_update_token {
            self.consume_validated_action_token(&token)?;
        }
        json_response(200, &session_response(url, &account, None)).map_err(HttpError::worker)
    }

    async fn xrpc_request_account_delete(&self, req: &Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let token = self.issue_action_token(
            &account.did,
            ACTION_ACCOUNT_DELETE,
            account.email.as_deref(),
        )?;
        action_token_response(&self.env, req, Some(&token)).map_err(HttpError::worker)
    }

    async fn xrpc_delete_account(&self, req: &mut Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let body: XrpcDeleteAccountRequest = req.json().await.map_err(HttpError::worker)?;
        let did = Did::new(body.did).map_err(HttpError::bad_request)?;
        if claims.sub != did.as_str() {
            return Err(HttpError::new(401, "InvalidToken"));
        }
        let account = self.account_for_claims(&claims)?;
        if account.did != did {
            return Err(HttpError::new(401, "InvalidToken"));
        }
        if !verify_password(&body.password, &account.password_hash).map_err(HttpError::auth)? {
            return Err(HttpError::new(401, "invalid password"));
        }
        let token = self.validate_action_token(ACTION_ACCOUNT_DELETE, &body.token)?;
        if token.did != account.did {
            return Err(HttpError::new(400, "InvalidToken"));
        }
        let store = self.store();
        store
            .delete_sessions_for_did(&account.did)
            .map_err(HttpError::worker)?;
        store
            .delete_app_passwords_for_did(&account.did)
            .map_err(HttpError::worker)?;
        store
            .delete_action_tokens_for_did(&account.did)
            .map_err(HttpError::worker)?;
        self.set_account_active(&account.did, false, Some("deleted"))?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_deactivate_account(&self, req: &Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        self.set_account_active(&account.did, false, Some("deactivated"))?;
        empty_response(200).map_err(HttpError::worker)
    }

    fn xrpc_activate_account(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims_allow_inactive(&claims)?;
        if account.status.as_deref() == Some("deleted") {
            return Err(HttpError::new(403, "AccountDeleted"));
        }
        self.set_account_active(&account.did, true, None)?;
        let account = self
            .store()
            .get_account_by_did(&account.did)
            .map_err(HttpError::worker)?
            .ok_or_else(|| HttpError::new(401, "InvalidToken"))?;
        json_response(200, &session_response(url, &account, None)).map_err(HttpError::worker)
    }

    async fn xrpc_check_account_status(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims_allow_inactive(&claims)?;
        let status = self
            .internal_account_repo_status(url, &account.repo_name)
            .await?;
        json_response(
            200,
            &json!({
                "activated": account.active,
                "validDid": status.did.as_deref() == Some(account.did.as_str()),
                "repoCommit": status.latest_commit.unwrap_or_default(),
                "repoRev": status.latest_rev.unwrap_or_default(),
                "repoBlocks": status.blocks,
                "indexedRecords": status.records,
                "privateStateValues": 0,
                "expectedBlobs": status.expected_blobs,
                "importedBlobs": status.imported_blobs,
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn xrpc_get_service_auth(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let params = query_pairs(url);
        let aud = Did::new(required_param(&params, "aud").map_err(HttpError::xrpc)?)
            .map_err(HttpError::bad_request)?;
        let lxm = optional_param(&params, "lxm")
            .filter(|value| !value.is_empty())
            .map(|value| Nsid::new(value).map_err(HttpError::bad_request))
            .transpose()?;
        let now = current_unix_time();
        let exp = match optional_param(&params, "exp").filter(|value| !value.is_empty()) {
            Some(value) => value
                .parse::<i64>()
                .map_err(|_| HttpError::new(400, "BadExpiration"))?,
            None => now.saturating_add(60),
        };
        if exp <= now || exp > now.saturating_add(60 * 60) {
            return Err(HttpError::new(400, "BadExpiration"));
        }
        let token = self
            .internal_sign_account_service_auth(
                url,
                &account.repo_name,
                aud.as_str(),
                lxm.as_ref(),
                exp,
            )
            .await?;
        json_response(200, &json!({ "token": token })).map_err(HttpError::worker)
    }

    async fn xrpc_reserve_signing_key(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcReserveSigningKeyRequest = optional_json_body(req).await?;
        let did = body
            .did
            .map(Did::new)
            .transpose()
            .map_err(HttpError::bad_request)?;
        let key_hex = generate_repo_signing_key_hex()?;
        let key = RepoSigningKey::from_p256_hex(&key_hex).map_err(HttpError::identity)?;
        let public_key_multibase = key.public_key_multibase().map_err(HttpError::identity)?;
        let signing_key = did_key_from_public_key_multibase(&public_key_multibase)?;
        self.store()
            .insert_reserved_signing_key(&DirectoryReservedSigningKeyInput {
                signing_key: signing_key.clone(),
                public_key_multibase,
                signing_key_p256_hex: key.to_p256_hex(),
                did,
            })
            .map_err(HttpError::worker)?;
        json_response(
            200,
            &json!({
                "signingKey": signing_key,
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn xrpc_create_invite_code(&self, req: &mut Request) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcCreateInviteCodeRequest = req.json().await.map_err(HttpError::worker)?;
        let for_account = match body.for_account {
            Some(did) => Did::new(did).map_err(HttpError::bad_request)?,
            None => self.host_account_did(req)?,
        };
        let code = self.create_invite_code(&for_account, &for_account, body.use_count)?;
        json_response(200, &json!({ "code": code })).map_err(HttpError::worker)
    }

    async fn xrpc_create_invite_codes(&self, req: &mut Request) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcCreateInviteCodesRequest = req.json().await.map_err(HttpError::worker)?;
        let code_count = body.code_count.unwrap_or(1).clamp(1, 100);
        let accounts = if let Some(accounts) = body.for_accounts {
            accounts
                .into_iter()
                .map(Did::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(HttpError::bad_request)?
        } else {
            vec![self.host_account_did(req)?]
        };
        let mut rows = Vec::new();
        for account in accounts {
            let mut codes = Vec::new();
            for _ in 0..code_count {
                codes.push(self.create_invite_code(&account, &account, body.use_count)?);
            }
            rows.push(json!({
                "account": account.to_string(),
                "codes": codes,
            }));
        }
        json_response(200, &json!({ "codes": rows })).map_err(HttpError::worker)
    }

    fn xrpc_get_account_invite_codes(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let params = query_pairs(url);
        let include_used = bool_param(&params, "includeUsed", true)?;
        let codes = self
            .store()
            .list_invite_codes_for_account(&account.did, include_used)
            .map_err(HttpError::worker)?;
        let codes = self.invite_code_values(&codes)?;
        json_response(200, &json!({ "codes": codes })).map_err(HttpError::worker)
    }

    async fn xrpc_admin_delete_account(&self, req: &mut Request) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcAdminDidRequest = req.json().await.map_err(HttpError::worker)?;
        let did = Did::new(body.did).map_err(HttpError::bad_request)?;
        self.delete_account_as_admin(&did)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_admin_disable_account_invites(
        &self,
        req: &mut Request,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcAdminAccountInvitesRequest = req.json().await.map_err(HttpError::worker)?;
        let did = Did::new(body.account).map_err(HttpError::bad_request)?;
        self.ensure_account_exists(&did)?;
        self.store()
            .set_account_invites_disabled(&did, true, body.note.as_deref())
            .map_err(HttpError::worker)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_admin_disable_invite_codes(
        &self,
        req: &mut Request,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcAdminDisableInviteCodesRequest =
            req.json().await.map_err(HttpError::worker)?;
        let accounts = body
            .accounts
            .unwrap_or_default()
            .into_iter()
            .map(Did::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(HttpError::bad_request)?;
        self.store()
            .disable_invite_codes(&body.codes.unwrap_or_default(), &accounts)
            .map_err(HttpError::worker)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_admin_enable_account_invites(
        &self,
        req: &mut Request,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcAdminAccountInvitesRequest = req.json().await.map_err(HttpError::worker)?;
        let did = Did::new(body.account).map_err(HttpError::bad_request)?;
        self.ensure_account_exists(&did)?;
        self.store()
            .set_account_invites_disabled(&did, false, body.note.as_deref())
            .map_err(HttpError::worker)?;
        empty_response(200).map_err(HttpError::worker)
    }

    fn xrpc_admin_get_account_info(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let params = query_pairs(url);
        let did = Did::new(required_param(&params, "did").map_err(HttpError::xrpc)?)
            .map_err(HttpError::bad_request)?;
        let account = self.account_by_did(&did)?;
        let invites = self
            .store()
            .list_invite_codes_for_account(&did, true)
            .map_err(HttpError::worker)?;
        let invites = self.invite_code_values(&invites)?;
        json_response(200, &account_view_json(&account, Some(invites))).map_err(HttpError::worker)
    }

    fn xrpc_admin_get_account_infos(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let params = query_pairs(url);
        let dids = did_array_param(&params, "dids")?;
        let accounts = self
            .store()
            .list_accounts_by_dids(&dids)
            .map_err(HttpError::worker)?;
        let infos = accounts
            .iter()
            .map(|account| account_view_json(account, None))
            .collect::<Vec<_>>();
        json_response(200, &json!({ "infos": infos })).map_err(HttpError::worker)
    }

    fn xrpc_admin_get_invite_codes(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let params = query_pairs(url);
        let limit = parse_xrpc_limit(optional_param(&params, "limit").as_deref(), 100, 500)?;
        let cursor = optional_param(&params, "cursor").filter(|value| !value.is_empty());
        let (codes, next_cursor) = self
            .store()
            .list_invite_codes(limit, cursor.as_deref())
            .map_err(HttpError::worker)?;
        let mut body = json!({ "codes": self.invite_code_values(&codes)? });
        if let Some(cursor) = next_cursor {
            body["cursor"] = json!(cursor);
        }
        json_response(200, &body).map_err(HttpError::worker)
    }

    fn xrpc_admin_get_subject_status(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let params = query_pairs(url);
        let Some(did) = optional_param(&params, "did").filter(|value| !value.is_empty()) else {
            return Err(HttpError::new(
                400,
                "UnsupportedSubject: only account DID subjects are implemented",
            ));
        };
        let did = Did::new(did).map_err(HttpError::bad_request)?;
        let account = self.account_by_did(&did)?;
        json_response(200, &subject_status_json(&account)).map_err(HttpError::worker)
    }

    fn xrpc_admin_search_accounts(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let params = query_pairs(url);
        let limit = parse_xrpc_limit(optional_param(&params, "limit").as_deref(), 50, 100)?;
        let cursor = optional_param(&params, "cursor").filter(|value| !value.is_empty());
        let email = optional_param(&params, "email")
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty());
        let (accounts, next_cursor) = self
            .store()
            .search_accounts(email.as_deref(), limit, cursor.as_deref())
            .map_err(HttpError::worker)?;
        let mut body = json!({
            "accounts": accounts.iter().map(|account| account_view_json(account, None)).collect::<Vec<_>>(),
        });
        if let Some(cursor) = next_cursor {
            body["cursor"] = json!(cursor);
        }
        json_response(200, &body).map_err(HttpError::worker)
    }

    async fn xrpc_admin_send_email(&self, req: &mut Request) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcAdminSendEmailRequest = req.json().await.map_err(HttpError::worker)?;
        let recipient = Did::new(body.recipient_did).map_err(HttpError::bad_request)?;
        let sender = Did::new(body.sender_did).map_err(HttpError::bad_request)?;
        self.ensure_account_exists(&recipient)?;
        let _ = (sender, body.content, body.subject, body.comment);
        json_response(200, &json!({ "sent": false })).map_err(HttpError::worker)
    }

    async fn xrpc_admin_update_account_email(
        &self,
        req: &mut Request,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcAdminUpdateAccountEmailRequest =
            req.json().await.map_err(HttpError::worker)?;
        let account = self.account_by_identifier(&body.account)?;
        let email = normalize_required_email(&body.email)?;
        self.store()
            .update_account_email(&account.did, Some(&email), false)
            .map_err(HttpError::worker)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_admin_update_account_handle(
        &self,
        req: &mut Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let mut body: XrpcAdminUpdateAccountHandleRequest =
            req.json().await.map_err(HttpError::worker)?;
        body.handle = body.handle.to_ascii_lowercase();
        validate_handle_syntax(&body.handle).map_err(HttpError::bad_request)?;
        let request_host = request_host(req)?;
        if body.handle != request_host
            && !configured_account_handle_allowed(&self.env, &body.handle)
        {
            return Err(HttpError::new(
                400,
                format!(
                    "UnsupportedDomain: `{}` is not the request host `{request_host}` and is not allowed by PDS_ALLOWED_ACCOUNT_HANDLES or PDS_ALLOWED_ACCOUNT_HANDLE_SUFFIXES",
                    body.handle
                ),
            ));
        }
        let did = Did::new(body.did).map_err(HttpError::bad_request)?;
        let mut account = self.account_by_did(&did)?;
        if account.handle != body.handle {
            let store = self.store();
            if let Some(existing) = store
                .get_account_by_identifier(&body.handle)
                .map_err(HttpError::worker)?
            {
                if existing.did != did {
                    return Err(HttpError::new(400, "HandleNotAvailable"));
                }
            }
            store
                .update_account_handle(&did, &body.handle)
                .map_err(HttpError::worker)?;
            store
                .update_repo_handle(&did, &body.handle)
                .map_err(HttpError::worker)?;
            self.internal_update_account_repo_identity(url, &account.repo_name, &body.handle)
                .await?;
            let event = store
                .append_identity_event(&did, &body.handle)
                .map_err(HttpError::worker)?;
            self.broadcast_repo_event(&event)?;
            account.handle = body.handle;
        }
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_admin_update_account_password(
        &self,
        req: &mut Request,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcAdminUpdateAccountPasswordRequest =
            req.json().await.map_err(HttpError::worker)?;
        let did = Did::new(body.did).map_err(HttpError::bad_request)?;
        self.ensure_account_exists(&did)?;
        ensure_password_strength(&body.password)?;
        let salt = random_bytes::<PASSWORD_SALT_BYTES>()?;
        let store = self.store();
        store
            .update_account_password(&did, &hash_password(&body.password, &salt))
            .map_err(HttpError::worker)?;
        store
            .delete_sessions_for_did(&did)
            .map_err(HttpError::worker)?;
        store
            .delete_app_passwords_for_did(&did)
            .map_err(HttpError::worker)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_admin_update_account_signing_key(
        &self,
        req: &mut Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcAdminUpdateAccountSigningKeyRequest =
            req.json().await.map_err(HttpError::worker)?;
        let did = Did::new(body.did).map_err(HttpError::bad_request)?;
        let account = self.account_by_did(&did)?;
        let reserved = self.take_reserved_signing_key(&did, &body.signing_key)?;
        self.internal_update_account_repo_signing_key(
            url,
            &account.repo_name,
            &reserved.signing_key_p256_hex,
        )
        .await?;
        self.store()
            .update_account_public_key(&did, &reserved.public_key_multibase)
            .map_err(HttpError::worker)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_admin_update_subject_status(
        &self,
        req: &mut Request,
    ) -> Result<Response, HttpError> {
        require_admin_with_env(&self.env, req)?;
        let body: XrpcAdminUpdateSubjectStatusRequest =
            req.json().await.map_err(HttpError::worker)?;
        let did = did_from_admin_subject(&body.subject)?;
        self.ensure_account_exists(&did)?;
        let takedown = body.takedown.as_ref().is_some_and(|status| status.applied);
        let deactivated = body
            .deactivated
            .as_ref()
            .is_some_and(|status| status.applied);
        let _status_refs = (
            body.takedown
                .as_ref()
                .and_then(|status| status.ref_value.as_deref()),
            body.deactivated
                .as_ref()
                .and_then(|status| status.ref_value.as_deref()),
        );
        let (active, status) = if takedown {
            (false, Some("takedown"))
        } else if deactivated {
            (false, Some("deactivated"))
        } else {
            (true, None)
        };
        self.set_account_active(&did, active, status)?;
        let account = self.account_by_did(&did)?;
        json_response(200, &subject_status_json(&account)).map_err(HttpError::worker)
    }

    async fn xrpc_create_app_password(&self, req: &mut Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let body: XrpcCreateAppPasswordRequest = req.json().await.map_err(HttpError::worker)?;
        ensure_app_password_name(&body.name)?;
        let password = generate_app_password()?;
        let salt = random_bytes::<PASSWORD_SALT_BYTES>()?;
        let created_at = self
            .store()
            .put_app_password(
                &account.did,
                &body.name,
                &hash_password(&password, &salt),
                body.privileged.unwrap_or(false),
            )
            .map_err(HttpError::worker)?;
        json_response(
            200,
            &json!({
                "name": body.name,
                "password": password,
                "createdAt": created_at,
                "privileged": body.privileged.unwrap_or(false),
            }),
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_list_app_passwords(&self, req: &Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let passwords = self
            .store()
            .list_app_passwords(&account.did)
            .map_err(HttpError::worker)?
            .into_iter()
            .map(|row| {
                json!({
                    "name": row.name,
                    "createdAt": row.created_at,
                    "privileged": row.privileged,
                })
            })
            .collect::<Vec<_>>();
        json_response(200, &json!({ "passwords": passwords })).map_err(HttpError::worker)
    }

    async fn xrpc_revoke_app_password(&self, req: &mut Request) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let body: XrpcRevokeAppPasswordRequest = req.json().await.map_err(HttpError::worker)?;
        self.store()
            .delete_app_password(&account.did, &body.name)
            .map_err(HttpError::worker)?;
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_update_handle(
        &self,
        req: &mut Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let mut account = self.account_for_claims(&claims)?;
        let mut body: XrpcUpdateHandleRequest = req.json().await.map_err(HttpError::worker)?;
        body.handle = body.handle.to_ascii_lowercase();
        self.ensure_handle_update_allowed(req, &account, &body.handle)
            .await?;
        if account.handle != body.handle {
            let store = self.store();
            if let Some(existing) = store
                .get_account_by_identifier(&body.handle)
                .map_err(HttpError::worker)?
            {
                if existing.did != account.did {
                    return Err(HttpError::new(400, "HandleNotAvailable"));
                }
            }
            store
                .update_account_handle(&account.did, &body.handle)
                .map_err(HttpError::worker)?;
            store
                .update_repo_handle(&account.did, &body.handle)
                .map_err(HttpError::worker)?;
            self.internal_update_account_repo_identity(url, &account.repo_name, &body.handle)
                .await?;
            let event = store
                .append_identity_event(&account.did, &body.handle)
                .map_err(HttpError::worker)?;
            self.broadcast_repo_event(&event)?;
            account.handle = body.handle;
        }
        empty_response(200).map_err(HttpError::worker)
    }

    async fn xrpc_refresh_identity(
        &self,
        req: &mut Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let body: XrpcRefreshIdentityRequest = req.json().await.map_err(HttpError::worker)?;
        let identifier = normalize_at_identifier(&body.identifier);
        let account = if identifier.starts_with("did:") {
            let did = Did::new(identifier.clone()).map_err(HttpError::bad_request)?;
            self.store()
                .get_account_by_did(&did)
                .map_err(HttpError::worker)?
                .ok_or_else(|| HttpError::new(404, "DidNotFound"))?
        } else {
            match self
                .store()
                .get_account_by_identifier(&identifier)
                .map_err(HttpError::worker)?
            {
                Some(account) => account,
                None => {
                    let Some(did) = resolve_handle_did(&identifier).await? else {
                        return Err(HttpError::new(404, "HandleNotFound"));
                    };
                    let did = Did::new(did).map_err(HttpError::bad_request)?;
                    self.store()
                        .get_account_by_did(&did)
                        .map_err(HttpError::worker)?
                        .ok_or_else(|| HttpError::new(404, "DidNotFound"))?
                }
            }
        };
        if !account.active {
            return Err(HttpError::new(400, "DidDeactivated"));
        }
        json_response(
            200,
            &identity_info_response_body(&request_origin(url), &account),
        )
        .map_err(HttpError::worker)
    }

    async fn ensure_handle_update_allowed(
        &self,
        req: &Request,
        account: &DirectoryAccountRow,
        handle: &str,
    ) -> Result<(), HttpError> {
        validate_handle_syntax(handle).map_err(HttpError::bad_request)?;
        if handle == account.handle {
            return Ok(());
        }
        let request_host = request_host(req)?;
        if handle != request_host && !configured_account_handle_allowed(&self.env, handle) {
            return Err(HttpError::new(
                400,
                format!(
                    "UnsupportedDomain: `{handle}` is not the request host `{request_host}` and is not allowed by PDS_ALLOWED_ACCOUNT_HANDLES or PDS_ALLOWED_ACCOUNT_HANDLE_SUFFIXES"
                ),
            ));
        }
        let Some(resolved_did) = resolve_handle_did(handle).await? else {
            return Err(HttpError::new(
                400,
                format!("HandleNotResolvable: `{handle}` did not resolve to a DID"),
            ));
        };
        if resolved_did != account.did.as_str() {
            return Err(HttpError::new(
                400,
                format!(
                    "HandleMismatch: `{handle}` resolves to `{resolved_did}`, expected `{}`",
                    account.did
                ),
            ));
        }
        Ok(())
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

    fn oauth_authorize(&self, req: &Request, url: &worker::Url) -> Result<Response, HttpError> {
        let request = match parse_authorization_request(&query_pairs(url)) {
            Ok(request) => request,
            Err(error) => return oauth_request_error_response(error).map_err(HttpError::worker),
        };
        if req
            .headers()
            .get("authorization")
            .map_err(HttpError::worker)?
            .is_some()
        {
            return self.oauth_authorize_with_bearer(req, url, request);
        }

        let now = current_unix_time();
        let store = self.store();
        let par = self.oauth_par_for_authorization(&store, &request, now)?;
        oauth_authorization_form_response(200, &par, None).map_err(HttpError::worker)
    }

    fn oauth_authorize_with_bearer(
        &self,
        req: &Request,
        url: &worker::Url,
        request: crate::oauth::AuthorizationRequest,
    ) -> Result<Response, HttpError> {
        let claims = self.require_bearer_claims(req, ACCESS_SCOPE)?;
        let account = self.account_for_claims(&claims)?;
        let now = current_unix_time();
        let store = self.store();
        let par = self.oauth_par_for_authorization(&store, &request, now)?;
        self.ensure_oauth_login_hint_matches(&par, &account)?;
        self.issue_oauth_authorization_code(url, &store, par, account, now)
    }

    async fn oauth_authorize_submit(
        &self,
        req: &mut Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        if let Err(error) = ensure_form_urlencoded(req) {
            return oauth_error_response(415, "invalid_request", &error.message)
                .map_err(HttpError::worker);
        }
        let body = req.text().await.map_err(HttpError::worker)?;
        let form = match parse_authorization_form(&body) {
            Ok(form) => form,
            Err(error) => return oauth_request_error_response(error).map_err(HttpError::worker),
        };
        let request = crate::oauth::AuthorizationRequest {
            client_id: form.client_id.clone(),
            request_uri: form.request_uri.clone(),
        };
        let now = current_unix_time();
        let store = self.store();
        let par = self.oauth_par_for_authorization(&store, &request, now)?;
        if !form.approved {
            return oauth_authorization_error_redirect(
                &par.redirect_uri,
                "access_denied",
                "authorization was denied",
                &par.state,
                &request_origin(url),
            );
        }

        let Some(account) = store
            .get_account_by_identifier(&form.identifier)
            .map_err(HttpError::worker)?
        else {
            return oauth_authorization_form_response(
                401,
                &par,
                Some("Invalid identifier or password"),
            )
            .map_err(HttpError::worker);
        };
        if !verify_password(&form.password, &account.password_hash).map_err(HttpError::auth)?
            || !account.active
        {
            return oauth_authorization_form_response(
                401,
                &par,
                Some("Invalid identifier or password"),
            )
            .map_err(HttpError::worker);
        }
        self.ensure_oauth_login_hint_matches(&par, &account)?;
        self.issue_oauth_authorization_code(url, &store, par, account, now)
    }

    fn oauth_par_for_authorization(
        &self,
        store: &SqlDirectoryStore,
        request: &crate::oauth::AuthorizationRequest,
        now: i64,
    ) -> Result<DirectoryOauthParRequestRow, HttpError> {
        store
            .purge_expired_oauth_par_requests(now)
            .map_err(HttpError::worker)?;
        store
            .purge_expired_oauth_authorization_codes(now)
            .map_err(HttpError::worker)?;
        let Some(par) = store
            .get_oauth_par_request(&request.request_uri, now)
            .map_err(HttpError::worker)?
        else {
            return Err(HttpError::new(400, "unknown or expired request_uri"));
        };
        if par.client_id != request.client_id {
            return Err(HttpError::new(400, "client_id did not match request_uri"));
        }
        Ok(par)
    }

    fn ensure_oauth_login_hint_matches(
        &self,
        par: &DirectoryOauthParRequestRow,
        account: &DirectoryAccountRow,
    ) -> Result<(), HttpError> {
        if par.login_hint.as_deref().is_some_and(|login_hint| {
            login_hint != account.handle.as_str() && login_hint != account.did.as_str()
        }) {
            return Err(HttpError::new(403, "login_hint did not match account"));
        }
        Ok(())
    }

    fn issue_oauth_authorization_code(
        &self,
        url: &worker::Url,
        store: &SqlDirectoryStore,
        par: DirectoryOauthParRequestRow,
        account: DirectoryAccountRow,
        now: i64,
    ) -> Result<Response, HttpError> {
        let code = random_urlsafe_token::<OAUTH_AUTHORIZATION_CODE_BYTES>()?;
        store
            .insert_oauth_authorization_code(&DirectoryOauthAuthorizationCodeInput {
                code: code.clone(),
                request_uri: par.request_uri.clone(),
                client_id: par.client_id.clone(),
                redirect_uri: par.redirect_uri.clone(),
                scope: par.scope.clone(),
                state: par.state.clone(),
                code_challenge: par.code_challenge.clone(),
                code_challenge_method: par.code_challenge_method.clone(),
                did: account.did,
                handle: account.handle,
                dpop_jkt: par.dpop_jkt.clone(),
                dpop_nonce: par.dpop_nonce,
                client_auth_method: par.client_auth_method,
                client_auth_kid: par.client_auth_kid,
                client_auth_alg: par.client_auth_alg,
                client_auth_jkt: par.client_auth_jkt,
                expires_at: now.saturating_add(OAUTH_AUTHORIZATION_CODE_TTL_SECONDS),
            })
            .map_err(HttpError::worker)?;
        store
            .delete_oauth_par_request(&par.request_uri)
            .map_err(HttpError::worker)?;

        oauth_authorization_redirect(&par.redirect_uri, &code, &par.state, &request_origin(url))
    }

    async fn oauth_pushed_authorization_request(
        &self,
        req: &mut Request,
    ) -> Result<Response, HttpError> {
        if let Err(error) = ensure_form_urlencoded(req) {
            return oauth_error_response(415, "invalid_request", &error.message)
                .map_err(HttpError::worker);
        }
        let body = req.text().await.map_err(HttpError::worker)?;
        let request = match parse_pushed_authorization_request(&body) {
            Ok(request) => request,
            Err(error) => return oauth_request_error_response(error).map_err(HttpError::worker),
        };
        let issuer = request_origin(&req.url().map_err(HttpError::worker)?);
        let client_auth = self.validate_oauth_par_client(&request, &issuer).await?;
        let dpop_proof = match verify_request_dpop(req, None, None, None) {
            Ok(proof) => proof,
            Err(error) => return oauth_dpop_error_response(error, None).map_err(HttpError::worker),
        };

        let now = current_unix_time();
        let store = self.store();
        self.remember_dpop_proof(&store, &dpop_proof, now)?;
        store
            .purge_expired_oauth_par_requests(now)
            .map_err(HttpError::worker)?;
        if store
            .has_oauth_par_state(&request.client_id, &request.state, now)
            .map_err(HttpError::worker)?
        {
            return oauth_error_response(
                400,
                "invalid_request",
                "duplicate OAuth state for this client",
            )
            .map_err(HttpError::worker);
        }

        let request_uri = format!(
            "{OAUTH_REQUEST_URI_PREFIX}{}",
            random_urlsafe_token::<OAUTH_REQUEST_URI_BYTES>()?
        );
        let dpop_nonce = random_urlsafe_token::<OAUTH_DPOP_NONCE_BYTES>()?;
        let expires_at = now.saturating_add(OAUTH_PAR_EXPIRES_IN_SECONDS);
        let params_json = to_string(&request.to_json()).map_err(HttpError::worker)?;
        store
            .insert_oauth_par_request(&DirectoryOauthParRequestInput {
                request_uri: request_uri.clone(),
                client_id: request.client_id,
                redirect_uri: request.redirect_uri,
                scope: request.scope,
                state: request.state,
                code_challenge: request.code_challenge,
                code_challenge_method: request.code_challenge_method,
                login_hint: request.login_hint,
                dpop_jkt: dpop_proof.jkt,
                dpop_nonce: dpop_nonce.clone(),
                client_auth_method: client_auth.method_str().to_string(),
                client_auth_kid: client_auth.kid.clone(),
                client_auth_alg: client_auth.alg.clone(),
                client_auth_jkt: client_auth.jkt.clone(),
                params_json,
                expires_at,
            })
            .map_err(HttpError::worker)?;

        oauth_par_response(&request_uri, OAUTH_PAR_EXPIRES_IN_SECONDS, &dpop_nonce)
            .map_err(HttpError::worker)
    }

    async fn oauth_token(&self, req: &mut Request) -> Result<Response, HttpError> {
        if let Err(error) = ensure_form_urlencoded(req) {
            return oauth_error_response(415, "invalid_request", &error.message)
                .map_err(HttpError::worker);
        }
        let body = req.text().await.map_err(HttpError::worker)?;
        let request = match parse_token_request(&body) {
            Ok(request) => request,
            Err(error) => return oauth_request_error_response(error).map_err(HttpError::worker),
        };
        match request {
            TokenRequest::AuthorizationCode {
                client_id,
                code,
                redirect_uri,
                code_verifier,
                client_auth,
            } => {
                self.oauth_authorization_code_token(
                    req,
                    &client_id,
                    &code,
                    &redirect_uri,
                    &code_verifier,
                    &client_auth,
                )
                .await
            }
            TokenRequest::RefreshToken {
                client_id,
                refresh_token,
                client_auth,
            } => {
                self.oauth_refresh_token(req, &client_id, &refresh_token, &client_auth)
                    .await
            }
        }
    }

    async fn oauth_authorization_code_token(
        &self,
        req: &Request,
        client_id: &str,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
        client_auth: &OAuthClientAuth,
    ) -> Result<Response, HttpError> {
        let now = current_unix_time();
        let store = self.store();
        store
            .purge_expired_oauth_authorization_codes(now)
            .map_err(HttpError::worker)?;
        let Some(authorization_code) = store
            .get_oauth_authorization_code(code, now)
            .map_err(HttpError::worker)?
        else {
            return oauth_error_response(
                400,
                "invalid_grant",
                "unknown or expired authorization code",
            )
            .map_err(HttpError::worker);
        };
        if authorization_code.client_id != client_id {
            return oauth_error_response(400, "invalid_grant", "client_id did not match code")
                .map_err(HttpError::worker);
        }
        if authorization_code.redirect_uri != redirect_uri {
            return oauth_error_response(400, "invalid_grant", "redirect_uri did not match code")
                .map_err(HttpError::worker);
        }
        if authorization_code.code_challenge_method != "S256"
            || pkce_s256_challenge(code_verifier) != authorization_code.code_challenge
        {
            return oauth_error_response(400, "invalid_grant", "PKCE verification failed")
                .map_err(HttpError::worker);
        }
        let expected_client_auth = OAuthClientAuthBinding::from_parts(
            &authorization_code.client_auth_method,
            authorization_code.client_auth_kid.clone(),
            authorization_code.client_auth_alg.clone(),
            authorization_code.client_auth_jkt.clone(),
        )?;
        let issuer = request_origin(&req.url().map_err(HttpError::worker)?);
        self.validate_oauth_client_auth(
            client_id,
            Some(&authorization_code.redirect_uri),
            &authorization_code.scope,
            client_auth,
            Some(&expected_client_auth),
            &issuer,
        )
        .await?;
        let dpop_proof = match verify_request_dpop(
            req,
            Some(&authorization_code.dpop_jkt),
            Some(&authorization_code.dpop_nonce),
            None,
        ) {
            Ok(proof) => proof,
            Err(error) => {
                return oauth_dpop_error_response(error, Some(&authorization_code.dpop_nonce))
                    .map_err(HttpError::worker);
            }
        };
        self.remember_dpop_proof(&store, &dpop_proof, now)?;

        let Some(account) = store
            .get_account_by_did(&authorization_code.did)
            .map_err(HttpError::worker)?
            .filter(|account| account.active)
        else {
            return oauth_error_response(
                400,
                "invalid_grant",
                "authorization account is unavailable",
            )
            .map_err(HttpError::worker);
        };
        store
            .consume_oauth_authorization_code(code, now)
            .map_err(HttpError::worker)?;
        let oauth_session = self.create_oauth_session_for_account(
            &account,
            client_id,
            &authorization_code.scope,
            &authorization_code.dpop_jkt,
            &expected_client_auth,
            None,
        )?;
        store
            .insert_session(&oauth_session.row)
            .map_err(HttpError::worker)?;
        oauth_token_response(
            &oauth_session.tokens,
            &authorization_code.scope,
            account.did.as_str(),
            &oauth_session.dpop_nonce,
        )
        .map_err(HttpError::worker)
    }

    async fn oauth_refresh_token(
        &self,
        req: &Request,
        client_id: &str,
        refresh_token: &str,
        client_auth: &OAuthClientAuth,
    ) -> Result<Response, HttpError> {
        let now = current_unix_time();
        let claims = match verify_token(
            &token_secret_from_env(&self.env)?,
            refresh_token,
            REFRESH_SCOPE,
            now,
        ) {
            Ok(claims) => claims,
            Err(_) => {
                return oauth_error_response(400, "invalid_grant", "invalid refresh token")
                    .map_err(HttpError::worker);
            }
        };
        if claims.client_id.as_deref() != Some(client_id) {
            return oauth_error_response(
                400,
                "invalid_grant",
                "client_id did not match refresh token",
            )
            .map_err(HttpError::worker);
        }
        let Some(scope) = claims.oauth_scope.as_deref() else {
            return oauth_error_response(
                400,
                "invalid_grant",
                "refresh token is not an OAuth token",
            )
            .map_err(HttpError::worker);
        };
        let Some(dpop_jkt) = claims.dpop_jkt.as_deref() else {
            return oauth_error_response(400, "invalid_grant", "refresh token is not DPoP-bound")
                .map_err(HttpError::worker);
        };
        let dpop_proof =
            match verify_request_dpop(req, Some(dpop_jkt), claims.dpop_nonce.as_deref(), None) {
                Ok(proof) => proof,
                Err(error) => {
                    return oauth_dpop_error_response(error, claims.dpop_nonce.as_deref())
                        .map_err(HttpError::worker);
                }
            };
        let store = self.store();
        self.remember_dpop_proof(&store, &dpop_proof, now)?;
        let Some(session) = store
            .get_session_by_refresh_jti(&claims.jti)
            .map_err(HttpError::worker)?
        else {
            return oauth_error_response(400, "invalid_grant", "refresh token is no longer active")
                .map_err(HttpError::worker);
        };
        if !session.active {
            return oauth_error_response(400, "invalid_grant", "refresh token is no longer active")
                .map_err(HttpError::worker);
        }
        let expected_client_auth = OAuthClientAuthBinding::from_parts(
            &session.client_auth_method,
            session.client_auth_kid.clone(),
            session.client_auth_alg.clone(),
            session.client_auth_jkt.clone(),
        )?;
        let issuer = request_origin(&req.url().map_err(HttpError::worker)?);
        self.validate_oauth_client_auth(
            client_id,
            None,
            scope,
            client_auth,
            Some(&expected_client_auth),
            &issuer,
        )
        .await?;
        let Some(account) = store
            .get_account_by_did(&session.did)
            .map_err(HttpError::worker)?
            .filter(|account| account.active)
        else {
            return oauth_error_response(
                400,
                "invalid_grant",
                "authorization account is unavailable",
            )
            .map_err(HttpError::worker);
        };
        let oauth_session = self.create_oauth_session_for_account(
            &account,
            client_id,
            scope,
            dpop_jkt,
            &expected_client_auth,
            Some(session.session_id),
        )?;
        store
            .rotate_session_refresh(
                &oauth_session.row.session_id,
                &oauth_session.row.refresh_jti,
            )
            .map_err(HttpError::worker)?;
        oauth_token_response(
            &oauth_session.tokens,
            scope,
            account.did.as_str(),
            &oauth_session.dpop_nonce,
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

    async fn internal_upsert_repo(&self, req: &mut Request) -> Result<Response, HttpError> {
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
            let event_type = event.event_type;
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
                prev_data: event
                    .prev_data
                    .map(|cid| parse_cid(&cid))
                    .transpose()
                    .map_err(HttpError::bad_request)?,
                blocks,
                ops_json: to_string(&event.ops).map_err(HttpError::worker)?,
                blobs_json: to_string(&event.blobs.unwrap_or_default())
                    .map_err(HttpError::worker)?,
            };
            let stored = match event_type {
                DirectoryCommitEventType::Sync => {
                    store.append_sync_event(&event).map_err(HttpError::worker)?
                }
                DirectoryCommitEventType::Commit => store
                    .append_commit_event(&event)
                    .map_err(HttpError::worker)?,
            };
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

    async fn fetch_internal_repo_control(
        &self,
        url: &worker::Url,
        repo_name: &str,
        method: Method,
        action: &str,
        body: Option<&Value>,
    ) -> Result<Response, HttpError> {
        let namespace = self
            .env
            .durable_object("REPO_OBJECTS")
            .map_err(HttpError::worker)?;
        let id = namespace
            .id_from_name(repo_name)
            .map_err(HttpError::worker)?;
        let stub = id.get_stub().map_err(HttpError::worker)?;
        let headers = Headers::new();
        headers
            .set("x-pds-admin-token", &admin_token_from_env(&self.env)?)
            .map_err(HttpError::worker)?;
        if body.is_some() {
            headers
                .set("content-type", "application/json")
                .map_err(HttpError::worker)?;
        }
        let mut init = RequestInit::new();
        init.with_method(method).with_headers(headers);
        if let Some(body) = body {
            init.with_body(Some(JsValue::from_str(
                &to_string(body).map_err(HttpError::worker)?,
            )));
        }
        let request =
            Request::new_with_init(&internal_repo_control_url(url, repo_name, action), &init)
                .map_err(HttpError::worker)?;
        stub.fetch_with_request(request)
            .await
            .map_err(HttpError::worker)
    }

    async fn internal_repo_control_response(
        &self,
        url: &worker::Url,
        repo_name: &str,
        method: Method,
        action: &str,
        body: Option<&Value>,
        failure_prefix: &str,
    ) -> Result<Response, HttpError> {
        let mut response = self
            .fetch_internal_repo_control(url, repo_name, method, action, body)
            .await?;
        if !(200..=299).contains(&response.status_code()) {
            let text = response.text().await.unwrap_or_else(|_| String::new());
            return Err(HttpError::new(
                response.status_code(),
                format!("{failure_prefix}: {text}"),
            ));
        }
        Ok(response)
    }

    async fn internal_repo_control_json<T: DeserializeOwned>(
        &self,
        url: &worker::Url,
        repo_name: &str,
        method: Method,
        action: &str,
        body: Option<&Value>,
        failure_prefix: &str,
    ) -> Result<T, HttpError> {
        let mut response = self
            .internal_repo_control_response(url, repo_name, method, action, body, failure_prefix)
            .await?;
        response.json().await.map_err(HttpError::worker)
    }

    async fn internal_initialize_account_repo(
        &self,
        url: &worker::Url,
        repo_name: &str,
        did: &str,
        handle: &str,
        signing_key_p256_hex: &str,
    ) -> Result<InternalInitRepoResponse, HttpError> {
        let body = json!({
            "did": did,
            "handle": handle,
            "rev": generated_initial_repo_rev()?.to_string(),
            "signingKeyP256Hex": signing_key_p256_hex,
            "reset": false,
            "notifyDirectory": false,
        });
        self.internal_repo_control_json(
            url,
            repo_name,
            Method::Post,
            INTERNAL_REPO_CONTROL_INIT,
            Some(&body),
            "failed to initialize repo",
        )
        .await
    }

    async fn recover_initialized_account_repo(
        &self,
        url: &worker::Url,
        repo_name: &str,
        expected_did: &str,
        expected_handle: &str,
    ) -> Result<InternalInitRepoResponse, HttpError> {
        let status = self.internal_account_repo_status(url, repo_name).await?;
        init_response_from_repo_status(status, expected_did, expected_handle)
    }

    async fn internal_update_account_repo_identity(
        &self,
        url: &worker::Url,
        repo_name: &str,
        handle: &str,
    ) -> Result<(), HttpError> {
        let body = json!({ "handle": handle });
        self.internal_repo_control_response(
            url,
            repo_name,
            Method::Put,
            INTERNAL_REPO_CONTROL_IDENTITY,
            Some(&body),
            "failed to update repo identity",
        )
        .await?;
        Ok(())
    }

    async fn internal_update_account_repo_signing_key(
        &self,
        url: &worker::Url,
        repo_name: &str,
        signing_key_p256_hex: &str,
    ) -> Result<(), HttpError> {
        let body = json!({ "signingKeyP256Hex": signing_key_p256_hex });
        self.internal_repo_control_response(
            url,
            repo_name,
            Method::Put,
            INTERNAL_REPO_CONTROL_SIGNING_KEY,
            Some(&body),
            "failed to update repo signing key",
        )
        .await?;
        Ok(())
    }

    async fn internal_account_repo_status(
        &self,
        url: &worker::Url,
        repo_name: &str,
    ) -> Result<InternalRepoStatusResponse, HttpError> {
        self.internal_repo_control_json(
            url,
            repo_name,
            Method::Get,
            INTERNAL_REPO_CONTROL_STATUS,
            None,
            "failed to read initialized repo status",
        )
        .await
    }

    async fn internal_sign_account_service_auth(
        &self,
        url: &worker::Url,
        repo_name: &str,
        aud: &str,
        lxm: Option<&Nsid>,
        exp: i64,
    ) -> Result<String, HttpError> {
        let mut body = json!({
            "aud": aud,
            "exp": exp,
        });
        if let Some(lxm) = lxm {
            body["lxm"] = json!(lxm.as_str());
        }
        let body: ServiceAuthResponse = self
            .internal_repo_control_json(
                url,
                repo_name,
                Method::Post,
                INTERNAL_REPO_CONTROL_SERVICE_AUTH,
                Some(&body),
                "failed to sign service auth token",
            )
            .await?;
        Ok(body.token)
    }

    fn create_invite_code(
        &self,
        for_account: &Did,
        created_by: &Did,
        use_count: i64,
    ) -> Result<String, HttpError> {
        if !(1..=100).contains(&use_count) {
            return Err(HttpError::new(400, "InvalidUseCount"));
        }
        let account = self.account_by_did(for_account)?;
        if !account.active {
            return Err(HttpError::new(403, "AccountTakedown"));
        }
        if account.invites_disabled {
            return Err(HttpError::new(403, "InvitesDisabled"));
        }
        let code = format!("gsv-{}", random_urlsafe_token::<INVITE_CODE_BYTES>()?);
        self.store()
            .insert_invite_code(&DirectoryInviteCodeInput {
                code: code.clone(),
                available: use_count,
                for_account: for_account.clone(),
                created_by: created_by.clone(),
            })
            .map_err(HttpError::worker)?;
        Ok(code)
    }

    fn ensure_invite_code_usable(
        &self,
        store: &SqlDirectoryStore,
        code: &str,
    ) -> Result<DirectoryInviteCodeRow, HttpError> {
        let invite = store
            .get_invite_code(code)
            .map_err(HttpError::worker)?
            .ok_or_else(|| HttpError::new(400, "InvalidInviteCode"))?;
        if invite.disabled || invite.available <= 0 {
            return Err(HttpError::new(400, "InvalidInviteCode"));
        }
        let Some(inviter) = store
            .get_account_by_did(&invite.for_account)
            .map_err(HttpError::worker)?
        else {
            return Err(HttpError::new(400, "InvalidInviteCode"));
        };
        if !inviter.active || inviter.invites_disabled {
            return Err(HttpError::new(400, "InvalidInviteCode"));
        }
        Ok(invite)
    }

    fn consume_invite_code(
        &self,
        store: &SqlDirectoryStore,
        code: &str,
        used_by: &Did,
    ) -> Result<(), HttpError> {
        self.ensure_invite_code_usable(store, code)?;
        store
            .consume_invite_code(code, used_by)
            .map_err(HttpError::worker)
    }

    fn invite_code_values(
        &self,
        codes: &[DirectoryInviteCodeRow],
    ) -> Result<Vec<Value>, HttpError> {
        let code_values = codes
            .iter()
            .map(|code| code.code.clone())
            .collect::<Vec<_>>();
        let uses_by_code = self
            .store()
            .list_invite_code_uses_for_codes(&code_values)
            .map_err(HttpError::worker)?;
        Ok(codes
            .iter()
            .map(|code| {
                let uses = uses_by_code
                    .get(&code.code)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]);
                invite_code_json(code, uses)
            })
            .collect())
    }

    fn host_account_did(&self, req: &Request) -> Result<Did, HttpError> {
        let host = request_host(req)?;
        Did::new(format!("did:web:{host}")).map_err(HttpError::bad_request)
    }

    fn account_by_did(&self, did: &Did) -> Result<DirectoryAccountRow, HttpError> {
        self.store()
            .get_account_by_did(did)
            .map_err(HttpError::worker)?
            .ok_or_else(|| HttpError::new(404, "AccountNotFound"))
    }

    fn account_by_identifier(&self, identifier: &str) -> Result<DirectoryAccountRow, HttpError> {
        let identifier = normalize_at_identifier(identifier);
        self.store()
            .get_account_by_identifier(&identifier)
            .map_err(HttpError::worker)?
            .ok_or_else(|| HttpError::new(404, "AccountNotFound"))
    }

    fn ensure_account_exists(&self, did: &Did) -> Result<(), HttpError> {
        self.account_by_did(did).map(|_| ())
    }

    fn delete_account_as_admin(&self, did: &Did) -> Result<(), HttpError> {
        let account = self.account_by_did(did)?;
        let store = self.store();
        store
            .delete_sessions_for_did(&account.did)
            .map_err(HttpError::worker)?;
        store
            .delete_app_passwords_for_did(&account.did)
            .map_err(HttpError::worker)?;
        store
            .delete_action_tokens_for_did(&account.did)
            .map_err(HttpError::worker)?;
        self.set_account_active(&account.did, false, Some("deleted"))
    }

    fn take_reserved_signing_key(
        &self,
        did: &Did,
        signing_key: &str,
    ) -> Result<DirectoryReservedSigningKeyRow, HttpError> {
        let signing_key = normalize_did_key(signing_key)?;
        let reserved = self
            .store()
            .get_reserved_signing_key(&signing_key)
            .map_err(HttpError::worker)?
            .ok_or_else(|| HttpError::new(400, "InvalidSigningKey"))?;
        if reserved.consumed_at.is_some() {
            return Err(HttpError::new(400, "InvalidSigningKey"));
        }
        if reserved
            .did
            .as_ref()
            .is_some_and(|reserved_did| reserved_did != did)
        {
            return Err(HttpError::new(400, "InvalidSigningKey"));
        }
        let public_key_multibase = public_key_multibase_from_did_key(&signing_key)?;
        if public_key_multibase != reserved.public_key_multibase {
            return Err(HttpError::new(400, "InvalidSigningKey"));
        }
        self.store()
            .consume_reserved_signing_key(&signing_key, did)
            .map_err(HttpError::worker)?;
        Ok(reserved)
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
                client_auth_method: "none".to_string(),
                client_auth_kid: None,
                client_auth_alg: None,
                client_auth_jkt: None,
            },
            tokens: SessionTokens {
                access_jwt,
                refresh_jwt,
            },
        })
    }

    fn create_oauth_session_for_account(
        &self,
        account: &DirectoryAccountRow,
        client_id: &str,
        oauth_scope: &str,
        dpop_jkt: &str,
        client_auth: &OAuthClientAuthBinding,
        session_id: Option<String>,
    ) -> Result<CreatedOAuthSession, HttpError> {
        let now = current_unix_time();
        let session_id = match session_id {
            Some(session_id) => session_id,
            None => random_token_id()?,
        };
        let access_jti = random_token_id()?;
        let refresh_jti = random_token_id()?;
        let dpop_nonce = random_urlsafe_token::<OAUTH_DPOP_NONCE_BYTES>()?;
        let secret = token_secret_from_env(&self.env)?;
        let access_jwt = sign_token(
            &secret,
            &oauth_session_claims(
                account.did.as_str(),
                &account.handle,
                &access_jti,
                ACCESS_SCOPE,
                now,
                ACCESS_TOKEN_TTL_SECONDS,
                client_id,
                oauth_scope,
                dpop_jkt,
                &dpop_nonce,
            ),
        )
        .map_err(HttpError::auth)?;
        let refresh_jwt = sign_token(
            &secret,
            &oauth_session_claims(
                account.did.as_str(),
                &account.handle,
                &refresh_jti,
                REFRESH_SCOPE,
                now,
                REFRESH_TOKEN_TTL_SECONDS,
                client_id,
                oauth_scope,
                dpop_jkt,
                &dpop_nonce,
            ),
        )
        .map_err(HttpError::auth)?;
        Ok(CreatedOAuthSession {
            row: DirectorySessionRow {
                session_id,
                did: account.did.clone(),
                refresh_jti,
                active: true,
                client_auth_method: client_auth.method_str().to_string(),
                client_auth_kid: client_auth.kid.clone(),
                client_auth_alg: client_auth.alg.clone(),
                client_auth_jkt: client_auth.jkt.clone(),
            },
            tokens: SessionTokens {
                access_jwt,
                refresh_jwt,
            },
            dpop_nonce,
        })
    }

    fn require_bearer_claims(
        &self,
        req: &Request,
        scope: &str,
    ) -> Result<crate::auth::TokenClaims, HttpError> {
        let presented = authorization_token(req)?;
        verify_token(
            &token_secret_from_env(&self.env)?,
            &presented.token,
            scope,
            current_unix_time(),
        )
        .map_err(HttpError::auth)
        .and_then(|claims| {
            if let Some(jkt) = claims.dpop_jkt.as_deref() {
                if presented.scheme != AuthScheme::Dpop {
                    return Err(HttpError::new(
                        401,
                        "DPoP-bound token requires DPoP authorization",
                    ));
                }
                let proof = verify_request_dpop(
                    req,
                    Some(jkt),
                    claims.dpop_nonce.as_deref(),
                    Some(&presented.token),
                )
                .map_err(|error| HttpError::new(401, error.to_string()))?;
                let store = self.store();
                self.remember_dpop_proof(&store, &proof, current_unix_time())?;
            }
            Ok(claims)
        })
    }

    fn account_for_claims(
        &self,
        claims: &crate::auth::TokenClaims,
    ) -> Result<DirectoryAccountRow, HttpError> {
        let account = self.account_for_claims_allow_inactive(claims)?;
        if !account.active {
            return Err(HttpError::new(403, "AccountTakedown"));
        }
        Ok(account)
    }

    fn account_for_claims_allow_inactive(
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
        Ok(account)
    }

    fn verify_account_or_app_password(
        &self,
        account: &DirectoryAccountRow,
        password: &str,
    ) -> Result<bool, HttpError> {
        if verify_password(password, &account.password_hash).map_err(HttpError::auth)? {
            return Ok(true);
        }
        for app_password in self
            .store()
            .list_app_passwords(&account.did)
            .map_err(HttpError::worker)?
        {
            if verify_password(password, &app_password.password_hash).map_err(HttpError::auth)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn issue_action_token(
        &self,
        did: &Did,
        purpose: &str,
        email: Option<&str>,
    ) -> Result<String, HttpError> {
        let now = current_unix_time();
        let token = random_urlsafe_token::<ACTION_TOKEN_BYTES>()?;
        self.store()
            .purge_expired_action_tokens(now)
            .map_err(HttpError::worker)?;
        self.store()
            .insert_action_token(&DirectoryActionTokenInput {
                token_digest: action_token_digest(&token),
                did: did.clone(),
                purpose: purpose.to_string(),
                email: email.map(|value| value.to_string()),
                expires_at: now.saturating_add(ACTION_TOKEN_TTL_SECONDS),
            })
            .map_err(HttpError::worker)?;
        Ok(token)
    }

    fn validate_action_token(
        &self,
        purpose: &str,
        token: &str,
    ) -> Result<DirectoryActionTokenRow, HttpError> {
        let now = current_unix_time();
        let digest = action_token_digest(token);
        let Some(row) = self
            .store()
            .get_action_token(purpose, &digest)
            .map_err(HttpError::worker)?
        else {
            return Err(HttpError::new(400, "InvalidToken"));
        };
        if row.consumed_at.is_some() {
            return Err(HttpError::new(400, "InvalidToken"));
        }
        if row.expires_at <= now {
            return Err(HttpError::new(400, "ExpiredToken"));
        }
        Ok(row)
    }

    fn consume_validated_action_token(
        &self,
        token: &DirectoryActionTokenRow,
    ) -> Result<(), HttpError> {
        self.store()
            .consume_action_token(&token.token_digest, current_unix_time())
            .map_err(HttpError::worker)
    }

    async fn validate_oauth_par_client(
        &self,
        request: &crate::oauth::PushedAuthorizationRequest,
        issuer: &str,
    ) -> Result<OAuthClientAuthBinding, HttpError> {
        self.validate_oauth_client_auth(
            &request.client_id,
            Some(&request.redirect_uri),
            &request.scope,
            &request.client_auth,
            None,
            issuer,
        )
        .await
    }

    async fn validate_oauth_client_auth(
        &self,
        client_id: &str,
        redirect_uri: Option<&str>,
        scope: &str,
        client_auth: &OAuthClientAuth,
        expected: Option<&OAuthClientAuthBinding>,
        issuer: &str,
    ) -> Result<OAuthClientAuthBinding, HttpError> {
        let metadata = if is_localhost_client_id(client_id) {
            None
        } else {
            Some(fetch_oauth_client_metadata(client_id).await?)
        };
        if let Some(redirect_uri) = redirect_uri {
            validate_client_metadata(client_id, metadata.as_ref(), redirect_uri, scope)
                .map_err(HttpError::bad_request)?;
        }

        let method = if let Some(metadata) = metadata.as_ref() {
            if metadata.get("client_id").and_then(Value::as_str) != Some(client_id) {
                return Err(HttpError::bad_request(
                    OAuthRequestError::InvalidParameter {
                        parameter: "client_id",
                        message: "client metadata client_id did not match".to_string(),
                    },
                ));
            }
            client_auth_method_from_metadata(metadata).map_err(HttpError::bad_request)?
        } else {
            OAuthClientAuthMethod::None
        };
        if method != client_auth.method() {
            return Err(HttpError::new(
                401,
                format!(
                    "OAuth client authentication method `{}` did not match client metadata `{}`",
                    client_auth.method().as_str(),
                    method.as_str()
                ),
            ));
        }

        let binding = match client_auth {
            OAuthClientAuth::None => OAuthClientAuthBinding::none(),
            OAuthClientAuth::PrivateKeyJwt { assertion } => {
                let metadata = metadata.as_ref().ok_or_else(|| {
                    HttpError::new(401, "localhost clients cannot use private_key_jwt")
                })?;
                let jwks = self.fetch_oauth_client_jwks(metadata).await?;
                let verified = verify_private_key_jwt(
                    assertion,
                    client_id,
                    issuer,
                    &jwks,
                    current_unix_time(),
                )
                .map_err(HttpError::bad_request)?;
                self.remember_oauth_client_assertion(client_id, &verified)?;
                OAuthClientAuthBinding::from_verified(verified)
            }
        };
        if let Some(expected) = expected {
            binding.ensure_matches(expected)?;
        }
        Ok(binding)
    }

    async fn fetch_oauth_client_jwks(&self, metadata: &Value) -> Result<Value, HttpError> {
        let fetched_jwks =
            if let Some(jwks_uri) = client_jwks_uri(metadata).map_err(HttpError::bad_request)? {
                Some(fetch_oauth_jwks(&jwks_uri).await?)
            } else {
                None
            };
        client_jwks_from_metadata(metadata, fetched_jwks.as_ref()).map_err(HttpError::bad_request)
    }

    fn remember_oauth_client_assertion(
        &self,
        client_id: &str,
        assertion: &crate::oauth::VerifiedClientAssertion,
    ) -> Result<(), HttpError> {
        let now = current_unix_time();
        let store = self.store();
        store
            .purge_expired_oauth_client_jtis(now)
            .map_err(HttpError::worker)?;
        if store
            .has_oauth_client_jti(client_id, &assertion.jti)
            .map_err(HttpError::worker)?
        {
            return Err(HttpError::new(401, "OAuth client assertion replay"));
        }
        store
            .insert_oauth_client_jti(client_id, &assertion.jti, assertion.expires_at)
            .map_err(HttpError::worker)?;
        Ok(())
    }

    fn remember_dpop_proof(
        &self,
        store: &SqlDirectoryStore,
        proof: &VerifiedDpopProof,
        now: i64,
    ) -> Result<(), HttpError> {
        store
            .purge_expired_dpop_jtis(now)
            .map_err(HttpError::worker)?;
        if store
            .has_dpop_jti(&proof.jkt, &proof.jti)
            .map_err(HttpError::worker)?
        {
            return Err(HttpError::new(400, "DPoP proof replay"));
        }
        store
            .insert_dpop_jti(&proof.jkt, &proof.jti, now.saturating_add(600))
            .map_err(HttpError::worker)?;
        Ok(())
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

        if let Some((repo_name, action)) = internal_repo_control_parts(&parts) {
            return match (req.method(), action) {
                (Method::Get, INTERNAL_REPO_CONTROL_STATUS) => self.status(),
                (Method::Post, INTERNAL_REPO_CONTROL_INIT) => self.init(req, repo_name).await,
                (Method::Put, INTERNAL_REPO_CONTROL_IDENTITY) => self.update_identity(req).await,
                (Method::Put, INTERNAL_REPO_CONTROL_SIGNING_KEY) => {
                    self.update_signing_key(req).await
                }
                (Method::Post, INTERNAL_REPO_CONTROL_SERVICE_AUTH) => self.service_auth(req).await,
                (Method::Post, INTERNAL_REPO_CONTROL_LEXICONS) => {
                    self.put_lexicon(req, repo_name).await
                }
                (Method::Get, INTERNAL_REPO_CONTROL_LEXICONS) => self.list_lexicons(req).await,
                _ => Err(HttpError::new(404, "not found")),
            };
        }

        Err(HttpError::new(404, "not found"))
    }

    fn store(&self) -> SqlRepoStore {
        SqlRepoStore::new(self.sql.clone())
    }

    async fn ensure_record_envelope_dynamic(
        &self,
        collection: &Nsid,
        record: &Value,
        validate: Option<bool>,
    ) -> Result<RecordValidationStatus, HttpError> {
        ensure_record_shape(collection, record)?;
        if validate == Some(false) {
            return Ok(RecordValidationStatus::Unknown);
        }
        let lexicons = self
            .lexicons_for_collection(collection, validate == Some(true))
            .await?;
        lexicon::validate_record_with_lexicons(
            collection.as_str(),
            record,
            validate == Some(true),
            &lexicons,
        )
        .map_err(|error| HttpError::new(400, error.to_string()))
    }

    async fn lexicons_for_collection(
        &self,
        collection: &Nsid,
        explicit: bool,
    ) -> Result<Vec<Value>, HttpError> {
        let mut lexicons = extra_lexicons_from_env(&self.env)?;
        for (nsid, cached) in self.store().list_lexicons().map_err(HttpError::worker)? {
            if lexicons
                .iter()
                .any(|lexicon| lexicon.get("id").and_then(Value::as_str) == Some(nsid.as_str()))
            {
                continue;
            }
            lexicons.push(from_str(&cached).map_err(|error| {
                HttpError::new(
                    500,
                    format!("cached Lexicon `{nsid}` could not be parsed: {error}"),
                )
            })?);
        }

        let has_collection = lexicons
            .iter()
            .any(|lexicon| lexicon.get("id").and_then(Value::as_str) == Some(collection.as_str()));

        if !has_collection && explicit {
            if let Some(published) = fetch_published_lexicon(&self.env, collection.as_str()).await?
            {
                let published_json = to_string(&published).map_err(HttpError::worker)?;
                self.store()
                    .put_lexicon(collection.as_str(), &published_json, "published")
                    .map_err(HttpError::worker)?;
                lexicons.push(published);
            }
        }
        if explicit {
            self.resolve_published_lexicon_dependencies(&mut lexicons)
                .await?;
        }

        Ok(lexicons)
    }

    async fn resolve_published_lexicon_dependencies(
        &self,
        lexicons: &mut Vec<Value>,
    ) -> Result<(), HttpError> {
        let mut known = lexicons
            .iter()
            .filter_map(|lexicon| lexicon.get("id").and_then(Value::as_str))
            .map(ToString::to_string)
            .collect::<BTreeSet<_>>();
        let mut queue = lexicons
            .iter()
            .flat_map(lexicon::referenced_lexicon_ids)
            .filter(|nsid| !known.contains(nsid))
            .collect::<VecDeque<_>>();
        let mut fetched = 0;

        while let Some(nsid) = queue.pop_front() {
            if known.contains(&nsid) {
                continue;
            }
            if fetched >= MAX_DYNAMIC_LEXICON_FETCHES {
                return Err(HttpError::new(
                    400,
                    format!(
                        "Lexicon dependency resolution exceeded {MAX_DYNAMIC_LEXICON_FETCHES} remote fetches"
                    ),
                ));
            }
            fetched += 1;

            let Some(published) = fetch_published_lexicon(&self.env, &nsid).await? else {
                continue;
            };
            let published_json = to_string(&published).map_err(HttpError::worker)?;
            self.store()
                .put_lexicon(&nsid, &published_json, "published")
                .map_err(HttpError::worker)?;
            known.insert(nsid);
            for reference in lexicon::referenced_lexicon_ids(&published) {
                if !known.contains(&reference) {
                    queue.push_back(reference);
                }
            }
            lexicons.push(published);
        }

        Ok(())
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
            (Method::Get, SYNC_GET_REPO_STATUS) => self.xrpc_get_repo_status(url).await,
            (Method::Get, SYNC_LIST_BLOBS) => self.xrpc_list_blobs(url).await,
            (Method::Get, SYNC_GET_BLOB) => self.xrpc_get_blob(url).await,
            (Method::Get, SYNC_GET_BLOCKS) => self.xrpc_get_blocks(url),
            (Method::Get, SYNC_GET_RECORD) => self.xrpc_get_sync_record(url).await,
            (Method::Get, SYNC_GET_CHECKOUT) => self.xrpc_get_checkout(url).await,
            (Method::Get, SYNC_GET_REPO) => self.xrpc_get_repo(url).await,
            (Method::Get, IDENTITY_RESOLVE_DID) => self.xrpc_resolve_did(url),
            (Method::Get, REPO_LIST_MISSING_BLOBS) => self.xrpc_list_missing_blobs(req, url).await,
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
                | IDENTITY_RESOLVE_DID
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
        let blobs = store.blob_count().map_err(HttpError::worker)?;
        let blob_bytes = store.total_blob_bytes().map_err(HttpError::worker)?;
        let expected_blobs = store.expected_blob_count().map_err(HttpError::worker)?;
        let imported_blobs = store.imported_blob_count().map_err(HttpError::worker)?;

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
                "blobs": blobs,
                "blobBytes": blob_bytes,
                "expectedBlobs": expected_blobs,
                "importedBlobs": imported_blobs,
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn service_auth(&self, req: &mut Request) -> Result<Response, HttpError> {
        self.require_admin(req)?;
        let body: ServiceAuthRequest = req.json().await.map_err(HttpError::worker)?;
        let aud = Did::new(body.aud).map_err(HttpError::bad_request)?;
        let lxm = body
            .lxm
            .map(Nsid::new)
            .transpose()
            .map_err(HttpError::bad_request)?;
        if body.exp <= current_unix_time() {
            return Err(HttpError::new(400, "BadExpiration"));
        }

        let state = self.repo_state()?;
        let identity = self.repo_identity()?;
        let signing_key = identity.signing_key().map_err(HttpError::identity)?;
        let token = service_auth_jwt(
            &signing_key,
            state.did.as_str(),
            aud.as_str(),
            lxm.as_ref().map(Nsid::as_str),
            body.exp,
        )?;
        json_response(200, &json!({ "token": token })).map_err(HttpError::worker)
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

    fn xrpc_resolve_did(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let store = self.store();
        let Some(state) = store.get_repo_state().map_err(HttpError::worker)? else {
            return Err(HttpError::new(404, "DidNotFound"));
        };
        if state.did.as_str() != did {
            return Err(HttpError::new(404, "DidNotFound"));
        }
        let identity = self.repo_identity_from(&store)?;
        json_response(
            200,
            &json!({
                "didDoc": did_document(
                    state.did.as_str(),
                    &identity.handle,
                    &identity.public_key_multibase,
                    &request_origin(url),
                ),
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

    async fn xrpc_get_repo_status(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let Some(state) = self.store().get_repo_state().map_err(HttpError::worker)? else {
            return Err(HttpError::new(404, "RepoNotFound"));
        };
        if state.did.as_str() != did {
            return Err(HttpError::new(404, "RepoNotFound"));
        }

        let account_status = self
            .directory_account_status_for_repo(url, state.did.as_str())
            .await?;
        let active = account_status.as_ref().is_none_or(|status| status.active);
        let mut body = json!({
            "did": state.did.to_string(),
            "active": active,
        });
        if active {
            body["rev"] = json!(state.latest_rev.to_string());
        } else if let Some(status) = account_status.and_then(|status| status.status) {
            body["status"] = json!(status);
        }

        json_response(200, &body).map_err(HttpError::worker)
    }

    async fn directory_account_status_for_repo(
        &self,
        url: &worker::Url,
        did: &str,
    ) -> Result<Option<InternalAccountStatusResponse>, HttpError> {
        let Some(host) = url.host_str() else {
            return Ok(None);
        };
        let path = internal_directory_account_status_path(did);
        let mut response =
            fetch_internal_directory_request(&self.env, host, Method::Get, &path, None).await?;
        let status = response.status_code();
        if status == 404 {
            return Ok(None);
        }
        if !(200..300).contains(&status) {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read directory response".to_string());
            return Err(HttpError::new(
                500,
                format!("account status lookup failed with status {status}: {message}"),
            ));
        }
        response.json().await.map(Some).map_err(HttpError::worker)
    }

    async fn ensure_repo_publicly_active(
        &self,
        url: &worker::Url,
        state: &RepoStateRow,
    ) -> Result<(), HttpError> {
        if self
            .directory_account_status_for_repo(url, state.did.as_str())
            .await?
            .is_some_and(|status| !status.active)
        {
            Err(HttpError::new(403, "RepoDeactivated"))
        } else {
            Ok(())
        }
    }

    async fn xrpc_list_blobs(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let state = self.repo_state()?;
        ensure_repo_did(&state, &did)?;
        self.ensure_repo_publicly_active(url, &state).await?;
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

    async fn xrpc_list_missing_blobs(
        &self,
        req: &Request,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let repo = required_param(&params, "repo").map_err(HttpError::xrpc)?;
        let limit = parse_xrpc_limit(optional_param(&params, "limit").as_deref(), 500, 1000)?;
        let cursor = optional_param(&params, "cursor").filter(|value| !value.is_empty());
        let state = self.repo_state()?;
        ensure_repo_identifier(&state, &self.repo_identity()?, &repo)?;
        self.require_repo_write_auth(req, &state.did).await?;
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
        self.ensure_repo_publicly_active(url, &state).await?;
        let cid = parse_cid(&cid).map_err(HttpError::bad_request)?;
        if self
            .store()
            .blob_ref_count(&cid)
            .map_err(HttpError::worker)?
            == 0
        {
            return Err(HttpError::new(404, "BlobNotFound"));
        }
        let Some(blob) = self.store().get_blob(&cid).map_err(HttpError::worker)? else {
            return Err(HttpError::new(404, "BlobNotFound"));
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

    async fn update_identity(&self, req: &mut Request) -> Result<Response, HttpError> {
        self.require_admin(req)?;
        let body: UpdateRepoIdentityRequest = req.json().await.map_err(HttpError::worker)?;
        let store = self.store();
        let mut identity = self.repo_identity_from(&store)?;
        identity.handle = body.handle.to_ascii_lowercase();
        validate_handle_syntax(&identity.handle).map_err(HttpError::bad_request)?;
        store
            .put_repo_identity(&identity)
            .map_err(HttpError::worker)?;
        json_response(
            200,
            &json!({
                "handle": identity.handle,
                "publicKeyMultibase": identity.public_key_multibase,
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn update_signing_key(&self, req: &mut Request) -> Result<Response, HttpError> {
        self.require_admin(req)?;
        let body: UpdateRepoSigningKeyRequest = req.json().await.map_err(HttpError::worker)?;
        let signing_key = RepoSigningKey::from_p256_hex(&body.signing_key_p256_hex)
            .map_err(HttpError::identity)?;
        let public_key_multibase = signing_key
            .public_key_multibase()
            .map_err(HttpError::identity)?;
        let store = self.store();
        self.repo_identity_from(&store)?;
        store
            .update_repo_signing_key(&signing_key.to_p256_hex(), &public_key_multibase)
            .map_err(HttpError::worker)?;
        json_response(
            200,
            &json!({
                "signingKey": did_key_from_public_key_multibase(&public_key_multibase)?,
                "publicKeyMultibase": public_key_multibase,
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn put_lexicon(&self, req: &mut Request, repo_name: &str) -> Result<Response, HttpError> {
        self.require_admin(req)?;
        let request_host = request_host(req)?;
        let body: Value = req.json().await.map_err(HttpError::worker)?;
        let submitted = submitted_lexicon_from_body(body)?;
        let lexicon = lexicon::normalize_schema_record(&submitted.lexicon)
            .map_err(|error| HttpError::new(400, error.to_string()))?;
        lexicon::validate_lexicon_schema(&lexicon)
            .map_err(|error| HttpError::new(400, error.to_string()))?;
        let nsid = lexicon::schema_id(&lexicon)
            .ok_or_else(|| HttpError::new(400, "Lexicon document must contain string `id`"))?;
        let lexicon_json = to_string(&lexicon).map_err(HttpError::worker)?;
        self.store()
            .put_lexicon(nsid, &lexicon_json, "admin")
            .map_err(HttpError::worker)?;

        let mut body = json!({
            "id": nsid,
            "stored": true,
            "published": false,
        });
        if submitted.publish {
            let published = self
                .publish_lexicon_record(&request_host, &repo_name, nsid, &lexicon)
                .await?;
            body["published"] = json!(true);
            body["uri"] = json!(published.uri);
            body["cid"] = json!(published.cid);
            body["commit"] = json!({
                "cid": published.commit_cid,
                "rev": published.commit_rev,
                "changed": published.changed,
            });
        }

        json_response(200, &body).map_err(HttpError::worker)
    }

    async fn list_lexicons(&self, req: &Request) -> Result<Response, HttpError> {
        self.require_admin(req)?;
        let nsids = self
            .store()
            .list_lexicon_nsids()
            .map_err(HttpError::worker)?;
        json_response(200, &json!({ "lexicons": nsids })).map_err(HttpError::worker)
    }

    async fn publish_lexicon_record(
        &self,
        request_host: &str,
        repo_name: &str,
        nsid: &str,
        lexicon: &Value,
    ) -> Result<PublishedLexiconRecord, HttpError> {
        let path = RepoPath::new(
            Nsid::new(lexicon::LEXICON_SCHEMA_COLLECTION).map_err(HttpError::bad_request)?,
            RecordKey::new(nsid).map_err(HttpError::bad_request)?,
        );
        let record = lexicon::published_schema_record(lexicon)
            .map_err(|error| HttpError::new(400, error.to_string()))?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        let existing = repo
            .get_record::<Value>(&path)
            .await
            .map_err(HttpError::repo)?;
        if let Some(existing) = existing.as_ref().filter(|stored| stored.record == record) {
            return Ok(PublishedLexiconRecord {
                uri: at_uri(
                    previous_state.did.as_str(),
                    path.collection.as_str(),
                    path.rkey.as_str(),
                ),
                cid: existing.cid.to_string(),
                commit_cid: previous_state.latest_commit.to_string(),
                commit_rev: previous_state.latest_rev.to_string(),
                changed: false,
            });
        }

        let rev = generated_repo_rev(&previous_state.latest_commit)?;
        let mutation = if existing.is_some() {
            repo.update_record(path.clone(), &record, rev, &signing_key)
                .await
        } else {
            repo.create_record(path.clone(), &record, rev, &signing_key)
                .await
        }
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
        let record_paths = [path.clone()];
        self.notify_directory(
            request_host,
            repo_name,
            &identity,
            &state,
            Some(&record_paths),
            Some(&event),
        )
        .await?;
        let record_cid = mutation
            .record_cid
            .ok_or_else(|| HttpError::new(500, "Lexicon publication is missing record cid"))?;

        Ok(PublishedLexiconRecord {
            uri: at_uri(
                state.did.as_str(),
                path.collection.as_str(),
                path.rkey.as_str(),
            ),
            cid: record_cid.to_string(),
            commit_cid: state.latest_commit.to_string(),
            commit_rev: state.latest_rev.to_string(),
            changed: true,
        })
    }

    async fn xrpc_create_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcCreateRecordRequest = req.json().await.map_err(HttpError::worker)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        ensure_repo_identifier(&previous_state, &identity, &body.repo)?;
        self.require_repo_write_auth(req, &previous_state.did)
            .await?;
        ensure_swap_commit(&previous_state, body.swap_commit.as_deref())?;

        let collection = Nsid::new(body.collection).map_err(HttpError::bad_request)?;
        let rkey = if let Some(rkey) = body.rkey {
            RecordKey::new(rkey).map_err(HttpError::bad_request)?
        } else {
            generated_record_key(&previous_state.latest_commit)?
        };
        let path = RepoPath::new(collection, rkey);
        let validation_status = self
            .ensure_record_envelope_dynamic(&path.collection, &body.record, body.validate)
            .await?;
        let blob_cids = extract_record_blob_refs(&body.record)?;
        ensure_blob_refs_available(repo.storage(), &blob_cids)?;
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

        let body = xrpc_record_mutation_response(&state.did, &path, &mutation, validation_status)?;
        json_response(200, &body).map_err(HttpError::worker)
    }

    async fn xrpc_put_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcPutRecordRequest = req.json().await.map_err(HttpError::worker)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        ensure_repo_identifier(&previous_state, &identity, &body.repo)?;
        self.require_repo_write_auth(req, &previous_state.did)
            .await?;
        ensure_swap_commit(&previous_state, body.swap_commit.as_deref())?;

        let path = RepoPath::new(
            Nsid::new(body.collection).map_err(HttpError::bad_request)?,
            RecordKey::new(body.rkey).map_err(HttpError::bad_request)?,
        );
        let existing = repo
            .get_record::<Value>(&path)
            .await
            .map_err(HttpError::repo)?;
        let previous_blob_cids = repo
            .storage()
            .blob_cids_for_path(&path)
            .map_err(HttpError::worker)?;
        ensure_swap_record_field(
            existing.as_ref().map(|record| record.cid),
            &body.swap_record,
        )?;
        let validation_status = self
            .ensure_record_envelope_dynamic(&path.collection, &body.record, body.validate)
            .await?;
        let blob_cids = extract_record_blob_refs(&body.record)?;
        ensure_blob_refs_available(repo.storage(), &blob_cids)?;
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
        self.delete_orphan_blobs(repo.storage(), &previous_blob_cids)
            .await?;
        self.notify_directory(
            &request_host,
            &identity.handle,
            &identity,
            &state,
            None,
            Some(&event),
        )
        .await?;

        let body = xrpc_record_mutation_response(&state.did, &path, &mutation, validation_status)?;
        json_response(200, &body).map_err(HttpError::worker)
    }

    async fn xrpc_delete_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: XrpcDeleteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        let request_host = request_host(req)?;
        let (previous_state, identity, signing_key, mut repo) =
            self.open_repo_for_write_with_state()?;
        ensure_repo_identifier(&previous_state, &identity, &body.repo)?;
        self.require_repo_write_auth(req, &previous_state.did)
            .await?;
        ensure_swap_commit(&previous_state, body.swap_commit.as_deref())?;

        let path = RepoPath::new(
            Nsid::new(body.collection).map_err(HttpError::bad_request)?,
            RecordKey::new(body.rkey).map_err(HttpError::bad_request)?,
        );
        let existing = repo
            .get_record::<Value>(&path)
            .await
            .map_err(HttpError::repo)?;
        let previous_blob_cids = repo
            .storage()
            .blob_cids_for_path(&path)
            .map_err(HttpError::worker)?;
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
        self.delete_orphan_blobs(repo.storage(), &previous_blob_cids)
            .await?;
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
        self.require_repo_write_auth(req, &previous_state.did)
            .await?;
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
        let mut orphan_blob_candidates = BTreeSet::new();
        let mut validation_statuses = BTreeMap::new();
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
                    let validation_status = self
                        .ensure_record_envelope_dynamic(&path.collection, &record, body.validate)
                        .await?;
                    let blobs = extract_record_blob_refs(&record)?;
                    ensure_blob_refs_available(repo.storage(), &blobs)?;
                    event_blobs.extend(blobs.iter().copied());
                    blob_ref_updates.push((path.clone(), Some(blobs)));
                    validation_statuses.insert(path.clone(), validation_status);
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
                    orphan_blob_candidates.extend(
                        repo.storage()
                            .blob_cids_for_path(&path)
                            .map_err(HttpError::worker)?,
                    );
                    let validation_status = self
                        .ensure_record_envelope_dynamic(&path.collection, &record, body.validate)
                        .await?;
                    let blobs = extract_record_blob_refs(&record)?;
                    ensure_blob_refs_available(repo.storage(), &blobs)?;
                    event_blobs.extend(blobs.iter().copied());
                    blob_ref_updates.push((path.clone(), Some(blobs)));
                    validation_statuses.insert(path.clone(), validation_status);
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
                    orphan_blob_candidates.extend(
                        repo.storage()
                            .blob_cids_for_path(&path)
                            .map_err(HttpError::worker)?,
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
        let orphan_blob_candidates = orphan_blob_candidates.into_iter().collect::<Vec<_>>();
        self.delete_orphan_blobs(repo.storage(), &orphan_blob_candidates)
            .await?;
        self.notify_directory(
            &request_host,
            &identity.handle,
            &identity,
            &state,
            None,
            Some(&event),
        )
        .await?;

        let body = xrpc_apply_writes_response(&state.did, &mutation, &validation_statuses)?;
        json_response(200, &body).map_err(HttpError::worker)
    }

    async fn xrpc_import_repo(&self, req: &mut Request) -> Result<Response, HttpError> {
        let request_host = request_host(req)?;
        let (previous_state, identity, mut existing_repo) = self.open_repo_with_identity()?;
        self.require_repo_write_auth(req, &previous_state.did)
            .await?;
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
        let previous_blob_cids = existing_repo
            .storage()
            .list_referenced_blob_cids()
            .map_err(HttpError::worker)?;
        let bytes = req.bytes().await.map_err(HttpError::worker)?;
        ensure_import_repo_size_limit(bytes.len() as u64)?;
        let decoded = decode_car(&bytes).map_err(|error| HttpError::new(400, error.to_string()))?;
        let imported = validate_imported_repo(decoded, &previous_state.did)
            .await
            .map_err(HttpError::import)?;
        let ops = diff_imported_records(existing_records, &imported.records);
        let event = DirectoryCommitEventPayload {
            event_type: DirectoryCommitEventType::Sync,
            since: Some(previous_state.latest_rev.clone()),
            prev_data: Some(existing_repo.mst_root()),
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
        self.delete_orphan_blobs(&store, &previous_blob_cids)
            .await?;
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
        self.require_repo_write_auth(req, &state.did).await?;
        self.purge_expired_unreferenced_blobs(&self.store(), current_unix_time())
            .await?;
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

    async fn require_repo_write_auth(&self, req: &Request, did: &Did) -> Result<(), HttpError> {
        if is_admin_authorized(&self.env, req)? {
            return Ok(());
        }
        let presented = authorization_token(req)?;
        let claims = verify_token(
            &token_secret_from_env(&self.env)?,
            &presented.token,
            ACCESS_SCOPE,
            current_unix_time(),
        )
        .map_err(HttpError::auth)?;
        if let Some(jkt) = claims.dpop_jkt.as_deref() {
            if presented.scheme != AuthScheme::Dpop {
                return Err(HttpError::new(
                    401,
                    "DPoP-bound token requires DPoP authorization",
                ));
            }
            verify_request_dpop(
                req,
                Some(jkt),
                claims.dpop_nonce.as_deref(),
                Some(&presented.token),
            )
            .map_err(|error| HttpError::new(401, error.to_string()))?;
        }
        if claims.sub != did.as_str() {
            return Err(HttpError::new(403, "token does not match repo DID"));
        }

        let request_host = request_host(req)?;
        self.ensure_directory_account_active(&request_host, did)
            .await
    }

    async fn ensure_directory_account_active(
        &self,
        request_host: &str,
        did: &Did,
    ) -> Result<(), HttpError> {
        let path = internal_directory_account_status_path(did.as_str());
        let mut response =
            fetch_internal_directory_request(&self.env, request_host, Method::Get, &path, None)
                .await?;
        let status = response.status_code();
        if status == 404 {
            return Err(HttpError::new(403, "AccountTakedown"));
        }
        if !(200..300).contains(&status) {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| "failed to read directory response".to_string());
            return Err(HttpError::new(
                500,
                format!("account status lookup failed with status {status}: {message}"),
            ));
        }
        let account_status = response
            .json::<InternalAccountStatusResponse>()
            .await
            .map_err(HttpError::worker)?;
        if account_status.active {
            Ok(())
        } else {
            Err(HttpError::new(403, "AccountTakedown"))
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
                "eventType": event.event_type,
                "since": event.since.as_ref().map(|rev| rev.to_string()),
                "prevData": event.prev_data.map(|cid| cid.to_string()),
                "blocksBase64": BASE64_STANDARD.encode(&event.blocks),
                "ops": event.ops,
                "blobs": event.blobs,
            });
        }
        let path = internal_directory_repo_upsert_path();
        let mut response =
            fetch_internal_directory_json(&self.env, request_host, Method::Post, &path, &body)
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
        let prev_data = previous_data_root(repo.storage(), mutation.commit.prev)?;
        self.repo_commit_event_payload_from_cids(
            repo,
            DirectoryCommitEventType::Commit,
            mutation.commit_cid,
            since,
            prev_data,
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
        self.repo_commit_event_payload_from_cids(
            repo,
            DirectoryCommitEventType::Commit,
            commit_cid,
            since,
            None,
            ops,
            Vec::new(),
            cids,
        )
        .await
    }

    async fn repo_commit_event_payload_from_cids(
        &self,
        repo: &mut SignedRepository<SqlRepoStore>,
        event_type: DirectoryCommitEventType,
        commit_cid: crate::cid::Cid,
        since: Option<RepoRev>,
        prev_data: Option<crate::cid::Cid>,
        ops: Vec<DirectoryCommitOp>,
        blobs: Vec<crate::cid::Cid>,
        cids: Vec<crate::cid::Cid>,
    ) -> Result<DirectoryCommitEventPayload, HttpError> {
        let blocks =
            encode_car_from_store(&[commit_cid], cids, repo.storage()).map_err(HttpError::car)?;
        Ok(DirectoryCommitEventPayload {
            event_type,
            since,
            prev_data,
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
            prev_data: event.prev_data,
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
            if byte_len != content_length {
                let _ = bucket.delete(key).await;
                return Err(HttpError::new(
                    400,
                    "blob upload byte count did not match content-length",
                ));
            }
            if let Some(existing) = self.store().get_blob(&cid).map_err(HttpError::worker)? {
                let _ = bucket.delete(key).await;
                return Ok(existing);
            }
            if let Err(error) = self.ensure_blob_quota(&cid, byte_len as i64) {
                let _ = bucket.delete(key).await;
                return Err(error);
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
        if content_length.is_some_and(|expected| expected != bytes.len() as u64) {
            return Err(HttpError::new(
                400,
                "blob upload byte count did not match content-length",
            ));
        }
        self.put_blob_bytes(mime_type, bytes).await
    }

    async fn put_blob_bytes(
        &self,
        mime_type: &str,
        bytes: Vec<u8>,
    ) -> Result<RepoBlobRow, HttpError> {
        let cid = raw_cid(&bytes);
        let byte_len = bytes.len();
        self.ensure_blob_quota(&cid, byte_len as i64)?;
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

    async fn delete_orphan_blobs(
        &self,
        store: &SqlRepoStore,
        cids: &[crate::cid::Cid],
    ) -> Result<(), HttpError> {
        let mut seen = BTreeSet::new();
        for cid in cids {
            if !seen.insert(*cid) || store.blob_ref_count(cid).map_err(HttpError::worker)? > 0 {
                continue;
            }
            let Some(blob) = store.get_blob(cid).map_err(HttpError::worker)? else {
                continue;
            };
            if blob.storage_kind == "r2" {
                if let Ok(bucket) = self.env.bucket(BLOB_BUCKET_BINDING) {
                    let key = blob.storage_key.unwrap_or_else(|| blob_storage_key(cid));
                    let _ = bucket.delete(key).await;
                }
            }
            store
                .delete_unreferenced_blob_metadata(cid)
                .map_err(HttpError::worker)?;
        }
        Ok(())
    }

    fn ensure_blob_quota(&self, cid: &crate::cid::Cid, byte_len: i64) -> Result<(), HttpError> {
        let max_bytes = max_account_blob_bytes_from_env(&self.env)?;
        let store = self.store();
        if store.get_blob(cid).map_err(HttpError::worker)?.is_some() {
            return Ok(());
        }
        let total = store.total_blob_bytes().map_err(HttpError::worker)?;
        if total.saturating_add(byte_len) > max_bytes {
            return Err(HttpError::new(
                400,
                format!("BlobQuotaExceeded: account blob quota is {max_bytes} bytes"),
            ));
        }
        Ok(())
    }

    async fn purge_expired_unreferenced_blobs(
        &self,
        store: &SqlRepoStore,
        now: i64,
    ) -> Result<(), HttpError> {
        let cutoff = now.saturating_sub(TEMP_BLOB_TTL_SECONDS);
        let rows = store
            .list_unreferenced_blobs_older_than(cutoff, BLOB_GC_BATCH_LIMIT)
            .map_err(HttpError::worker)?;
        for blob in rows {
            if blob.storage_kind == "r2" {
                if let Ok(bucket) = self.env.bucket(BLOB_BUCKET_BINDING) {
                    let key = blob
                        .storage_key
                        .unwrap_or_else(|| blob_storage_key(&blob.cid));
                    let _ = bucket.delete(key).await;
                }
            }
            store
                .delete_unreferenced_blob_metadata(&blob.cid)
                .map_err(HttpError::worker)?;
        }
        Ok(())
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
struct UpdateRepoIdentityRequest {
    handle: String,
}

#[derive(Debug, Deserialize)]
struct UpdateRepoSigningKeyRequest {
    #[serde(rename = "signingKeyP256Hex", alias = "signing_key_p256_hex")]
    signing_key_p256_hex: String,
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
    #[serde(default, rename = "inviteCode", alias = "invite_code")]
    invite_code: Option<String>,
    #[serde(default, rename = "plcOp")]
    plc_op: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct XrpcCreateSessionRequest {
    identifier: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct XrpcChangePasswordRequest {
    #[serde(rename = "oldPassword", alias = "old_password")]
    old_password: String,
    #[serde(rename = "newPassword", alias = "new_password")]
    new_password: String,
}

#[derive(Debug, Deserialize)]
struct XrpcRequestPasswordResetRequest {
    email: String,
}

#[derive(Debug, Deserialize)]
struct XrpcResetPasswordRequest {
    token: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct XrpcConfirmEmailRequest {
    email: String,
    token: String,
}

#[derive(Debug, Deserialize)]
struct XrpcUpdateEmailRequest {
    email: String,
    #[serde(default)]
    token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrpcDeleteAccountRequest {
    did: String,
    password: String,
    token: String,
}

#[derive(Debug, Deserialize)]
struct XrpcUpdateHandleRequest {
    handle: String,
}

#[derive(Debug, Deserialize)]
struct XrpcRefreshIdentityRequest {
    identifier: String,
}

#[derive(Debug, Default, Deserialize)]
struct XrpcReserveSigningKeyRequest {
    #[serde(default)]
    did: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrpcCreateInviteCodeRequest {
    #[serde(rename = "useCount", alias = "use_count")]
    use_count: i64,
    #[serde(default, rename = "forAccount", alias = "for_account")]
    for_account: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrpcCreateInviteCodesRequest {
    #[serde(rename = "useCount", alias = "use_count")]
    use_count: i64,
    #[serde(default, rename = "codeCount", alias = "code_count")]
    code_count: Option<i64>,
    #[serde(default, rename = "forAccounts", alias = "for_accounts")]
    for_accounts: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct XrpcCreateAppPasswordRequest {
    name: String,
    #[serde(default)]
    privileged: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct XrpcRevokeAppPasswordRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminDidRequest {
    did: String,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminAccountInvitesRequest {
    account: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminDisableInviteCodesRequest {
    #[serde(default)]
    codes: Option<Vec<String>>,
    #[serde(default)]
    accounts: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminSendEmailRequest {
    #[serde(rename = "recipientDid", alias = "recipient_did")]
    recipient_did: String,
    content: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(rename = "senderDid", alias = "sender_did")]
    sender_did: String,
    #[serde(default)]
    comment: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminUpdateAccountEmailRequest {
    account: String,
    email: String,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminUpdateAccountHandleRequest {
    did: String,
    handle: String,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminUpdateAccountPasswordRequest {
    did: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminUpdateAccountSigningKeyRequest {
    did: String,
    #[serde(rename = "signingKey", alias = "signing_key")]
    signing_key: String,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminStatusAttrRequest {
    applied: bool,
    #[serde(default, rename = "ref")]
    ref_value: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XrpcAdminUpdateSubjectStatusRequest {
    subject: Value,
    #[serde(default)]
    takedown: Option<XrpcAdminStatusAttrRequest>,
    #[serde(default)]
    deactivated: Option<XrpcAdminStatusAttrRequest>,
}

#[derive(Debug, Deserialize)]
struct ServiceAuthRequest {
    aud: String,
    exp: i64,
    #[serde(default)]
    lxm: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ServiceAuthResponse {
    token: String,
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

#[derive(Debug, Deserialize)]
struct InternalRepoStatusResponse {
    initialized: bool,
    did: Option<String>,
    handle: Option<String>,
    #[serde(rename = "publicKeyMultibase")]
    public_key_multibase: Option<String>,
    #[serde(rename = "latestCommit")]
    latest_commit: Option<String>,
    #[serde(rename = "latestRev")]
    latest_rev: Option<String>,
    #[serde(default)]
    blocks: i64,
    #[serde(default)]
    records: i64,
    #[serde(default, rename = "expectedBlobs")]
    expected_blobs: i64,
    #[serde(default, rename = "importedBlobs")]
    imported_blobs: i64,
}

#[derive(Debug, Deserialize)]
struct InternalAccountStatusResponse {
    active: bool,
    status: Option<String>,
}

struct CreatedSession {
    row: DirectorySessionRow,
    tokens: SessionTokens,
}

struct CreatedOAuthSession {
    row: DirectorySessionRow,
    tokens: SessionTokens,
    dpop_nonce: String,
}

struct SubmittedLexicon {
    lexicon: Value,
    publish: bool,
}

struct PublishedLexiconRecord {
    uri: String,
    cid: String,
    commit_cid: String,
    commit_rev: String,
    changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OAuthClientAuthBinding {
    method: OAuthClientAuthMethod,
    kid: Option<String>,
    alg: Option<String>,
    jkt: Option<String>,
}

impl OAuthClientAuthBinding {
    fn none() -> Self {
        Self {
            method: OAuthClientAuthMethod::None,
            kid: None,
            alg: None,
            jkt: None,
        }
    }

    fn from_verified(assertion: crate::oauth::VerifiedClientAssertion) -> Self {
        Self {
            method: OAuthClientAuthMethod::PrivateKeyJwt,
            kid: Some(assertion.kid),
            alg: Some(assertion.alg),
            jkt: Some(assertion.jkt),
        }
    }

    fn from_parts(
        method: &str,
        kid: Option<String>,
        alg: Option<String>,
        jkt: Option<String>,
    ) -> Result<Self, HttpError> {
        let method = match method {
            "none" => OAuthClientAuthMethod::None,
            "private_key_jwt" => OAuthClientAuthMethod::PrivateKeyJwt,
            other => {
                return Err(HttpError::new(
                    500,
                    format!("unknown OAuth client auth `{other}`"),
                ))
            }
        };
        Ok(Self {
            method,
            kid,
            alg,
            jkt,
        })
    }

    fn method_str(&self) -> &'static str {
        self.method.as_str()
    }

    fn ensure_matches(&self, expected: &Self) -> Result<(), HttpError> {
        if self == expected {
            Ok(())
        } else {
            Err(HttpError::new(
                401,
                "OAuth client authentication key does not match this authorization session",
            ))
        }
    }
}

struct SessionTokens {
    access_jwt: String,
    refresh_jwt: String,
}

#[derive(Debug, Deserialize)]
struct XrpcCreateRecordRequest {
    repo: String,
    collection: String,
    #[serde(default)]
    rkey: Option<String>,
    record: Value,
    #[serde(default, rename = "validate")]
    validate: Option<bool>,
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
    validate: Option<bool>,
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
    validate: Option<bool>,
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
    #[serde(default, rename = "eventType")]
    event_type: DirectoryCommitEventType,
    #[serde(default)]
    since: Option<String>,
    #[serde(default, rename = "prevData")]
    prev_data: Option<String>,
    #[serde(rename = "blocksBase64")]
    blocks_base64: String,
    #[serde(default)]
    ops: Vec<DirectoryCommitOp>,
    #[serde(default)]
    blobs: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize)]
struct DirectoryCommitEventPayload {
    #[serde(rename = "eventType")]
    event_type: DirectoryCommitEventType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    since: Option<RepoRev>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "prevData")]
    prev_data: Option<crate::cid::Cid>,
    blocks: Vec<u8>,
    ops: Vec<DirectoryCommitOp>,
    blobs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DirectoryCommitEventType {
    Commit,
    Sync,
}

impl Default for DirectoryCommitEventType {
    fn default() -> Self {
        Self::Commit
    }
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

fn is_repo_already_initialized_error(error: &HttpError) -> bool {
    error.status == 409 && error.message.contains("repo already initialized")
}

fn init_response_from_repo_status(
    status: InternalRepoStatusResponse,
    expected_did: &str,
    expected_handle: &str,
) -> Result<InternalInitRepoResponse, HttpError> {
    if !status.initialized {
        return Err(HttpError::new(
            409,
            "repo initialization conflict, but repo status is uninitialized",
        ));
    }

    let did = status
        .did
        .ok_or_else(|| HttpError::new(409, "initialized repo status is missing DID"))?;
    if did != expected_did {
        return Err(HttpError::new(
            409,
            "repo already initialized for a different DID",
        ));
    }

    let handle = status
        .handle
        .ok_or_else(|| HttpError::new(409, "initialized repo status is missing handle"))?;
    if handle != expected_handle {
        return Err(HttpError::new(
            409,
            "repo already initialized for a different handle",
        ));
    }

    Ok(InternalInitRepoResponse {
        public_key_multibase: status
            .public_key_multibase
            .ok_or_else(|| HttpError::new(409, "initialized repo status is missing public key"))?,
        latest_commit: status.latest_commit.ok_or_else(|| {
            HttpError::new(409, "initialized repo status is missing latest commit")
        })?,
        latest_rev: status
            .latest_rev
            .ok_or_else(|| HttpError::new(409, "initialized repo status is missing latest rev"))?,
    })
}

fn xrpc_record_mutation_response(
    did: &Did,
    path: &RepoPath,
    mutation: &RepoMutation,
    validation_status: RecordValidationStatus,
) -> Result<Value, HttpError> {
    let record_cid = mutation
        .record_cid
        .ok_or_else(|| HttpError::new(500, "record mutation is missing record cid"))?;
    let record = strong_ref(
        did.as_str(),
        path.collection.as_str(),
        path.rkey.as_str(),
        &record_cid.to_string(),
    );
    Ok(json!({
        "uri": record.uri,
        "cid": record.cid,
        "commit": {
            "cid": mutation.commit_cid.to_string(),
            "rev": mutation.commit.rev.to_string(),
        },
        "validationStatus": validation_status.as_str(),
    }))
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

fn xrpc_apply_writes_response(
    did: &Did,
    mutation: &RepoMutation,
    validation_statuses: &BTreeMap<RepoPath, RecordValidationStatus>,
) -> Result<Value, HttpError> {
    let results = mutation
        .ops
        .iter()
        .map(|op| match op.action {
            RepoOperationAction::Create => {
                let cid = op
                    .cid
                    .ok_or_else(|| HttpError::new(500, "create operation is missing record cid"))?;
                let record = strong_ref(
                    did.as_str(),
                    op.path.collection.as_str(),
                    op.path.rkey.as_str(),
                    &cid.to_string(),
                );
                Ok(json!({
                    "$type": "com.atproto.repo.applyWrites#createResult",
                    "uri": record.uri,
                    "cid": record.cid,
                    "validationStatus": validation_statuses
                        .get(&op.path)
                        .copied()
                        .unwrap_or(RecordValidationStatus::Unknown)
                        .as_str(),
                }))
            }
            RepoOperationAction::Update => {
                let cid = op
                    .cid
                    .ok_or_else(|| HttpError::new(500, "update operation is missing record cid"))?;
                let record = strong_ref(
                    did.as_str(),
                    op.path.collection.as_str(),
                    op.path.rkey.as_str(),
                    &cid.to_string(),
                );
                Ok(json!({
                    "$type": "com.atproto.repo.applyWrites#updateResult",
                    "uri": record.uri,
                    "cid": record.cid,
                    "validationStatus": validation_statuses
                        .get(&op.path)
                        .copied()
                        .unwrap_or(RecordValidationStatus::Unknown)
                        .as_str(),
                }))
            }
            RepoOperationAction::Delete => Ok(json!({
                "$type": "com.atproto.repo.applyWrites#deleteResult",
            })),
        })
        .collect::<Result<Vec<_>, HttpError>>()?;

    Ok(json!({
        "commit": {
            "cid": mutation.commit_cid.to_string(),
            "rev": mutation.commit.rev.to_string(),
        },
        "results": results,
    }))
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

fn previous_data_root(
    store: &SqlRepoStore,
    previous_commit: Option<crate::cid::Cid>,
) -> Result<Option<crate::cid::Cid>, HttpError> {
    previous_commit
        .map(|cid| {
            CommitBlock::read_from(store, &cid)
                .map_err(HttpError::worker)?
                .map(|block| block.commit.data)
                .ok_or_else(|| HttpError::new(500, format!("previous commit `{cid}` not found")))
        })
        .transpose()
}

fn extract_record_blob_refs(record: &Value) -> Result<Vec<crate::cid::Cid>, HttpError> {
    extract_import_record_blob_refs(record).map_err(HttpError::import)
}

#[allow(dead_code)]
fn ensure_record_envelope(
    collection: &Nsid,
    record: &Value,
    validate: Option<bool>,
    extra_lexicons: &[Value],
) -> Result<RecordValidationStatus, HttpError> {
    ensure_record_shape(collection, record)?;
    if validate == Some(false) {
        return Ok(RecordValidationStatus::Unknown);
    }
    lexicon::validate_record_with_lexicons(
        collection.as_str(),
        record,
        validate == Some(true),
        extra_lexicons,
    )
    .map_err(|error| HttpError::new(400, error.to_string()))
}

fn ensure_record_shape(collection: &Nsid, record: &Value) -> Result<(), HttpError> {
    let Some(object) = record.as_object() else {
        return Err(HttpError::new(400, "record must be a JSON object"));
    };
    match object.get("$type").and_then(Value::as_str) {
        Some(record_type) if record_type == collection.as_str() => {}
        Some(record_type) => {
            return Err(HttpError::new(
                400,
                format!("record $type `{record_type}` does not match collection `{collection}`"),
            ));
        }
        None => return Err(HttpError::new(400, "record must contain a string $type")),
    }
    Ok(())
}

fn ensure_blob_refs_available(
    store: &SqlRepoStore,
    cids: &[crate::cid::Cid],
) -> Result<(), HttpError> {
    for cid in cids {
        if store.get_blob(cid).map_err(HttpError::worker)?.is_none() {
            return Err(HttpError::new(
                400,
                format!("referenced blob `{cid}` is missing"),
            ));
        }
    }
    Ok(())
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
    if content_type.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
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

fn max_account_blob_bytes_from_env(env: &Env) -> Result<i64, HttpError> {
    let Ok(value) = env.var("PDS_MAX_ACCOUNT_BLOB_BYTES") else {
        return Ok(DEFAULT_MAX_ACCOUNT_BLOB_BYTES);
    };
    let value = value.to_string();
    if value.trim().is_empty() {
        return Ok(DEFAULT_MAX_ACCOUNT_BLOB_BYTES);
    }
    value
        .trim()
        .parse::<i64>()
        .map_err(|_| {
            HttpError::new(
                500,
                "PDS_MAX_ACCOUNT_BLOB_BYTES must be a positive integer byte count",
            )
        })
        .and_then(|bytes| {
            if bytes > 0 {
                Ok(bytes)
            } else {
                Err(HttpError::new(
                    500,
                    "PDS_MAX_ACCOUNT_BLOB_BYTES must be greater than zero",
                ))
            }
        })
}

fn extra_lexicons_from_env(env: &Env) -> Result<Vec<Value>, HttpError> {
    let Ok(value) = env.var("PDS_LEXICONS_JSON") else {
        return Ok(Vec::new());
    };
    let value = value.to_string();
    if value.trim().is_empty() {
        return Ok(Vec::new());
    }
    match from_str::<Value>(&value).map_err(|error| {
        HttpError::new(
            500,
            format!("PDS_LEXICONS_JSON must be a Lexicon JSON object or array: {error}"),
        )
    })? {
        Value::Array(values) => Ok(values),
        Value::Object(_) => Ok(vec![from_str(&value).map_err(|error| {
            HttpError::new(
                500,
                format!("PDS_LEXICONS_JSON object could not be parsed: {error}"),
            )
        })?]),
        _ => Err(HttpError::new(
            500,
            "PDS_LEXICONS_JSON must be a Lexicon JSON object or array",
        )),
    }
}

fn submitted_lexicon_from_body(body: Value) -> Result<SubmittedLexicon, HttpError> {
    if body.get("lexicon").is_some() && body.get("id").is_some() && body.get("defs").is_some() {
        return Ok(SubmittedLexicon {
            lexicon: body,
            publish: true,
        });
    }

    let publish = body.get("publish").and_then(Value::as_bool).unwrap_or(true);
    let lexicon = body
        .get("schema")
        .or_else(|| {
            body.get("lexicon")
                .filter(|value| value.get("id").is_some() && value.get("defs").is_some())
        })
        .cloned()
        .filter(Value::is_object)
        .ok_or_else(|| {
            HttpError::new(
                400,
                "request body must be a Lexicon JSON document or {\"schema\": {...}, \"publish\": bool}",
            )
        })?;
    Ok(SubmittedLexicon { lexicon, publish })
}

async fn fetch_published_lexicon(env: &Env, collection: &str) -> Result<Option<Value>, HttpError> {
    let Some(txt_name) = lexicon_txt_name(collection) else {
        return Ok(None);
    };
    let did = if let Some(did) = lexicon_authority_did_from_env(env, collection)? {
        did
    } else {
        let records = fetch_dns_txt_records(&txt_name).await?;
        let Some(did) = unique_prefixed_txt_value(&records, "did=", &txt_name)? else {
            return Ok(None);
        };
        did
    };
    Did::new(did.clone()).map_err(HttpError::bad_request)?;
    let did_doc = fetch_did_document(&did).await?;
    ensure_did_document_id(&did_doc, &did).map_err(HttpError::bad_request)?;
    let endpoint = did_document_pds_endpoint(&did_doc).ok_or_else(|| {
        HttpError::new(
            502,
            format!("Lexicon authority DID `{did}` has no AtprotoPersonalDataServer service"),
        )
    })?;
    let url = format!(
        "{endpoint}/xrpc/com.atproto.repo.getRecord?repo={}&collection=com.atproto.lexicon.schema&rkey={}",
        encode_query_component(&did),
        encode_query_component(collection),
    );
    let Some(record) = fetch_json_url_optional(&url).await? else {
        return Ok(None);
    };
    let lexicon = record
        .get("value")
        .cloned()
        .ok_or_else(|| HttpError::new(502, "published Lexicon record did not contain `value`"))?;
    let lexicon = lexicon::normalize_schema_record(&lexicon)
        .map_err(|error| HttpError::new(502, error.to_string()))?;
    if lexicon::schema_id(&lexicon) != Some(collection) {
        return Err(HttpError::new(
            502,
            format!("published Lexicon record value id did not match `{collection}`"),
        ));
    }
    lexicon::validate_lexicon_schema(&lexicon)
        .map_err(|error| HttpError::new(502, error.to_string()))?;
    Ok(Some(lexicon))
}

fn lexicon_authority_did_from_env(
    env: &Env,
    collection: &str,
) -> Result<Option<String>, HttpError> {
    let Some(authority_domain) = lexicon_authority_domain(collection) else {
        return Ok(None);
    };
    let Ok(value) = env.var("PDS_LEXICON_AUTHORITY_DIDS") else {
        return Ok(None);
    };
    let did = lexicon_authority_did_override(&value.to_string(), &authority_domain)
        .map_err(HttpError::bad_request)?;
    if let Some(did) = did.as_deref() {
        Did::new(did.to_string()).map_err(HttpError::bad_request)?;
    }
    Ok(did)
}

async fn resolve_handle_did(handle: &str) -> Result<Option<String>, HttpError> {
    validate_handle_syntax(handle).map_err(HttpError::bad_request)?;
    if let Ok(records) = fetch_dns_txt_records(&handle_did_txt_name(handle)).await {
        if let Some(did) = unique_prefixed_txt_value(&records, "did=", handle)? {
            Did::new(did.clone()).map_err(HttpError::bad_request)?;
            return Ok(Some(did));
        }
    }

    let url = format!("https://{handle}/.well-known/atproto-did");
    let Some(text) = fetch_text_url_optional(&url).await? else {
        return Ok(None);
    };
    let did = text.trim().to_string();
    if did.is_empty() {
        return Ok(None);
    }
    Did::new(did.clone()).map_err(HttpError::bad_request)?;
    Ok(Some(did))
}

fn unique_prefixed_txt_value(
    records: &[String],
    prefix: &str,
    label: &str,
) -> Result<Option<String>, HttpError> {
    let values = prefixed_txt_values(records, prefix)
        .into_iter()
        .collect::<BTreeSet<_>>();
    if values.len() > 1 {
        return Err(HttpError::new(
            400,
            format!("ambiguous TXT records for `{label}`"),
        ));
    }
    Ok(values.into_iter().next())
}

async fn fetch_did_document(did: &str) -> Result<Value, HttpError> {
    let url = if did.starts_with("did:web:") {
        did_web_document_url(did).map_err(HttpError::bad_request)?
    } else if did.starts_with("did:plc:") {
        format!("https://plc.directory/{}", encode_query_component(did))
    } else {
        return Err(HttpError::new(
            400,
            format!("unsupported DID method for `{did}`"),
        ));
    };
    let doc = fetch_json_url(&url).await?;
    ensure_did_document_id(&doc, did).map_err(HttpError::bad_request)?;
    Ok(doc)
}

async fn fetch_dns_txt_records(name: &str) -> Result<Vec<String>, HttpError> {
    let url = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type=TXT",
        encode_query_component(name)
    );
    let headers = Headers::new();
    headers
        .set("accept", "application/dns-json")
        .map_err(HttpError::worker)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let request = Request::new_with_init(&url, &init).map_err(HttpError::worker)?;
    let mut response = Fetch::Request(request)
        .send()
        .await
        .map_err(HttpError::worker)?;
    if response.status_code() != 200 {
        return Err(HttpError::new(
            502,
            format!(
                "DNS TXT lookup for `{name}` failed with status {}",
                response.status_code()
            ),
        ));
    }
    let body: DnsJsonResponse = response.json().await.map_err(HttpError::worker)?;
    Ok(body
        .answers
        .unwrap_or_default()
        .into_iter()
        .filter(|answer| answer.record_type == 16)
        .map(|answer| answer.data)
        .collect())
}

async fn fetch_json_url(url: &str) -> Result<Value, HttpError> {
    fetch_json_url_optional(url)
        .await?
        .ok_or_else(|| HttpError::new(404, "remote JSON document not found"))
}

async fn fetch_json_url_optional(url: &str) -> Result<Option<Value>, HttpError> {
    let url = ::url::Url::parse(url)
        .map_err(|error| HttpError::new(400, format!("invalid URL: {error}")))?;
    let mut response = Fetch::Url(url).send().await.map_err(HttpError::worker)?;
    let status = response.status_code();
    if status == 404 {
        return Ok(None);
    }
    if !(200..=299).contains(&status) {
        return Err(HttpError::new(
            502,
            format!("remote JSON fetch failed with status {status}"),
        ));
    }
    response.json().await.map(Some).map_err(HttpError::worker)
}

async fn fetch_text_url_optional(url: &str) -> Result<Option<String>, HttpError> {
    let url = ::url::Url::parse(url)
        .map_err(|error| HttpError::new(400, format!("invalid URL: {error}")))?;
    let mut response = Fetch::Url(url).send().await.map_err(HttpError::worker)?;
    let status = response.status_code();
    if status == 404 {
        return Ok(None);
    }
    if !(200..=299).contains(&status) {
        return Err(HttpError::new(
            502,
            format!("remote text fetch failed with status {status}"),
        ));
    }
    response.text().await.map(Some).map_err(HttpError::worker)
}

#[derive(Debug, Deserialize)]
struct DnsJsonResponse {
    #[serde(default, rename = "Answer")]
    answers: Option<Vec<DnsJsonAnswer>>,
}

#[derive(Debug, Deserialize)]
struct DnsJsonAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthScheme {
    Bearer,
    Dpop,
}

struct PresentedToken {
    scheme: AuthScheme,
    token: String,
}

fn authorization_token(req: &Request) -> Result<PresentedToken, HttpError> {
    let authorization = req
        .headers()
        .get("authorization")
        .map_err(HttpError::worker)?
        .ok_or_else(|| HttpError::new(401, "authorization bearer token required"))?;
    if let Some(token) = authorization
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
    {
        Ok(PresentedToken {
            scheme: AuthScheme::Bearer,
            token: token.to_string(),
        })
    } else if let Some(token) = authorization
        .strip_prefix("DPoP ")
        .filter(|token| !token.is_empty())
    {
        Ok(PresentedToken {
            scheme: AuthScheme::Dpop,
            token: token.to_string(),
        })
    } else {
        Err(HttpError::new(401, "authorization bearer token required"))
    }
}

fn verify_request_dpop(
    req: &Request,
    expected_jkt: Option<&str>,
    expected_nonce: Option<&str>,
    access_token: Option<&str>,
) -> Result<VerifiedDpopProof, DpopError> {
    let proof = req
        .headers()
        .get("dpop")
        .map_err(|_| DpopError::MissingProof)?
        .filter(|value| !value.is_empty())
        .ok_or(DpopError::MissingProof)?;
    let url = req.url().map_err(|_| DpopError::UriMismatch)?;
    verify_dpop_proof(
        &proof,
        http_method_name(&req.method()),
        &dpop_htu(&url),
        current_unix_time(),
        expected_nonce,
        expected_jkt,
        access_token,
    )
}

fn http_method_name(method: &Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Head => "HEAD",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Options => "OPTIONS",
        Method::Connect => "CONNECT",
        Method::Patch => "PATCH",
        Method::Trace => "TRACE",
        Method::Report => "REPORT",
    }
}

async fn validate_account_handle_for_creation(
    env: &Env,
    handle: &str,
    request_host: &str,
    expected_did: &str,
) -> Result<(), HttpError> {
    validate_handle_syntax(handle).map_err(HttpError::bad_request)?;
    if handle == request_host {
        return Ok(());
    }
    if !configured_account_handle_allowed(env, handle) {
        return Err(HttpError::new(
            400,
            format!(
                "UnsupportedDomain: `{handle}` is not the request host `{request_host}` and is not allowed by PDS_ALLOWED_ACCOUNT_HANDLES or PDS_ALLOWED_ACCOUNT_HANDLE_SUFFIXES"
            ),
        ));
    }
    let Some(resolved_did) = resolve_handle_did(handle).await? else {
        return Err(HttpError::new(
            400,
            format!("HandleNotResolvable: `{handle}` did not resolve to a DID"),
        ));
    };
    if resolved_did == expected_did {
        Ok(())
    } else {
        Err(HttpError::new(
            400,
            format!("HandleMismatch: `{handle}` resolves to `{resolved_did}`, expected `{expected_did}`"),
        ))
    }
}

async fn validate_account_did_document(handle: &str, did: &str) -> Result<(), HttpError> {
    let doc = fetch_did_document(did).await?;
    if !did_document_claims_handle(&doc, handle) {
        return Err(HttpError::new(
            400,
            format!("HandleMismatch: DID document `{did}` does not claim at://{handle}"),
        ));
    }
    let Some(resolved_did) = resolve_handle_did(handle).await? else {
        return Err(HttpError::new(
            400,
            format!("HandleNotResolvable: `{handle}` did not resolve to a DID"),
        ));
    };
    if resolved_did != did {
        return Err(HttpError::new(
            400,
            format!("HandleMismatch: `{handle}` resolves to `{resolved_did}`, expected `{did}`"),
        ));
    }
    if did_document_pds_endpoint(&doc).is_none() {
        return Err(HttpError::new(
            400,
            format!(
                "InvalidDidDocument: DID document `{did}` has no AtprotoPersonalDataServer service"
            ),
        ));
    }
    Ok(())
}

async fn account_identity_for_creation(
    env: &Env,
    handle: &str,
    requested_did: Option<&str>,
    request_host: &str,
) -> Result<(Did, String, bool), HttpError> {
    validate_handle_syntax(handle).map_err(HttpError::bad_request)?;
    let Some(requested_did) = requested_did else {
        let did = Did::new(format!("did:web:{handle}")).map_err(HttpError::bad_request)?;
        validate_account_handle_for_creation(env, handle, request_host, did.as_str()).await?;
        return Ok((did, handle.to_string(), true));
    };

    let did = Did::new(requested_did.to_string()).map_err(HttpError::bad_request)?;
    if !did.as_str().starts_with("did:gsv:") {
        return Err(HttpError::new(
            400,
            "UnsupportedDid: admin-created custom accounts currently support did:gsv DIDs only",
        ));
    }
    let repo_name = repo_object_name_from_identifier(did.as_str());
    if repo_name.is_empty() {
        return Err(HttpError::new(400, "InvalidDid"));
    }
    Ok((did, repo_name, false))
}

fn configured_account_handle_allowed(env: &Env, handle: &str) -> bool {
    env_list(env, "PDS_ALLOWED_ACCOUNT_HANDLES")
        .iter()
        .any(|allowed| allowed == "*" || allowed.eq_ignore_ascii_case(handle))
        || env_list(env, "PDS_ALLOWED_ACCOUNT_HANDLE_SUFFIXES")
            .iter()
            .any(|suffix| handle_matches_suffix(handle, suffix))
}

fn handle_matches_suffix(handle: &str, suffix: &str) -> bool {
    let suffix = suffix.trim_start_matches('.');
    handle.eq_ignore_ascii_case(suffix)
        || handle
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn normalize_at_identifier(identifier: &str) -> String {
    if identifier.starts_with("did:") {
        identifier.to_string()
    } else {
        identifier.to_ascii_lowercase()
    }
}

fn env_list(env: &Env, name: &str) -> Vec<String> {
    env.var(name)
        .ok()
        .map(|value| value.to_string())
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
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

fn ensure_app_password_name(name: &str) -> Result<(), HttpError> {
    let len = name.chars().count();
    if name.trim().is_empty() || len > 64 {
        return Err(HttpError::new(
            400,
            "InvalidName: app password name must be 1-64 characters",
        ));
    }
    Ok(())
}

fn generate_app_password() -> Result<String, HttpError> {
    random_urlsafe_token::<APP_PASSWORD_BYTES>()
}

fn action_token_digest(token: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

fn action_token_response(
    env: &Env,
    req: &Request,
    token: Option<&str>,
) -> worker::Result<Response> {
    if is_admin_authorized(env, req).unwrap_or(false) {
        let mut body = json!({});
        if let Some(token) = token {
            body["token"] = json!(token);
        }
        json_response(200, &body)
    } else {
        empty_response(200)
    }
}

fn normalize_required_email(email: &str) -> Result<String, HttpError> {
    let email = email.trim().to_ascii_lowercase();
    let Some((local, domain)) = email.split_once('@') else {
        return Err(HttpError::new(400, "InvalidEmail"));
    };
    if email.len() > 254
        || local.is_empty()
        || domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain.contains('.')
    {
        return Err(HttpError::new(400, "InvalidEmail"));
    }
    Ok(email)
}

fn normalize_account_email(email: Option<String>) -> Option<String> {
    email
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
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
        body["emailConfirmed"] = json!(account.email_confirmed);
        body["emailAuthFactor"] = json!(false);
    }
    if let Some(tokens) = tokens {
        body["accessJwt"] = json!(tokens.access_jwt);
        body["refreshJwt"] = json!(tokens.refresh_jwt);
    }
    body
}

fn identity_info_response_body(origin: &str, account: &DirectoryAccountRow) -> Value {
    json!({
        "did": account.did.to_string(),
        "handle": account.handle.clone(),
        "didDoc": did_document(
            account.did.as_str(),
            &account.handle,
            &account.public_key_multibase,
            origin,
        ),
    })
}

fn did_from_admin_subject(subject: &Value) -> Result<Did, HttpError> {
    let Some(did) = subject.get("did").and_then(Value::as_str) else {
        return Err(HttpError::new(
            400,
            "UnsupportedSubject: only account DID subjects are implemented",
        ));
    };
    Did::new(did.to_string()).map_err(HttpError::bad_request)
}

async fn optional_json_body<T>(req: &mut Request) -> Result<T, HttpError>
where
    T: for<'de> Deserialize<'de> + Default,
{
    let body = req.text().await.map_err(HttpError::worker)?;
    if body.trim().is_empty() {
        return Ok(T::default());
    }
    from_str(&body).map_err(HttpError::bad_request)
}

fn did_key_from_public_key_multibase(public_key_multibase: &str) -> Result<String, HttpError> {
    validate_public_key_multibase(public_key_multibase)?;
    Ok(format!("did:key:{public_key_multibase}"))
}

fn normalize_did_key(signing_key: &str) -> Result<String, HttpError> {
    let signing_key = signing_key.trim();
    if let Some(public_key_multibase) = signing_key.strip_prefix("did:key:") {
        validate_public_key_multibase(public_key_multibase)?;
        return Ok(format!("did:key:{public_key_multibase}"));
    }
    validate_public_key_multibase(signing_key)?;
    Ok(format!("did:key:{signing_key}"))
}

fn public_key_multibase_from_did_key(signing_key: &str) -> Result<String, HttpError> {
    let signing_key = normalize_did_key(signing_key)?;
    signing_key
        .strip_prefix("did:key:")
        .map(ToString::to_string)
        .ok_or_else(|| HttpError::new(400, "InvalidSigningKey"))
}

fn validate_public_key_multibase(public_key_multibase: &str) -> Result<(), HttpError> {
    if !public_key_multibase.starts_with('z') {
        return Err(HttpError::new(400, "InvalidSigningKey"));
    }
    let decoded = bs58::decode(public_key_multibase.trim_start_matches('z'))
        .into_vec()
        .map_err(|_| HttpError::new(400, "InvalidSigningKey"))?;
    if decoded.len() == 35 && decoded.starts_with(&[0x80, 0x24]) {
        Ok(())
    } else {
        Err(HttpError::new(400, "InvalidSigningKey"))
    }
}

fn service_auth_jwt(
    signing_key: &RepoSigningKey,
    iss: &str,
    aud: &str,
    lxm: Option<&str>,
    exp: i64,
) -> Result<String, HttpError> {
    let header = json!({
        "typ": "JWT",
        "alg": "ES256",
        "kid": format!("{iss}#atproto"),
    });
    let mut payload = json!({
        "iss": iss,
        "aud": aud,
        "exp": exp,
    });
    if let Some(lxm) = lxm {
        payload["lxm"] = json!(lxm);
    }
    let header = BASE64_URL_SAFE_NO_PAD.encode(to_vec(&header).map_err(HttpError::worker)?);
    let payload = BASE64_URL_SAFE_NO_PAD.encode(to_vec(&payload).map_err(HttpError::worker)?);
    let signing_input = format!("{header}.{payload}");
    let signature = signing_key
        .sign_sha256(signing_input.as_bytes())
        .map_err(HttpError::identity)?;
    Ok(format!(
        "{signing_input}.{}",
        BASE64_URL_SAFE_NO_PAD.encode(signature)
    ))
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

fn random_urlsafe_token<const N: usize>() -> Result<String, HttpError> {
    Ok(BASE64_URL_SAFE_NO_PAD.encode(random_bytes::<N>()?))
}

fn pkce_s256_challenge(verifier: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
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

fn current_datetime_string() -> String {
    js_sys::Date::new_0()
        .to_iso_string()
        .as_string()
        .unwrap_or_else(|| "1970-01-01T00:00:00.000Z".to_string())
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
    match event.event_type.as_str() {
        "account" => return subscribe_account_event_frame(event),
        "identity" => return subscribe_identity_event_frame(event),
        "sync" => return subscribe_sync_event_frame(event),
        _ => {}
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
        prev_data: event.prev_data,
        blocks: event.blocks.clone().unwrap_or_default(),
        ops: frame_ops,
        blobs: frame_blobs,
        time: event.created_at.clone(),
    };

    let mut frame = encode_dag_cbor(&header).map_err(HttpError::worker)?;
    frame.extend(encode_dag_cbor(&body).map_err(HttpError::worker)?);
    Ok(frame)
}

fn subscribe_sync_event_frame(event: &DirectoryEventRow) -> Result<Vec<u8>, HttpError> {
    let rev = event
        .rev
        .as_ref()
        .ok_or_else(|| HttpError::new(500, "directory sync event is missing rev"))?;
    let header = SubscribeReposHeader {
        op: 1,
        kind: "#sync",
    };
    let body = SubscribeReposSync {
        seq: event.seq,
        did: event.did.to_string(),
        blocks: event.blocks.clone().unwrap_or_default(),
        rev: rev.to_string(),
        time: event.created_at.clone(),
    };

    let mut frame = encode_dag_cbor(&header).map_err(HttpError::worker)?;
    frame.extend(encode_dag_cbor(&body).map_err(HttpError::worker)?);
    Ok(frame)
}

fn subscribe_identity_event_frame(event: &DirectoryEventRow) -> Result<Vec<u8>, HttpError> {
    let payload =
        from_str::<DirectoryIdentityEventPayload>(&event.blobs_json).map_err(HttpError::worker)?;
    let header = SubscribeReposHeader {
        op: 1,
        kind: "#identity",
    };
    let body = SubscribeReposIdentity {
        seq: event.seq,
        did: event.did.to_string(),
        handle: payload.handle,
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
    since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "prevData")]
    prev_data: Option<crate::cid::Cid>,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
    ops: Vec<SubscribeReposOp>,
    blobs: Vec<crate::cid::Cid>,
    time: String,
}

#[derive(Serialize)]
struct SubscribeReposSync {
    seq: i64,
    did: String,
    #[serde(with = "serde_bytes")]
    blocks: Vec<u8>,
    rev: String,
    time: String,
}

#[derive(Deserialize)]
struct DirectoryIdentityEventPayload {
    handle: Option<String>,
}

#[derive(Serialize)]
struct SubscribeReposIdentity {
    seq: i64,
    did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    handle: Option<String>,
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

fn xrpc_error_body(error: &str, message: Option<&str>) -> Value {
    let mut body = json!({ "error": error });
    if let Some(message) = message.filter(|message| !message.is_empty()) {
        body["message"] = json!(message);
    }
    body
}

fn handle_worker_xrpc(
    http_method: Method,
    xrpc_method: &str,
    url: &worker::Url,
) -> worker::Result<Response> {
    match (http_method, xrpc_method) {
        (Method::Get, SERVER_DESCRIBE_SERVER) => describe_server(url),
        (Method::Get, IDENTITY_RESOLVE_HANDLE) => match xrpc_resolve_handle(url) {
            Ok(response) => Ok(response),
            Err(error) => json_response(
                error.status,
                &xrpc_error_body(&error.message, Some(error.message.as_str())),
            ),
        },
        (_, SERVER_DESCRIBE_SERVER | IDENTITY_RESOLVE_HANDLE) => json_response(
            405,
            &xrpc_error_body("MethodNotAllowed", Some("method not allowed")),
        ),
        _ => json_response(
            404,
            &json!({
                "error": "MethodNotFound",
                "message": format!("unsupported XRPC method `{xrpc_method}`"),
            }),
        ),
    }
}

fn describe_server(url: &worker::Url) -> worker::Result<Response> {
    let Some(host) = url.host_str() else {
        return json_response(
            400,
            &xrpc_error_body("InvalidRequest", Some("request host is required")),
        );
    };
    json_response(
        200,
        &json!({
            "did": format!("did:web:{host}"),
            "availableUserDomains": [host],
            "inviteCodeRequired": true,
            "phoneVerificationRequired": false,
            "links": {},
            "contact": {},
        }),
    )
}

fn xrpc_resolve_handle(url: &worker::Url) -> Result<Response, HttpError> {
    let params = query_pairs(url);
    let handle = required_param(&params, "handle")
        .map_err(HttpError::xrpc)?
        .to_ascii_lowercase();
    let Some(host) = url.host_str() else {
        return Err(HttpError::new(400, "request host is required"));
    };
    if handle != host {
        return Err(HttpError::new(404, "HandleNotFound"));
    }
    json_response(
        200,
        &json!({
            "did": format!("did:web:{handle}"),
        }),
    )
    .map_err(HttpError::worker)
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

async fn fetch_internal_directory_json(
    env: &Env,
    directory_name: &str,
    method: Method,
    path: &str,
    body: &Value,
) -> Result<Response, HttpError> {
    fetch_internal_directory_request(env, directory_name, method, path, Some(body)).await
}

async fn fetch_internal_directory_request(
    env: &Env,
    directory_name: &str,
    method: Method,
    path: &str,
    body: Option<&Value>,
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
    init.with_method(method).with_headers(headers);
    if let Some(body) = body {
        init.with_body(Some(JsValue::from_str(
            &to_string(body).map_err(HttpError::worker)?,
        )));
    }
    let request = Request::new_with_init(&format!("https://pds.internal{path}"), &init)
        .map_err(HttpError::worker)?;

    stub.fetch_with_request(request)
        .await
        .map_err(HttpError::worker)
}

async fn fetch_oauth_client_metadata(client_id: &str) -> Result<Value, HttpError> {
    let url = ::url::Url::parse(client_id)
        .map_err(|error| HttpError::new(400, format!("invalid client_id: {error}")))?;
    let mut response = Fetch::Url(url).send().await.map_err(HttpError::worker)?;
    if response.status_code() != 200 {
        return Err(HttpError::new(
            400,
            format!(
                "client metadata fetch failed with status {}",
                response.status_code()
            ),
        ));
    }
    let content_type = response
        .headers()
        .get("content-type")
        .map_err(HttpError::worker)?
        .and_then(|value| value.split(';').next().map(|part| part.trim().to_string()))
        .unwrap_or_default();
    if !content_type.eq_ignore_ascii_case("application/json") {
        return Err(HttpError::new(
            400,
            "client metadata response must have content-type application/json",
        ));
    }
    response.json().await.map_err(HttpError::worker)
}

async fn fetch_oauth_jwks(jwks_uri: &str) -> Result<Value, HttpError> {
    let url = ::url::Url::parse(jwks_uri)
        .map_err(|error| HttpError::new(400, format!("invalid jwks_uri: {error}")))?;
    let mut response = Fetch::Url(url).send().await.map_err(HttpError::worker)?;
    if response.status_code() != 200 {
        return Err(HttpError::new(
            400,
            format!("JWKS fetch failed with status {}", response.status_code()),
        ));
    }
    let content_type = response
        .headers()
        .get("content-type")
        .map_err(HttpError::worker)?
        .and_then(|value| value.split(';').next().map(|part| part.trim().to_string()))
        .unwrap_or_default();
    if !content_type.eq_ignore_ascii_case("application/json") {
        return Err(HttpError::new(
            400,
            "JWKS response must have content-type application/json",
        ));
    }
    response.json().await.map_err(HttpError::worker)
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

fn invite_code_json(row: &DirectoryInviteCodeRow, uses: &[DirectoryInviteCodeUseRow]) -> Value {
    json!({
        "code": row.code.clone(),
        "available": row.available,
        "disabled": row.disabled,
        "forAccount": row.for_account.to_string(),
        "createdBy": row.created_by.to_string(),
        "createdAt": row.created_at.clone(),
        "uses": uses.iter().map(invite_code_use_json).collect::<Vec<_>>(),
    })
}

fn invite_code_use_json(row: &DirectoryInviteCodeUseRow) -> Value {
    json!({
        "usedBy": row.used_by.to_string(),
        "usedAt": row.used_at.clone(),
    })
}

fn account_view_json(account: &DirectoryAccountRow, invites: Option<Vec<Value>>) -> Value {
    let mut body = json!({
        "did": account.did.to_string(),
        "handle": account.handle.clone(),
        "email": account.email.clone(),
        "relatedRecords": [],
        "indexedAt": account.created_at.clone(),
        "invitesDisabled": account.invites_disabled,
    });
    if account.email_confirmed {
        body["emailConfirmedAt"] = json!(account.created_at.clone());
    }
    if let Some(note) = account.invite_note.as_deref() {
        body["inviteNote"] = json!(note);
    }
    if !account.active {
        body["deactivatedAt"] = json!(account.created_at.clone());
    }
    if let Some(invites) = invites {
        body["invites"] = json!(invites);
    }
    body
}

fn subject_status_json(account: &DirectoryAccountRow) -> Value {
    let mut body = json!({
        "subject": {
            "$type": "com.atproto.admin.defs#repoRef",
            "did": account.did.to_string(),
        },
        "takedown": {
            "applied": account.status.as_deref() == Some("takedown"),
        },
        "deactivated": {
            "applied": !account.active && account.status.as_deref() != Some("takedown"),
        },
    });
    if let Some(status) = account
        .status
        .as_deref()
        .filter(|status| !status.is_empty())
    {
        body["status"] = json!(status);
    }
    body
}

fn query_pairs(url: &worker::Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn did_array_param(query: &[(String, String)], param: &'static str) -> Result<Vec<Did>, HttpError> {
    let values = query
        .iter()
        .filter(|(key, _)| key == param)
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| Did::new(value.to_string()).map_err(HttpError::bad_request))
        .collect::<Result<Vec<_>, _>>()?;
    if values.is_empty() {
        return Err(HttpError::new(
            400,
            format!("missing required param `{param}`"),
        ));
    }
    Ok(values)
}

fn encode_query_component(value: &str) -> String {
    ::url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

fn internal_repo_control_url(url: &worker::Url, repo_name: &str, action: &str) -> String {
    format!(
        "{}/{}/{}/{}/{}",
        request_origin(url),
        INTERNAL_REPO_CONTROL_ROOT,
        INTERNAL_REPO_CONTROL_REPOS,
        encode_query_component(repo_name),
        action,
    )
}

fn internal_repo_control_parts<'a>(parts: &'a [&'a str]) -> Option<(&'a str, &'a str)> {
    if parts.len() == 4
        && parts[0] == INTERNAL_REPO_CONTROL_ROOT
        && parts[1] == INTERNAL_REPO_CONTROL_REPOS
        && !parts[2].is_empty()
        && !parts[3].is_empty()
    {
        Some((parts[2], parts[3]))
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InternalDirectoryControlAction {
    Status,
    AccountStatus,
    RepoUpsert,
}

fn internal_directory_account_status_path(did: &str) -> String {
    format!(
        "/{}/{}/{}/{}?did={}",
        INTERNAL_REPO_CONTROL_ROOT,
        INTERNAL_DIRECTORY_CONTROL_DIRECTORY,
        INTERNAL_DIRECTORY_CONTROL_ACCOUNTS,
        INTERNAL_DIRECTORY_CONTROL_STATUS,
        encode_query_component(did),
    )
}

fn internal_directory_repo_upsert_path() -> String {
    format!(
        "/{}/{}/{}/{}",
        INTERNAL_REPO_CONTROL_ROOT,
        INTERNAL_DIRECTORY_CONTROL_DIRECTORY,
        INTERNAL_DIRECTORY_CONTROL_REPOS,
        INTERNAL_DIRECTORY_CONTROL_UPSERT,
    )
}

fn internal_directory_control_action(parts: &[&str]) -> Option<InternalDirectoryControlAction> {
    match parts {
        [root, directory, status]
            if *root == INTERNAL_REPO_CONTROL_ROOT
                && *directory == INTERNAL_DIRECTORY_CONTROL_DIRECTORY
                && *status == INTERNAL_DIRECTORY_CONTROL_STATUS =>
        {
            Some(InternalDirectoryControlAction::Status)
        }
        [root, directory, accounts, status]
            if *root == INTERNAL_REPO_CONTROL_ROOT
                && *directory == INTERNAL_DIRECTORY_CONTROL_DIRECTORY
                && *accounts == INTERNAL_DIRECTORY_CONTROL_ACCOUNTS
                && *status == INTERNAL_DIRECTORY_CONTROL_STATUS =>
        {
            Some(InternalDirectoryControlAction::AccountStatus)
        }
        [root, directory, repos, upsert]
            if *root == INTERNAL_REPO_CONTROL_ROOT
                && *directory == INTERNAL_DIRECTORY_CONTROL_DIRECTORY
                && *repos == INTERNAL_DIRECTORY_CONTROL_REPOS
                && *upsert == INTERNAL_DIRECTORY_CONTROL_UPSERT =>
        {
            Some(InternalDirectoryControlAction::RepoUpsert)
        }
        _ => None,
    }
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

fn bool_param(query: &[(String, String)], param: &str, default: bool) -> Result<bool, HttpError> {
    let Some(value) = optional_param(query, param) else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(HttpError::new(
            400,
            format!("invalid boolean query parameter `{param}`"),
        )),
    }
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
    response
        .headers_mut()
        .set("content-security-policy", "default-src 'none'; sandbox")?;
    response
        .headers_mut()
        .set("x-content-type-options", "nosniff")?;
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
    response
        .headers_mut()
        .set("content-security-policy", "default-src 'none'; sandbox")?;
    response
        .headers_mut()
        .set("x-content-type-options", "nosniff")?;
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

fn oauth_request_error_response(error: OAuthRequestError) -> worker::Result<Response> {
    oauth_error_response(400, error.error_code(), &error.to_string())
}

fn oauth_dpop_error_response(error: DpopError, nonce: Option<&str>) -> worker::Result<Response> {
    let error_code = if matches!(error, DpopError::NonceMismatch) {
        "use_dpop_nonce"
    } else {
        "invalid_dpop_proof"
    };
    let mut response = oauth_error_response(400, error_code, &error.to_string())?;
    if let Some(nonce) = nonce {
        response.headers_mut().set("dpop-nonce", nonce)?;
    }
    Ok(response)
}

fn oauth_authorization_redirect(
    redirect_uri: &str,
    code: &str,
    state: &str,
    issuer: &str,
) -> Result<Response, HttpError> {
    let mut redirect = ::url::Url::parse(redirect_uri)
        .map_err(|error| HttpError::new(400, format!("invalid redirect_uri: {error}")))?;
    {
        let mut query = redirect.query_pairs_mut();
        query.append_pair("code", code);
        query.append_pair("state", state);
        query.append_pair("iss", issuer);
    }

    let mut response = Response::empty()
        .map_err(HttpError::worker)?
        .with_status(302);
    response
        .headers_mut()
        .set("location", redirect.as_str())
        .map_err(HttpError::worker)?;
    response
        .headers_mut()
        .set("cache-control", "no-store")
        .map_err(HttpError::worker)?;
    set_cors(&mut response).map_err(HttpError::worker)?;
    Ok(response)
}

fn oauth_authorization_error_redirect(
    redirect_uri: &str,
    error: &str,
    error_description: &str,
    state: &str,
    issuer: &str,
) -> Result<Response, HttpError> {
    let mut redirect = ::url::Url::parse(redirect_uri).map_err(|parse_error| {
        HttpError::new(400, format!("invalid redirect_uri: {parse_error}"))
    })?;
    {
        let mut query = redirect.query_pairs_mut();
        query.append_pair("error", error);
        query.append_pair("error_description", error_description);
        query.append_pair("state", state);
        query.append_pair("iss", issuer);
    }

    let mut response = Response::empty()
        .map_err(HttpError::worker)?
        .with_status(302);
    response
        .headers_mut()
        .set("location", redirect.as_str())
        .map_err(HttpError::worker)?;
    response
        .headers_mut()
        .set("cache-control", "no-store")
        .map_err(HttpError::worker)?;
    set_cors(&mut response).map_err(HttpError::worker)?;
    Ok(response)
}

fn oauth_authorization_form_response(
    status: u16,
    par: &DirectoryOauthParRequestRow,
    error: Option<&str>,
) -> worker::Result<Response> {
    let login_hint = par.login_hint.as_deref().unwrap_or_default();
    let error_html = error
        .map(|message| {
            format!(
                r#"<div class="error" role="alert">{}</div>"#,
                html_escape(message)
            )
        })
        .unwrap_or_default();
    let scopes = par
        .scope
        .split_whitespace()
        .map(|scope| format!("<li>{}</li>", html_escape(scope)))
        .collect::<String>();
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize client</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f6f7f9; color: #15171a; }}
main {{ width: min(92vw, 440px); background: #fff; border: 1px solid #d9dde3; border-radius: 8px; padding: 24px; box-shadow: 0 16px 48px rgb(20 28 40 / 12%); }}
h1 {{ font-size: 1.35rem; margin: 0 0 12px; }}
p {{ line-height: 1.45; margin: 0 0 16px; }}
code {{ overflow-wrap: anywhere; }}
label {{ display: block; font-weight: 600; margin: 14px 0 6px; }}
input[type="text"], input[type="password"] {{ box-sizing: border-box; width: 100%; padding: 10px 12px; border: 1px solid #b8c0cc; border-radius: 6px; font: inherit; }}
.consent {{ display: flex; gap: 10px; align-items: flex-start; margin: 16px 0; font-weight: 500; }}
.consent input {{ margin-top: 3px; }}
.actions {{ display: flex; gap: 10px; justify-content: flex-end; margin-top: 18px; }}
button {{ border: 0; border-radius: 6px; padding: 10px 14px; font: inherit; cursor: pointer; }}
button.primary {{ background: #175bcc; color: #fff; }}
button.secondary {{ background: #e8ebf0; color: #1f252d; }}
.error {{ border: 1px solid #d83b3b; background: #fff0f0; color: #9b1c1c; padding: 10px 12px; border-radius: 6px; margin-bottom: 14px; }}
@media (prefers-color-scheme: dark) {{ body {{ background: #111418; color: #f0f3f6; }} main {{ background: #191e24; border-color: #303842; }} input[type="text"], input[type="password"] {{ background: #111418; border-color: #4a5563; color: #f0f3f6; }} button.secondary {{ background: #2b333d; color: #f0f3f6; }} }}
</style>
</head>
<body>
<main>
<h1>Authorize client</h1>
{error_html}
<p><code>{client_id}</code> is requesting access to this account.</p>
<p>Requested scopes:</p>
<ul>{scopes}</ul>
<form method="post" action="/oauth/authorize">
<input type="hidden" name="client_id" value="{client_id_attr}">
<input type="hidden" name="request_uri" value="{request_uri_attr}">
<label for="identifier">Account</label>
<input id="identifier" name="identifier" type="text" autocomplete="username" value="{identifier_attr}" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<label class="consent"><input name="consent" type="checkbox" value="yes" required><span>Approve this client for the requested scopes.</span></label>
<div class="actions">
<button class="secondary" type="submit" name="approve" value="no" formnovalidate>Cancel</button>
<button class="primary" type="submit" name="approve" value="yes">Authorize</button>
</div>
</form>
</main>
</body>
</html>"#,
        client_id = html_escape(&par.client_id),
        client_id_attr = html_attr_escape(&par.client_id),
        request_uri_attr = html_attr_escape(&par.request_uri),
        identifier_attr = html_attr_escape(login_hint),
    );
    html_response(status, &html)
}

fn oauth_par_response(
    request_uri: &str,
    expires_in: i64,
    dpop_nonce: &str,
) -> worker::Result<Response> {
    let mut response = Response::from_json(&json!({
        "request_uri": request_uri,
        "expires_in": expires_in,
    }))?
    .with_status(201);
    response.headers_mut().set("cache-control", "no-store")?;
    response.headers_mut().set("dpop-nonce", dpop_nonce)?;
    set_cors(&mut response)?;
    Ok(response)
}

fn oauth_token_response(
    tokens: &SessionTokens,
    scope: &str,
    sub: &str,
    dpop_nonce: &str,
) -> worker::Result<Response> {
    let mut response = Response::from_json(&json!({
        "access_token": &tokens.access_jwt,
        "token_type": "DPoP",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "refresh_token": &tokens.refresh_jwt,
        "scope": scope,
        "sub": sub,
    }))?;
    response.headers_mut().set("cache-control", "no-store")?;
    response.headers_mut().set("pragma", "no-cache")?;
    response.headers_mut().set("dpop-nonce", dpop_nonce)?;
    set_cors(&mut response)?;
    Ok(response)
}

fn text_response(status: u16, value: &str) -> worker::Result<Response> {
    let mut response = Response::from_bytes(value.as_bytes().to_vec())?.with_status(status);
    response.headers_mut().set("content-type", "text/plain")?;
    set_cors(&mut response)?;
    Ok(response)
}

fn html_response(status: u16, value: &str) -> worker::Result<Response> {
    let mut response = Response::from_bytes(value.as_bytes().to_vec())?.with_status(status);
    response
        .headers_mut()
        .set("content-type", "text/html; charset=utf-8")?;
    response.headers_mut().set("cache-control", "no-store")?;
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

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn html_attr_escape(value: &str) -> String {
    html_escape(value).replace('"', "&quot;")
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

    #[test]
    fn detects_repo_already_initialized_error() {
        let error = HttpError::new(
            409,
            "failed to initialize repo: {\"error\":\"repo already initialized\"}",
        );
        assert!(is_repo_already_initialized_error(&error));
        assert!(!is_repo_already_initialized_error(&HttpError::new(
            409,
            "different conflict",
        )));
    }

    #[test]
    fn converts_matching_repo_status_to_init_response() {
        let response = init_response_from_repo_status(
            matching_repo_status(),
            "did:web:gsv-pds.example.com",
            "gsv-pds.example.com",
        )
        .unwrap();

        assert_eq!(response.public_key_multibase, "zPublicKey");
        assert_eq!(response.latest_commit, "bafyreiatestcommit");
        assert_eq!(response.latest_rev, "3lzpfxn2f6h2c");
    }

    #[test]
    fn rejects_recovery_status_for_different_identity() {
        let error = init_response_from_repo_status(
            matching_repo_status(),
            "did:web:other.example.com",
            "gsv-pds.example.com",
        )
        .unwrap_err();
        assert_eq!(error.status, 409);
        assert!(error.message.contains("different DID"));

        let error = init_response_from_repo_status(
            matching_repo_status(),
            "did:web:gsv-pds.example.com",
            "other.example.com",
        )
        .unwrap_err();
        assert_eq!(error.status, 409);
        assert!(error.message.contains("different handle"));
    }

    #[test]
    fn rejects_incomplete_recovery_status() {
        let error = init_response_from_repo_status(
            InternalRepoStatusResponse {
                initialized: false,
                did: None,
                handle: None,
                public_key_multibase: None,
                latest_commit: None,
                latest_rev: None,
                blocks: 0,
                records: 0,
                expected_blobs: 0,
                imported_blobs: 0,
            },
            "did:web:gsv-pds.example.com",
            "gsv-pds.example.com",
        )
        .unwrap_err();
        assert_eq!(error.status, 409);
        assert!(error.message.contains("uninitialized"));

        let mut status = matching_repo_status();
        status.latest_commit = None;
        let error = init_response_from_repo_status(
            status,
            "did:web:gsv-pds.example.com",
            "gsv-pds.example.com",
        )
        .unwrap_err();
        assert_eq!(error.status, 409);
        assert!(error.message.contains("latest commit"));
    }

    #[test]
    fn builds_identity_info_response_body() {
        let account = DirectoryAccountRow {
            did: Did::new("did:web:gsv-pds.example.com").unwrap(),
            handle: "gsv-pds.example.com".to_string(),
            email: None,
            email_confirmed: false,
            invites_disabled: false,
            invite_note: None,
            password_hash: "hash".to_string(),
            repo_name: "gsv-pds.example.com".to_string(),
            public_key_multibase: "zPublicKey".to_string(),
            active: true,
            status: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };

        let body = identity_info_response_body("https://gsv-pds.example.com", &account);

        assert_eq!(body["did"], "did:web:gsv-pds.example.com");
        assert_eq!(body["handle"], "gsv-pds.example.com");
        assert_eq!(body["didDoc"]["id"], "did:web:gsv-pds.example.com");
        assert_eq!(
            body["didDoc"]["service"][0]["serviceEndpoint"],
            "https://gsv-pds.example.com"
        );
    }

    #[test]
    fn builds_admin_account_and_subject_views() {
        let account = DirectoryAccountRow {
            did: Did::new("did:web:gsv-pds.example.com").unwrap(),
            handle: "gsv-pds.example.com".to_string(),
            email: Some("hank@example.com".to_string()),
            email_confirmed: true,
            invites_disabled: true,
            invite_note: Some("maintenance".to_string()),
            password_hash: "hash".to_string(),
            repo_name: "gsv-pds.example.com".to_string(),
            public_key_multibase: "zPublicKey".to_string(),
            active: false,
            status: Some("takedown".to_string()),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let invite = DirectoryInviteCodeRow {
            code: "gsv-test".to_string(),
            available: 2,
            disabled: false,
            for_account: account.did.clone(),
            created_by: account.did.clone(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let invite_use = DirectoryInviteCodeUseRow {
            code: invite.code.clone(),
            used_by: Did::new("did:gsv:invited").unwrap(),
            used_at: "2026-01-01T00:01:00Z".to_string(),
        };
        let invite = invite_code_json(&invite, &[invite_use]);

        let view = account_view_json(&account, Some(vec![invite]));
        assert_eq!(view["did"], account.did.to_string());
        assert_eq!(view["invitesDisabled"], true);
        assert_eq!(view["inviteNote"], "maintenance");
        assert_eq!(view["invites"][0]["code"], "gsv-test");
        assert_eq!(view["invites"][0]["uses"][0]["usedBy"], "did:gsv:invited");

        let status = subject_status_json(&account);
        assert_eq!(status["subject"]["did"], account.did.to_string());
        assert_eq!(status["takedown"]["applied"], true);
        assert_eq!(status["deactivated"]["applied"], false);
    }

    #[test]
    fn builds_verifiable_service_auth_jwt() {
        let key = RepoSigningKey::from_p256_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let token = service_auth_jwt(
            &key,
            "did:web:gsv-pds.example.com",
            "did:web:service.example.com",
            Some("com.atproto.repo.getRecord"),
            1_776_722_400,
        )
        .unwrap();
        let parts = token.split('.').collect::<Vec<_>>();
        assert_eq!(parts.len(), 3);

        let payload = BASE64_URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let payload: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["iss"], "did:web:gsv-pds.example.com");
        assert_eq!(payload["aud"], "did:web:service.example.com");
        assert_eq!(payload["lxm"], "com.atproto.repo.getRecord");

        let signature = BASE64_URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        crate::identity::verify_p256_signature(
            &key.verifying_key().unwrap(),
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &signature,
        )
        .unwrap();
    }

    #[test]
    fn normalizes_at_identifiers() {
        assert_eq!(
            normalize_at_identifier("GSV-PDS.EXAMPLE.COM"),
            "gsv-pds.example.com"
        );
        assert_eq!(
            normalize_at_identifier("did:web:MiXeD.example.com"),
            "did:web:MiXeD.example.com"
        );
    }

    #[test]
    fn parses_only_internal_repo_control_paths() {
        assert_eq!(
            internal_repo_control_parts(&["_pds_internal", "repos", "alice", "init"]),
            Some(("alice", "init"))
        );
        assert_eq!(
            internal_repo_control_parts(&["repos", "alice", "init"]),
            None
        );
        assert_eq!(
            internal_repo_control_parts(&["_pds_internal", "repos", "alice"]),
            None
        );
        assert_eq!(
            internal_repo_control_parts(&["_pds_internal", "repos", "alice", "init", "extra"]),
            None
        );
    }

    #[test]
    fn parses_only_internal_directory_control_paths() {
        assert_eq!(
            internal_directory_control_action(&["_pds_internal", "directory", "status"]),
            Some(InternalDirectoryControlAction::Status)
        );
        assert_eq!(
            internal_directory_control_action(&[
                "_pds_internal",
                "directory",
                "accounts",
                "status"
            ]),
            Some(InternalDirectoryControlAction::AccountStatus)
        );
        assert_eq!(
            internal_directory_control_action(&["_pds_internal", "directory", "repos", "upsert"]),
            Some(InternalDirectoryControlAction::RepoUpsert)
        );
        assert_eq!(
            internal_directory_control_action(&["directory", "status"]),
            None
        );
        assert_eq!(
            internal_directory_control_action(&["_pds_internal", "directory", "repos"]),
            None
        );
    }

    #[test]
    fn validates_app_password_names() {
        assert!(ensure_app_password_name("desktop client").is_ok());
        assert!(ensure_app_password_name("").is_err());
        assert!(ensure_app_password_name("   ").is_err());
        assert!(ensure_app_password_name(&"x".repeat(65)).is_err());
    }

    #[test]
    fn accepts_and_validates_known_record_envelopes() {
        let collection = Nsid::new("app.gsv.record").unwrap();
        let lexicons = vec![test_record_lexicon("app.gsv.record")];
        assert_eq!(
            ensure_record_envelope(
                &collection,
                &json!({
                    "$type": "app.gsv.record",
                    "text": "hello",
                }),
                None,
                &lexicons,
            )
            .unwrap(),
            RecordValidationStatus::Valid
        );
        assert_eq!(
            ensure_record_envelope(
                &collection,
                &json!({
                    "$type": "app.gsv.record",
                    "text": "hello",
                }),
                Some(true),
                &lexicons,
            )
            .unwrap(),
            RecordValidationStatus::Valid
        );
    }

    #[test]
    fn explicit_no_validation_returns_unknown_status() {
        let collection = Nsid::new("app.gsv.record").unwrap();
        assert_eq!(
            ensure_record_envelope(
                &collection,
                &json!({
                    "$type": "app.gsv.record",
                    "text": "hello",
                }),
                Some(false),
                &[],
            )
            .unwrap(),
            RecordValidationStatus::Unknown
        );
    }

    #[test]
    fn optimistic_unknown_lexicon_returns_unknown_status() {
        let collection = Nsid::new("app.gsv.unknown").unwrap();
        assert_eq!(
            ensure_record_envelope(
                &collection,
                &json!({
                    "$type": "app.gsv.unknown",
                    "text": "hello",
                }),
                None,
                &[],
            )
            .unwrap(),
            RecordValidationStatus::Unknown
        );
    }

    #[test]
    fn rejects_invalid_record_envelopes_and_unknown_validate_true() {
        let collection = Nsid::new("app.gsv.record").unwrap();

        let error =
            ensure_record_envelope(&collection, &json!({"text": "hello"}), None, &[]).unwrap_err();
        assert_eq!(error.status, 400);
        assert!(error.message.contains("$type"));

        let error = ensure_record_envelope(
            &collection,
            &json!({
                "$type": "app.gsv.other",
                "text": "hello",
            }),
            None,
            &[],
        )
        .unwrap_err();
        assert_eq!(error.status, 400);
        assert!(error.message.contains("does not match"));

        let unknown_collection = Nsid::new("app.gsv.unknown").unwrap();
        let error = ensure_record_envelope(
            &unknown_collection,
            &json!({
                "$type": "app.gsv.unknown",
                "text": "hello",
            }),
            Some(true),
            &[],
        )
        .unwrap_err();
        assert_eq!(error.status, 400);
        assert!(error.message.contains("lexicon"));
    }

    fn matching_repo_status() -> InternalRepoStatusResponse {
        InternalRepoStatusResponse {
            initialized: true,
            did: Some("did:web:gsv-pds.example.com".to_string()),
            handle: Some("gsv-pds.example.com".to_string()),
            public_key_multibase: Some("zPublicKey".to_string()),
            latest_commit: Some("bafyreiatestcommit".to_string()),
            latest_rev: Some("3lzpfxn2f6h2c".to_string()),
            blocks: 42,
            records: 7,
            expected_blobs: 2,
            imported_blobs: 1,
        }
    }

    fn test_record_lexicon(id: &str) -> Value {
        json!({
            "lexicon": 1,
            "id": id,
            "defs": {
                "main": {
                    "type": "record",
                    "key": "any",
                    "record": {
                        "type": "object",
                        "required": ["$type", "text"],
                        "properties": {
                            "$type": { "type": "string", "const": id },
                            "text": { "type": "string" }
                        }
                    }
                }
            }
        })
    }
}
