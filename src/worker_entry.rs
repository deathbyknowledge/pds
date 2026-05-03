use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, to_string, Value};
use wasm_bindgen::JsValue;
use worker::{
    durable_object, event, Context, DurableObject, Env, Headers, Method, Request, RequestInit,
    Response, SqlStorage, State,
};

use crate::car::{encode_car_from_store, CarError};
use crate::cid::parse_cid;
use crate::commit::{Did, RepoRev};
use crate::data_model::{Nsid, RecordKey, RepoPath};
use crate::do_store::{
    DirectoryRepoRow, RepoIdentityRow, RepoStateRow, SqlDirectoryStore, SqlRepoStore,
};
use crate::identity::{IdentityError, RepoSigningKey};
use crate::repo::{RepoError, RepoMutation, SignedRepository};
use crate::xrpc::{
    at_uri, optional_param, parse_list_records_params, required_param, route_xrpc_method,
    REPO_DESCRIBE_REPO, REPO_GET_RECORD, REPO_LIST_RECORDS, SERVER_DESCRIBE_SERVER, SYNC_GET_BLOB,
    SYNC_GET_LATEST_COMMIT, SYNC_GET_RECORD, SYNC_GET_REPO, SYNC_GET_REPO_STATUS, SYNC_LIST_BLOBS,
    SYNC_LIST_REPOS,
};
use crate::xrpc::{XrpcError, XrpcRoute};

const DID_DOCUMENT_PATH: &str = "/.well-known/did.json";
const ATPROTO_DID_PATH: &str = "/.well-known/atproto-did";

#[event(fetch)]
async fn fetch(req: Request, env: worker::Env, _ctx: Context) -> worker::Result<Response> {
    let url = req.url()?;
    let parts = url
        .path()
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();

    if req.method() == Method::Get && url.path() == "/xrpc/_health" {
        return health_response();
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
                "recordCreate": "POST /repos/:name/records",
                "recordUpdate": "PUT /repos/:name/records",
                "recordDelete": "DELETE /repos/:name/records",
                "recordRead": "GET /repos/:name/records?path=collection/rkey",
                "recordList": "GET /repos/:name/records?collection=nsid",
                "xrpcDescribeServer": "GET /xrpc/com.atproto.server.describeServer",
                "xrpcDescribeRepo": "GET /xrpc/com.atproto.repo.describeRepo?repo=:repo",
                "xrpcGetRecord": "GET /xrpc/com.atproto.repo.getRecord?repo=:repo&collection=:nsid&rkey=:rkey",
                "xrpcListRecords": "GET /xrpc/com.atproto.repo.listRecords?repo=:repo&collection=:nsid",
                "xrpcGetLatestCommit": "GET /xrpc/com.atproto.sync.getLatestCommit?did=:did",
                "xrpcGetRepoStatus": "GET /xrpc/com.atproto.sync.getRepoStatus?did=:did",
                "xrpcListRepos": "GET /xrpc/com.atproto.sync.listRepos",
                "xrpcListBlobs": "GET /xrpc/com.atproto.sync.listBlobs?did=:did",
                "xrpcGetBlob": "GET /xrpc/com.atproto.sync.getBlob?did=:did&cid=:cid",
                "xrpcSyncGetRecord": "GET /xrpc/com.atproto.sync.getRecord?did=:did&collection=:nsid&rkey=:rkey",
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
                "events": store.event_count().map_err(HttpError::worker)?,
            }),
        )
        .map_err(HttpError::worker)
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

    async fn upsert_repo(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: DirectoryUpsertRepoRequest = req.json().await.map_err(HttpError::worker)?;
        let row = DirectoryRepoRow {
            did: Did::new(body.did).map_err(HttpError::bad_request)?,
            handle: body.handle,
            repo_name: body.repo_name,
            head: parse_cid(&body.head).map_err(HttpError::bad_request)?,
            rev: RepoRev::new(body.rev).map_err(HttpError::bad_request)?,
            active: body.active.unwrap_or(true),
        };
        self.store().upsert_repo(&row).map_err(HttpError::worker)?;

        json_response(
            200,
            &json!({
                "ok": true,
                "repo": directory_repo_json(row),
            }),
        )
        .map_err(HttpError::worker)
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
            return self.handle_xrpc(req.method(), parts[1], &url).await;
        }

        let repo_name = parts.get(1).copied().unwrap_or("").to_string();
        let action = parts.get(2).copied().unwrap_or("");

        match (req.method(), action) {
            (Method::Get, "status") => self.status(),
            (Method::Post, "init") => self.init(req, &repo_name).await,
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
        method: Method,
        xrpc_method: &str,
        url: &worker::Url,
    ) -> Result<Response, HttpError> {
        if method != Method::Get {
            return Err(HttpError::new(405, "method not allowed"));
        }

        match xrpc_method {
            REPO_DESCRIBE_REPO => self.xrpc_describe_repo(url).await,
            REPO_GET_RECORD => self.xrpc_get_record(url).await,
            REPO_LIST_RECORDS => self.xrpc_list_records(url).await,
            SYNC_GET_LATEST_COMMIT => self.xrpc_get_latest_commit(url),
            SYNC_GET_REPO_STATUS => self.xrpc_get_repo_status(url),
            SYNC_LIST_BLOBS => self.xrpc_list_blobs(url),
            SYNC_GET_BLOB => self.xrpc_get_blob(url),
            SYNC_GET_RECORD => self.xrpc_get_sync_record(url).await,
            SYNC_GET_REPO => self.xrpc_get_repo(url).await,
            SERVER_DESCRIBE_SERVER => describe_server(url).map_err(HttpError::worker),
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

        json_response(
            200,
            &json!({
                "cids": [],
            }),
        )
        .map_err(HttpError::worker)
    }

    fn xrpc_get_blob(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        let cid = required_param(&params, "cid").map_err(HttpError::xrpc)?;
        parse_cid(&cid).map_err(HttpError::bad_request)?;
        let state = self.repo_state()?;
        ensure_repo_did(&state, &did)?;

        Err(HttpError::new(404, "blob not found"))
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

    async fn xrpc_get_repo(&self, url: &worker::Url) -> Result<Response, HttpError> {
        let params = query_pairs(url);
        let did = required_param(&params, "did").map_err(HttpError::xrpc)?;
        if optional_param(&params, "since").is_some_and(|value| !value.is_empty()) {
            return Err(HttpError::new(
                501,
                "com.atproto.sync.getRepo diff export is not implemented yet",
            ));
        }

        let (state, mut repo) = self.open_repo_with_state()?;
        ensure_repo_did(&state, &did)?;
        let cids = repo.export_cids().await.map_err(HttpError::repo)?;
        let car = encode_car_from_store(&[state.latest_commit], cids, repo.storage())
            .map_err(HttpError::car)?;
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
        let repo = SignedRepository::create(store, did.clone(), rev.clone(), &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let state = RepoStateRow {
            did,
            latest_commit: repo.latest_commit_cid(),
            latest_rev: rev,
        };
        repo.storage()
            .put_repo_state(&state)
            .map_err(HttpError::worker)?;
        repo.storage()
            .put_repo_identity(&identity)
            .map_err(HttpError::worker)?;
        self.notify_directory(&request_host, repo_name, &identity, &state)
            .await?;

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
        let (identity, signing_key, mut repo) = self.open_repo_for_write()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .create_record(path.clone(), &body.record, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.notify_directory(&request_host, repo_name, &identity, &state)
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
        let (identity, signing_key, mut repo) = self.open_repo_for_write()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .update_record(path.clone(), &body.record, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.notify_directory(&request_host, repo_name, &identity, &state)
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
        let (identity, signing_key, mut repo) = self.open_repo_for_write()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .delete_record(&path, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        let state = self
            .persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        self.notify_directory(&request_host, repo_name, &identity, &state)
            .await?;
        json_response(200, &mutation_response(&path, &mutation)).map_err(HttpError::worker)
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

    fn open_repo_for_write(
        &self,
    ) -> Result<
        (
            RepoIdentityRow,
            RepoSigningKey,
            SignedRepository<SqlRepoStore>,
        ),
        HttpError,
    > {
        let (_, identity, repo) = self.open_repo_with_identity()?;
        let signing_key = identity.signing_key().map_err(HttpError::identity)?;
        Ok((identity, signing_key, repo))
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
        let token = self.admin_token()?;
        let authorization = req
            .headers()
            .get("authorization")
            .map_err(HttpError::worker)?;
        let admin_header = req
            .headers()
            .get("x-pds-admin-token")
            .map_err(HttpError::worker)?;
        let expected_authorization = format!("Bearer {token}");

        if authorization.as_deref() == Some(expected_authorization.as_str())
            || admin_header.as_deref() == Some(token.as_str())
        {
            Ok(())
        } else {
            Err(HttpError::new(401, "admin token required"))
        }
    }

    fn admin_token(&self) -> Result<String, HttpError> {
        let token = self
            .env
            .secret("PDS_ADMIN_TOKEN")
            .or_else(|_| self.env.var("PDS_ADMIN_TOKEN"))
            .map_err(|_| HttpError::new(500, "PDS_ADMIN_TOKEN binding is required"))?
            .to_string();
        if token.is_empty() {
            Err(HttpError::new(500, "PDS_ADMIN_TOKEN must not be empty"))
        } else {
            Ok(token)
        }
    }

    async fn notify_directory(
        &self,
        request_host: &str,
        repo_name: &str,
        identity: &RepoIdentityRow,
        state: &RepoStateRow,
    ) -> Result<(), HttpError> {
        let body = json!({
            "did": state.did.to_string(),
            "handle": identity.handle.clone(),
            "repoName": repo_name,
            "head": state.latest_commit.to_string(),
            "rev": state.latest_rev.to_string(),
            "active": true,
        });
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
}

#[derive(Debug, Deserialize)]
struct WriteRecordRequest {
    path: String,
    rev: String,
    record: Value,
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

fn health_response() -> worker::Result<Response> {
    json_response(
        200,
        &json!({
            "version": env!("CARGO_PKG_VERSION"),
            "status": "ok",
        }),
    )
}

fn describe_server(_url: &worker::Url) -> worker::Result<Response> {
    json_response(
        200,
        &json!({
            "did": "did:gsv:pds",
            "availableUserDomains": [],
            "inviteCodeRequired": false,
            "phoneVerificationRequired": false,
            "links": {},
            "contact": {},
        }),
    )
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

fn json_response(status: u16, value: &impl Serialize) -> worker::Result<Response> {
    let mut response = Response::from_json(value)?.with_status(status);
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
        "authorization, content-type, x-pds-admin-token",
    )?;
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
