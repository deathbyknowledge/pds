use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use worker::{
    durable_object, event, Context, DurableObject, Env, Method, Request, Response, SqlStorage,
    State,
};

use crate::car::{encode_car_from_store, CarError};
use crate::cid::parse_cid;
use crate::commit::{Did, RepoRev};
use crate::data_model::{Nsid, RecordKey, RepoPath};
use crate::do_store::{RepoIdentityRow, RepoStateRow, SqlRepoStore};
use crate::identity::{IdentityError, RepoSigningKey};
use crate::repo::{RepoError, RepoMutation, SignedRepository};
use crate::xrpc::{
    at_uri, optional_param, parse_list_records_params, required_param, route_xrpc_method,
    REPO_DESCRIBE_REPO, REPO_GET_RECORD, REPO_LIST_RECORDS, SERVER_DESCRIBE_SERVER,
    SYNC_GET_LATEST_COMMIT, SYNC_GET_RECORD, SYNC_GET_REPO, SYNC_GET_REPO_STATUS,
};
use crate::xrpc::{XrpcError, XrpcRoute};

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

    if req.method() == Method::Get && url.path() == "/.well-known/did.json" {
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
                "xrpcSyncGetRecord": "GET /xrpc/com.atproto.sync.getRecord?did=:did&collection=:nsid&rkey=:rkey",
                "xrpcSyncGetRepo": "GET /xrpc/com.atproto.sync.getRepo?did=:did",
                "didWeb": "GET /.well-known/did.json"
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
        if req.method() == Method::Get && url.path() == "/.well-known/did.json" {
            return self.did_document_response(&url);
        }

        if parts.len() >= 2 && parts[0] == "xrpc" && !parts[1].is_empty() {
            return self.handle_xrpc(req.method(), parts[1], &url).await;
        }

        let action = parts.get(2).copied().unwrap_or("");

        match (req.method(), action) {
            (Method::Get, "status") => self.status(),
            (Method::Post, "init") => self.init(req).await,
            (Method::Post, "records") => self.create_record(req).await,
            (Method::Put, "records") => self.update_record(req).await,
            (Method::Delete, "records") => self.delete_record(req).await,
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

    async fn init(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: InitRepoRequest = req.json().await.map_err(HttpError::worker)?;
        self.require_admin(req)?;
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

    async fn create_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: WriteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        self.require_admin(req)?;
        let (signing_key, mut repo) = self.open_repo_for_write()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .create_record(path.clone(), &body.record, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        self.persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        json_response(201, &mutation_response(&path, &mutation)).map_err(HttpError::worker)
    }

    async fn update_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: WriteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        self.require_admin(req)?;
        let (signing_key, mut repo) = self.open_repo_for_write()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .update_record(path.clone(), &body.record, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        self.persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        json_response(200, &mutation_response(&path, &mutation)).map_err(HttpError::worker)
    }

    async fn delete_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: DeleteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        self.require_admin(req)?;
        let (signing_key, mut repo) = self.open_repo_for_write()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .delete_record(&path, rev, &signing_key)
            .await
            .map_err(HttpError::repo)?;
        self.persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
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
    ) -> Result<(RepoSigningKey, SignedRepository<SqlRepoStore>), HttpError> {
        let (_, identity, repo) = self.open_repo_with_identity()?;
        let signing_key = identity.signing_key().map_err(HttpError::identity)?;
        Ok((signing_key, repo))
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

    fn persist_mutation(
        &self,
        store: &SqlRepoStore,
        mutation: &RepoMutation,
    ) -> worker::Result<()> {
        store.put_repo_state(&RepoStateRow {
            did: mutation.commit.did.clone(),
            latest_commit: mutation.commit_cid,
            latest_rev: mutation.commit.rev.clone(),
        })
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

fn query_pairs(url: &worker::Url) -> Vec<(String, String)> {
    url.query_pairs()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
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
