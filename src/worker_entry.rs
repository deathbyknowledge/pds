use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use worker::{
    durable_object, event, Context, DurableObject, Env, Method, Request, Response, SqlStorage,
    State,
};

use crate::commit::{CommitSigner, Did, RepoRev};
use crate::data_model::{Nsid, RepoPath};
use crate::do_store::{RepoStateRow, SqlRepoStore};
use crate::repo::{RepoError, RepoMutation, SignedRepository};

#[event(fetch)]
async fn fetch(req: Request, env: worker::Env, _ctx: Context) -> worker::Result<Response> {
    let url = req.url()?;
    let parts = url
        .path()
        .trim_start_matches('/')
        .split('/')
        .collect::<Vec<_>>();

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
                "recordList": "GET /repos/:name/records?collection=nsid"
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

    fn status(&self) -> Result<Response, HttpError> {
        let store = self.store();
        let state = store.get_repo_state().map_err(HttpError::worker)?;
        let blocks = store.block_count().map_err(HttpError::worker)?;
        let records = store.record_count().map_err(HttpError::worker)?;

        json_response(
            200,
            &json!({
                "initialized": state.is_some(),
                "did": state.as_ref().map(|row| row.did.to_string()),
                "latestCommit": state.as_ref().map(|row| row.latest_commit.to_string()),
                "latestRev": state.as_ref().map(|row| row.latest_rev.to_string()),
                "blocks": blocks,
                "records": records,
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn init(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: InitRepoRequest = req.json().await.map_err(HttpError::worker)?;
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
        let repo = SignedRepository::create(store, did.clone(), rev.clone(), &DevSigner)
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

        json_response(
            201,
            &json!({
                "did": state.did.to_string(),
                "latestCommit": state.latest_commit.to_string(),
                "latestRev": state.latest_rev.to_string(),
                "mstRoot": repo.mst_root().to_string(),
            }),
        )
        .map_err(HttpError::worker)
    }

    async fn create_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: WriteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        let mut repo = self.open_repo()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .create_record(path.clone(), &body.record, rev, &DevSigner)
            .await
            .map_err(HttpError::repo)?;
        self.persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        json_response(201, &mutation_response(&path, &mutation)).map_err(HttpError::worker)
    }

    async fn update_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: WriteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        let mut repo = self.open_repo()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .update_record(path.clone(), &body.record, rev, &DevSigner)
            .await
            .map_err(HttpError::repo)?;
        self.persist_mutation(repo.storage(), &mutation)
            .map_err(HttpError::worker)?;
        json_response(200, &mutation_response(&path, &mutation)).map_err(HttpError::worker)
    }

    async fn delete_record(&self, req: &mut Request) -> Result<Response, HttpError> {
        let body: DeleteRecordRequest = req.json().await.map_err(HttpError::worker)?;
        let mut repo = self.open_repo()?;
        let path = RepoPath::parse(&body.path).map_err(HttpError::bad_request)?;
        let rev = RepoRev::new(body.rev).map_err(HttpError::bad_request)?;
        let mutation = repo
            .delete_record(&path, rev, &DevSigner)
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
        let store = self.store();
        let Some(state) = store.get_repo_state().map_err(HttpError::worker)? else {
            return Err(HttpError::new(404, "repo not initialized"));
        };
        SignedRepository::open(store, state.latest_commit).map_err(HttpError::repo)
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
    rev: String,
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
struct DevSigner;

impl CommitSigner for DevSigner {
    fn sign_commit(&self, signable_bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut hasher = Sha256::new();
        hasher.update(b"gsv-pds-dev-signer");
        hasher.update(signable_bytes);
        Ok(hasher.finalize().to_vec())
    }
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
    headers.set("Access-Control-Allow-Headers", "content-type")?;
    Ok(())
}
