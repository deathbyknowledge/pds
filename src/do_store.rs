//! Durable Object SQLite storage adapter.

use serde::Deserialize;
use worker::{Error as WorkerError, SqlStorage, SqlStorageValue};

use crate::cid::{parse_cid, raw_cid, verify_repo_block_cid, Cid};
use crate::commit::{Did, RepoRev};
use crate::data_model::{Nsid, RepoPath};
use crate::do_schema::{ALL_SCHEMA_STATEMENTS, DIRECTORY_SCHEMA_STATEMENTS};
use crate::identity::{IdentityError, RepoSigningKey};
use crate::storage::{RepoBlockStore, RepoRecordIndex, StorageError};

#[derive(Clone, Debug)]
pub struct SqlRepoStore {
    sql: SqlStorage,
}

#[derive(Clone, Debug)]
pub struct SqlDirectoryStore {
    sql: SqlStorage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoStateRow {
    pub did: Did,
    pub latest_commit: Cid,
    pub latest_rev: RepoRev,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoIdentityRow {
    pub handle: String,
    pub signing_key_p256_hex: String,
    pub public_key_multibase: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryRepoRow {
    pub did: Did,
    pub handle: String,
    pub repo_name: String,
    pub head: Cid,
    pub rev: RepoRev,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryCommitEventInput {
    pub did: Did,
    pub commit_cid: Cid,
    pub rev: RepoRev,
    pub since: Option<RepoRev>,
    pub blocks: Vec<u8>,
    pub ops_json: String,
    pub blobs_json: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryEventRow {
    pub seq: i64,
    pub did: Did,
    pub event_type: String,
    pub commit_cid: Option<Cid>,
    pub rev: Option<RepoRev>,
    pub since: Option<RepoRev>,
    pub blocks: Option<Vec<u8>>,
    pub ops_json: String,
    pub blobs_json: String,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoBlobRow {
    pub cid: Cid,
    pub mime_type: String,
    pub bytes: Vec<u8>,
}

impl RepoIdentityRow {
    pub fn signing_key(&self) -> Result<RepoSigningKey, IdentityError> {
        RepoSigningKey::from_p256_hex(&self.signing_key_p256_hex)
    }
}

impl SqlRepoStore {
    pub fn new(sql: SqlStorage) -> Self {
        Self { sql }
    }

    pub fn init_schema(&self) -> worker::Result<()> {
        for statement in ALL_SCHEMA_STATEMENTS {
            self.sql.exec(statement, None)?;
        }
        Ok(())
    }

    pub fn get_repo_state(&self) -> worker::Result<Option<RepoStateRow>> {
        #[derive(Deserialize)]
        struct Row {
            did: String,
            latest_commit: String,
            latest_rev: String,
        }

        let rows: Vec<Row> = self
            .sql
            .exec(
                "SELECT did, latest_commit, latest_rev FROM repo_state WHERE id = 1",
                None,
            )?
            .to_array()?;

        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };

        Ok(Some(RepoStateRow {
            did: Did::new(row.did).map_err(worker_error)?,
            latest_commit: parse_cid(&row.latest_commit).map_err(worker_error)?,
            latest_rev: RepoRev::new(row.latest_rev).map_err(worker_error)?,
        }))
    }

    pub fn put_repo_state(&self, row: &RepoStateRow) -> worker::Result<()> {
        self.sql.exec(
            "INSERT INTO repo_state (id, did, latest_commit, latest_rev)
             VALUES (1, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                did = excluded.did,
                latest_commit = excluded.latest_commit,
                latest_rev = excluded.latest_rev",
            vec![
                SqlStorageValue::from(row.did.to_string()),
                SqlStorageValue::from(row.latest_commit.to_string()),
                SqlStorageValue::from(row.latest_rev.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn get_repo_identity(&self) -> worker::Result<Option<RepoIdentityRow>> {
        #[derive(Deserialize)]
        struct Row {
            handle: String,
            signing_key_p256_hex: String,
            public_key_multibase: String,
        }

        let rows: Vec<Row> = self
            .sql
            .exec(
                "SELECT handle, signing_key_p256_hex, public_key_multibase
                 FROM repo_identity
                 WHERE id = 1",
                None,
            )?
            .to_array()?;

        Ok(rows.into_iter().next().map(|row| RepoIdentityRow {
            handle: row.handle,
            signing_key_p256_hex: row.signing_key_p256_hex,
            public_key_multibase: row.public_key_multibase,
        }))
    }

    pub fn put_repo_identity(&self, row: &RepoIdentityRow) -> worker::Result<()> {
        self.sql.exec(
            "INSERT INTO repo_identity (id, handle, signing_key_p256_hex, public_key_multibase)
             VALUES (1, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                handle = excluded.handle,
                signing_key_p256_hex = excluded.signing_key_p256_hex,
                public_key_multibase = excluded.public_key_multibase",
            vec![
                SqlStorageValue::from(row.handle.clone()),
                SqlStorageValue::from(row.signing_key_p256_hex.clone()),
                SqlStorageValue::from(row.public_key_multibase.clone()),
            ],
        )?;
        Ok(())
    }

    pub fn block_count(&self) -> worker::Result<i64> {
        count(&self.sql, "SELECT COUNT(*) AS n FROM repo_blocks")
    }

    pub fn record_count(&self) -> worker::Result<i64> {
        count(&self.sql, "SELECT COUNT(*) AS n FROM record_index")
    }

    pub fn clear_all(&self) -> worker::Result<()> {
        self.sql.exec("DELETE FROM record_index", None)?;
        self.sql.exec("DELETE FROM repo_blobs", None)?;
        self.sql.exec("DELETE FROM repo_blocks", None)?;
        self.sql.exec("DELETE FROM repo_identity", None)?;
        self.sql.exec("DELETE FROM repo_state", None)?;
        Ok(())
    }

    pub fn put_blob(&self, mime_type: &str, bytes: Vec<u8>) -> worker::Result<RepoBlobRow> {
        let cid = raw_cid(&bytes);
        self.sql.exec(
            "INSERT OR IGNORE INTO repo_blobs (cid, mime_type, bytes, byte_len)
             VALUES (?, ?, ?, ?)",
            vec![
                SqlStorageValue::from(cid.to_string()),
                SqlStorageValue::from(mime_type.to_string()),
                SqlStorageValue::Blob(bytes.clone()),
                SqlStorageValue::from(bytes.len() as i64),
            ],
        )?;

        Ok(RepoBlobRow {
            cid,
            mime_type: mime_type.to_string(),
            bytes,
        })
    }

    pub fn get_blob(&self, cid: &Cid) -> worker::Result<Option<RepoBlobRow>> {
        #[derive(Deserialize)]
        struct Row {
            mime_type: String,
        }

        let rows: Vec<Row> = self
            .sql
            .exec(
                "SELECT mime_type FROM repo_blobs WHERE cid = ?",
                vec![SqlStorageValue::from(cid.to_string())],
            )?
            .to_array()?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };

        let cursor = self.sql.exec(
            "SELECT bytes FROM repo_blobs WHERE cid = ?",
            vec![SqlStorageValue::from(cid.to_string())],
        )?;
        let Some(raw_row) = cursor.raw().next() else {
            return Ok(None);
        };
        let values = raw_row?;
        let Some(SqlStorageValue::Blob(bytes)) = values.into_iter().next() else {
            return Err(worker_error(std::io::Error::other(
                "blob query returned non-blob bytes",
            )));
        };

        Ok(Some(RepoBlobRow {
            cid: *cid,
            mime_type: row.mime_type,
            bytes,
        }))
    }

    pub fn list_blob_cids(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> worker::Result<(Vec<Cid>, Option<String>)> {
        #[derive(Deserialize)]
        struct Row {
            cid: String,
        }

        let query_limit = limit.saturating_add(1);
        let rows: Vec<Row> = if let Some(cursor) = cursor {
            self.sql
                .exec(
                    "SELECT cid FROM repo_blobs
                     WHERE cid > ?
                     ORDER BY cid ASC
                     LIMIT ?",
                    vec![
                        SqlStorageValue::from(cursor.to_string()),
                        SqlStorageValue::from(query_limit as i64),
                    ],
                )?
                .to_array()?
        } else {
            self.sql
                .exec(
                    "SELECT cid FROM repo_blobs
                     ORDER BY cid ASC
                     LIMIT ?",
                    vec![SqlStorageValue::from(query_limit as i64)],
                )?
                .to_array()?
        };

        let has_more = rows.len() > limit;
        let cids = rows
            .into_iter()
            .take(limit)
            .map(|row| parse_cid(&row.cid).map_err(worker_error))
            .collect::<worker::Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            cids.last().map(|cid| cid.to_string())
        } else {
            None
        };

        Ok((cids, next_cursor))
    }
}

impl SqlDirectoryStore {
    pub fn new(sql: SqlStorage) -> Self {
        Self { sql }
    }

    pub fn init_schema(&self) -> worker::Result<()> {
        for statement in DIRECTORY_SCHEMA_STATEMENTS {
            self.sql.exec(statement, None)?;
        }
        for statement in [
            "ALTER TABLE directory_events ADD COLUMN since TEXT",
            "ALTER TABLE directory_events ADD COLUMN blocks BLOB",
            "ALTER TABLE directory_events ADD COLUMN ops_json TEXT NOT NULL DEFAULT '[]'",
            "ALTER TABLE directory_events ADD COLUMN blobs_json TEXT NOT NULL DEFAULT '[]'",
        ] {
            exec_ignore_duplicate_column(&self.sql, statement)?;
        }
        Ok(())
    }

    pub fn upsert_repo(&self, row: &DirectoryRepoRow) -> worker::Result<()> {
        self.sql.exec(
            "INSERT INTO directory_repos (did, handle, repo_name, head, rev, active, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, unixepoch())
             ON CONFLICT(did) DO UPDATE SET
                handle = excluded.handle,
                repo_name = excluded.repo_name,
                head = excluded.head,
                rev = excluded.rev,
                active = excluded.active,
                updated_at = excluded.updated_at",
            vec![
                SqlStorageValue::from(row.did.to_string()),
                SqlStorageValue::from(row.handle.clone()),
                SqlStorageValue::from(row.repo_name.clone()),
                SqlStorageValue::from(row.head.to_string()),
                SqlStorageValue::from(row.rev.to_string()),
                SqlStorageValue::from(if row.active { 1_i64 } else { 0_i64 }),
            ],
        )?;

        Ok(())
    }

    pub fn append_commit_event(
        &self,
        event: &DirectoryCommitEventInput,
    ) -> worker::Result<DirectoryEventRow> {
        self.sql.exec(
            "INSERT INTO directory_events (
                did, event_type, commit_cid, rev, since, blocks, ops_json, blobs_json
             )
             VALUES (?, 'commit', ?, ?, ?, ?, ?, ?)",
            vec![
                SqlStorageValue::from(event.did.to_string()),
                SqlStorageValue::from(event.commit_cid.to_string()),
                SqlStorageValue::from(event.rev.to_string()),
                optional_text(event.since.as_ref().map(|rev| rev.to_string())),
                SqlStorageValue::Blob(event.blocks.clone()),
                SqlStorageValue::from(event.ops_json.clone()),
                SqlStorageValue::from(event.blobs_json.clone()),
            ],
        )?;

        let seq = last_insert_rowid(&self.sql)?;
        self.get_event(seq)?.ok_or_else(|| {
            worker_error(std::io::Error::other("inserted directory event not found"))
        })
    }

    pub fn max_event_seq(&self) -> worker::Result<i64> {
        count(
            &self.sql,
            "SELECT COALESCE(MAX(seq), 0) AS n FROM directory_events",
        )
    }

    pub fn list_events_after(
        &self,
        cursor: i64,
        limit: usize,
    ) -> worker::Result<Vec<DirectoryEventRow>> {
        let rows = self.sql.exec(
            "SELECT seq, did, event_type, commit_cid, rev, since, blocks, ops_json, blobs_json,
                    strftime('%Y-%m-%dT%H:%M:%SZ', created_at, 'unixepoch') AS created_at
                 FROM directory_events
                 WHERE seq > ? AND event_type = 'commit'
                 ORDER BY seq ASC
                 LIMIT ?",
            vec![
                SqlStorageValue::from(cursor),
                SqlStorageValue::from(limit as i64),
            ],
        )?;

        rows.raw()
            .map(|row| directory_event_from_values(row?))
            .collect()
    }

    fn get_event(&self, seq: i64) -> worker::Result<Option<DirectoryEventRow>> {
        let rows = self.sql.exec(
            "SELECT seq, did, event_type, commit_cid, rev, since, blocks, ops_json, blobs_json,
                strftime('%Y-%m-%dT%H:%M:%SZ', created_at, 'unixepoch') AS created_at
             FROM directory_events
             WHERE seq = ?",
            vec![SqlStorageValue::from(seq)],
        )?;

        let Some(row) = rows.raw().next() else {
            return Ok(None);
        };
        Ok(Some(directory_event_from_values(row?)?))
    }

    pub fn list_repos(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> worker::Result<(Vec<DirectoryRepoRow>, Option<String>)> {
        let query_limit = limit.saturating_add(1);
        let rows: Vec<DirectoryRepoStorageRow> = if let Some(cursor) = cursor {
            self.sql
                .exec(
                    "SELECT did, handle, repo_name, head, rev, active
                     FROM directory_repos
                     WHERE did > ?
                     ORDER BY did ASC
                     LIMIT ?",
                    vec![
                        SqlStorageValue::from(cursor.to_string()),
                        SqlStorageValue::from(query_limit as i64),
                    ],
                )?
                .to_array()?
        } else {
            self.sql
                .exec(
                    "SELECT did, handle, repo_name, head, rev, active
                     FROM directory_repos
                     ORDER BY did ASC
                     LIMIT ?",
                    vec![SqlStorageValue::from(query_limit as i64)],
                )?
                .to_array()?
        };

        let has_more = rows.len() > limit;
        let repos = rows
            .into_iter()
            .take(limit)
            .map(directory_repo_from_row)
            .collect::<worker::Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            repos.last().map(|repo| repo.did.to_string())
        } else {
            None
        };

        Ok((repos, next_cursor))
    }

    pub fn repo_count(&self) -> worker::Result<i64> {
        count(&self.sql, "SELECT COUNT(*) AS n FROM directory_repos")
    }

    pub fn event_count(&self) -> worker::Result<i64> {
        count(&self.sql, "SELECT COUNT(*) AS n FROM directory_events")
    }
}

impl RepoBlockStore for SqlRepoStore {
    fn put_block_with_cid(&mut self, cid: Cid, bytes: Vec<u8>) -> Result<(), StorageError> {
        verify_repo_block_cid(&cid, &bytes)?;
        self.sql
            .exec(
                "INSERT OR IGNORE INTO repo_blocks (cid, bytes, byte_len)
                 VALUES (?, ?, ?)",
                vec![
                    SqlStorageValue::from(cid.to_string()),
                    SqlStorageValue::Blob(bytes.clone()),
                    SqlStorageValue::from(bytes.len() as i64),
                ],
            )
            .map_err(storage_error)?;
        Ok(())
    }

    fn get_block(&self, cid: &Cid) -> Result<Option<Vec<u8>>, StorageError> {
        let cursor = self
            .sql
            .exec(
                "SELECT bytes FROM repo_blocks WHERE cid = ?",
                vec![SqlStorageValue::from(cid.to_string())],
            )
            .map_err(storage_error)?;

        let Some(row) = cursor.raw().next() else {
            return Ok(None);
        };
        let values = row.map_err(storage_error)?;
        match values.into_iter().next() {
            Some(SqlStorageValue::Blob(bytes)) => Ok(Some(bytes)),
            Some(other) => Err(StorageError::Backend(format!(
                "expected repo block bytes, got {other:?}"
            ))),
            None => Err(StorageError::Backend(
                "repo block query returned an empty row".to_string(),
            )),
        }
    }
}

impl RepoRecordIndex for SqlRepoStore {
    fn put_record_pointer(
        &mut self,
        path: RepoPath,
        cid: Cid,
    ) -> Result<Option<Cid>, StorageError> {
        let previous = self.get_record_pointer(&path)?;
        self.sql
            .exec(
                "INSERT INTO record_index (path, collection, rkey, cid, updated_at)
                 VALUES (?, ?, ?, ?, unixepoch())
                 ON CONFLICT(path) DO UPDATE SET
                    collection = excluded.collection,
                    rkey = excluded.rkey,
                    cid = excluded.cid,
                    updated_at = excluded.updated_at",
                vec![
                    SqlStorageValue::from(path.as_mst_key()),
                    SqlStorageValue::from(path.collection.to_string()),
                    SqlStorageValue::from(path.rkey.to_string()),
                    SqlStorageValue::from(cid.to_string()),
                ],
            )
            .map_err(storage_error)?;
        Ok(previous)
    }

    fn get_record_pointer(&self, path: &RepoPath) -> Result<Option<Cid>, StorageError> {
        #[derive(Deserialize)]
        struct Row {
            cid: String,
        }

        let rows: Vec<Row> = self
            .sql
            .exec(
                "SELECT cid FROM record_index WHERE path = ?",
                vec![SqlStorageValue::from(path.as_mst_key())],
            )
            .map_err(storage_error)?
            .to_array()
            .map_err(storage_error)?;

        rows.into_iter()
            .next()
            .map(|row| parse_cid(&row.cid).map_err(StorageError::from))
            .transpose()
    }

    fn delete_record_pointer(&mut self, path: &RepoPath) -> Result<Option<Cid>, StorageError> {
        let previous = self.get_record_pointer(path)?;
        self.sql
            .exec(
                "DELETE FROM record_index WHERE path = ?",
                vec![SqlStorageValue::from(path.as_mst_key())],
            )
            .map_err(storage_error)?;
        Ok(previous)
    }

    fn list_record_pointers(
        &self,
        collection: &Nsid,
    ) -> Result<Vec<(RepoPath, Cid)>, StorageError> {
        #[derive(Deserialize)]
        struct Row {
            path: String,
            cid: String,
        }

        let rows: Vec<Row> = self
            .sql
            .exec(
                "SELECT path, cid FROM record_index
                 WHERE collection = ?
                 ORDER BY path ASC",
                vec![SqlStorageValue::from(collection.to_string())],
            )
            .map_err(storage_error)?
            .to_array()
            .map_err(storage_error)?;

        rows.into_iter()
            .map(|row| Ok((RepoPath::parse(&row.path)?, parse_cid(&row.cid)?)))
            .collect()
    }
}

fn directory_repo_from_row<Row>(row: Row) -> worker::Result<DirectoryRepoRow>
where
    Row: IntoDirectoryRepoRow,
{
    row.into_directory_repo_row()
}

trait IntoDirectoryRepoRow {
    fn into_directory_repo_row(self) -> worker::Result<DirectoryRepoRow>;
}

impl IntoDirectoryRepoRow for DirectoryRepoStorageRow {
    fn into_directory_repo_row(self) -> worker::Result<DirectoryRepoRow> {
        Ok(DirectoryRepoRow {
            did: Did::new(self.did).map_err(worker_error)?,
            handle: self.handle,
            repo_name: self.repo_name,
            head: parse_cid(&self.head).map_err(worker_error)?,
            rev: RepoRev::new(self.rev).map_err(worker_error)?,
            active: self.active != 0,
        })
    }
}

#[derive(Deserialize)]
struct DirectoryRepoStorageRow {
    did: String,
    handle: String,
    repo_name: String,
    head: String,
    rev: String,
    active: i64,
}

fn worker_error(error: impl std::error::Error) -> WorkerError {
    WorkerError::RustError(error.to_string())
}

fn exec_ignore_duplicate_column(sql: &SqlStorage, statement: &str) -> worker::Result<()> {
    match sql.exec(statement, None) {
        Ok(_) => Ok(()),
        Err(error) if error.to_string().contains("duplicate column name") => Ok(()),
        Err(error) => Err(error),
    }
}

fn optional_text(value: Option<String>) -> SqlStorageValue {
    value
        .map(SqlStorageValue::from)
        .unwrap_or(SqlStorageValue::Null)
}

fn last_insert_rowid(sql: &SqlStorage) -> worker::Result<i64> {
    #[derive(Deserialize)]
    struct Row {
        n: i64,
    }

    let row: Row = sql.exec("SELECT last_insert_rowid() AS n", None)?.one()?;
    Ok(row.n)
}

fn directory_event_from_values(values: Vec<SqlStorageValue>) -> worker::Result<DirectoryEventRow> {
    let mut values = values.into_iter();
    let seq = next_i64(&mut values, "seq")?;
    let did = Did::new(next_string(&mut values, "did")?).map_err(worker_error)?;
    let event_type = next_string(&mut values, "event_type")?;
    let commit_cid = next_optional_string(&mut values, "commit_cid")?
        .map(|value| parse_cid(&value).map_err(worker_error))
        .transpose()?;
    let rev = next_optional_string(&mut values, "rev")?
        .map(|value| RepoRev::new(value).map_err(worker_error))
        .transpose()?;
    let since = next_optional_string(&mut values, "since")?
        .map(|value| RepoRev::new(value).map_err(worker_error))
        .transpose()?;
    let blocks = next_optional_blob(&mut values, "blocks")?;
    let ops_json = next_string(&mut values, "ops_json")?;
    let blobs_json = next_string(&mut values, "blobs_json")?;
    let created_at = next_string(&mut values, "created_at")?;

    Ok(DirectoryEventRow {
        seq,
        did,
        event_type,
        commit_cid,
        rev,
        since,
        blocks,
        ops_json,
        blobs_json,
        created_at,
    })
}

fn next_i64(values: &mut impl Iterator<Item = SqlStorageValue>, name: &str) -> worker::Result<i64> {
    match values.next() {
        Some(SqlStorageValue::Integer(value)) => Ok(value),
        Some(other) => Err(worker_error(std::io::Error::other(format!(
            "expected integer column `{name}`, got {other:?}"
        )))),
        None => Err(worker_error(std::io::Error::other(format!(
            "missing column `{name}`"
        )))),
    }
}

fn next_string(
    values: &mut impl Iterator<Item = SqlStorageValue>,
    name: &str,
) -> worker::Result<String> {
    match values.next() {
        Some(SqlStorageValue::String(value)) => Ok(value),
        Some(other) => Err(worker_error(std::io::Error::other(format!(
            "expected string column `{name}`, got {other:?}"
        )))),
        None => Err(worker_error(std::io::Error::other(format!(
            "missing column `{name}`"
        )))),
    }
}

fn next_optional_string(
    values: &mut impl Iterator<Item = SqlStorageValue>,
    name: &str,
) -> worker::Result<Option<String>> {
    match values.next() {
        Some(SqlStorageValue::String(value)) => Ok(Some(value)),
        Some(SqlStorageValue::Null) => Ok(None),
        Some(other) => Err(worker_error(std::io::Error::other(format!(
            "expected optional string column `{name}`, got {other:?}"
        )))),
        None => Err(worker_error(std::io::Error::other(format!(
            "missing column `{name}`"
        )))),
    }
}

fn next_optional_blob(
    values: &mut impl Iterator<Item = SqlStorageValue>,
    name: &str,
) -> worker::Result<Option<Vec<u8>>> {
    match values.next() {
        Some(SqlStorageValue::Blob(value)) => Ok(Some(value)),
        Some(SqlStorageValue::Null) => Ok(None),
        Some(other) => Err(worker_error(std::io::Error::other(format!(
            "expected optional blob column `{name}`, got {other:?}"
        )))),
        None => Err(worker_error(std::io::Error::other(format!(
            "missing column `{name}`"
        )))),
    }
}

fn storage_error(error: WorkerError) -> StorageError {
    StorageError::Backend(error.to_string())
}

fn count(sql: &SqlStorage, query: &str) -> worker::Result<i64> {
    #[derive(Deserialize)]
    struct Row {
        n: i64,
    }

    let row: Row = sql.exec(query, None)?.one()?;
    Ok(row.n)
}
