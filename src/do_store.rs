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
pub struct DirectoryAccountRow {
    pub did: Did,
    pub handle: String,
    pub email: Option<String>,
    pub password_hash: String,
    pub repo_name: String,
    pub public_key_multibase: String,
    pub active: bool,
    pub status: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectorySessionRow {
    pub session_id: String,
    pub did: Did,
    pub refresh_jti: String,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoBlobRow {
    pub cid: Cid,
    pub mime_type: String,
    pub bytes: Vec<u8>,
    pub byte_len: i64,
    pub storage_kind: String,
    pub storage_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoBlobRefRow {
    pub path: RepoPath,
    pub cid: Cid,
    pub record_cid: Cid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoCommitEventInput {
    pub rev: RepoRev,
    pub since: Option<RepoRev>,
    pub commit_cid: Cid,
    pub blocks: Vec<u8>,
    pub ops_json: String,
    pub blobs_json: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoCommitEventRow {
    pub seq: i64,
    pub rev: RepoRev,
    pub since: Option<RepoRev>,
    pub commit_cid: Cid,
    pub blocks: Vec<u8>,
    pub ops_json: String,
    pub blobs_json: String,
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
        for statement in [
            "ALTER TABLE repo_blobs ADD COLUMN storage_kind TEXT NOT NULL DEFAULT 'sqlite'",
            "ALTER TABLE repo_blobs ADD COLUMN storage_key TEXT",
        ] {
            exec_ignore_duplicate_column(&self.sql, statement)?;
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
        self.sql.exec("DELETE FROM repo_blob_refs", None)?;
        self.sql.exec("DELETE FROM repo_commit_events", None)?;
        self.sql.exec("DELETE FROM repo_blobs", None)?;
        self.sql.exec("DELETE FROM repo_blocks", None)?;
        self.sql.exec("DELETE FROM repo_identity", None)?;
        self.sql.exec("DELETE FROM repo_state", None)?;
        Ok(())
    }

    pub fn clear_repo_data_for_import(&self) -> worker::Result<()> {
        self.sql.exec("DELETE FROM record_index", None)?;
        self.sql.exec("DELETE FROM repo_blob_refs", None)?;
        self.sql.exec("DELETE FROM repo_commit_events", None)?;
        self.sql.exec("DELETE FROM repo_blocks", None)?;
        self.sql.exec("DELETE FROM repo_state", None)?;
        Ok(())
    }

    pub fn put_blob_bytes(&self, mime_type: &str, bytes: Vec<u8>) -> worker::Result<RepoBlobRow> {
        let cid = raw_cid(&bytes);
        self.sql.exec(
            "INSERT OR IGNORE INTO repo_blobs (
                cid, mime_type, bytes, byte_len, storage_kind, storage_key
             )
             VALUES (?, ?, ?, ?, 'sqlite', NULL)",
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
            byte_len: bytes.len() as i64,
            bytes,
            storage_kind: "sqlite".to_string(),
            storage_key: None,
        })
    }

    pub fn put_blob_metadata(
        &self,
        cid: Cid,
        mime_type: &str,
        byte_len: usize,
        storage_kind: &str,
        storage_key: Option<&str>,
    ) -> worker::Result<RepoBlobRow> {
        self.sql.exec(
            "INSERT INTO repo_blobs (
                cid, mime_type, bytes, byte_len, storage_kind, storage_key
             )
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(cid) DO UPDATE SET
                mime_type = excluded.mime_type,
                byte_len = excluded.byte_len,
                storage_kind = excluded.storage_kind,
                storage_key = excluded.storage_key",
            vec![
                SqlStorageValue::from(cid.to_string()),
                SqlStorageValue::from(mime_type.to_string()),
                SqlStorageValue::Blob(Vec::new()),
                SqlStorageValue::from(byte_len as i64),
                SqlStorageValue::from(storage_kind.to_string()),
                optional_text(storage_key.map(|key| key.to_string())),
            ],
        )?;

        Ok(RepoBlobRow {
            cid,
            mime_type: mime_type.to_string(),
            bytes: Vec::new(),
            byte_len: byte_len as i64,
            storage_kind: storage_kind.to_string(),
            storage_key: storage_key.map(|key| key.to_string()),
        })
    }

    pub fn get_blob(&self, cid: &Cid) -> worker::Result<Option<RepoBlobRow>> {
        let cursor = self.sql.exec(
            "SELECT cid, mime_type, bytes, byte_len, storage_kind, storage_key
             FROM repo_blobs
             WHERE cid = ?",
            vec![SqlStorageValue::from(cid.to_string())],
        )?;
        let Some(raw_row) = cursor.raw().next() else {
            return Ok(None);
        };
        Ok(Some(repo_blob_from_values(raw_row?)?))
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

    pub fn replace_blob_refs(
        &self,
        path: &RepoPath,
        record_cid: Cid,
        blob_cids: &[Cid],
    ) -> worker::Result<()> {
        self.delete_blob_refs(path)?;
        for cid in blob_cids {
            self.sql.exec(
                "INSERT OR IGNORE INTO repo_blob_refs (path, cid, record_cid)
                 VALUES (?, ?, ?)",
                vec![
                    SqlStorageValue::from(path.as_mst_key()),
                    SqlStorageValue::from(cid.to_string()),
                    SqlStorageValue::from(record_cid.to_string()),
                ],
            )?;
        }
        Ok(())
    }

    pub fn delete_blob_refs(&self, path: &RepoPath) -> worker::Result<()> {
        self.sql.exec(
            "DELETE FROM repo_blob_refs WHERE path = ?",
            vec![SqlStorageValue::from(path.as_mst_key())],
        )?;
        Ok(())
    }

    pub fn list_missing_blob_refs(
        &self,
        limit: usize,
        cursor: Option<&str>,
    ) -> worker::Result<(Vec<RepoBlobRefRow>, Option<String>)> {
        let query_limit = limit.saturating_add(1);
        let rows = if let Some(cursor) = cursor {
            self.sql.exec(
                "SELECT refs.path, refs.cid, refs.record_cid
                 FROM repo_blob_refs refs
                 LEFT JOIN repo_blobs blobs ON blobs.cid = refs.cid
                 WHERE blobs.cid IS NULL AND (refs.path || ' ' || refs.cid) > ?
                 ORDER BY refs.path ASC, refs.cid ASC
                 LIMIT ?",
                vec![
                    SqlStorageValue::from(cursor.to_string()),
                    SqlStorageValue::from(query_limit as i64),
                ],
            )?
        } else {
            self.sql.exec(
                "SELECT refs.path, refs.cid, refs.record_cid
                 FROM repo_blob_refs refs
                 LEFT JOIN repo_blobs blobs ON blobs.cid = refs.cid
                 WHERE blobs.cid IS NULL
                 ORDER BY refs.path ASC, refs.cid ASC
                 LIMIT ?",
                vec![SqlStorageValue::from(query_limit as i64)],
            )?
        };

        let mut refs = Vec::new();
        for row in rows.raw() {
            refs.push(blob_ref_from_values(row?)?);
        }
        let has_more = refs.len() > limit;
        refs.truncate(limit);
        let next_cursor = if has_more {
            refs.last()
                .map(|row| format!("{} {}", row.path.as_mst_key(), row.cid))
        } else {
            None
        };
        Ok((refs, next_cursor))
    }

    pub fn append_commit_event(&self, event: &RepoCommitEventInput) -> worker::Result<()> {
        self.sql.exec(
            "INSERT INTO repo_commit_events (
                rev, since, commit_cid, blocks, ops_json, blobs_json
             )
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(rev) DO UPDATE SET
                since = excluded.since,
                commit_cid = excluded.commit_cid,
                blocks = excluded.blocks,
                ops_json = excluded.ops_json,
                blobs_json = excluded.blobs_json",
            vec![
                SqlStorageValue::from(event.rev.to_string()),
                optional_text(event.since.as_ref().map(|rev| rev.to_string())),
                SqlStorageValue::from(event.commit_cid.to_string()),
                SqlStorageValue::Blob(event.blocks.clone()),
                SqlStorageValue::from(event.ops_json.clone()),
                SqlStorageValue::from(event.blobs_json.clone()),
            ],
        )?;
        Ok(())
    }

    pub fn list_commit_events_after_rev(
        &self,
        since: &RepoRev,
    ) -> worker::Result<Vec<RepoCommitEventRow>> {
        let rows = self.sql.exec(
            "SELECT seq, rev, since, commit_cid, blocks, ops_json, blobs_json
             FROM repo_commit_events
             WHERE seq > (
                SELECT seq FROM repo_commit_events WHERE rev = ?
             )
             ORDER BY seq ASC",
            vec![SqlStorageValue::from(since.to_string())],
        )?;

        rows.raw()
            .map(|row| repo_commit_event_from_values(row?))
            .collect()
    }

    pub fn has_commit_event_rev(&self, rev: &RepoRev) -> worker::Result<bool> {
        let rows: Vec<CountRow> = self
            .sql
            .exec(
                "SELECT COUNT(*) AS n FROM repo_commit_events WHERE rev = ?",
                vec![SqlStorageValue::from(rev.to_string())],
            )?
            .to_array()?;
        Ok(rows.first().is_some_and(|row| row.n > 0))
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
            "ALTER TABLE directory_accounts ADD COLUMN email TEXT",
            "ALTER TABLE directory_accounts ADD COLUMN public_key_multibase TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE directory_accounts ADD COLUMN active INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE directory_accounts ADD COLUMN status TEXT",
        ] {
            exec_ignore_duplicate_column(&self.sql, statement)?;
        }
        Ok(())
    }

    pub fn insert_account(&self, row: &DirectoryAccountRow) -> worker::Result<()> {
        self.sql.exec(
            "INSERT INTO directory_accounts (
                did, handle, email, password_hash, repo_name, public_key_multibase, active, status
             )
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                SqlStorageValue::from(row.did.to_string()),
                SqlStorageValue::from(row.handle.clone()),
                optional_text(row.email.clone()),
                SqlStorageValue::from(row.password_hash.clone()),
                SqlStorageValue::from(row.repo_name.clone()),
                SqlStorageValue::from(row.public_key_multibase.clone()),
                SqlStorageValue::from(if row.active { 1_i64 } else { 0_i64 }),
                optional_text(row.status.clone()),
            ],
        )?;
        Ok(())
    }

    pub fn get_account_by_identifier(
        &self,
        identifier: &str,
    ) -> worker::Result<Option<DirectoryAccountRow>> {
        let rows: Vec<DirectoryAccountStorageRow> = self
            .sql
            .exec(
                "SELECT did, handle, email, password_hash, repo_name, public_key_multibase,
                        active, status
                 FROM directory_accounts
                 WHERE handle = ? OR did = ?
                 LIMIT 1",
                vec![
                    SqlStorageValue::from(identifier.to_string()),
                    SqlStorageValue::from(identifier.to_string()),
                ],
            )?
            .to_array()?;
        rows.into_iter()
            .next()
            .map(directory_account_from_row)
            .transpose()
    }

    pub fn get_account_by_did(&self, did: &Did) -> worker::Result<Option<DirectoryAccountRow>> {
        self.get_account_by_identifier(did.as_str())
    }

    pub fn append_account_event(
        &self,
        did: &Did,
        active: bool,
        status: Option<&str>,
    ) -> worker::Result<DirectoryEventRow> {
        self.sql.exec(
            "INSERT INTO directory_events (
                did, event_type, commit_cid, rev, since, blocks, ops_json, blobs_json
             )
             VALUES (?, 'account', NULL, NULL, NULL, NULL, ?, ?)",
            vec![
                SqlStorageValue::from(did.to_string()),
                SqlStorageValue::from("[]".to_string()),
                SqlStorageValue::from(
                    serde_json::to_string(&serde_json::json!({
                        "active": active,
                        "status": status,
                    }))
                    .map_err(worker_error)?,
                ),
            ],
        )?;
        let seq = last_insert_rowid(&self.sql)?;
        self.get_event(seq)?
            .ok_or_else(|| worker_error(std::io::Error::other("inserted account event not found")))
    }

    pub fn insert_session(&self, row: &DirectorySessionRow) -> worker::Result<()> {
        self.sql.exec(
            "INSERT INTO directory_sessions (session_id, did, refresh_jti, active)
             VALUES (?, ?, ?, ?)",
            vec![
                SqlStorageValue::from(row.session_id.clone()),
                SqlStorageValue::from(row.did.to_string()),
                SqlStorageValue::from(row.refresh_jti.clone()),
                SqlStorageValue::from(if row.active { 1_i64 } else { 0_i64 }),
            ],
        )?;
        Ok(())
    }

    pub fn get_session_by_refresh_jti(
        &self,
        refresh_jti: &str,
    ) -> worker::Result<Option<DirectorySessionRow>> {
        let rows: Vec<DirectorySessionStorageRow> = self
            .sql
            .exec(
                "SELECT session_id, did, refresh_jti, active
                 FROM directory_sessions
                 WHERE refresh_jti = ?
                 LIMIT 1",
                vec![SqlStorageValue::from(refresh_jti.to_string())],
            )?
            .to_array()?;
        rows.into_iter()
            .next()
            .map(directory_session_from_row)
            .transpose()
    }

    pub fn rotate_session_refresh(
        &self,
        session_id: &str,
        refresh_jti: &str,
    ) -> worker::Result<()> {
        self.sql.exec(
            "UPDATE directory_sessions
             SET refresh_jti = ?, updated_at = unixepoch()
             WHERE session_id = ? AND active = 1",
            vec![
                SqlStorageValue::from(refresh_jti.to_string()),
                SqlStorageValue::from(session_id.to_string()),
            ],
        )?;
        Ok(())
    }

    pub fn delete_session_by_refresh_jti(&self, refresh_jti: &str) -> worker::Result<()> {
        self.sql.exec(
            "UPDATE directory_sessions
             SET active = 0, updated_at = unixepoch()
             WHERE refresh_jti = ?",
            vec![SqlStorageValue::from(refresh_jti.to_string())],
        )?;
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

    pub fn replace_repo_record_paths(&self, did: &Did, paths: &[RepoPath]) -> worker::Result<()> {
        self.sql.exec(
            "DELETE FROM directory_repo_records WHERE did = ?",
            vec![SqlStorageValue::from(did.to_string())],
        )?;
        self.upsert_repo_record_paths(did, paths)
    }

    pub fn upsert_repo_record_paths(&self, did: &Did, paths: &[RepoPath]) -> worker::Result<()> {
        for path in paths {
            self.sql.exec(
                "INSERT INTO directory_repo_records (did, path, collection, updated_at)
                 VALUES (?, ?, ?, unixepoch())
                 ON CONFLICT(did, path) DO UPDATE SET
                    collection = excluded.collection,
                    updated_at = excluded.updated_at",
                vec![
                    SqlStorageValue::from(did.to_string()),
                    SqlStorageValue::from(path.to_string()),
                    SqlStorageValue::from(path.collection.to_string()),
                ],
            )?;
        }
        Ok(())
    }

    pub fn delete_repo_record_paths(&self, did: &Did, paths: &[RepoPath]) -> worker::Result<()> {
        for path in paths {
            self.sql.exec(
                "DELETE FROM directory_repo_records WHERE did = ? AND path = ?",
                vec![
                    SqlStorageValue::from(did.to_string()),
                    SqlStorageValue::from(path.to_string()),
                ],
            )?;
        }
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
                 WHERE seq > ?
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

    pub fn list_repos_by_collection(
        &self,
        collection: &Nsid,
        limit: usize,
        cursor: Option<&str>,
    ) -> worker::Result<(Vec<Did>, Option<String>)> {
        #[derive(Deserialize)]
        struct Row {
            did: String,
        }

        let query_limit = limit.saturating_add(1);
        let rows: Vec<Row> = if let Some(cursor) = cursor {
            self.sql
                .exec(
                    "SELECT records.did
                     FROM directory_repo_records AS records
                     JOIN directory_repos AS repos ON repos.did = records.did
                     WHERE records.collection = ? AND records.did > ? AND repos.active = 1
                     GROUP BY records.did
                     ORDER BY records.did ASC
                     LIMIT ?",
                    vec![
                        SqlStorageValue::from(collection.to_string()),
                        SqlStorageValue::from(cursor.to_string()),
                        SqlStorageValue::from(query_limit as i64),
                    ],
                )?
                .to_array()?
        } else {
            self.sql
                .exec(
                    "SELECT records.did
                     FROM directory_repo_records AS records
                     JOIN directory_repos AS repos ON repos.did = records.did
                     WHERE records.collection = ? AND repos.active = 1
                     GROUP BY records.did
                     ORDER BY records.did ASC
                     LIMIT ?",
                    vec![
                        SqlStorageValue::from(collection.to_string()),
                        SqlStorageValue::from(query_limit as i64),
                    ],
                )?
                .to_array()?
        };

        let has_more = rows.len() > limit;
        let repos = rows
            .into_iter()
            .take(limit)
            .map(|row| Did::new(row.did).map_err(worker_error))
            .collect::<worker::Result<Vec<_>>>()?;
        let next_cursor = if has_more {
            repos.last().map(|did| did.to_string())
        } else {
            None
        };

        Ok((repos, next_cursor))
    }

    pub fn repo_count(&self) -> worker::Result<i64> {
        count(&self.sql, "SELECT COUNT(*) AS n FROM directory_repos")
    }

    pub fn account_count(&self) -> worker::Result<i64> {
        count(&self.sql, "SELECT COUNT(*) AS n FROM directory_accounts")
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

fn directory_account_from_row(
    row: DirectoryAccountStorageRow,
) -> worker::Result<DirectoryAccountRow> {
    Ok(DirectoryAccountRow {
        did: Did::new(row.did).map_err(worker_error)?,
        handle: row.handle,
        email: row.email,
        password_hash: row.password_hash,
        repo_name: row.repo_name,
        public_key_multibase: row.public_key_multibase,
        active: row.active != 0,
        status: row.status,
    })
}

fn directory_session_from_row(
    row: DirectorySessionStorageRow,
) -> worker::Result<DirectorySessionRow> {
    Ok(DirectorySessionRow {
        session_id: row.session_id,
        did: Did::new(row.did).map_err(worker_error)?,
        refresh_jti: row.refresh_jti,
        active: row.active != 0,
    })
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

#[derive(Deserialize)]
struct DirectoryAccountStorageRow {
    did: String,
    handle: String,
    email: Option<String>,
    password_hash: String,
    repo_name: String,
    public_key_multibase: String,
    active: i64,
    status: Option<String>,
}

#[derive(Deserialize)]
struct DirectorySessionStorageRow {
    session_id: String,
    did: String,
    refresh_jti: String,
    active: i64,
}

#[derive(Deserialize)]
struct CountRow {
    n: i64,
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

fn repo_blob_from_values(values: Vec<SqlStorageValue>) -> worker::Result<RepoBlobRow> {
    let mut values = values.into_iter();
    let cid = parse_cid(&next_string(&mut values, "cid")?).map_err(worker_error)?;
    let mime_type = next_string(&mut values, "mime_type")?;
    let bytes = next_blob(&mut values, "bytes")?;
    let byte_len = next_i64(&mut values, "byte_len")?;
    let storage_kind = next_string(&mut values, "storage_kind")?;
    let storage_key = next_optional_string(&mut values, "storage_key")?;

    Ok(RepoBlobRow {
        cid,
        mime_type,
        bytes,
        byte_len,
        storage_kind,
        storage_key,
    })
}

fn blob_ref_from_values(values: Vec<SqlStorageValue>) -> worker::Result<RepoBlobRefRow> {
    let mut values = values.into_iter();
    let path = RepoPath::parse(&next_string(&mut values, "path")?).map_err(worker_error)?;
    let cid = parse_cid(&next_string(&mut values, "cid")?).map_err(worker_error)?;
    let record_cid = parse_cid(&next_string(&mut values, "record_cid")?).map_err(worker_error)?;

    Ok(RepoBlobRefRow {
        path,
        cid,
        record_cid,
    })
}

fn repo_commit_event_from_values(
    values: Vec<SqlStorageValue>,
) -> worker::Result<RepoCommitEventRow> {
    let mut values = values.into_iter();
    let seq = next_i64(&mut values, "seq")?;
    let rev = RepoRev::new(next_string(&mut values, "rev")?).map_err(worker_error)?;
    let since = next_optional_string(&mut values, "since")?
        .map(|value| RepoRev::new(value).map_err(worker_error))
        .transpose()?;
    let commit_cid = parse_cid(&next_string(&mut values, "commit_cid")?).map_err(worker_error)?;
    let blocks = next_blob(&mut values, "blocks")?;
    let ops_json = next_string(&mut values, "ops_json")?;
    let blobs_json = next_string(&mut values, "blobs_json")?;

    Ok(RepoCommitEventRow {
        seq,
        rev,
        since,
        commit_cid,
        blocks,
        ops_json,
        blobs_json,
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

fn next_blob(
    values: &mut impl Iterator<Item = SqlStorageValue>,
    name: &str,
) -> worker::Result<Vec<u8>> {
    match values.next() {
        Some(SqlStorageValue::Blob(value)) => Ok(value),
        Some(other) => Err(worker_error(std::io::Error::other(format!(
            "expected blob column `{name}`, got {other:?}"
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
    let row: CountRow = sql.exec(query, None)?.one()?;
    Ok(row.n)
}
