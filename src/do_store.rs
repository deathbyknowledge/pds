//! Durable Object SQLite storage adapter.

use serde::Deserialize;
use worker::{Error as WorkerError, SqlStorage, SqlStorageValue};

use crate::cid::{parse_cid, verify_repo_block_cid, Cid};
use crate::commit::{Did, RepoRev};
use crate::data_model::{Nsid, RepoPath};
use crate::do_schema::ALL_SCHEMA_STATEMENTS;
use crate::identity::{IdentityError, RepoSigningKey};
use crate::storage::{RepoBlockStore, RepoRecordIndex, StorageError};

#[derive(Clone, Debug)]
pub struct SqlRepoStore {
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
        self.sql.exec("DELETE FROM repo_blocks", None)?;
        self.sql.exec("DELETE FROM repo_identity", None)?;
        self.sql.exec("DELETE FROM repo_state", None)?;
        Ok(())
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

fn worker_error(error: impl std::error::Error) -> WorkerError {
    WorkerError::RustError(error.to_string())
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
