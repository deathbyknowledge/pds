//! Repository mutation, commit, and record logic.

use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use crate::cbor::{decode_dag_cbor, encode_block, CborError};
use crate::cid::Cid;
use crate::data_model::{Nsid, RepoPath};
use crate::storage::{RepoBlockStore, RepoRecordIndex, StorageError};

#[derive(Debug, Error)]
pub enum RepoError {
    #[error(transparent)]
    Cbor(#[from] CborError),

    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error("record already exists at `{path}`")]
    RecordAlreadyExists { path: RepoPath },

    #[error("record does not exist at `{path}`")]
    RecordNotFound { path: RepoPath },

    #[error("record `{path}` points to missing block `{cid}`")]
    MissingRecordBlock { path: RepoPath, cid: Cid },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRecord<T> {
    pub path: RepoPath,
    pub cid: Cid,
    pub record: T,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordListItem {
    pub path: RepoPath,
    pub cid: Cid,
}

#[derive(Clone, Debug)]
pub struct Repository<S> {
    storage: S,
}

impl<S> Repository<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn storage_mut(&mut self) -> &mut S {
        &mut self.storage
    }

    pub fn into_storage(self) -> S {
        self.storage
    }
}

impl<S> Repository<S>
where
    S: RepoBlockStore + RepoRecordIndex,
{
    pub fn create_record<T: Serialize>(
        &mut self,
        path: RepoPath,
        record: &T,
    ) -> Result<Cid, RepoError> {
        if self.storage.get_record_pointer(&path)?.is_some() {
            return Err(RepoError::RecordAlreadyExists { path });
        }
        self.put_record(path, record)
    }

    pub fn put_record<T: Serialize>(
        &mut self,
        path: RepoPath,
        record: &T,
    ) -> Result<Cid, RepoError> {
        let block = encode_block(record)?;
        self.storage
            .put_block_with_cid(block.cid, block.bytes.clone())?;
        self.storage.put_record_pointer(path, block.cid)?;
        Ok(block.cid)
    }

    pub fn update_record<T: Serialize>(
        &mut self,
        path: RepoPath,
        record: &T,
    ) -> Result<Cid, RepoError> {
        if self.storage.get_record_pointer(&path)?.is_none() {
            return Err(RepoError::RecordNotFound { path });
        }
        self.put_record(path, record)
    }

    pub fn get_record<T: DeserializeOwned>(
        &self,
        path: &RepoPath,
    ) -> Result<Option<StoredRecord<T>>, RepoError> {
        let Some(cid) = self.storage.get_record_pointer(path)? else {
            return Ok(None);
        };
        let Some(bytes) = self.storage.get_block(&cid)? else {
            return Err(RepoError::MissingRecordBlock {
                path: path.clone(),
                cid,
            });
        };
        let record = decode_dag_cbor(&bytes)?;
        Ok(Some(StoredRecord {
            path: path.clone(),
            cid,
            record,
        }))
    }

    pub fn delete_record(&mut self, path: &RepoPath) -> Result<Option<Cid>, RepoError> {
        Ok(self.storage.delete_record_pointer(path)?)
    }

    pub fn list_records(&self, collection: &Nsid) -> Result<Vec<RecordListItem>, RepoError> {
        Ok(self
            .storage
            .list_record_pointers(collection)?
            .into_iter()
            .map(|(path, cid)| RecordListItem { path, cid })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::storage::MemoryRepoStore;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct TestRecord {
        #[serde(rename = "$type")]
        record_type: String,
        text: String,
    }

    fn record(text: &str) -> TestRecord {
        TestRecord {
            record_type: "app.gsv.record".to_string(),
            text: text.to_string(),
        }
    }

    fn path(rkey: &str) -> RepoPath {
        RepoPath::parse(&format!("app.gsv.record/{rkey}")).unwrap()
    }

    #[test]
    fn put_record_stores_block_and_pointer() {
        let mut repo = Repository::new(MemoryRepoStore::new());
        let path = path("a");
        let cid = repo.put_record(path.clone(), &record("hello")).unwrap();

        assert_eq!(repo.storage().block_count(), 1);
        assert_eq!(repo.storage().record_count(), 1);
        assert_eq!(
            repo.get_record::<TestRecord>(&path).unwrap().unwrap().cid,
            cid
        );
    }

    #[test]
    fn create_record_rejects_existing_path() {
        let mut repo = Repository::new(MemoryRepoStore::new());
        let path = path("a");

        repo.create_record(path.clone(), &record("hello")).unwrap();

        assert!(matches!(
            repo.create_record(path, &record("again")),
            Err(RepoError::RecordAlreadyExists { .. })
        ));
    }

    #[test]
    fn update_record_rejects_missing_path() {
        let mut repo = Repository::new(MemoryRepoStore::new());

        assert!(matches!(
            repo.update_record(path("missing"), &record("hello")),
            Err(RepoError::RecordNotFound { .. })
        ));
    }

    #[test]
    fn updating_record_changes_pointer_and_keeps_old_block() {
        let mut repo = Repository::new(MemoryRepoStore::new());
        let path = path("a");
        let old_cid = repo.put_record(path.clone(), &record("old")).unwrap();
        let new_cid = repo.update_record(path.clone(), &record("new")).unwrap();
        let stored = repo.get_record::<TestRecord>(&path).unwrap().unwrap();

        assert_ne!(old_cid, new_cid);
        assert_eq!(stored.cid, new_cid);
        assert_eq!(stored.record, record("new"));
        assert_eq!(repo.storage().block_count(), 2);
    }

    #[test]
    fn same_record_bytes_produce_same_cid() {
        let mut repo = Repository::new(MemoryRepoStore::new());
        let cid_a = repo.put_record(path("a"), &record("same")).unwrap();
        let cid_b = repo.put_record(path("b"), &record("same")).unwrap();

        assert_eq!(cid_a, cid_b);
        assert_eq!(repo.storage().block_count(), 1);
        assert_eq!(repo.storage().record_count(), 2);
    }

    #[test]
    fn delete_record_removes_pointer_but_not_block() {
        let mut repo = Repository::new(MemoryRepoStore::new());
        let path = path("a");
        let cid = repo.put_record(path.clone(), &record("hello")).unwrap();

        assert_eq!(repo.delete_record(&path).unwrap(), Some(cid));
        assert!(repo.get_record::<TestRecord>(&path).unwrap().is_none());
        assert_eq!(repo.storage().block_count(), 1);
    }

    #[test]
    fn lists_records_by_collection_in_path_order() {
        let mut repo = Repository::new(MemoryRepoStore::new());
        let cid_b = repo.put_record(path("b"), &record("b")).unwrap();
        let cid_a = repo.put_record(path("a"), &record("a")).unwrap();
        repo.put_record(
            RepoPath::parse("app.gsv.other/a").unwrap(),
            &record("other"),
        )
        .unwrap();

        let listed = repo
            .list_records(&Nsid::new("app.gsv.record").unwrap())
            .unwrap();

        assert_eq!(
            listed,
            vec![
                RecordListItem {
                    path: path("a"),
                    cid: cid_a,
                },
                RecordListItem {
                    path: path("b"),
                    cid: cid_b,
                },
            ]
        );
    }
}
