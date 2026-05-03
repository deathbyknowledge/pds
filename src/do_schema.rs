//! SQLite schema for the repository Durable Object.

pub const CREATE_REPO_STATE: &str = "CREATE TABLE IF NOT EXISTS repo_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    did           TEXT NOT NULL,
    latest_commit TEXT NOT NULL,
    latest_rev    TEXT NOT NULL
)";

pub const CREATE_REPO_IDENTITY: &str = "CREATE TABLE IF NOT EXISTS repo_identity (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    handle                TEXT NOT NULL,
    signing_key_p256_hex  TEXT NOT NULL,
    public_key_multibase  TEXT NOT NULL
)";

pub const CREATE_REPO_BLOCKS: &str = "CREATE TABLE IF NOT EXISTS repo_blocks (
    cid        TEXT PRIMARY KEY,
    bytes      BLOB NOT NULL,
    byte_len   INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
)";

pub const CREATE_REPO_BLOBS: &str = "CREATE TABLE IF NOT EXISTS repo_blobs (
    cid        TEXT PRIMARY KEY,
    mime_type  TEXT NOT NULL,
    bytes      BLOB NOT NULL,
    byte_len   INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
)";

pub const CREATE_REPO_BLOBS_CREATED_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_repo_blobs_created_at
     ON repo_blobs(created_at, cid)";

pub const CREATE_RECORD_INDEX: &str = "CREATE TABLE IF NOT EXISTS record_index (
    path       TEXT PRIMARY KEY,
    collection TEXT NOT NULL,
    rkey       TEXT NOT NULL,
    cid        TEXT NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
)";

pub const CREATE_RECORD_COLLECTION_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_record_index_collection_path
     ON record_index(collection, path)";

pub const ALL_SCHEMA_STATEMENTS: &[&str] = &[
    CREATE_REPO_STATE,
    CREATE_REPO_IDENTITY,
    CREATE_REPO_BLOCKS,
    CREATE_REPO_BLOBS,
    CREATE_REPO_BLOBS_CREATED_INDEX,
    CREATE_RECORD_INDEX,
    CREATE_RECORD_COLLECTION_INDEX,
];

pub const CREATE_DIRECTORY_REPOS: &str = "CREATE TABLE IF NOT EXISTS directory_repos (
    did        TEXT PRIMARY KEY,
    handle     TEXT NOT NULL,
    repo_name  TEXT NOT NULL,
    head       TEXT NOT NULL,
    rev        TEXT NOT NULL,
    active     INTEGER NOT NULL DEFAULT 1,
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
)";

pub const CREATE_DIRECTORY_REPOS_UPDATED_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_directory_repos_updated_at
     ON directory_repos(updated_at, did)";

pub const CREATE_DIRECTORY_EVENTS: &str = "CREATE TABLE IF NOT EXISTS directory_events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    did        TEXT NOT NULL,
    event_type TEXT NOT NULL,
    commit_cid TEXT,
    rev        TEXT,
    since      TEXT,
    blocks     BLOB,
    ops_json   TEXT NOT NULL DEFAULT '[]',
    blobs_json TEXT NOT NULL DEFAULT '[]',
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
)";

pub const CREATE_DIRECTORY_EVENTS_DID_INDEX: &str =
    "CREATE INDEX IF NOT EXISTS idx_directory_events_did_seq
     ON directory_events(did, seq)";

pub const DIRECTORY_SCHEMA_STATEMENTS: &[&str] = &[
    CREATE_DIRECTORY_REPOS,
    CREATE_DIRECTORY_REPOS_UPDATED_INDEX,
    CREATE_DIRECTORY_EVENTS,
    CREATE_DIRECTORY_EVENTS_DID_INDEX,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_creates_expected_tables() {
        let joined = ALL_SCHEMA_STATEMENTS.join("\n");

        assert!(joined.contains("repo_state"));
        assert!(joined.contains("repo_identity"));
        assert!(joined.contains("repo_blocks"));
        assert!(joined.contains("repo_blobs"));
        assert!(joined.contains("record_index"));
        assert!(joined.contains("idx_record_index_collection_path"));
    }

    #[test]
    fn repo_state_is_singleton_table() {
        assert!(CREATE_REPO_STATE.contains("CHECK (id = 1)"));
        assert!(CREATE_REPO_STATE.contains("latest_commit TEXT NOT NULL"));
    }

    #[test]
    fn repo_identity_stores_signing_metadata() {
        assert!(CREATE_REPO_IDENTITY.contains("CHECK (id = 1)"));
        assert!(CREATE_REPO_IDENTITY.contains("handle                TEXT NOT NULL"));
        assert!(CREATE_REPO_IDENTITY.contains("signing_key_p256_hex  TEXT NOT NULL"));
        assert!(CREATE_REPO_IDENTITY.contains("public_key_multibase  TEXT NOT NULL"));
    }

    #[test]
    fn repo_blocks_store_bytes_by_cid() {
        assert!(CREATE_REPO_BLOCKS.contains("cid        TEXT PRIMARY KEY"));
        assert!(CREATE_REPO_BLOCKS.contains("bytes      BLOB NOT NULL"));
    }

    #[test]
    fn repo_blobs_store_raw_bytes_by_cid() {
        assert!(CREATE_REPO_BLOBS.contains("cid        TEXT PRIMARY KEY"));
        assert!(CREATE_REPO_BLOBS.contains("mime_type  TEXT NOT NULL"));
        assert!(CREATE_REPO_BLOBS.contains("bytes      BLOB NOT NULL"));
    }

    #[test]
    fn directory_schema_indexes_repos_and_events() {
        let joined = DIRECTORY_SCHEMA_STATEMENTS.join("\n");

        assert!(joined.contains("directory_repos"));
        assert!(joined.contains("did        TEXT PRIMARY KEY"));
        assert!(joined.contains("idx_directory_repos_updated_at"));
        assert!(joined.contains("directory_events"));
        assert!(joined.contains("seq        INTEGER PRIMARY KEY AUTOINCREMENT"));
        assert!(joined.contains("blocks     BLOB"));
        assert!(joined.contains("ops_json   TEXT NOT NULL DEFAULT '[]'"));
        assert!(joined.contains("idx_directory_events_did_seq"));
    }
}
