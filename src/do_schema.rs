//! SQLite schema for the repository Durable Object.

pub const CREATE_REPO_STATE: &str = "CREATE TABLE IF NOT EXISTS repo_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    did           TEXT NOT NULL,
    latest_commit TEXT NOT NULL,
    latest_rev    TEXT NOT NULL
)";

pub const CREATE_REPO_BLOCKS: &str = "CREATE TABLE IF NOT EXISTS repo_blocks (
    cid        TEXT PRIMARY KEY,
    bytes      BLOB NOT NULL,
    byte_len   INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
)";

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
    CREATE_REPO_BLOCKS,
    CREATE_RECORD_INDEX,
    CREATE_RECORD_COLLECTION_INDEX,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_creates_expected_tables() {
        let joined = ALL_SCHEMA_STATEMENTS.join("\n");

        assert!(joined.contains("repo_state"));
        assert!(joined.contains("repo_blocks"));
        assert!(joined.contains("record_index"));
        assert!(joined.contains("idx_record_index_collection_path"));
    }

    #[test]
    fn repo_state_is_singleton_table() {
        assert!(CREATE_REPO_STATE.contains("CHECK (id = 1)"));
        assert!(CREATE_REPO_STATE.contains("latest_commit TEXT NOT NULL"));
    }

    #[test]
    fn repo_blocks_store_bytes_by_cid() {
        assert!(CREATE_REPO_BLOCKS.contains("cid        TEXT PRIMARY KEY"));
        assert!(CREATE_REPO_BLOCKS.contains("bytes      BLOB NOT NULL"));
    }
}
