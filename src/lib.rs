#![recursion_limit = "512"]

pub mod atproto_resolver;
pub mod auth;
pub mod car;
pub mod cbor;
pub mod cid;
pub mod commit;
pub mod data_model;
pub mod diagnostics;
pub mod do_schema;
pub mod dpop;
pub mod identity;
pub mod lexicon;
pub mod model;
pub mod mst;
pub mod oauth;
pub mod plc;
pub mod repo;
pub mod repo_import;
pub mod service;
pub mod storage;
pub mod xrpc;

#[cfg(target_arch = "wasm32")]
mod do_store;

#[cfg(target_arch = "wasm32")]
mod worker_entry;
