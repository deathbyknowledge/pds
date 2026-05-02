use serde_json::json;
use worker::{event, Context, Request, Response};

#[event(fetch)]
async fn fetch(_req: Request, _env: worker::Env, _ctx: Context) -> worker::Result<Response> {
    Response::from_json(&json!({
        "name": "gsv-pds",
        "version": env!("CARGO_PKG_VERSION"),
        "status": "ready"
    }))
}
