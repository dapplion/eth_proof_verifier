//! The HTTP surface, driven through the router rather than over a socket.

use std::{fs, path::PathBuf, sync::Arc};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use eth_proof_verifier::{api, registry::Registry};
use serde_json::Value;
use tower::ServiceExt;

const PROOF: &[u8] = include_bytes!("fixtures/proof.bin");

/// The program the fixture proof was produced for, which no default proof type names.
const FIXTURE_PROGRAM_VK: &str = "002d67597a7afdbb45a24a311ea77a6b07ccdebab8b92db5a95fe8371beed380";

const ROOT: &str = "0x1111111111111111111111111111111111111111111111111111111111111111";

/// A router serving the default proof types, plus `proof_type = 3` for the fixture's own program so
/// that a proof can reach verification and be turned away on its public input alone.
fn router(name: &str) -> axum::Router {
    let path = config_naming_the_fixture_program(name);
    let registry = Registry::load(Some(&path)).expect("registry loads");
    let _ = fs::remove_file(&path);
    api::router(Arc::new(registry))
}

fn config_naming_the_fixture_program(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("eth_proof_verifier-{name}.toml"));
    fs::write(
        &path,
        format!(
            "[[proof_types]]\n\
             proof_type = 3\n\
             proof_system = \"sp1\"\n\
             proof_system_version = \"6.4.0\"\n\
             guest = \"fixture\"\n\
             guest_version = \"fixture\"\n\
             program_vk = \"{FIXTURE_PROGRAM_VK}\"\n"
        ),
    )
    .expect("config is writable");
    path
}

async fn send(router: axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.oneshot(request).await.expect("router responds");
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body is readable");
    (status, serde_json::from_slice(&body).expect("body is json"))
}

fn verification(proof_type: u8, root: &str, proof: &[u8]) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(format!(
            "/v1/execution_proof_verifications\
             ?proof_type={proof_type}\
             &new_payload_request_root={root}\
             &successful_validation=true\
             &chain_id=1\
             &schema_id=5377"
        ))
        .body(Body::from(proof.to_vec()))
        .expect("request builds")
}

#[tokio::test]
async fn lists_the_proof_types_it_serves() {
    let request = Request::builder()
        .uri("/v1/proof_types")
        .body(Body::empty())
        .expect("request builds");

    let (status, body) = send(router("list"), request).await;

    assert_eq!(status, StatusCode::OK);
    let served: Vec<u8> = body
        .as_array()
        .expect("an array")
        .iter()
        .map(|spec| spec["proof_type"].as_u64().expect("a number") as u8)
        .collect();
    assert_eq!(served, vec![1, 2, 3]);
}

/// An unknown proof type is its own error. Reported as `INVALID`, a misconfigured proof type would
/// be indistinguishable from a network with no provers on it.
#[tokio::test]
async fn reports_an_unsupported_proof_type_as_an_error() {
    let (status, body) = send(router("unsupported"), verification(9, ROOT, PROOF)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unsupported proof type");
    assert_eq!(body["proof_type"], 9);
    assert_eq!(body["supported"], serde_json::json!([1, 2, 3]));
}

#[tokio::test]
async fn rejects_a_root_that_is_not_32_bytes() {
    let (status, body) = send(router("root"), verification(3, "0xdead", PROOF)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        body["error"],
        "new_payload_request_root is not a 32-byte hex string"
    );
}

/// A proof of some other payload is not an answer to the question that was asked, even though it
/// verifies.
#[tokio::test]
async fn rejects_a_proof_that_commits_to_another_public_input() {
    let (status, body) = send(router("mismatch"), verification(3, ROOT, PROOF)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "INVALID");
    assert_eq!(body["reason"], "proof commits to a different public input");
}

/// The same proof offered as a proof of a different guest program does not verify at all.
#[tokio::test]
async fn rejects_a_proof_of_a_different_program() {
    let (status, body) = send(router("program"), verification(1, ROOT, PROOF)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "INVALID");
    assert!(
        body["reason"]
            .as_str()
            .expect("a reason")
            .contains("vk hash mismatch"),
        "unexpected reason: {}",
        body["reason"]
    );
}
