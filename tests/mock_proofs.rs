//! `--mock-proofs` end to end: the compiled-in proof types, behind the HTTP API a beacon node calls.

use std::sync::Arc;

use axum::{body::Body, http::Request};
use eth_proof_verifier::{api, public_input::PublicInput, registry::Registry};
use serde_json::Value;
use tower::ServiceExt;

fn public_input() -> PublicInput {
    PublicInput {
        new_payload_request_root: [0x11; 32],
        successful_validation: true,
        chain_id: 3_151_908,
        schema_id: 0x1501,
    }
}

/// An SSZ `MockProof`, as zkboost's mock zkVMs send it.
fn mock_proof(public_values: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(&(8 + public_values.len() as u32).to_le_bytes());
    bytes.extend_from_slice(public_values);
    bytes.extend_from_slice(&[0x5a; 32]);
    bytes
}

async fn verify(registry: Registry, proof: Vec<u8>) -> Value {
    let input = public_input();
    let request = Request::builder()
        .method("POST")
        .uri(format!(
            "/v1/execution_proof_verifications?proof_type=2\
             &new_payload_request_root=0x{}&successful_validation=true&chain_id={}&schema_id={}",
            hex::encode(input.new_payload_request_root),
            input.chain_id,
            input.schema_id,
        ))
        .body(Body::from(proof))
        .expect("request builds");
    let response = api::router(Arc::new(registry))
        .oneshot(request)
        .await
        .expect("router responds");
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body is readable");
    serde_json::from_slice(&body).expect("body is json")
}

fn registry() -> Registry {
    Registry::load(None).expect("defaults load")
}

#[tokio::test]
async fn accepts_a_mock_proof_of_the_public_input() {
    let body = verify(
        registry().with_mock_proofs(),
        mock_proof(&public_input().encode()),
    )
    .await;
    assert_eq!(body["status"], "VALID", "{body}");
}

#[tokio::test]
async fn rejects_a_mock_proof_of_another_public_input() {
    let other = PublicInput {
        new_payload_request_root: [0x22; 32],
        ..public_input()
    };
    let body = verify(registry().with_mock_proofs(), mock_proof(&other.encode())).await;
    assert_eq!(body["status"], "INVALID", "{body}");
    assert_eq!(body["reason"], "proof commits to a different public input");
}

#[tokio::test]
async fn rejects_a_mock_proof_without_the_flag() {
    let body = verify(registry(), mock_proof(&public_input().encode())).await;
    assert_eq!(body["status"], "INVALID", "{body}");
}
