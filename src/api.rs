//! The public input travels as query parameters and the proof as the body, so neither side needs an
//! SSZ codec. Unknown parameters are ignored.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State, rejection::QueryRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::{
    MAX_PROOF_SIZE, hex_bytes,
    public_input::{PublicInput, UNDECODABLE_SCHEMA_ID},
    registry::{ProofTypeSpec, Registry},
};

#[derive(Clone)]
struct Verifier {
    registry: Arc<Registry>,
    /// Each verification is tens of milliseconds of CPU and holds its whole body, so without a cap
    /// a burst starves the cheap routes.
    concurrency: Arc<Semaphore>,
}

pub fn router(registry: Arc<Registry>) -> Router {
    let concurrency = std::thread::available_parallelism()
        .map(Into::into)
        .unwrap_or(4);

    Router::new()
        .route(
            "/v1/execution_proof_verifications",
            post(verify_execution_proof),
        )
        .route("/v1/proof_types", get(proof_types))
        .layer(DefaultBodyLimit::max(MAX_PROOF_SIZE))
        .with_state(Verifier {
            registry,
            concurrency: Arc::new(Semaphore::new(concurrency)),
        })
}

#[derive(Deserialize)]
struct VerifyQuery {
    proof_type: u8,
    /// Hex, with an optional `0x` prefix.
    new_payload_request_root: String,
    successful_validation: bool,
    chain_id: u64,
    schema_id: u16,
}

#[derive(Serialize)]
struct Verification {
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

impl Verification {
    fn valid() -> Self {
        Self {
            status: "VALID",
            reason: None,
        }
    }

    fn invalid(reason: impl Into<String>) -> Self {
        Self {
            status: "INVALID",
            reason: Some(reason.into()),
        }
    }
}

async fn verify_execution_proof(
    State(state): State<Verifier>,
    query: Result<Query<VerifyQuery>, QueryRejection>,
    proof: Bytes,
) -> Result<Json<Verification>, ApiError> {
    let Query(query) = query.map_err(|e| ApiError::Query(e.body_text()))?;

    // Its own error, not `INVALID`: a validator rejecting every proof over a misconfigured proof
    // type looks exactly like a network with no provers.
    let verifier = state.registry.verifier(query.proof_type).ok_or_else(|| {
        ApiError::UnsupportedProofType {
            proof_type: query.proof_type,
            supported: state.registry.supported(),
        }
    })?;

    // `VALID` would endorse a proof that calls the payload invalid.
    if !query.successful_validation {
        return Err(ApiError::NotAPositiveSignal);
    }
    // The guests' sentinel for "could not decode the input".
    if query.schema_id == UNDECODABLE_SCHEMA_ID {
        return Err(ApiError::UndecodableSchemaId);
    }

    let public_input = PublicInput {
        new_payload_request_root: hex_bytes::decode(&query.new_payload_request_root)
            .map_err(|source| ApiError::InvalidRoot { source })?,
        successful_validation: query.successful_validation,
        chain_id: query.chain_id,
        schema_id: query.schema_id,
    };
    let root = hex::encode(public_input.new_payload_request_root);

    let _permit = state
        .concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ApiError::Internal)?;
    let proof_bytes = proof.len();
    let verified = tokio::task::spawn_blocking(move || verifier.verify(&proof))
        .await
        .map_err(|_| ApiError::Internal)?;

    let committed = match verified {
        Ok(committed) => committed,
        Err(rejection) => {
            // At `warn`: a steady stream of these is a misconfigured verifying key.
            warn!(
                proof_type = query.proof_type,
                proof_bytes, %rejection, "Proof did not verify"
            );
            return Ok(Json(Verification::invalid(rejection.to_string())));
        }
    };

    // It verifies, but a proof of another payload answers a different question.
    if !public_input.is_committed_by(&committed) {
        warn!(
            proof_type = query.proof_type,
            %root, "Proof verifies but commits to a different public input"
        );
        return Ok(Json(Verification::invalid(
            "proof commits to a different public input",
        )));
    }

    debug!(
        proof_type = query.proof_type,
        %root, proof_bytes, "Proof verified"
    );
    Ok(Json(Verification::valid()))
}

async fn proof_types(State(state): State<Verifier>) -> Json<Vec<ProofTypeSpec>> {
    Json(state.registry.specs().into_iter().cloned().collect())
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("unsupported proof type")]
    UnsupportedProofType { proof_type: u8, supported: Vec<u8> },
    #[error("new_payload_request_root is not 32 bytes of hex: {source}")]
    InvalidRoot { source: hex_bytes::Error },
    #[error("{0}")]
    Query(String),
    #[error(
        "successful_validation must be true; a proof of an invalid payload is not a positive signal"
    )]
    NotAPositiveSignal,
    #[error("schema_id 0 is the sentinel for a guest that could not decode its input")]
    UndecodableSchemaId,
    #[error("verification did not complete")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::UnsupportedProofType { .. }
            | Self::InvalidRoot { .. }
            | Self::Query(_)
            | Self::NotAPositiveSignal
            | Self::UndecodableSchemaId => StatusCode::BAD_REQUEST,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let mut body = serde_json::json!({ "error": self.to_string() });
        if let Self::UnsupportedProofType {
            proof_type,
            supported,
        } = &self
        {
            body["proof_type"] = serde_json::json!(proof_type);
            body["supported"] = serde_json::json!(supported);
        }
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{ProofSystem, ProofVerifier, Rejection};
    use serde_json::Value;
    use tower::ServiceExt;

    /// Stands in for a proof system, so each case needs no proof. The cryptography is covered in
    /// `tests/sp1_verifier.rs`.
    struct Stub(Result<Vec<u8>, &'static str>);

    impl ProofVerifier for Stub {
        fn verify(&self, _proof: &[u8]) -> Result<Vec<u8>, Rejection> {
            self.0.clone().map_err(Rejection::unverified)
        }
    }

    fn spec(proof_type: u8) -> ProofTypeSpec {
        ProofTypeSpec {
            proof_type,
            proof_system: ProofSystem::Sp1,
            proof_system_version: "6.4.0".to_owned(),
            guest: "stub".to_owned(),
            guest_version: "1".to_owned(),
            program_vk: "00".repeat(32),
        }
    }

    fn public_input() -> PublicInput {
        PublicInput {
            new_payload_request_root: [0x11; 32],
            successful_validation: true,
            chain_id: 1,
            schema_id: 0x1501,
        }
    }

    /// 1 commits the public input asked about, 2 commits something else, 3 refuses to verify.
    fn router_with_stubs() -> Router {
        let registry = Registry::from_entries(vec![
            (
                spec(1),
                Arc::new(Stub(Ok(public_input().encode().to_vec()))) as Arc<dyn ProofVerifier>,
            ),
            (spec(2), Arc::new(Stub(Ok(vec![0xcd; 43])))),
            (spec(3), Arc::new(Stub(Err("the proof does not verify")))),
        ]);
        router(Arc::new(registry))
    }

    /// Built from the input itself, so no field is spelled one way here and another there.
    fn query(proof_type: u8, input: PublicInput) -> String {
        format!(
            "proof_type={proof_type}\
             &new_payload_request_root=0x{}\
             &successful_validation={}\
             &chain_id={}\
             &schema_id={}",
            hex::encode(input.new_payload_request_root),
            input.successful_validation,
            input.chain_id,
            input.schema_id,
        )
    }

    async fn verify(query: &str) -> (StatusCode, Value) {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/v1/execution_proof_verifications?{query}"))
            .body(axum::body::Body::from(vec![0u8; 8]))
            .expect("request builds");

        let response = router_with_stubs()
            .oneshot(request)
            .await
            .expect("router responds");
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body is readable");
        (status, serde_json::from_slice(&body).expect("body is json"))
    }

    #[tokio::test]
    async fn accepts_a_proof_that_commits_to_the_public_input() {
        let (status, body) = verify(&query(1, public_input())).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "VALID");
        assert!(body["reason"].is_null());
    }

    #[tokio::test]
    async fn rejects_a_proof_that_commits_to_another_public_input() {
        let (status, body) = verify(&query(2, public_input())).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "INVALID");
        assert_eq!(body["reason"], "proof commits to a different public input");
    }

    /// A verdict, not an error: a beacon node has to tell a proof that does not verify from a
    /// sidecar that could not answer.
    #[tokio::test]
    async fn reports_why_a_proof_did_not_verify() {
        let (status, body) = verify(&query(3, public_input())).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "INVALID");
        assert_eq!(body["reason"], "the proof does not verify");
    }

    /// As `INVALID`, a misconfigured proof type would look like a network with no provers.
    #[tokio::test]
    async fn reports_an_unsupported_proof_type_as_an_error() {
        let (status, body) = verify(&query(9, public_input())).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "unsupported proof type");
        assert_eq!(body["proof_type"], 9);
        assert_eq!(body["supported"], serde_json::json!([1, 2, 3]));
    }

    #[tokio::test]
    async fn refuses_a_question_that_is_not_about_a_valid_payload() {
        let input = PublicInput {
            successful_validation: false,
            ..public_input()
        };
        let (status, body) = verify(&query(1, input)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]
                .as_str()
                .expect("an error")
                .contains("successful_validation must be true")
        );
    }

    #[tokio::test]
    async fn refuses_the_undecodable_input_sentinel() {
        let input = PublicInput {
            schema_id: UNDECODABLE_SCHEMA_ID,
            ..public_input()
        };
        let (status, body) = verify(&query(1, input)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]
                .as_str()
                .expect("an error")
                .contains("sentinel")
        );
    }

    /// Without the fallible extractor this is `text/plain`, unlike every other error.
    #[tokio::test]
    async fn reports_a_missing_parameter_as_json() {
        let without_chain_id = query(1, public_input())
            .split('&')
            .filter(|parameter| !parameter.starts_with("chain_id="))
            .collect::<Vec<_>>()
            .join("&");
        let (status, body) = verify(&without_chain_id).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]
                .as_str()
                .expect("an error")
                .contains("chain_id")
        );
    }

    #[tokio::test]
    async fn lists_the_proof_types_it_serves() {
        let request = axum::http::Request::builder()
            .uri("/v1/proof_types")
            .body(axum::body::Body::empty())
            .expect("request builds");

        let response = router_with_stubs()
            .oneshot(request)
            .await
            .expect("router responds");
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body is readable");
        let specs: Value = serde_json::from_slice(&body).expect("body is json");

        let served: Vec<u64> = specs
            .as_array()
            .expect("an array")
            .iter()
            .map(|spec| spec["proof_type"].as_u64().expect("a number"))
            .collect();
        assert_eq!(served, vec![1, 2, 3]);
    }
}
