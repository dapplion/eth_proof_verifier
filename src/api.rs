//! The HTTP surface: verify a proof, and say which proof types can be verified.
//!
//! The public input travels as query parameters and the proof as the request body, so neither side
//! needs an SSZ codec. Unknown parameters are ignored, so a beacon node may send more than this
//! verifier reads.

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
    /// Caps how many proofs are verified at once.
    ///
    /// Verification is tens of milliseconds of pure CPU. Without a cap, a burst of proofs occupies
    /// every blocking thread and every byte of every body at the same time, and the cheap routes
    /// queue behind arithmetic.
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
    /// Why a proof did not verify. Absent when it did.
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

/// `POST /v1/execution_proof_verifications`
async fn verify_execution_proof(
    State(state): State<Verifier>,
    query: Result<Query<VerifyQuery>, QueryRejection>,
    proof: Bytes,
) -> Result<Json<Verification>, ApiError> {
    let Query(query) = query.map_err(|e| ApiError::Query(e.body_text()))?;

    // An unknown proof type is reported as its own error rather than as `INVALID`. A validator that
    // silently rejected every proof it was sent because of a misconfigured proof type would look
    // exactly like a network with no provers on it.
    let verifier = state.registry.verifier(query.proof_type).ok_or_else(|| {
        ApiError::UnsupportedProofType {
            proof_type: query.proof_type,
            supported: state.registry.supported(),
        }
    })?;

    // EIP-8025 requires a verifier to check `successful_validation` before treating a proof as a
    // positive signal. A beacon node derives it as `true`, so anything else is a caller asking the
    // wrong question, and answering `VALID` would endorse a proof that says the payload is invalid.
    if !query.successful_validation {
        return Err(ApiError::NotAPositiveSignal);
    }
    // The guests' sentinel for "could not decode the input", which no beacon node derives.
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

    // Verification is CPU-bound, so it does not belong on a runtime worker.
    let _permit = state
        .concurrency
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ApiError::ShuttingDown)?;
    let proof_bytes = proof.len();
    let verified = tokio::task::spawn_blocking(move || verifier.verify(&proof))
        .await
        .map_err(|_| ApiError::VerificationPanicked)?;

    let committed = match verified {
        Ok(committed) => committed,
        Err(rejection) => {
            // At `warn`, because the ordinary case is a network with no bad proofs on it: a steady
            // stream of these is a misconfigured verifying key, not business as usual.
            warn!(
                proof_type = query.proof_type,
                proof_bytes, %rejection, "Proof did not verify"
            );
            return Ok(Json(Verification::invalid(rejection.to_string())));
        }
    };

    // The proof verifies, but a proof of some other payload is not an answer to the question that
    // was asked.
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

/// `GET /v1/proof_types`
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
    #[error("verification failed unexpectedly")]
    VerificationPanicked,
    #[error("shutting down")]
    ShuttingDown,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            Self::UnsupportedProofType { .. }
            | Self::InvalidRoot { .. }
            | Self::Query(_)
            | Self::NotAPositiveSignal
            | Self::UndecodableSchemaId => StatusCode::BAD_REQUEST,
            Self::VerificationPanicked => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ShuttingDown => StatusCode::SERVICE_UNAVAILABLE,
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

    /// A stand-in for a proof system, so the handler's own composition can be tested without a
    /// proof for every case. The cryptography is covered in `tests/sp1_verifier.rs`.
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

    /// Proof type 1 commits the public input the requests below ask about, 2 commits something else,
    /// and 3 refuses to verify at all.
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

    fn query_for(proof_type: u8) -> String {
        format!(
            "proof_type={proof_type}\
             &new_payload_request_root=0x{}\
             &successful_validation=true\
             &chain_id=1\
             &schema_id=5377",
            "11".repeat(32)
        )
    }

    #[tokio::test]
    async fn accepts_a_proof_that_commits_to_the_public_input() {
        let (status, body) = verify(&query_for(1)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "VALID");
        assert!(body["reason"].is_null());
    }

    #[tokio::test]
    async fn rejects_a_proof_that_commits_to_another_public_input() {
        let (status, body) = verify(&query_for(2)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "INVALID");
        assert_eq!(body["reason"], "proof commits to a different public input");
    }

    #[tokio::test]
    async fn reports_why_a_proof_did_not_verify() {
        let (status, body) = verify(&query_for(3)).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["status"], "INVALID");
        assert_eq!(body["reason"], "the proof does not verify");
    }

    /// An unknown proof type is its own error. Reported as `INVALID`, a misconfigured proof type
    /// would be indistinguishable from a network with no provers on it.
    #[tokio::test]
    async fn reports_an_unsupported_proof_type_as_an_error() {
        let (status, body) = verify(&query_for(9)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "unsupported proof type");
        assert_eq!(body["proof_type"], 9);
        assert_eq!(body["supported"], serde_json::json!([1, 2, 3]));
    }

    /// Answering `VALID` here would endorse a proof that says the payload is invalid.
    #[tokio::test]
    async fn refuses_a_question_that_is_not_about_a_valid_payload() {
        let query =
            query_for(1).replace("successful_validation=true", "successful_validation=false");
        let (status, body) = verify(&query).await;

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
        let query = query_for(1).replace("schema_id=5377", "schema_id=0");
        let (status, body) = verify(&query).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]
                .as_str()
                .expect("an error")
                .contains("sentinel")
        );
    }

    #[tokio::test]
    async fn rejects_a_root_that_is_not_32_bytes() {
        let query = query_for(1).replace(&"11".repeat(32), "dead");
        let (status, body) = verify(&query).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            body["error"]
                .as_str()
                .expect("an error")
                .contains("new_payload_request_root")
        );
    }

    /// A missing parameter used to come back as `text/plain`, unlike every other error here.
    #[tokio::test]
    async fn reports_a_missing_parameter_as_json() {
        let query = query_for(1).replace("&chain_id=1", "");
        let (status, body) = verify(&query).await;

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
