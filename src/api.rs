//! The HTTP surface: verify a proof, and say which proof types can be verified.
//!
//! The public input travels as query parameters and the proof as the request body, so neither side
//! needs an SSZ codec. Unknown parameters are ignored, so a beacon node may send more than this
//! verifier reads.

use std::sync::Arc;

use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::{
    public_input::PublicInput,
    registry::{ProofTypeSpec, Registry},
};

/// EIP-8025 `MAX_PROOF_SIZE`. A larger body is refused before it is read into memory.
pub const MAX_PROOF_SIZE: usize = 4_194_304;

pub fn router(registry: Arc<Registry>) -> Router {
    Router::new()
        .route(
            "/v1/execution_proof_verifications",
            post(verify_execution_proof),
        )
        .route("/v1/proof_types", get(proof_types))
        .layer(DefaultBodyLimit::max(MAX_PROOF_SIZE))
        .with_state(registry)
}

#[derive(Deserialize)]
struct VerifyQuery {
    proof_type: u8,
    /// Hex, with or without a `0x` prefix.
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
    State(registry): State<Arc<Registry>>,
    Query(query): Query<VerifyQuery>,
    proof: Bytes,
) -> Result<Json<Verification>, ApiError> {
    // An unknown proof type is reported as its own error rather than as `INVALID`. A validator that
    // silently rejected every proof it was sent because of a misconfigured proof type would look
    // exactly like a network with no provers on it.
    let verifier =
        registry
            .verifier(query.proof_type)
            .ok_or_else(|| ApiError::UnsupportedProofType {
                proof_type: query.proof_type,
                supported: registry.supported(),
            })?;

    let public_input = PublicInput {
        new_payload_request_root: parse_root(&query.new_payload_request_root)?,
        successful_validation: query.successful_validation,
        chain_id: query.chain_id,
        schema_id: query.schema_id,
    };

    let committed = match verifier.verify(&proof) {
        Ok(committed) => committed,
        Err(rejection) => {
            debug!(
                proof_type = query.proof_type,
                proof_bytes = proof.len(),
                %rejection,
                "Proof did not verify"
            );
            return Ok(Json(Verification::invalid(rejection.to_string())));
        }
    };

    // The proof verifies, but a proof of some other payload is not an answer to the question that
    // was asked.
    if !public_input.is_committed_by(&committed) {
        warn!(
            proof_type = query.proof_type,
            root = %query.new_payload_request_root,
            "Proof verifies but commits to a different public input"
        );
        return Ok(Json(Verification::invalid(
            "proof commits to a different public input",
        )));
    }

    debug!(
        proof_type = query.proof_type,
        root = %query.new_payload_request_root,
        proof_bytes = proof.len(),
        "Proof verified"
    );
    Ok(Json(Verification::valid()))
}

/// `GET /v1/proof_types`
async fn proof_types(State(registry): State<Arc<Registry>>) -> Json<Vec<ProofTypeSpec>> {
    Json(registry.specs().into_iter().cloned().collect())
}

fn parse_root(root: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(root.trim_start_matches("0x"))
        .map_err(|_| ApiError::InvalidRoot(root.to_owned()))?;
    bytes
        .try_into()
        .map_err(|_| ApiError::InvalidRoot(root.to_owned()))
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("unsupported proof type")]
    UnsupportedProofType { proof_type: u8, supported: Vec<u8> },
    #[error("new_payload_request_root is not a 32-byte hex string")]
    InvalidRoot(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = match &self {
            Self::UnsupportedProofType {
                proof_type,
                supported,
            } => serde_json::json!({
                "error": self.to_string(),
                "proof_type": proof_type,
                "supported": supported,
            }),
            Self::InvalidRoot(root) => serde_json::json!({
                "error": self.to_string(),
                "new_payload_request_root": root,
            }),
        };
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    }
}
