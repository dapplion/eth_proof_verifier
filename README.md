# eth_proof_verifier

Verify [EIP-8025](https://eips.ethereum.org/EIPS/eip-8025) execution proofs. One binary, no setup.

Point a beacon node here and it checks execution payloads by verifying a proof instead of re-executing them. **~30 ms and ~7 MB per proof, constant in block gas.** No proving, no keys, no gossip, no chain state, no execution client.

## Run

```sh
cargo install --git https://github.com/dapplion/eth_proof_verifier
eth_proof_verifier
```

Or take a binary from [releases](https://github.com/dapplion/eth_proof_verifier/releases).

Then on Lighthouse: `--proof-engine-endpoint http://127.0.0.1:8025`.

| flag | default |
| --- | --- |
| `--listen-address` | `127.0.0.1:8025` |
| `--proof-types FILE` | the table below |

## API

**`POST /v1/execution_proof_verifications`** — query: `proof_type`, `new_payload_request_root`, `successful_validation`, `chain_id`, `schema_id`. Body: the proof bytes.

```json
{"status": "VALID"}
{"status": "INVALID", "reason": "proof commits to a different public input"}
```

An unknown `proof_type` is `400`, never `INVALID` — a validator silently rejecting every proof looks exactly like a network with no provers on it.

**`GET /v1/proof_types`** — what this binary can verify, for the ENR `eproof` field and the `ExecutionProofStatus` handshake.

## Proof types

A proof type is an immutable `(proof system, guest program, version)` triple. Change any part and it takes a new number.

| `proof_type` | system | guest |
| --- | --- | --- |
| 1 | SP1 6.4.0 | reth 0.1.0-rc.3 |
| 2 | SP1 6.4.0 | ethrex 27.0.0 |

EIP-8025 fixes the set at `{1, 2, 3}` but assigns no meanings, so these are ours. Override or extend by number:

```toml
[[proof_types]]
proof_type = 3
proof_system = "sp1"
proof_system_version = "6.4.0"
guest = "zesu"
guest_version = "tests-glamsterdam-devnet@v8.1.4"
program_vk = "00a03cbf…dd"
```

## Add your proving system

**zk teams: PRs very welcome.** A backend is small — implement `ProofVerifier::verify`, returning the bytes your guest committed to, add a `ProofSystem` variant, and add a row to `default_proof_types.toml`. Everything else is shared. See `src/backend/sp1.rs`, which is about 80 lines of real work.

Two asks, both so operators get a binary that just works:

- **Your verifier on crates.io, at a pinned version.** Not a git branch.
- **A verifying key per guest program**, published and small enough to compile in. SP1's is 32 bytes.
- **A real proof as a test fixture**, so CI proves the backend verifies rather than asserting it.

| system | |
| --- | --- |
| SP1 | ✅ |
| ZisK | blocked: of the aggregation keys only `1.3.1-alpha` is published, and no guest key exists for it |
| OpenVM | blocked: guests target `v2.1.0-preview`, crates.io has `2.0.x`, and the matching verifier lives on fork branches |

Neither is unwanted — both have a slot waiting.

## One deviation from the spec

`proof-engine.md` says to use `hash_tree_root(public_input)` as the proof-system public input. No shipped guest commits a root; every one commits the 43-byte SSZ of its `StatelessValidationResult`, so that is what a proof is bound to here. The field list is identical and the encoding is fixed-length and injective, so the binding is exactly as tight — and nothing in this crate has to merkleize anything.

## Tests

```sh
cargo test --release
```

`tests/sp1_verifier.rs` runs a real 1.27 MB SP1 proof. It must verify, and must be rejected under a different program, when corrupted, with trailing bytes, with a declared length beyond the input, and when its **public values are edited** — that last one is what makes the public-input comparison a binding and not theatre.

## License

Apache-2.0 OR MIT. Guest programs, verifying keys and the test fixture come from [eth-act/ere-guests](https://github.com/eth-act/ere-guests) and [ere](https://github.com/eth-act/ere).
