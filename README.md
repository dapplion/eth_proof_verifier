# eth_proof_verifier

Verify [EIP-8025](https://eips.ethereum.org/EIPS/eip-8025) execution proofs. One binary, no setup, 12-30 ms per proof.

```sh
cargo install --locked --git https://github.com/dapplion/eth_proof_verifier   # or a release binary
eth_proof_verifier --listen-address 127.0.0.1:8025
```

Lighthouse: `--proof-engine-endpoint http://127.0.0.1:8025`.

## API

- `POST /v1/execution_proof_verifications` — query `proof_type`, `new_payload_request_root`, `successful_validation`, `chain_id`, `schema_id`; body the proof. `{"status":"VALID"}`, or `INVALID` with a reason. An unknown `proof_type` is `400`, never `INVALID`.
- `GET /v1/proof_types` — for the ENR `eproof` field and `ExecutionProofStatus`.

## Proof systems

SP1 by default. ZisK under `--features zisk`, which is off because its verifier builds rapidsnark
from C++ sources and so wants a C++ toolchain, `nlohmann/json.hpp`, libsodium and nasm; a default
build installs with none of that.

No proof type names a ZisK guest either way: the aggregation key changes between ZisK patch releases,
and the one for 1.2.0-alpha, the version `ere-guests` built its ZisK guests with, is not published.
`--proof-types` takes an entry the day a guest and a published key line up.

## Proof types

Immutable `(system, guest, version)` triples. `--proof-types FILE` adds more.

| # | guest | built with |
| --- | --- | --- |
| 1 | reth 0.1.0-rc.3 | SP1 6.4.0 |
| 2 | ethrex 27.0.0 | SP1 6.4.0 |

## Adding a proving system

PRs welcome: implement `ProofVerifier::verify`, add a row. See `src/backend/zisk.rs`, ~140 lines. Bring a crates.io verifier at a pinned version, a published verifying key per guest, and a real proof as a fixture. OpenVM waits on the first: its guests are built for 2.1.0-preview and crates.io carries 2.0.x.

Apache-2.0 OR MIT. Guests, keys and fixture from [ere](https://github.com/eth-act/ere).
