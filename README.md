# eth_proof_verifier

A standalone verifier for [EIP-8025](https://eips.ethereum.org/EIPS/eip-8025) execution proofs. It is the sidecar a validator runs in order to check an execution payload by verifying a proof of its execution, instead of re-executing it.

One binary, one job, no setup. Start it, point your beacon node at it, done.

## Why

EIP-8025 adds execution proofs to the consensus layer as an optional second oracle for execution validity. A beacon node that can verify such a proof does not have to re-execute the payload to believe it, and the cost of checking a proof is roughly constant in the size of the block: a 60M-gas block and a 600M-gas block verify in about the same time. That lowers the hardware floor for attesting.

The proofs themselves are produced by *provers* — opt-in validators running a full execution client and a proving stack. Proving is expensive and specialised. **Verifying is not**, and verifying is all a validator needs. This repository implements only that side.

## Scope

It verifies proofs. That is the whole of it.

- No proof generation, and no proving stack.
- No validator key, no signing, no gossip, no peers, no chain state, no database.
- No execution client, and no execution witness.

The consensus specs call this component a *proof node*. It has no peers and holds no chain, so that name is not used here.

## How a proof is verified

A beacon node hands over a `proof_type`, the four public-input fields it derived from its own state, and the proof bytes. The verifier then:

1. Resolves `proof_type` to a registry entry: proof system, guest program, versions, and that program's verifying key.
2. Decodes the proof bytes with that proof system's codec, rejecting trailing bytes.
3. Verifies the proof against the verifying key.
4. Extracts the public values the guest committed to, and for SP1 requires the committed guest exit code to be `0`.
5. Requires those committed bytes to equal the canonical encoding of the public input the beacon node supplied.

Step 5 is the binding that matters. A proof is only an answer to the question the beacon node asked if it commits to exactly the payload, chain and schema the beacon node named.

## Batteries included

Verifying needs the proof system's verifier and the guest program's verifying key, and **a verifying key is 32 bytes** for SP1 and ZisK. The multi-megabyte guest ELF is a proving input and plays no part in verification.

So there is nothing to install and nothing to fetch. The verifying keys are compiled in, the verifiers are ordinary Rust dependencies pinned to published versions, and the binary verifies out of the box:

- no Docker,
- no zkVM SDK installation,
- no artifact or ceremony download,
- no proving-key directory,
- no configuration required.

Adding a proof type is pasting 32 bytes of hex into a config file, not provisioning a machine.

## API

### `POST /v1/execution_proof_verifications`

The public input is passed as query parameters and the proof as the request body, so no SSZ is involved on either side.

```
POST /v1/execution_proof_verifications
    ?proof_type=1
    &new_payload_request_root=0x8f1c...
    &successful_validation=true
    &chain_id=1
    &schema_id=5377
Content-Type: application/octet-stream

<proof bytes>
```

```json
{ "status": "VALID" }
{ "status": "INVALID", "reason": "committed public input does not match" }
```

An unknown `proof_type` is **not** reported as `INVALID`. It is a distinct error, because a validator that silently rejects every proof it is sent on account of a misconfigured proof type is the worst outcome this component has:

```json
{ "error": "unsupported proof type", "proof_type": 7, "supported": [1, 2, 3] }
```

### `GET /v1/proof_types`

The proof types this verifier can check, which a beacon node needs in order to advertise the ENR `eproof` field and to answer the `ExecutionProofStatus` handshake.

## Usage

```
eth_proof_verifier [--listen-address 127.0.0.1:8025] [--proof-types FILE]
```

Then point your beacon node at it. On Lighthouse that is `--proof-engine-endpoint http://127.0.0.1:8025`.

## Proof types

A `ProofType` names an immutable triple of proof system, guest program and version. It is not a proof system on its own: a proof is checked against one specific compiled program, so changing the guest or either version takes a new proof type, never a redefinition of an existing one.

EIP-8025 fixes the supported set at `{1, 2, 3}` but assigns the numbers no meanings, and expects further values to be socialised out of band. These assignments are therefore this project's, and `--proof-types` overrides or extends them by number:

| `proof_type` | Proof system | Guest |
| --- | --- | --- |
| 1 | SP1 6.4.0 | reth 0.1.0-rc.3 |
| 2 | SP1 6.4.0 | ethrex 27.0.0 |

Guest programs and their verifying keys come from [`eth-act/ere-guests`](https://github.com/eth-act/ere-guests) v0.17.1 and the execution clients' own releases. A verifying key is only meaningful for the proof-system version its guest was compiled and proved with, which is why every entry carries that version and why they all agree with the pinned `sp1-verifier`.

```toml
[[proof_types]]
proof_type = 3
proof_system = "sp1"
proof_system_version = "6.4.0"
guest = "zesu"
guest_version = "tests-glamsterdam-devnet@v8.1.4"
program_vk = "00a03cbf...dd"
```

## Proof systems

| Proof system | Status |
| --- | --- |
| SP1 | supported, via `sp1-verifier`, compressed proofs |
| ZisK | blocked |
| OpenVM | blocked |

Both of the others are blocked on published artifacts rather than unwanted, and each has a backend slot waiting.

**ZisK** verification needs three things to agree: the verifier crate version, the guest program's verifying key, and the proof system's aggregation verifying key. `zisk-verifier` is on crates.io for 1.1.0-alpha through 1.3.1-alpha, and guest keys exist for v1.1.0-alpha and v1.2.0-alpha, but of the aggregation keys **only 1.3.1-alpha is published** — and no guest key exists for it. No obtainable combination lines up.

**OpenVM** guest programs are built against `v2.1.0-preview`. crates.io carries only 2.0.x, and the one verifier matching those guests lives on unmerged branches of personal forks of both `openvm` and `stark-backend`. There is nothing to pin.

## Where this deviates from the specification

`proof-engine.md` says to use `hash_tree_root(execution_proof.public_input)` as the proof-system public input. This verifier instead binds to the canonical SSZ **serialisation** of those fields, because no guest program commits to a root:

- Every shipped guest commits 43 plain SSZ bytes — `new_payload_request_root` (32), `successful_validation` (1), `chain_id` (8, little endian), `schema_id` (2, little endian) — which is the guest's `StatelessValidationResult`.
- The field list is identical to the spec's `PublicInput`, and the encoding is fixed-length and injective, so binding to the bytes binds exactly as tightly as binding to their root.
- The two roots could not agree in any case. The spec's `PublicInput` is an EIP-7688 `ProgressiveContainer`, and the guest's result is a plain fixed container, so they merkleize differently.

A happy consequence: this verifier merkleizes nothing, and therefore carries no SSZ library and no progressive-container support.

A zero `schema_id` is the guests' sentinel for "could not decode the input or produce a result", so such a proof can never match a real public input.

## Status

Early, but working. SP1 verification is implemented and tested against a real proof, and the API above may still move.

`tests/sp1_verifier.rs` runs the SP1 backend against a genuine 1.27 MB SP1 compressed proof. It checks that the proof verifies and returns exactly the bytes its guest committed to, and that each of a different program, a corrupted proof, trailing bytes, a declared length beyond the input, and **edited public values** is rejected. That last one is the property the public-input binding rests on: if the bytes a proof carries were not authenticated by the proof, a valid proof of one payload could be relabelled as a proof of another.

On one core of a 2026 x86 server, verifying that proof takes about **30 ms** in roughly **7 MB** of resident memory. The binary is about 5.5 MB and needs nothing beside it.

## Credits

The guest programs, their verifying keys, and the proof-encoding details this verifier has to agree with are the work of [eth-act](https://github.com/eth-act) on [`ere`](https://github.com/eth-act/ere) and [`ere-guests`](https://github.com/eth-act/ere-guests), and of the SP1 and ZisK teams on the verifiers themselves.
