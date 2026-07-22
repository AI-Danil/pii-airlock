# Architecture and threat model

## Components and boundaries

| Component | Location | Trust assumption |
|---|---|---|
| API, redaction, mapping, gate, restoration | Python process | Local process; contains raw data temporarily |
| DOCX/PDF parser workers | Spawned local processes | Untrusted document parsers with bounded lifetime and resources |
| LM Studio detector | `127.0.0.1:1234` | Local but fallible; output is validated |
| Source document | Local input | Untrusted data; may contain prompt injection or token-like text |
| Provider | HTTPS endpoint | Untrusted output; receives pseudonymized fields only after runtime checks |
| Caller/operator | Web UI, CLI, or API | Chooses whether review is sufficient for the intended use |

The source task and document are analysed together so one mapping can cover both, then they are redacted as separate fields. The API returns `outbound_content.instructions` and `outbound_content.input_text`; those same strings are passed to the provider client. Provider instructions delimit the task and document as untrusted data and prohibit treating document text as an instruction to call tools, access networks, or disclose secrets. The OpenAI client adds the configured model and `store: false`.

Deterministic rules first canonicalize selected Unicode, whitespace, line-break, and zero-width variants while keeping a character-to-source offset map. LM Studio adds semantic candidates. Exact occurrences are collected per field. Candidate spans are selected by decreasing length, overlapping candidates are discarded, and the selected spans are replaced from their recorded offsets. A shorter value is retained only when it has a separate non-overlapping occurrence. Unused model proposals never enter the mapping. New operations use a 32-hex-character nonce (128 random bits). The default `opaque` mode assigns a distinct non-semantic token to every occurrence, hiding type and repeated-value linkage. The optional `typed` mode reuses tokens for equal values and encodes type; it is diagnostic and less private. Public `redactions` expose field, offsets, type, and token, but not the raw value. The application does not serialize mappings.

The reviewer can add, remove, or retag exact source spans. The request repeats the source fields, and the service verifies their SHA-256 digests against the operation snapshot before applying the edit. A semantic detector failure retains deterministic rule spans but sets a mandatory-review warning; even an empty review action is an explicit confirmation. Prompt-like text is separately flagged. The Web UI can continue after inspection, while the unattended stateless route blocks such input.

Completion signs the reviewed state before claiming the provider result. The receipt contains HMAC fingerprints of source digests and tokens, span coordinates, review channel, model, token mode, warnings, and build identifier; it contains neither source values nor raw tokens. A configured signing key allows later verification. An ephemeral default key limits verification to the current process. The receipt is an integrity record, not evidence that a human found every entity.

The operation store has one background TTL sweeper and a 100-operation pending limit. Analysis is bounded by a four-request semaphore by default. A completion request atomically removes its operation from the store before dry-run or provider work starts. A concurrent retry therefore receives `operation_not_found` instead of starting another call. This is an at-most-once attempt; a failed provider call is not retried by the service.

## Operation states

```mermaid
stateDiagram-v2
    [*] --> Analysing
    Analysing --> Blocked: residual match or semantic warning
    Analysing --> ReadyForReview: deterministic checks found no recognised residual
    Blocked --> ReadyForReview: source-bound manual edits and confirmation pass the gate
    Blocked --> Destroyed: mapping removed immediately
    ReadyForReview --> Destroyed: delete or TTL expiry
    ReadyForReview --> ProviderCall: caller completes operation
    ProviderCall --> RejectedRetry: concurrent completion sees operation_not_found
    ProviderCall --> Destroyed: dry-run, success, timeout, provider error, or bad token
    RejectedRetry --> [*]
```

`READY_FOR_REVIEW` is deliberately not named `SAFE_TO_SEND`: the detector can omit sensitive values. It is also not a permission to send. Completion requires a second, separate state, `AUTHORIZED`, recorded by `POST /api/v1/operations/{id}/authorize` against the exact revision the reviewer saw; a later span edit clears it, and prompt-injection warnings additionally require an explicit acknowledgement. The stateless API route blocks prompt-like text but cannot provide human review; its caller still needs an external acceptance policy.

## Failure handling

| Condition | Result |
|---|---|
| LM Studio unavailable, timeout, HTTP error, oversized or invalid response | Rule spans retained for review; automatic completion blocked; no provider call |
| Model returns a value not present verbatim in the input | Rule spans retained; manual confirmation or edit required |
| Recognised residual value or no detected entity | Request blocked; mapping discarded |
| Source contains any reserved token prefix | Request blocked |
| Remote client, non-loopback `Host`, or foreign `Origin` | `403`; request is not processed |
| Browser write without its session cookie and same-origin `Origin` | `401` or `403` |
| Stateless call without configured bearer token | Route disabled or `401` |
| Pending operation count reaches 100 | `429`; new mapping is destroyed |
| Concurrent analysis capacity is exhausted | `429`; source is not queued indefinitely |
| HTTP body exceeds 5 MiB + 64 KiB | `413` before document parsing |
| Concurrent or repeated completion | `operation_not_found`; no second provider call |
| Provider alters, invents, truncates, changes case, or over-repeats a PII token | Answer blocked; mapping discarded |
| Provider timeout, HTTP error, invalid or oversized response | Error returned; mapping discarded |
| Downstream caller treats restored model text as an action | Output carries `untrusted_model_output` and `require_user_confirmation`; enforcement remains the caller's responsibility |

## Threat coverage

The design reduces accidental disclosure when the detector, a reviewer, or residual rules find the relevant value. It also handles selected Unicode obfuscation, model fabrication, parser size and expansion abuse, overlapping replacements, repeated completion, local cross-origin calls, a source-token collision, provider-token injection and amplification, stale mappings, and raw values in the application's own structured audit calls. DOCX/PDF parsing runs in short-lived processes with wall-clock and platform-supported resource limits. Extraction manifests expose what regions were covered and which isolation boundary actually ran. Unsupported hidden or active content is rejected.

It does not solve detector recall, all Unicode confusables, malicious parser code, or prompt injection in general. Delimiters and stateless blocking narrow the instruction boundary but do not make untrusted text executable-safe. Python audit hooks are not an OS sandbox; the OS sandbox is currently macOS-specific. The synthetic benchmark confirms that known values can cross the runtime gate. The fixture oracle used in evaluation is not a production component. A detached human-review protocol is prepared, but its result remains `not_collected`.

## Build evidence

Runtime, development, and security-tool inputs are hash-locked in separate files. CI installs them with `--require-hashes` and binary-only resolution, runs an offline stub suite, performs a high-confidence secret scan and `pip-audit`, and generates a CycloneDX SBOM. Tagged release builds use GitHub artifact attestations. Branch protection requires the Python 3.11/3.12 test jobs and the dependency/SBOM job before `main` can advance. These controls improve provenance and reviewability; they do not prove that a dependency or build runner is uncompromised.

## Outside V1

OCR, images, audio, malware scanning, encrypted persistence, multi-user identity and authorization, regulatory certification, provider-side guarantees, and protection from a privileged local attacker are not implemented.
