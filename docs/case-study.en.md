# Case study: a local privacy gate before a cloud-model call

## The narrow problem

A personal assistant may send both its task instructions and a document to a provider. Either field can contain names, contacts, identifiers, addresses, or credentials. This project tests one bounded question: can a local process replace selected source spans, show the exact outbound request, and restore only values from that operation?

It does not claim to anonymize arbitrary documents. The runtime benchmark still contains labelled values that cross the implemented gate.

## What was built

Deterministic rules and LM Studio propose spans. The rules normalize selected Unicode and zero-width obfuscations while retaining a map back to the exact source offsets. Model output must use the declared types and literal source substrings. Python resolves overlaps longest-first, creates random operation-scoped tokens only for spans actually used, and runs a residual scan.

The Web UI exposes value-free span metadata and lets a reviewer add, remove, or retag exact selections. A semantic-model failure preserves deterministic findings but blocks completion until they are confirmed. Prompt-like text is shown as a warning; the unattended stateless route blocks it. Provider instructions place the task and document in separate untrusted-content delimiters and prohibit treating document text as an action request.

Mappings live only in process memory. A ten-minute sweeper removes abandoned operations, the pending store is limited to 100, and completion atomically claims an operation before the provider attempt. This gives at-most-once calling, not guaranteed delivery or automatic retry. DOCX and PDF extraction runs in short-lived worker processes with time, size, expansion, page, and object limits.

The cloud response remains untrusted. Unknown, altered, incomplete, or over-repeated PII tokens block restoration. Only exact tokens belonging to the claimed operation can be restored.

## Evidence produced

- 52 synthetic documents: 26 Russian and 26 English; 6 clean controls and 20 tagged adversarial cases;
- live local runs of `qwen/qwen3.5-9b` and `google/gemma-4-e4b`, with no cloud call;
- 87 offline tests covering redaction, review edits, Unicode obfuscation, prompt boundaries, parser limits, at-most-once completion, TTL, authentication, token auditing, logs, and stubbed round trips;
- exact dependency locks, a high-confidence secret scan, dependency audit, CycloneDX SBOM workflow, and release-attestation workflow;
- a disabled, fail-closed Gosha adapter that requires bearer authentication and a token-audit result.

The fixtures contain no real personal data or usable credentials. The earlier 30-case numbers are not comparable because the dataset changed and four invalid oracle spans were corrected.

## Live result, 21 July 2026

| Metric | Qwen | Gemma |
|---|---:|---:|
| Entity recall | 0.8472 | 0.8056 |
| Entity precision | 0.8243 | 0.9062 |
| Detection failures | 11 | 0 |
| Runtime gate passes | 32 | 42 |
| Known-control leaks after runtime gate | 0 | 9 |
| Fixture-oracle passes | 32 | 33 |
| Fixture-assisted review projection | 42 | 42 |
| Clean cases without detections | 6 / 6 | 6 / 6 |
| Median latency | 11.053 s | 2.799 s |

Qwen's 11 failures were non-exact proposals. Deterministic findings survived for review, but the automatic path stayed blocked. Gemma had no schema failure, yet nine labelled values crossed the runtime gate. The fixture oracle stopped them because it knew the labels; real documents do not come with that oracle.

The review projection is also synthetic: it applies fixture labels as manual spans. It demonstrates the deterministic redaction path with ideal corrections, not reviewer speed or accuracy.

## Decision

PII Airlock is useful as a transparent demonstrator and a dry-run review tool. It is not evidence that unattended cloud calls are safe for high-risk documents. Both local models remain experimental, and the Gosha feature flag stays off. The next useful evidence would come from independent human review on a versioned synthetic set and explicit policy thresholds, not from stronger marketing language.
