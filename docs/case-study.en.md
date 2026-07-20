# Case study: local pseudonymization before a cloud-model call

## Context

A personal assistant can send both its instructions and a document to a provider. Either field may contain names, contact details, addresses, identifiers, or credentials. The question for this exercise was narrow: can a local stage remove known values, show the outgoing content, and restore only values from the same request?

## Implementation

LM Studio proposes exact sensitive substrings as structured JSON. Python checks that every value occurs verbatim in the combined task and document, replaces values longest first, and assigns operation-scoped tokens. A second detector scans the resulting fields for selected explicit formats. The mapping remains in process memory and is deleted after completion, failure, block, expiry, or explicit deletion.

The Web UI stops at `READY_FOR_REVIEW`. With no provider key it completes as a dry-run. If OpenAI is configured, the response is treated as untrusted: any unknown or altered `__PII_` fragment blocks restoration.

## Test material

- 30 synthetic documents: 15 Russian and 15 English;
- two installed local models: `qwen/qwen3.5-9b` and `google/gemma-4-e4b`;
- 52 offline tests for redaction, token handling, mapping lifetime, loopback enforcement, logs, file limits, provider limits, API behavior, and stubbed round trips;
- per-case JSON with status and elapsed time;
- Web UI screenshot, architecture note, security limits, and a disabled Gosha adapter.

The fixtures contain no real personal data or usable credentials. The benchmark did not call a cloud provider.

## Result from the published run

| Metric | Qwen | Gemma |
|---|---:|---:|
| Entity recall | 0.7037 | 0.7593 |
| Detection failures | 4 | 0 |
| Runtime gate passes | 23 | 26 |
| Known-control leaks after runtime gate | 0 | 4 |
| Fixture-oracle passes | 23 | 22 |
| Median latency | 1.948 s | 1.014 s |

The critical result is not the oracle's zero known values. The runtime gate caught the labelled Qwen controls in this run but missed four Gemma cases. The fixture oracle stopped them because it had access to the expected answers; an arbitrary document has no such oracle.

Qwen's four failures were values that did not match an exact input substring. They were blocked before replacement. There were no invalid JSON/schema outputs in this run. Gemma had higher recall and lower median latency, but four known controls crossed the runtime gate.

## Decision

The project is suitable as a demonstrator and as a dry-run inspection tool. It is not ready to authorize automatic provider calls for high-risk documents. The Gosha integration remains disabled. A next iteration would need a stronger, independently evaluated detector and an explicit policy for the stateless API; adding more reassuring UI language would not address the measured gap.
