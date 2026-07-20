# Case study: a local privacy airlock for an AI assistant

## Problem

A personal AI assistant benefits from cloud-model quality, yet its instructions and documents can contain names, contacts, identifiers, addresses, and credentials. Sending everything directly creates an avoidable disclosure path. A local model alone is not sufficient evidence because it can miss entities, return invalid JSON, or follow instructions embedded in the document.

## Small, testable intervention

PII Airlock places a local boundary before the cloud. LM Studio proposes exact sensitive substrings. Deterministic code validates and replaces them, a second rule gate inspects the exact outgoing fields, and the default mode stops at a visible dry-run. If cloud use is enabled, only tokens from the same operation may return and be restored.

## Evidence produced

- runnable Web UI, CLI, and local API;
- 30 synthetic documents split equally between Russian and English;
- offline tests for spans, overlap, mapping lifetime, formats, residual secrets, forged tokens, and stubbed round trips;
- live LM Studio comparison with per-case timings and machine-readable results;
- integration adapter for Gosha left behind a disabled feature flag.

## Honest result

The live run did not establish universal anonymization. Both models missed some semantic entities; Qwen also produced schema/exact-substring failures in Russian cases. The dataset-only release oracle therefore blocked unsafe cases. Approved payloads contained zero known control values, but that fact is bounded to the published fixtures and run. Gemma was faster and had no schema failures in this run; it still missed semantic controls and remains experimental.

## Product decision

Keep cloud off by default, preserve human payload review, keep both local models selectable, and treat the gateway as a fail-closed adapter—not a silent guarantee. The next useful experiment is to expand adversarial fixtures and improve semantic detection without weakening exact-substring validation.
