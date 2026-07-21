# Security policy

Do not attach real personal data, credentials, or customer documents to a public issue. Use GitHub's private security-advisory flow to report a vulnerability in this repository.

## Implemented controls

- The packaged server binds to loopback. The ASGI application validates the client address and `Host`; a supplied `Origin` must match the request origin exactly.
- Browser writes require a random HttpOnly, SameSite=Strict session cookie plus `Origin`. Machine writes require `Authorization: Bearer`; `/api/v1/complete` is disabled unless `PII_AIRLOCK_API_TOKEN` contains at least 32 characters.
- LM Studio accepts only loopback URLs. A cloud base URL must use HTTPS, except for an explicit loopback test endpoint.
- A mapping exists only in process memory. One background sweeper removes it after at most ten minutes without needing another request. Completion atomically claims the operation; concurrent completion attempts cannot repeat a provider call. This is at-most-once, not guaranteed retry or exactly-once delivery. The pending store is capped at 100 operations.
- Generated tokens use a 128-bit random nonce. Any `__PII_` fragment already present in source text is rejected.
- Deterministic rules normalize selected Unicode, whitespace, line-break, and zero-width obfuscations while retaining exact source offsets. Model-proposed values must be exact input substrings. Candidate spans are selected longest first within each field, then replaced by offset; nested unused values are not retained in the mapping. Public span metadata omits the source value. Manual review mutations require the unchanged source snapshot and exact offsets.
- A rules-based scan checks the outbound fields. No detected entity and any recognized residual value cause a block.
- Source task and document are delimited as untrusted content in provider instructions. Prompt-like text is warned in the Web UI and blocks the unattended stateless route. This boundary is a control against instruction confusion, not a sandbox.
- A provider response may contain only exact tokens from the current operation and may not repeat a known token more often than the outbound request did. Unknown, incomplete, case-changed, over-repeated, or otherwise altered PII-token fragments block restoration.
- HTTP request bodies are capped at 5 MiB + 64 KiB before application parsing. Uploaded files are read only up to 5 MiB + 1 byte. LM Studio and provider responses are capped at 2 MB; DOCX expansion at 25 MB; PDF pages at 100; extracted text at 20,000 characters. DOCX and PDF parsing runs in short-lived spawned processes with wall-clock, CPU, address-space, archive-member, expansion-ratio, page, and object limits where the platform exposes them.
- Application audit logs contain operation ID, model ID, entity counts, status, and error class. The logging calls do not include source text, mappings, prompts, or provider answers.
- The OpenAI client sends `store: false`. CI uses stubs and no model or provider credentials. Runtime and development dependencies are exactly pinned; CI scans high-confidence secret formats, audits runtime packages, emits a CycloneDX SBOM, and creates build-provenance attestations for tagged release artifacts.

## Limits

The detector is incomplete. In the published 52-case run, the runtime gate passed nine Gemma payloads that still contained a known labelled control. It passed no such Qwen case, but Qwen had 11 non-exact model proposals that blocked automatic completion. A fixture-only oracle stopped the nine Gemma cases, but that oracle is unavailable for arbitrary documents.

The rules are not a general DLP system. They cover selected formats and can miss names, addresses, organizations, unlabelled identifiers, novel credentials, and values split by parsing. A local model may also follow an instruction embedded in a document. Exact-substring validation prevents fabricated replacements; it does not prevent omissions.

Other limits:

- `store: false` is a request option, not a statement about every provider or account policy.
- A privileged local process can inspect memory, swap, clipboard history, terminal output, or LM Studio state.
- The bearer/session checks are a local single-user boundary, not multi-user identity or authorization. Do not place the service behind a reverse proxy or expose it to a LAN.
- Unicode canonicalization covers selected patterns, not every homoglyph, bidirectional-control trick, rendering ambiguity, or parser discrepancy.
- OS-enforced process limits vary by platform. Parser isolation reduces blast radius but is not a malware sandbox.
- OCR, images, audio, malware scanning, encrypted persistence, regulatory certification, and protection from a compromised host are outside V1.

For real high-risk material, keep the provider disabled and use independently reviewed controls. `READY_FOR_REVIEW` must not be treated as an authorization decision.
