# Security policy

Do not attach real personal data, credentials, or customer documents to a public issue. Use GitHub's private security-advisory flow to report a vulnerability in this repository.

## Implemented controls

- The packaged server binds to loopback. The ASGI application validates the client address and `Host`; a supplied `Origin` must match the request origin exactly.
- Browser writes require a random HttpOnly, SameSite=Strict session cookie plus `Origin`. Machine writes require `Authorization: Bearer`; `/api/v1/complete` is disabled unless `PII_AIRLOCK_API_TOKEN` contains at least 32 characters.
- LM Studio accepts only loopback URLs. A cloud base URL must use HTTPS, except for an explicit loopback test endpoint.
- A mapping exists only in process memory. One background sweeper removes it after at most ten minutes without needing another request. Completion atomically claims the operation; concurrent completion attempts cannot repeat a provider call. The pending store is capped at 100 operations.
- Generated tokens use a 128-bit random nonce. Any `__PII_` fragment already present in source text is rejected.
- Proposed values must be exact input substrings. Candidate spans are selected longest first within each field, then replaced by offset; nested unused values are not retained in the mapping. Public span metadata omits the source value.
- A rules-based scan checks the outbound fields. No detected entity and any recognized residual value cause a block.
- A provider response may contain only exact tokens from the current operation. Unknown, incomplete, case-changed, or otherwise altered PII-token fragments block restoration.
- HTTP request bodies are capped at 5 MiB + 64 KiB before application parsing. Uploaded files are read only up to 5 MiB + 1 byte. LM Studio and provider responses are capped at 2 MB; DOCX expansion at 25 MB; PDF pages at 100; extracted text at 20,000 characters.
- Application audit logs contain operation ID, model ID, entity counts, status, and error class. The logging calls do not include source text, mappings, prompts, or provider answers.
- The OpenAI client sends `store: false`. CI uses stubs and no model or provider credentials.

## Limits

The detector is incomplete. In the published 30-case run, the runtime gate caught the known Qwen controls but passed four Gemma payloads that still contained a known labelled control. A fixture-only oracle stopped those four cases, but that oracle is unavailable for arbitrary documents.

The rules are not a general DLP system. They cover selected formats and can miss names, addresses, organizations, unlabelled identifiers, novel credentials, and values split by parsing. A local model may also follow an instruction embedded in a document. Exact-substring validation prevents fabricated replacements; it does not prevent omissions.

Other limits:

- `store: false` is a request option, not a statement about every provider or account policy.
- A privileged local process can inspect memory, swap, clipboard history, terminal output, or LM Studio state.
- The bearer/session checks are a local single-user boundary, not multi-user identity or authorization. Do not place the service behind a reverse proxy or expose it to a LAN.
- OCR, images, audio, malware scanning, encrypted persistence, regulatory certification, and protection from a compromised host are outside V1.

For real high-risk material, keep the provider disabled and use independently reviewed controls. `READY_FOR_REVIEW` must not be treated as an authorization decision.
