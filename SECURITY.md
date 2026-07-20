# Security policy

## Scope and disclosure

PII Airlock is a defensive demonstrator. Do not submit real personal data, credentials, or customer documents in public issues. Report a vulnerability privately through GitHub's security-advisory flow for this repository.

## Security properties in V1

- The HTTP server and LM Studio client accept loopback hosts only.
- The application stores mappings in process memory with a 10-minute TTL and deletes them after completion or dry-run.
- Audit logs contain operation IDs, selected model, entity type counts, status, and error class—not source text, mapping values, prompts, or cloud answers.
- Cloud is off until `OPENAI_API_KEY` is supplied. Requests use the Responses API and `store: false`.
- Exact-substring validation rejects model inventions. Residual rules scan email, phone, supported card/key formats, and contextual identifiers. Cloud output may restore only current-operation tokens.
- CI uses offline stubs and no secrets.

## Known limitations

- A local model can miss semantic PII. Rules are not a universal DLP engine.
- `store: false` is a request parameter, not a replacement for reviewing provider policy.
- Process memory can be inspected by a sufficiently privileged local attacker.
- Clipboard history, OS swap, terminal output deliberately requested by the user, LM Studio internals, and upstream provider infrastructure are outside this repository's control.
- V1 has no authentication because it is loopback-only. Do not expose it through a reverse proxy or LAN binding.
- OCR and image-based documents are rejected, not sanitized.

For high-risk use, keep dry-run enabled, review the exact payload, and use a dedicated machine/account boundary.
