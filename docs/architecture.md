# Architecture and threat model

## Trust boundaries

1. **Local trusted process:** document parsing, LM Studio call, deterministic redaction, mapping, release gate, and restoration.
2. **Untrusted document:** its text may include prompt injection. It is delimited as data and cannot bypass deterministic substring checks.
3. **Untrusted cloud:** receives only the approved pseudonymized task and document. Its answer must preserve exact operation tokens.
4. **Local operator:** decides whether to configure a cloud key and can inspect the exact dry-run payload.

The mapping is a Python in-memory dictionary tied to a random eight-hex nonce. A repeated exact value reuses one token inside the operation. Values are sorted longest-first so an inner span cannot overwrite an accepted longer span. The mapping is never serialized by application code.

## Failure policy

| Failure | Result |
|---|---|
| LM Studio unavailable/timeout | `BLOCKED`; no cloud call |
| Invalid schema or invented value | `BLOCKED`; no cloud call |
| Residual high-confidence secret | `BLOCKED`; no cloud call |
| No entity detected | Manual-review block |
| Source contains reserved token | `BLOCKED` |
| Cloud changes or invents token | Result blocked; mapping destroyed |
| Cloud timeout/error | Error returned; mapping destroyed |

## Data flow

`instructions` and `input_text` are detected together, then pseudonymized as separate fields with one mapping. The exact sanitized fields shown in UI/API are the cloud-bound data. `PRESERVE_TOKENS` is prepended only after redaction and contains no source data.

## Threats considered

- accidental cloud disclosure from missed email, phone, supported cards and key formats;
- local-model hallucination or invalid JSON;
- prompt injection inside the source document;
- collisions/replay with pre-existing PII-like tokens;
- token injection or mutation by the cloud;
- mappings surviving longer than a request;
- sensitive data appearing in normal application logs.

## Non-goals

Universal de-identification, OCR, image/audio handling, malware scanning, encrypted persistence, multi-user authentication, regulatory certification, and protection from a privileged local attacker are outside V1.
