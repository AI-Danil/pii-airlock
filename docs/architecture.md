# Architecture and threat model

## Components and boundaries

| Component | Location | Trust assumption |
|---|---|---|
| File parser, redaction, mapping, gate, restoration | Python process | Local process; contains raw data temporarily |
| LM Studio detector | `127.0.0.1:1234` | Local but fallible; output is validated |
| Source document | Local input | Untrusted data; may contain prompt injection or token-like text |
| Provider | HTTPS endpoint | Untrusted output; receives pseudonymized fields only after runtime checks |
| Caller/operator | Web UI, CLI, or API | Chooses whether review is sufficient for the intended use |

The source task and document are analysed together so one mapping can cover both, then they are redacted as separate fields. The API returns `outbound_content.instructions` and `outbound_content.input_text`; those same strings are passed to the provider client. The OpenAI client adds the configured model and `store: false`.

Values are sorted by decreasing length before replacement. Equal values reuse a token within the operation. New operations use a 32-hex-character nonce (128 random bits). The application does not serialize mappings.

## Operation states

```mermaid
stateDiagram-v2
    [*] --> Analysing
    Analysing --> Blocked: detector error or residual rule match
    Analysing --> ReadyForReview: deterministic checks found no recognised residual
    Blocked --> Destroyed: mapping removed immediately
    ReadyForReview --> Destroyed: delete or TTL expiry
    ReadyForReview --> ProviderCall: caller completes operation
    ProviderCall --> Destroyed: dry-run, success, timeout, provider error, or bad token
```

`READY_FOR_REVIEW` is deliberately not named `SAFE_TO_SEND`: the detector can omit sensitive values. The Web UI requires an explicit review action. The stateless API route is automated, so its caller must supply an external policy if human review is required.

## Failure handling

| Condition | Result |
|---|---|
| LM Studio unavailable, timeout, HTTP error, oversized or invalid response | Request blocked; no provider call |
| Model returns a value not present verbatim in the input | Request blocked |
| Recognised residual value or no detected entity | Request blocked; mapping discarded |
| Source contains any reserved token prefix | Request blocked |
| Remote HTTP client | `403`; request is not processed |
| Provider alters, invents, truncates, or changes case of a PII token | Answer blocked; mapping discarded |
| Provider timeout, HTTP error, invalid or oversized response | Error returned; mapping discarded |

## Threat coverage

The design reduces accidental disclosure when the detector and residual rules find the relevant value. It also handles model fabrication, parser size abuse, a source-token collision, provider-token injection, stale mappings, and raw values in the application's own structured audit calls.

It does not solve detector recall. The synthetic benchmark confirms that known values can cross the runtime gate. The fixture oracle used in evaluation is not a production component.

## Outside V1

OCR, images, audio, malware scanning, encrypted persistence, multi-user authentication, regulatory certification, provider-side guarantees, and protection from a privileged local attacker are not implemented.
