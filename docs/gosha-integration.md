# Gosha integration

PII Airlock stays an independent service. Gosha does not copy its detection/redaction logic; a thin loopback client calls `POST /api/v1/complete` with both `instructions` and `input_text`, allowing one operation-scoped mapping to cover both fields.

```dotenv
GOSHA_PRIVACY_GATEWAY_ENABLED=false
GOSHA_PRIVACY_GATEWAY_URL=http://127.0.0.1:8787
GOSHA_PRIVACY_GATEWAY_TIMEOUT=180
```

The adapter validates that the URL is loopback-only. When enabled, a gateway error raises the existing Gosha LLM error and never falls through to direct OpenAI. The existing local fallback remains the caller's responsibility. A dry-run response is not treated as a completed generation because it has no restored cloud answer.

The initial integration was deliberately left local and disabled. Its dedicated tests cover restored output, no direct OpenAI call through the enabled gateway, fail-closed behavior, and unchanged direct behavior when the flag is off.
