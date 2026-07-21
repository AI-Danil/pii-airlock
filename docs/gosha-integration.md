# Gosha integration

PII Airlock runs as a separate loopback service. Gosha's adapter sends `instructions`, `input_text`, and `input_trust: untrusted` to `POST /api/v1/complete`; both text fields share one operation mapping. Detection and redaction code are not copied into Gosha.

```dotenv
GOSHA_PRIVACY_GATEWAY_ENABLED=false
GOSHA_PRIVACY_GATEWAY_URL=http://127.0.0.1:8787
GOSHA_PRIVACY_GATEWAY_TOKEN=
GOSHA_PRIVACY_GATEWAY_TIMEOUT=180
```

`GOSHA_PRIVACY_GATEWAY_TOKEN` must equal the Airlock process's `PII_AIRLOCK_API_TOKEN` and contain at least 32 characters. The adapter sends it only in the bearer header. When the feature flag is on, a missing token or any gateway error does not fall through to a direct OpenAI request. A dry-run response is rejected because it contains no restored provider answer. A completed response is also rejected unless it contains a structured token audit with observed counts and omitted-token data. With the flag off, the existing provider path is unchanged.

The adapter and its tests remain local to the private Gosha checkout. The flag remains off because the published benchmark found known controls that passed the runtime gate. The stateless endpoint now blocks prompt-like source instructions, but it still has no human span review. Enabling it needs an explicit acceptance policy and separate evidence; a successful HTTP response is not that policy.
