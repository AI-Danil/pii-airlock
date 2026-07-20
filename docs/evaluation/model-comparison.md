# Local detector comparison

Run date: 20 July 2026. Dataset: 30 synthetic documents (`15 ru + 15 en`). Endpoint: LM Studio `chat/completions`; temperature `0`; JSON schema enabled. No cloud provider was called. Hardware and model-build details are local to the author's machine, so latency is not transferable to another setup.

| Metric | Qwen 3.5 9B | Gemma 4 E4B |
|---|---:|---:|
| Cases | 30 | 30 |
| Entity recall | 0.7037 | 0.7593 |
| Extra replacement values | 5 | 4 |
| Detection failures | 4 | 0 |
| Invalid structured-output failures | 0 | 0 |
| Non-exact-substring failures | 4 | 0 |
| Runtime gate passes | 23 | 26 |
| Runtime gate blocks | 3 | 4 |
| Known-control leaks after runtime gate | 0 | 4 |
| Fixture-oracle passes | 23 | 22 |
| Known controls in fixture-oracle passes | 0 | 0 |
| Deterministic restoration checks | 23 | 26 |
| Median latency | 1.948 s | 1.014 s |
| Maximum latency | 4.152 s | 15.628 s |

## Interpretation

The runtime gate caught every known Qwen control in this run, but four Gemma payloads passed the implemented checks while still containing an expected sensitive value. The benchmark stopped those four payloads with its fixture oracle. This extra oracle compares output against labels in the test dataset and is unavailable for normal documents.

`Fixture-oracle passes` is therefore an evaluation count, not a count of payloads approved for real cloud use. The zero in `Known controls in fixture-oracle passes` only establishes that the labelled fixtures withheld known residual values.

Qwen produced four values that were not exact input substrings. They were rejected before pseudonymization. Neither model produced invalid JSON/schema output in this run. Gemma had higher recall and lower median latency, but four labelled leaks crossed the runtime gate. Neither result supports automatic use on high-risk documents.

The Qwen build returned its schema-constrained JSON in `reasoning_content` with an empty `content` field. The compatibility path parses the same JSON and applies enum and exact-substring validation before accepting it.

Machine-readable per-case output: [`live-combined.json`](live-combined.json). Reproduce with:

```bash
pii-airlock benchmark --models qwen,gemma --output docs/evaluation/live-combined.json
```

Repeated runs may differ despite temperature `0`, and model builds or hardware can change both detection and latency.
