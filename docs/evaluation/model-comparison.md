# Live model comparison

Run date: 2026-07-20. Hardware and LM Studio configuration are local to the author's machine; no cross-device performance claim is made. Dataset: 30 synthetic cases (`15 ru + 15 en`). Temperature: `0`. Endpoint: LM Studio OpenAI-compatible `chat/completions` with JSON schema. Cloud was not called.

| Metric | Qwen 3.5 9B | Gemma 4 E4B |
|---|---:|---:|
| Approved cloud payloads / 30 | 25 | 25 |
| Control-secret leaks in approved payloads | 0 | 0 |
| Entity-level recall | 0.6667 | 0.7593 |
| Extra replacement values | 5 | 4 |
| Schema/exact-substring failures | 4 | 0 |
| Runtime gate failures | 0 | 0 |
| Dataset release blocks | 1 | 5 |
| Round-trip fidelity cases | 26 | 30 |
| Median case time | 2.556 s | 1.567 s |
| Maximum case time | 6.182 s | 4.116 s |

Both models are **experimental**. Zero approved-payload leaks means the fixture oracle withheld any payload still containing a known expected value; it does not mean unseen documents are safe. Qwen required a compatibility path because this local reasoning build placed schema-constrained JSON in `reasoning_content` while leaving `content` empty. That JSON is still parsed and subjected to the same schema, enum, and exact-substring validation.

Raw per-case evidence: [`qwen.json`](qwen.json) and [`gemma.json`](gemma.json). Reproduce with `pii-airlock benchmark --models qwen,gemma`; results may vary across model builds and hardware.
