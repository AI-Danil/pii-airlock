# Local detector comparison

Run date: 21 July 2026. Dataset: 52 synthetic documents (`26 ru + 26 en`), including 6 clean controls and 20 adversarial cases. Endpoint: LM Studio `chat/completions`; temperature `0`; JSON schema enabled. The cloud provider was not called. Latency belongs to one local machine and the installed model builds, so it is not a transferable performance claim.

The previous 30-case run is not a baseline for direct comparison. This run expanded the dataset and corrected four oracle values that were not literal source substrings.

| Metric | Qwen 3.5 9B | Gemma 4 E4B |
|---|---:|---:|
| Cases | 52 | 52 |
| Entity recall | 0.8472 | 0.8056 |
| Entity precision | 0.8243 | 0.9062 |
| English recall | 0.8611 | 0.7778 |
| Russian recall | 0.8333 | 0.8333 |
| Extra replacement values | 9 | 4 |
| Detection failures | 11 | 0 |
| Invalid structured-output failures | 0 | 0 |
| Non-exact-substring failures | 11 | 0 |
| Runtime gate passes | 32 | 42 |
| Runtime gate blocks | 9 | 10 |
| Known-control leaks after runtime gate | 0 | 9 |
| Fixture-oracle passes | 32 | 33 |
| Fixture-assisted review projection | 42 | 42 |
| Deterministic restoration checks | 43 | 42 |
| Clean cases without detections | 6 / 6 | 6 / 6 |
| Median latency | 11.053 s | 2.799 s |
| Maximum latency | 20.860 s | 14.254 s |

## What the numbers mean

Qwen found more labelled entities overall, but returned 11 model values that were not exact input substrings. The hybrid path retained deterministic rule spans for inspection; automatic completion stayed blocked until a person would confirm or edit those spans. Gemma returned valid structured output in every case, but nine payloads that passed the runtime gate still contained a labelled value. Qwen was explicitly loaded with a 4,096-token context, one prediction slot, and speculative MTP disabled after the previous local runtime became unresponsive; the benchmark used a 30-second per-case timeout. Gemma was then loaded with the same settings. No timed-out case appears in the published result.

The fixture oracle stopped those nine Gemma payloads because it had the expected answers. An arbitrary document has no such oracle. `Fixture-assisted review projection` goes further: the benchmark applies the fixture labels as redactions and reruns the gate. It shows what the deterministic pipeline would do with perfect labels, not what a real reviewer achieved.

Per-type recall exposes different gaps. Qwen recall was 0.75 for `PERSON`, 0.6667 for `ADDRESS`, 0.5 for `ORG`, and 0.5 for `OTHER_SECRET`. Gemma recall was 0.4375 for `PERSON`, 0.5 for `ORG`, and 0.3333 for `TAX_ID`. Both reached 1.0 recall on the labelled phone and email cases, but that small synthetic slice does not establish general coverage.

The Qwen build placed schema-constrained JSON in `reasoning_content` while leaving `content` empty. The compatibility path parses that JSON and still applies enum, exact-span, and gate checks. Both models remain experimental; neither result supports unattended use on high-risk documents.

Machine-readable per-case output: [`live-combined.json`](live-combined.json). Reproduce with:

```bash
pii-airlock benchmark --models qwen,gemma --timeout 30 --output docs/evaluation/live-combined.json
```

Repeated runs may differ despite temperature `0`. Model builds and hardware can change detection and latency.
