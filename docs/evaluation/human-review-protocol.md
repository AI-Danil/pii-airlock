# Independent human review protocol

Status: infrastructure ready; no independent human labels or human-derived metrics have been collected.

## Purpose

The published fixture oracle was written together with the synthetic cases. It is useful for regression tests but is not independent evidence. This protocol produces a detached bundle with no labels or original case IDs, accepts exact entity labels from a second person, and scores model predictions only after the review is frozen.

## Procedure

1. Generate a bundle with a fresh confidential salt. Do not send the repository, salt, fixture file, or benchmark output to the reviewer.
2. Give the reviewer only `blind-items.jsonl`, `review-template.jsonl`, this protocol, and the entity-type definitions.
3. The reviewer records exact source substrings and types. Empty cases must remain present with an empty `entities` array.
4. Freeze and hash the completed review before running or exposing candidate predictions.
5. Score predictions with `scripts/score_human_review.py`. Keep the complete per-case output; do not publish only an aggregate.
6. A second reviewer is required for disagreements or any case used to justify an automatic high-risk release gate.

## Pre-registered release policy

- zero labelled sensitive values may remain in a payload accepted by the runtime gate;
- the lower bound of the 95% Wilson interval for overall entity recall must be at least 0.95;
- `PASSPORT`, `TAX_ID`, `CARD`, `API_KEY`, and `OTHER_SECRET` require observed recall of 1.0 with at least 20 independently labelled examples per type;
- every model/schema error is a blocked case, never a skipped case;
- fixture-assisted review projections do not count as human-review results.

The current 52-case bundle is a pilot and does not contain 20 examples of every high-risk type. It therefore cannot satisfy the release policy even if all pilot items are labelled correctly.

## Commands

```bash
python scripts/export_blind_review.py \
  --fixtures fixtures/synthetic_cases.jsonl \
  --output-dir review-bundle \
  --salt "fresh-confidential-random-value" \
  --version v1

python scripts/score_human_review.py \
  --items review-bundle/blind-items.jsonl \
  --human completed-review.jsonl \
  --predictions frozen-predictions.jsonl \
  --output human-review-report.json
```

Do not infer a result from the empty review template. Until a second person completes the bundle, the only honest status is `not_collected`.
