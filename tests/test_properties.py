from __future__ import annotations

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from pii_airlock import documents
from pii_airlock.models import AirlockError, EntityType, TokenMode, UnknownTokenError
from pii_airlock.redaction import RESERVED_TOKEN_PREFIX, redact_spans, restore_text


@given(
    st.lists(
        st.text(alphabet=st.characters(min_codepoint=65, max_codepoint=122), min_size=1, max_size=8),
        min_size=1,
        max_size=8,
    )
)
def test_opaque_span_redaction_round_trips_without_type_or_equality_linkage(values: list[str]) -> None:
    # The alphabet can spell the reserved prefix; such input is refused by
    # design and is covered by test_redaction, not by this round trip.
    assume(all(RESERVED_TOKEN_PREFIX.casefold() not in value.casefold() for value in values))
    text = "|".join(values)
    spans = []
    cursor = 0
    for value in values:
        spans.append((cursor, cursor + len(value), EntityType.PERSON))
        cursor += len(value) + 1
    result = redact_spans(
        {"text": text},
        {"text": spans},
        nonce="A1B2C3D4",
        token_mode=TokenMode.OPAQUE,
    )
    assert restore_text(result.sanitized_fields["text"], result.mapping) == text
    assert len(result.mapping) == len(values)
    assert all("PERSON" not in token for token in result.mapping)


@given(st.sampled_from(list(TokenMode)))
def test_mutated_token_fragments_always_fail_closed(token_mode: TokenMode) -> None:
    result = redact_spans(
        {"text": "Elena"},
        {"text": [(0, 5, EntityType.PERSON)]},
        nonce="A1B2C3D4",
        token_mode=token_mode,
    )
    token = next(iter(result.mapping))
    forged = token.replace("__PII_", "__PII_X", 1)
    try:
        restore_text(forged, result.mapping)
    except UnknownTokenError:
        return
    raise AssertionError("A mutated reserved token was accepted.")


@settings(max_examples=30, deadline=None)
@given(st.binary(min_size=1, max_size=2048), st.sampled_from([".docx", ".pdf"]))
def test_binary_parser_fuzz_inputs_fail_closed(data: bytes, suffix: str) -> None:
    try:
        documents._extract_binary_in_process(data, suffix)
    except AirlockError:
        return
    raise AssertionError("Random binary input unexpectedly parsed as a complete supported document.")
