import itertools

import pytest

from browsertrace.parsers.chromium import CORE_TYPES, QUALIFIERS, decode_transition


@pytest.mark.parametrize("code,name", sorted(CORE_TYPES.items()))
def test_every_core_type(code, name):
    assert decode_transition(code) == name


@pytest.mark.parametrize("bit,name", QUALIFIERS)
def test_every_single_qualifier(bit, name):
    assert decode_transition(1 | bit) == f"typed [{name}]"


def test_every_qualifier_combination_round_trips():
    bits = [b for b, _ in QUALIFIERS]
    for r in range(len(bits) + 1):
        for combo in itertools.combinations(QUALIFIERS, r):
            value = 7
            for bit, _ in combo:
                value |= bit
            decoded = decode_transition(value)
            assert decoded.startswith("form_submit")
            for _, name in combo:
                assert name in decoded
            if not combo:
                assert decoded == "form_submit"


def test_typical_typed_from_address_bar():
    # 0x30000001 is not a real combo; 805306368 = chain_start|chain_end, 0x02000000 = from_address_bar
    assert decode_transition(0x02000000 | 0x30000000 | 1) == "typed [from_address_bar, chain_start, chain_end]"


def test_signed_storage_is_handled():
    # Some databases store the unsigned 32-bit value as a negative signed integer.
    value = (0x80000000 | 0x30000000) - (1 << 32)
    assert decode_transition(value) == "link [chain_start, chain_end, server_redirect]"


def test_unknown_core_and_bad_input():
    assert decode_transition(0x55) == "unknown(85)"
    assert decode_transition(None) == ""
    assert decode_transition("x") == ""
