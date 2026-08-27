"""The pinned embit must agree with Bitcoin Knots on every sighash vector.

Deliberately imports embit the ordinary way, with no sys.path manipulation, so
this exercises the dependency actually installed from requirements.txt rather
than whatever happens to be checked out beside it.
"""
import json
import os

import pytest

from embit.script import Script
from embit.transaction import Transaction
from embit import hashes


VECTORS = os.path.join(os.path.dirname(__file__), "data", "unified_sighash.json")
BARE, WITNESS_V0, TAPROOT, TAPSCRIPT = 0, 1, 2, 3


def load():
    with open(VECTORS) as f:
        rows = json.load(f)
    header, rows = rows[0], rows[1:]
    return [dict(zip(header, r)) for r in rows]


def digest(v):
    tx = Transaction.parse(bytes.fromhex(v["rawTx"]))
    values = [amount for amount, _ in v["spentOutputs"]]
    spks = [Script(bytes.fromhex(spk)) for _, spk in v["spentOutputs"]]
    kwargs = {}
    if v["scriptType"] in (BARE, WITNESS_V0):
        kwargs["script_code"] = Script(bytes.fromhex(v["scriptCode"]))
    elif v["scriptType"] == TAPSCRIPT:
        # the vectors carry the leaf script in scriptCode; the leaf hash is
        # derived from it, as Knots' own vector test does
        leaf = Script(bytes.fromhex(v["scriptCode"]))
        kwargs["tapleaf_hash"] = hashes.tagged_hash(
            "TapLeaf", bytes([0xC0]) + leaf.serialize()
        )
    return tx.sighash_unified(
        v["inIdx"], v["scriptType"], spks, values, v["hashType"], **kwargs
    )


def test_vector_file_is_present_and_complete():
    vectors = load()
    assert len(vectors) == 166, f"expected 166 vectors, found {len(vectors)}"
    kinds = {v["scriptType"] for v in vectors}
    assert kinds == {BARE, WITNESS_V0, TAPROOT, TAPSCRIPT}, kinds


@pytest.mark.parametrize("idx", range(166))
def test_vector_matches_knots(idx):
    v = load()[idx]
    assert digest(v).hex() == v["sighash"], (
        f"vector {idx}: scriptType={v['scriptType']} hashType={hex(v['hashType'])}"
    )


def test_a_wrong_script_type_does_not_match():
    """Guards the test itself: if this passed, the check above would be vacuous."""
    v = next(x for x in load() if x["scriptType"] == BARE)
    wrong = dict(v, scriptType=WITNESS_V0)
    assert digest(wrong).hex() != v["sighash"]
