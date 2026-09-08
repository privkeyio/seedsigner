"""The card path, driven with a PSBT that asks for the unified opt-in.

The applet is handed 32 bytes and signs them blind, so nothing on the card decides
which message it just committed to. The digest and the byte appended to the signature
are both chosen on this side, and these tests hold that side to what the approval
screen named: the signature must verify against the unified message and must not
verify against the standard one.
"""
from base64 import b64decode

import pytest
from unittest.mock import patch

from embit.ec import PublicKey, Signature
from embit.psbt import PSBT, SIGHASH

from seedsigner.helpers.keycard_signer import sign_psbt_with_keycard
from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings import Settings, SettingsConstants

import test_flows_unified
from test_flows_unified import _root, _seed


class NoDummies:
    """The real settings with the chosen-nonce obfuscation turned off, so a test
    observes only the signatures the PSBT asked for. Everything else is delegated:
    the Controller reads settings this knows nothing about."""

    def __init__(self, real):
        self.real = real

    def get_value(self, setting, *args, **kwargs):
        if setting in (SettingsConstants.SETTING__SATOCHIP_SIGN_TIMEOUT,
                       SettingsConstants.SETTING__KEYCARD_SIGN_TIMEOUT):
            return 5
        if "dumm" in str(setting):
            return 0
        return self.real.get_value(setting, *args, **kwargs)


class Card:
    """A card holding the same keys as the seed, signing whatever 32 bytes it is handed.

    `card_sign_transaction_hash` names no key on either applet, so the key comes from
    the last path the caller selected: the Satochip signer selects by deriving, the
    Keycard signer by setting `_last_path` on the connector.
    """

    _last_path = None

    def __init__(self, root):
        self.root = root
        self.path = "m"
        self.hashes = []

    def card_bip32_get_extendedkey(self, path):
        self.path = path
        return _CardKey(self.root.derive(path)), b""

    def card_sign_transaction_hash(self, keynbr, digest, _pin):
        digest = bytes(digest)
        self.hashes.append(digest)
        key = self.root.derive(self._last_path or self.path).key
        return (key.sign(digest).serialize(), 0x90, 0x00)


class _CardKey:
    def __init__(self, hdkey):
        self.hdkey = hdkey

    def get_public_key_bytes(self, compressed=True):
        return self.hdkey.key.get_public_key().sec()


def _psbt(declared):
    psbt = PSBT.parse(b64decode(test_flows_unified.TestUnifiedSighashFlow.UNIFIED_PSBT))
    for inp in psbt.inputs:
        inp.sighash_type = declared
    return psbt


def _signatures(psbt):
    return [(i, key, bytes(sig))
            for i, inp in enumerate(psbt.inputs)
            for key, sig in inp.partial_sigs.items()]


@pytest.fixture(autouse=True)
def no_dummies(monkeypatch):
    stub = NoDummies(Settings.get_instance())
    monkeypatch.setattr(Settings, "get_instance", classmethod(lambda cls: stub))


@pytest.mark.parametrize("signer", [sign_psbt_with_satochip, sign_psbt_with_keycard])
@pytest.mark.parametrize("declared,expected", [
    (None, SIGHASH.ALL),
    (SIGHASH.ALL, SIGHASH.ALL),
    (SIGHASH.UNIFIED | SIGHASH.ALL, SIGHASH.UNIFIED | SIGHASH.ALL),
])
def test_the_card_signs_the_message_the_screen_named(signer, declared, expected):
    psbt = _psbt(declared)

    # The view's own decision, with no seed, which is what card-backed signing passes.
    shown, reason = PSBTParser.screen_sighash_type(psbt, None)
    assert shown == expected, f"screen would say {shown}, expected {hex(expected)}"

    result = signer(psbt, Card(_root()), sighash=shown)
    assert result.signed_count == len(psbt.inputs)

    produced = _signatures(psbt)
    assert len(produced) == len(psbt.inputs)
    for i, key, sig in produced:
        assert sig[-1] == shown, \
            f"input {i} carries {hex(sig[-1])}, screen said {hex(shown)}"
        assert PublicKey.parse(key.sec()).verify(
            Signature.parse(sig[:-1]), psbt.sighash(i, sighash=shown)), \
            f"input {i} does not verify against the message the screen named"


@pytest.mark.parametrize("signer", [sign_psbt_with_satochip, sign_psbt_with_keycard])
def test_a_unified_signature_is_not_a_standard_one(signer):
    """The point of the opt-in. Signing the standard message here would produce a
    signature valid on both rule sets, which is the replay the opt-in exists to stop,
    and nothing on the card would notice."""
    psbt = _psbt(SIGHASH.UNIFIED | SIGHASH.ALL)
    card = Card(_root())

    signer(psbt, card, sighash=SIGHASH.UNIFIED | SIGHASH.ALL)

    for i, key, sig in _signatures(psbt):
        standard = psbt.sighash(i, sighash=SIGHASH.ALL)
        unified = psbt.sighash(i, sighash=SIGHASH.UNIFIED | SIGHASH.ALL)
        assert standard != unified, "the fixture proves nothing if both messages agree"
        assert standard not in card.hashes, \
            f"input {i}: the card was handed the standard message"
        assert unified in card.hashes
        assert not PublicKey.parse(key.sec()).verify(Signature.parse(sig[:-1]), standard)


@pytest.mark.parametrize("signer", [sign_psbt_with_satochip, sign_psbt_with_keycard])
def test_without_the_hash_type_the_card_signs_the_standard_message(signer):
    """What the fork did before, and what it still does for a PSBT that asks for
    nothing: the default is the standard message, so this change is visible only where
    a PSBT opts in."""
    psbt = _psbt(None)
    card = Card(_root())

    signer(psbt, card)

    for i, _key, sig in _signatures(psbt):
        assert sig[-1] == SIGHASH.ALL
        assert psbt.sighash(i, sighash=SIGHASH.ALL) in card.hashes


def test_the_seed_and_the_card_reach_the_same_decision():
    """The screen is one function for both paths. With no seed it cannot recognise an
    input as ours, so it decides on the whole transaction; for this PSBT, whose inputs
    all belong to the seed, both readings have to agree."""
    for declared in (None, SIGHASH.ALL, SIGHASH.UNIFIED | SIGHASH.ALL):
        psbt = _psbt(declared)
        assert PSBTParser.screen_sighash_type(psbt, _seed()) \
            == PSBTParser.screen_sighash_type(psbt, None)


def test_the_finalize_view_names_it_on_the_card_path(monkeypatch):
    """Through PSBTFinalizeView, with the parser the card flow actually builds: an xpub,
    no seed. The screen has to name the type before the card is asked for anything, and
    the same value has to reach the signer."""
    from embit.bip32 import parse_path

    from seedsigner.controller import Controller
    from seedsigner.views import psbt_views

    root = _root()
    account = parse_path("m/84h/1h/0h")
    psbt = _psbt(SIGHASH.UNIFIED | SIGHASH.ALL)

    controller = Controller.get_instance()
    controller.psbt = psbt
    controller.psbt_seed = None
    controller.psbt_sign_with_satochip = True
    controller.psbt_parser = PSBTParser(
        psbt, seed=None, root=root.derive(account).to_public(), root_path=account,
        master_fingerprint=root.my_fingerprint, network=SettingsConstants.MAINNET)

    asked_for = []

    def fake_signer(signing_psbt, connector, timeout=None, sighash=SIGHASH.ALL):
        asked_for.append(sighash)
        return sign_psbt_with_satochip(signing_psbt, connector, timeout=timeout, sighash=sighash)

    monkeypatch.setattr("seedsigner.helpers.seedkeeper_utils.init_satochip",
                        lambda view, init_card_filter=None: Card(root))
    monkeypatch.setattr("seedsigner.helpers.satochip_signer.sign_psbt_with_satochip", fake_signer)

    with patch("seedsigner.views.view.View.run_screen") as run_screen:
        run_screen.return_value = 0  # the user approves
        destination = psbt_views.PSBTFinalizeView().run()

    shown = run_screen.call_args_list[0].kwargs["sighash_type"]
    assert shown == SIGHASH.UNIFIED | SIGHASH.ALL
    assert asked_for == [shown], "the card was asked for something other than what the screen said"
    assert destination.View_cls is psbt_views.PSBTSignedQRDisplayView
    assert PSBTParser.sig_count(controller.psbt) == len(controller.psbt.inputs)
