import pytest

from base import FlowTest, FlowStep

from seedsigner.controller import Controller
from seedsigner.views.view import MainMenuView
from seedsigner.views import scan_views, seed_views, psbt_views
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.psbt_parser import PSBTParser

from embit.transaction import SIGHASH


SEED_DIGITS = "080115060387063104071857067618681125136207731354"


def _seed():
    from embit.wordlists.bip39 import WORDLIST

    from seedsigner.models.seed import Seed

    return Seed(mnemonic=[WORDLIST[int(SEED_DIGITS[i:i + 4])] for i in range(0, len(SEED_DIGITS), 4)])


def _root():
    from embit.bip32 import HDKey

    return HDKey.from_seed(_seed().seed_bytes)


class TestUnifiedSighashFlow(FlowTest):
    """The full SeedSigner UI flow, driven with a PSBT that asks for the
    unified opt-in sighash. Same screens as test_flows_psbt, but the signature
    produced must carry hash type 0x21."""

    UNIFIED_PSBT = "cHNidP8BANgCAAAAAsTXZs3fz/dmGb6M80+jjvJZdYya+cw5bT/dGuhZFdSlAAAAAAD9////qo6xg/UZAvUkcbse1F+C9zbP/FeZNjThx7SCIn6eMCgBAAAAAP3///8EQOIBAAAAAAAWABSkZPM7kLcTRE2En1t33/0RCHgMjQXYnnYAAAAAFgAUKMaPRKXdY4m8iKrE9j+rycskJU1A4gEAAAAAABYAFPYc9wiHRrYKAZYLLztREAwpPBIwipVcAwAAAAAWABSiFuiJIa4NrxLUBVQNS0NIun6DDtoRAABPAQQ1h88DBcQGZIAAAAA+0J+jlNL3dpWwlnBi8Dx+Ipg4e6uvB3HdjzFPX7r9CAOOlAIxgII+/xCcj+XoEenKH7wj5s5wlu7Q7CCZWFLGLhA5Su0UVAAAgAEAAIAAAACAAAEA7QIAAAAEE6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0BAAAAAP3///8TqeNf9+e+fuFuQohFzHM1gU5J9sJ015ad3sV7/VRxDQMAAAAA/f///xOp41/3575+4W5CiEXMczWBTkn2wnTXlp3exXv9VHENBAAAAAD9////E6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0GAAAAAP3///8CUnheAwAAAAAWABRCfygPJ+Fjsx4BknYvvm3A3qKn2xJ/XQcAAAAAF6kU1I4TAst5nAj15ey7vwe5cM3OFq+HlhEAAAEBH1J4XgMAAAAAFgAUQn8oDyfhY7MeAZJ2L75twN6ip9sBAwQhAAAAIgYCo7sfm78RQY3B5n0ac/QF8VtMAzFnci+h5D1MtpgRY7oYOUrtFFQAAIABAACAAAAAgAEAAAAGAAAAAAEAcQIAAAABxY7wh0nsfJQfzWrD/9rN9BYsM+iOmPaO6I0ANFgO/PcAAAAAAP3///8CptiUAAAAAAAWABRIm4HhQY/TzOjeWSPRrbuJo9MlW826oHYAAAAAFgAU0z+0L2QSLGtyQTn8FhbCpcI7jbliAQAAAQEfzbqgdgAAAAAWABTTP7QvZBIsa3JBOfwWFsKlwjuNuQEDBCEAAAAiBgITHmebEANk81CraV4xZIpqkNjjw0tIvezl1Ism1NRH3Rg5Su0UVAAAgAEAAIAAAACAAQAAAAAAAAAAIgICuTT7WnuiUTpObjWnZFHzIeEvW9PTB+1LLVFNQJVFeIIYOUrtFFQAAIABAACAAAAAgAEAAAAHAAAAACICAk8f3hpc5C35chgSg+Pe2zZ9IhHREd4aKW2+yAMRIFeqGDlK7RRUAACAAQAAgAAAAIABAAAACQAAAAAAIgIDjt1CjvrnMMnjbmTNKUAYoKEDRbmKjNjbq+6Ppqj3bqQYOUrtFFQAAIABAACAAAAAgAEAAAAIAAAAAA=="

    def test_scan_unified_psbt_and_sign(self):
        def load_psbt_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(self.UNIFIED_PSBT)

        captured = {}

        def capture_signed(view):
            """The controller clears its PSBT on returning to the main menu, so
            grab the signed one while the signed-QR screen still holds it."""
            captured["psbt"] = Controller.get_instance().psbt

        def load_seed_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("080115060387063104071857067618681125136207731354")

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),  # simulate read PSBT; ret val is ignored
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_seed_into_decoder),
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, button_data_selection=0),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTFinalizeView, button_data_selection=psbt_views.PSBTFinalizeView.APPROVE_PSBT),
            FlowStep(psbt_views.PSBTSignedQRDisplayView, before_run=capture_signed),
            FlowStep(MainMenuView)
        ])

        # the flow reached PSBTFinalizeView and signed; check what it produced
        psbt = captured.get("psbt")
        assert psbt is not None, "the signed-QR screen was never reached"
        sigs = [s for inp in psbt.inputs for s in inp.partial_sigs.values()]
        assert sigs, "the flow produced no signatures"
        for s in sigs:
            assert s[-1] == (SIGHASH.ALL | SIGHASH.UNIFIED), \
                f"hash type byte is {hex(s[-1])}, expected 0x21"
        print(f"\n  flow signed {len(sigs)} input(s), every hash type byte 0x21")


class TestMixedSighashFlow(FlowTest):
    """A PSBT whose inputs declare hash types this device cannot ask for at once.

    The device names one hash type for the whole call, so the inputs that disagree
    are skipped. The signature count still goes up, so without a check this reviews
    and reports exactly like a fully signed transaction while producing one that
    cannot be broadcast.
    """

    MIXED_PSBT = "cHNidP8BANgCAAAAAsTXZs3fz/dmGb6M80+jjvJZdYya+cw5bT/dGuhZFdSlAAAAAAD9////qo6xg/UZAvUkcbse1F+C9zbP/FeZNjThx7SCIn6eMCgBAAAAAP3///8EQOIBAAAAAAAWABSkZPM7kLcTRE2En1t33/0RCHgMjQXYnnYAAAAAFgAUKMaPRKXdY4m8iKrE9j+rycskJU1A4gEAAAAAABYAFPYc9wiHRrYKAZYLLztREAwpPBIwipVcAwAAAAAWABSiFuiJIa4NrxLUBVQNS0NIun6DDtoRAABPAQQ1h88DBcQGZIAAAAA+0J+jlNL3dpWwlnBi8Dx+Ipg4e6uvB3HdjzFPX7r9CAOOlAIxgII+/xCcj+XoEenKH7wj5s5wlu7Q7CCZWFLGLhA5Su0UVAAAgAEAAIAAAACAAAEA7QIAAAAEE6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0BAAAAAP3///8TqeNf9+e+fuFuQohFzHM1gU5J9sJ015ad3sV7/VRxDQMAAAAA/f///xOp41/3575+4W5CiEXMczWBTkn2wnTXlp3exXv9VHENBAAAAAD9////E6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0GAAAAAP3///8CUnheAwAAAAAWABRCfygPJ+Fjsx4BknYvvm3A3qKn2xJ/XQcAAAAAF6kU1I4TAst5nAj15ey7vwe5cM3OFq+HlhEAAAEBH1J4XgMAAAAAFgAUQn8oDyfhY7MeAZJ2L75twN6ip9sBAwQhAAAAIgYCo7sfm78RQY3B5n0ac/QF8VtMAzFnci+h5D1MtpgRY7oYOUrtFFQAAIABAACAAAAAgAEAAAAGAAAAAAEAcQIAAAABxY7wh0nsfJQfzWrD/9rN9BYsM+iOmPaO6I0ANFgO/PcAAAAAAP3///8CptiUAAAAAAAWABRIm4HhQY/TzOjeWSPRrbuJo9MlW826oHYAAAAAFgAU0z+0L2QSLGtyQTn8FhbCpcI7jbliAQAAAQEfzbqgdgAAAAAWABTTP7QvZBIsa3JBOfwWFsKlwjuNuQEDBAIAAAAiBgITHmebEANk81CraV4xZIpqkNjjw0tIvezl1Ism1NRH3Rg5Su0UVAAAgAEAAIAAAACAAQAAAAAAAAAAIgICuTT7WnuiUTpObjWnZFHzIeEvW9PTB+1LLVFNQJVFeIIYOUrtFFQAAIABAACAAAAAgAEAAAAHAAAAACICAk8f3hpc5C35chgSg+Pe2zZ9IhHREd4aKW2+yAMRIFeqGDlK7RRUAACAAQAAgAAAAIABAAAACQAAAAAAIgIDjt1CjvrnMMnjbmTNKUAYoKEDRbmKjNjbq+6Ppqj3bqQYOUrtFFQAAIABAACAAAAAgAEAAAAIAAAAAA=="

    def test_a_transaction_it_cannot_fully_sign_is_refused(self):
        def load_psbt_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data(self.MIXED_PSBT)

        def load_seed_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("080115060387063104071857067618681125136207731354")

        self.run_sequence([
            FlowStep(MainMenuView, button_data_selection=MainMenuView.SCAN),
            FlowStep(scan_views.ScanView, before_run=load_psbt_into_decoder),
            FlowStep(psbt_views.PSBTSelectSeedView, button_data_selection=psbt_views.PSBTSelectSeedView.SCAN_SEED),
            FlowStep(scan_views.ScanSeedQRView, before_run=load_seed_into_decoder),
            FlowStep(seed_views.SeedFinalizeView, button_data_selection=seed_views.SeedFinalizeView.FINALIZE),
            FlowStep(seed_views.SeedOptionsView, is_redirect=True),
            FlowStep(psbt_views.PSBTOverviewView),
            FlowStep(psbt_views.PSBTMathView),
            FlowStep(psbt_views.PSBTAddressDetailsView, button_data_selection=0),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            FlowStep(psbt_views.PSBTChangeDetailsView, button_data_selection=psbt_views.PSBTChangeDetailsView.NEXT),
            # never reaches the approval screen: it is refused before the user is asked
            FlowStep(psbt_views.PSBTFinalizeView, is_redirect=True),
            FlowStep(psbt_views.PSBTUnsignableSighashView, button_data_selection=0),
            FlowStep(MainMenuView),
        ])

    def test_signing_it_would_sign_only_part_of_it(self):
        """The hazard the refusal exists for. The count going up is what made a
        partly signed transaction report success, so demonstrate it rather than
        asserting only on the screen the flow reached."""
        from base64 import b64decode

        from embit.psbt import PSBT

        psbt = PSBT.parse(b64decode(self.MIXED_PSBT))
        assert [inp.sighash_type for inp in psbt.inputs] == [
            SIGHASH.UNIFIED | SIGHASH.ALL, SIGHASH.NONE
        ]
        assert PSBTParser.unsignable_inputs(psbt) == [1]

        before = PSBTParser.sig_count(psbt)
        psbt.sign_with(_root(), sighash=PSBTParser.sighash_type(psbt))
        after = PSBTParser.sig_count(psbt)

        assert before == 0
        assert after == 1, "expected exactly one of the two inputs to be signed"
        assert after != before, "the count rises, which is what used to report success"
        assert after < len(psbt.inputs), "yet the transaction is not fully signed"


class TestSigningRaisesAfterApproval(FlowTest):
    """A PSBT that parses and reviews but raises partway through signing.

    Signing mutates the inputs in place as it goes, so the object the controller
    holds would keep the signatures made before the failure. Nothing broadcasts it,
    because the controller only takes the trimmed PSBT on success, but whatever runs
    next sees a PSBT that is neither the one scanned nor a signed one.
    """

    RAISING_PSBT = "cHNidP8BANgCAAAAAsTXZs3fz/dmGb6M80+jjvJZdYya+cw5bT/dGuhZFdSlAAAAAAD9////qo6xg/UZAvUkcbse1F+C9zbP/FeZNjThx7SCIn6eMCgBAAAAAP3///8EQOIBAAAAAAAWABSkZPM7kLcTRE2En1t33/0RCHgMjQXYnnYAAAAAFgAUKMaPRKXdY4m8iKrE9j+rycskJU1A4gEAAAAAABYAFPYc9wiHRrYKAZYLLztREAwpPBIwipVcAwAAAAAWABSiFuiJIa4NrxLUBVQNS0NIun6DDtoRAABPAQQ1h88DBcQGZIAAAAA+0J+jlNL3dpWwlnBi8Dx+Ipg4e6uvB3HdjzFPX7r9CAOOlAIxgII+/xCcj+XoEenKH7wj5s5wlu7Q7CCZWFLGLhA5Su0UVAAAgAEAAIAAAACAAAEA7QIAAAAEE6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0BAAAAAP3///8TqeNf9+e+fuFuQohFzHM1gU5J9sJ015ad3sV7/VRxDQMAAAAA/f///xOp41/3575+4W5CiEXMczWBTkn2wnTXlp3exXv9VHENBAAAAAD9////E6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0GAAAAAP3///8CUnheAwAAAAAWABRCfygPJ+Fjsx4BknYvvm3A3qKn2xJ/XQcAAAAAF6kU1I4TAst5nAj15ey7vwe5cM3OFq+HlhEAAAEBH1J4XgMAAAAAFgAUQn8oDyfhY7MeAZJ2L75twN6ip9siBgKjux+bvxFBjcHmfRpz9AXxW0wDMWdyL6HkPUy2mBFjuhg5Su0UVAAAgAEAAIAAAACAAQAAAAYAAAAAIgYCEx5nmxADZPNQq2leMWSKapDY48NLSL3s5dSLJtTUR90YOUrtFFQAAIABAACAAAAAgAEAAAAAAAAAACICArk0+1p7olE6Tm41p2RR8yHhL1vT0wftSy1RTUCVRXiCGDlK7RRUAACAAQAAgAAAAIABAAAABwAAAAAiAgJPH94aXOQt+XIYEoPj3ts2fSIR0RHeGiltvsgDESBXqhg5Su0UVAAAgAEAAIAAAACAAQAAAAkAAAAAACICA47dQo765zDJ425kzSlAGKChA0W5iozY26vuj6ao926kGDlK7RRUAACAAQAAgAAAAIABAAAACAAAAAA="

    def test_signing_in_place_leaves_a_half_signed_psbt(self):
        """The hazard itself, so the fix below is measured against something real."""
        from base64 import b64decode

        from embit.psbt import PSBT

        raw = b64decode(self.RAISING_PSBT)
        held = PSBT.parse(raw)
        # input 1 carries a derivation but no utxo of either kind, so resolving its
        # script_pubkey dereferences None. Asserted precisely: embit's own comments show
        # it moving toward skipping these, and this test should fail loudly if it does
        # rather than passing on whatever exception replaces it.
        with pytest.raises(AttributeError, match="script_pubkey"):
            held.sign_with(_root(), sighash=PSBTParser.sighash_type(held))

        assert PSBTParser.sig_count(held) == 1, "expected one input signed before the failure"
        assert held.serialize() != raw, "expected the object to have been mutated"

    def test_signing_a_copy_leaves_the_scanned_psbt_alone(self):
        from base64 import b64decode

        from embit.psbt import PSBT

        raw = b64decode(self.RAISING_PSBT)
        held = PSBT.parse(raw)

        # what the view does now
        signing_psbt = PSBT.parse(held.serialize())
        with pytest.raises(AttributeError, match="script_pubkey"):
            signing_psbt.sign_with(_root(), sighash=PSBTParser.sighash_type(signing_psbt))

        assert PSBTParser.sig_count(held) == 0
        assert held.serialize() == raw


class TestTheHashTypeIsShown(FlowTest):
    """The device signs whatever hash type the PSBT declares and used to display none
    of it, so a host that rewrites a request for the unified message down to the legacy
    one got a legacy signature and the same success screen.
    """

    @staticmethod
    def _finalize_kwargs(psbt_b64):
        """What PSBTFinalizeView hands the approval screen for this PSBT."""
        from base64 import b64decode
        from unittest.mock import patch

        from embit.psbt import PSBT

        from seedsigner.controller import Controller
        from seedsigner.models.psbt_parser import PSBTParser

        seed = _seed()

        controller = Controller.get_instance()
        controller.psbt = PSBT.parse(b64decode(psbt_b64))
        controller.psbt_seed = seed
        controller.psbt_parser = PSBTParser(controller.psbt, seed=seed, network=SettingsConstants.MAINNET)

        with patch("seedsigner.views.view.View.run_screen") as run_screen:
            run_screen.return_value = 0
            psbt_views.PSBTFinalizeView().run()
        assert run_screen.called, "the approval screen was never shown"
        return run_screen.call_args.kwargs

    def test_the_unified_opt_in_is_named(self):
        kwargs = self._finalize_kwargs(TestUnifiedSighashFlow.UNIFIED_PSBT)
        assert kwargs["sighash_type"] == SIGHASH.UNIFIED | SIGHASH.ALL

    def test_a_downgraded_request_is_visibly_different(self):
        """The case the display exists for: the PSBT asked for the unified message and
        a host rewrote it, so the device must not present the two identically."""
        from base64 import b64decode, b64encode

        from embit.psbt import PSBT

        psbt = PSBT.parse(b64decode(TestUnifiedSighashFlow.UNIFIED_PSBT))
        for inp in psbt.inputs:
            inp.sighash_type = SIGHASH.ALL
        downgraded = b64encode(psbt.serialize()).decode()

        unified = self._finalize_kwargs(TestUnifiedSighashFlow.UNIFIED_PSBT)["sighash_type"]
        legacy = self._finalize_kwargs(downgraded)["sighash_type"]

        assert unified == SIGHASH.UNIFIED | SIGHASH.ALL
        assert legacy == SIGHASH.ALL
        assert unified != legacy, "the screen would say the same thing for both"


class TestTheScreenNamesWhatIsSigned(FlowTest):
    """The invariant the display rests on: the type on the approval screen is the byte
    every signature actually carries.

    These two differ. `PSBTParser.sighash_type` is the value handed to sign_with; the
    byte a signature carries is what sign_with resolves per input from it. For the two
    commonest PSBTs, one declaring nothing and one declaring ALL, the request is DEFAULT
    and the signature is ALL, so showing the request would name a byte no signature has.
    """

    NETWORK = SettingsConstants.MAINNET

    @staticmethod
    def _psbt(declared):
        from base64 import b64decode

        from embit.psbt import PSBT

        psbt = PSBT.parse(b64decode(TestMixedSighashFlow.MIXED_PSBT))
        for i, sh in enumerate(declared):
            psbt.inputs[i].sighash_type = sh
        return psbt

    def _shown(self, psbt):
        """What PSBTFinalizeView puts on the screen, or None if it refuses.

        The view's own decision, not a copy of it: a reimplementation here would stay
        green while the device did something else.
        """
        return PSBTParser.screen_sighash_type(psbt, _seed(), self.NETWORK)

    @pytest.mark.parametrize("declared,expected", [
        ([None, None], SIGHASH.ALL),
        ([SIGHASH.ALL, SIGHASH.ALL], SIGHASH.ALL),
        ([None, SIGHASH.ALL], SIGHASH.ALL),
        ([SIGHASH.DEFAULT, SIGHASH.DEFAULT], SIGHASH.ALL),
        ([SIGHASH.UNIFIED | SIGHASH.ALL] * 2, SIGHASH.UNIFIED | SIGHASH.ALL),
    ])
    def test_the_screen_matches_every_signature_byte(self, declared, expected):
        psbt = self._psbt(declared)
        shown = self._shown(psbt)
        assert shown == expected, f"screen would say {hex(shown)}, expected {hex(expected)}"

        psbt.sign_with(_root(), sighash=PSBTParser.sighash_type(psbt))
        produced = {bytes(sig)[-1] for inp in psbt.inputs for sig in inp.partial_sigs.values()}
        assert produced, "nothing was signed, so the assertion below would be vacuous"
        assert produced == {shown}, \
            f"screen said {hex(shown)} but signatures carry {[hex(b) for b in produced]}"

    def test_a_psbt_with_no_honest_single_label_is_refused(self):
        """Inputs declaring 0x21 and 0x01 both sign, with different bytes. The request
        collapses to DEFAULT, which no signature carries, so there is nothing true to
        put on the screen and the transaction is refused instead."""
        psbt = self._psbt([SIGHASH.UNIFIED | SIGHASH.ALL, SIGHASH.ALL])
        assert PSBTParser.unsignable_inputs(psbt, seed=_seed(), network=self.NETWORK) == []
        assert self._shown(psbt) is None

        # and what it would have produced, had it not been refused
        psbt.sign_with(_root(), sighash=PSBTParser.sighash_type(psbt))
        produced = {bytes(sig)[-1] for inp in psbt.inputs for sig in inp.partial_sigs.values()}
        assert produced == {SIGHASH.UNIFIED | SIGHASH.ALL, SIGHASH.ALL}

    def test_an_input_this_seed_does_not_hold_is_not_our_problem(self):
        """A counterparty input declaring anything it likes must not stop this device
        signing its own. Refusing there would break collaborative transactions and hand
        a hostile host a way to block signing by appending one input."""
        psbt = self._psbt([SIGHASH.UNIFIED | SIGHASH.ALL, SIGHASH.NONE])
        psbt.inputs[1].bip32_derivations.clear()

        assert PSBTParser.unsignable_inputs(psbt, seed=_seed(), network=self.NETWORK) == []
        assert self._shown(psbt) == SIGHASH.UNIFIED | SIGHASH.ALL

        assert psbt.sign_with(_root(), sighash=PSBTParser.sighash_type(psbt)) == 1

    def test_a_coordinator_that_omitted_fingerprints_is_still_recognised(self):
        """A coordinator given only an xpub writes four zero bytes where the fingerprint
        goes. Comparing fingerprints alone answers False for inputs that are this seed's,
        which would skip the refusal and put us back to signing part of a transaction and
        calling it whole."""
        psbt = self._psbt([SIGHASH.UNIFIED | SIGHASH.ALL, SIGHASH.NONE])
        for inp in psbt.inputs:
            for pub, derivation in inp.bip32_derivations.items():
                derivation.fingerprint = b"\x00\x00\x00\x00"

        assert PSBTParser._input_is_ours(psbt.inputs[1], _seed(), self.NETWORK)
        assert PSBTParser.unsignable_inputs(psbt, seed=_seed(), network=self.NETWORK) == [1]

    def test_our_own_input_declaring_it_is_still_refused(self):
        psbt = self._psbt([SIGHASH.UNIFIED | SIGHASH.ALL, SIGHASH.NONE])
        assert PSBTParser.unsignable_inputs(psbt, seed=_seed(), network=self.NETWORK) == [1]


class TestThePredictionAgreesWithTheSigner(FlowTest):
    """`unsignable_inputs` predicts which inputs sign_with will skip. Prediction is only
    as good as the code it mirrors, and embit is a pinned dependency that moves.

    This signs for real across the matrix and compares, so the day the pin moves in a
    way that changes which inputs get skipped, this fails rather than the device quietly
    reporting success on a transaction it signed less of than it said.
    """

    NETWORK = SettingsConstants.MAINNET

    def test_predicted_skips_match_what_signing_actually_does(self):
        from base64 import b64decode

        from embit.psbt import PSBT

        seed = _seed()
        root = _root()
        raw = b64decode(TestMixedSighashFlow.MIXED_PSBT)
        values = [None, 0x00, 0x01, 0x02, 0x03, 0x20, 0x21, 0x22, 0x23, 0x81, 0xa1, 0x05, 0xff]

        compared = 0
        for a in values:
            for b in values:
                psbt = PSBT.parse(raw)
                psbt.inputs[0].sighash_type = a
                psbt.inputs[1].sighash_type = b

                predicted = PSBTParser.unsignable_inputs(psbt, seed=seed, network=self.NETWORK)
                requested = PSBTParser.sighash_type(psbt)
                try:
                    psbt.sign_with(root, sighash=requested)
                except Exception:
                    # an undefined hash type raises rather than skipping; not a skip
                    continue

                ours = [i for i, inp in enumerate(psbt.inputs)
                        if PSBTParser._input_is_ours(inp, seed, self.NETWORK)]
                actually_skipped = [i for i in ours if not psbt.inputs[i].partial_sigs]

                assert predicted == actually_skipped, (
                    f"declared {a!r}/{b!r}: predicted skips {predicted}, "
                    f"signing actually skipped {actually_skipped}"
                )
                compared += 1

        assert compared > 100, f"only {compared} combinations were comparable"
