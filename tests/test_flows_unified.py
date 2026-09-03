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
    """Signing mutates the inputs in place as it goes, so a PSBT that raises partway
    leaves the signatures already made on the object the controller holds. Nothing
    broadcasts it, because the controller only takes the trimmed PSBT on success, but
    whatever runs next sees a PSBT that is neither the one scanned nor a signed one.

    This fixture cannot reach PSBTFinalizeView: PSBTParser rejects it first, which
    test_this_fixture_never_reaches_the_finalize_view records. So it demonstrates the
    hazard and the fix at the point signing happens, not through the flow. Whether a
    PSBT exists that parses and then raises is not settled either way here; signing on
    a copy costs one serialize round trip and does not depend on the answer.
    """

    def test_this_fixture_never_reaches_the_finalize_view(self):
        """Stated rather than assumed: the class above would otherwise read as though
        it were covering the flow."""
        from base64 import b64decode

        from embit.psbt import PSBT, PSBTError

        with pytest.raises(PSBTError, match="Missing previous utxo"):
            PSBTParser(PSBT.parse(b64decode(self.RAISING_PSBT)), seed=_seed(),
                       network=SettingsConstants.MAINNET)

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
        shown, _reason = PSBTParser.screen_sighash_type(psbt, _seed(), self.NETWORK)
        return shown

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


class TestTaproot(FlowTest):
    """Every other fixture here is p2wpkh, so `inp.is_taproot` is False in all of them
    and the branch that exists for taproot never runs.

    Taproot is the one script type where DEFAULT is a real hash type rather than a
    stand-in for ALL: a key path signature is 64 bytes and carries no trailing byte at
    all. So 0x00 on the screen is correct here and wrong on segwit, which is exactly the
    distinction the display got wrong before.
    """

    NETWORK = SettingsConstants.MAINNET
    PATH = "m/86h/0h/0h/0/0"

    def _psbt(self, declared):
        from embit import bip32, script
        from embit.psbt import PSBT, DerivationPath
        from embit.transaction import Transaction, TransactionInput, TransactionOutput

        root = _root()
        pub = root.derive(self.PATH).to_public()
        spk = script.p2tr(pub)

        psbt = PSBT(Transaction(
            vin=[TransactionInput(bytes(32), 0)],
            vout=[TransactionOutput(90000, spk)],
        ))
        inp = psbt.inputs[0]
        inp.witness_utxo = TransactionOutput(100000, spk)
        inp.taproot_bip32_derivations[pub.key] = (
            [], DerivationPath(root.my_fingerprint, bip32.parse_path(self.PATH))
        )
        inp.sighash_type = declared
        return psbt

    def test_the_input_really_is_taproot(self):
        """Guards the rest of this class: if the fixture stopped being taproot the
        assertions below would still pass while testing the segwit branch."""
        assert self._psbt(None).inputs[0].is_taproot

    @pytest.mark.parametrize("declared,expected", [
        (None, SIGHASH.DEFAULT),
        (SIGHASH.DEFAULT, SIGHASH.DEFAULT),
        (SIGHASH.ALL, SIGHASH.ALL),
        (SIGHASH.UNIFIED | SIGHASH.ALL, SIGHASH.UNIFIED | SIGHASH.ALL),
    ])
    def test_the_screen_matches_the_signature(self, declared, expected):
        from embit.psbt import PSBT

        psbt = self._psbt(declared)
        shown, reason = PSBTParser.screen_sighash_type(psbt, _seed(), self.NETWORK)
        assert reason is None
        assert shown == expected

        before = PSBTParser.signed_hash_types(psbt)
        signed = PSBT.parse(psbt.serialize())
        assert signed.sign_with(_root(), sighash=PSBTParser.sighash_type(signed)) == 1

        added = {k: ht for k, (ht, raw) in PSBTParser.signed_hash_types(signed).items()
                 if before.get(k, (None, None))[1] != raw}
        assert added, "nothing was signed, so the assertion below would be vacuous"
        assert set(added.values()) == {shown}, \
            f"screen said {hex(shown)} but signatures carry {[hex(v) for v in added.values()]}"

    def test_a_key_path_signature_carries_no_trailing_byte(self):
        """Why DEFAULT survives on taproot: there is no byte to read it back from, so
        signed_hash_types has to infer it from the length rather than the last byte."""
        from embit.psbt import PSBT

        signed = PSBT.parse(self._psbt(SIGHASH.DEFAULT).serialize())
        signed.sign_with(_root(), sighash=SIGHASH.DEFAULT)

        sigs = list(signed.inputs[0].taproot_sigs.values())
        key_sig = getattr(signed.inputs[0], "taproot_key_sig", None)
        if key_sig is not None:
            sigs.append(key_sig)
        elif signed.inputs[0].final_scriptwitness:
            sigs.append(signed.inputs[0].final_scriptwitness.items[0])
        assert len(bytes(sigs[0])) == 64
        assert {ht for ht, _raw in PSBTParser.signed_hash_types(signed).values()} == {SIGHASH.DEFAULT}


class TestThePostConditionThroughTheView(FlowTest):
    """The safety net, exercised where it actually sits.

    Everything else here checks the prediction. This drives PSBTFinalizeView with the
    prediction sabotaged, so the only thing standing between a mislabelled screen and a
    signed QR is the check that reads the hash types back off the signatures.
    """

    def _run_finalize(self):
        from base64 import b64decode
        from unittest.mock import patch

        from embit.psbt import PSBT

        from seedsigner.controller import Controller

        seed = _seed()
        controller = Controller.get_instance()
        controller.psbt = PSBT.parse(b64decode(TestUnifiedSighashFlow.UNIFIED_PSBT))
        controller.psbt_seed = seed
        controller.psbt_parser = PSBTParser(controller.psbt, seed=seed,
                                            network=SettingsConstants.MAINNET)

        with patch("seedsigner.views.view.View.run_screen") as run_screen:
            run_screen.return_value = 0  # the user approves
            return psbt_views.PSBTFinalizeView().run()

    def test_a_truthful_screen_releases_the_signed_psbt(self):
        destination = self._run_finalize()
        assert destination.View_cls is psbt_views.PSBTSignedQRDisplayView

    def test_a_lying_screen_stops_the_signed_psbt(self):
        """Sabotage the prediction into naming a type nothing will be signed with. The
        prediction is what the user saw, so the only correct outcome is to refuse."""
        from unittest.mock import patch

        wrong = SIGHASH.NONE  # nothing this device signs will ever carry it
        with patch.object(PSBTParser, "screen_sighash_type", staticmethod(lambda *a, **k: (wrong, None))):
            destination = self._run_finalize()

        assert destination.View_cls is psbt_views.PSBTUnsignableTransactionView, \
            "a signature whose hash type differs from the screen reached the QR"


class TestAPsbtThatParsesAndThenRaises(FlowTest):
    """The case the copy exists for, reached through the view rather than asserted about.

    Input 1 keeps this seed's fingerprint but names a derivation whose key is not the
    pubkey the PSBT gives, so embit derives, compares, and refuses. That check happens
    while signing, not while parsing, so the transaction reviews as ordinary and fails
    only after the user has approved it, with input 0 already signed in place.
    """

    PSBT_B64 = "cHNidP8BANgCAAAAAsTXZs3fz/dmGb6M80+jjvJZdYya+cw5bT/dGuhZFdSlAAAAAAD9////qo6xg/UZAvUkcbse1F+C9zbP/FeZNjThx7SCIn6eMCgBAAAAAP3///8EQOIBAAAAAAAWABSkZPM7kLcTRE2En1t33/0RCHgMjQXYnnYAAAAAFgAUKMaPRKXdY4m8iKrE9j+rycskJU1A4gEAAAAAABYAFPYc9wiHRrYKAZYLLztREAwpPBIwipVcAwAAAAAWABSiFuiJIa4NrxLUBVQNS0NIun6DDtoRAABPAQQ1h88DBcQGZIAAAAA+0J+jlNL3dpWwlnBi8Dx+Ipg4e6uvB3HdjzFPX7r9CAOOlAIxgII+/xCcj+XoEenKH7wj5s5wlu7Q7CCZWFLGLhA5Su0UVAAAgAEAAIAAAACAAAEA7QIAAAAEE6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0BAAAAAP3///8TqeNf9+e+fuFuQohFzHM1gU5J9sJ015ad3sV7/VRxDQMAAAAA/f///xOp41/3575+4W5CiEXMczWBTkn2wnTXlp3exXv9VHENBAAAAAD9////E6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0GAAAAAP3///8CUnheAwAAAAAWABRCfygPJ+Fjsx4BknYvvm3A3qKn2xJ/XQcAAAAAF6kU1I4TAst5nAj15ey7vwe5cM3OFq+HlhEAAAEBH1J4XgMAAAAAFgAUQn8oDyfhY7MeAZJ2L75twN6ip9sBAwQhAAAAIgYCo7sfm78RQY3B5n0ac/QF8VtMAzFnci+h5D1MtpgRY7oYOUrtFFQAAIABAACAAAAAgAEAAAAGAAAAAAEAcQIAAAABxY7wh0nsfJQfzWrD/9rN9BYsM+iOmPaO6I0ANFgO/PcAAAAAAP3///8CptiUAAAAAAAWABRIm4HhQY/TzOjeWSPRrbuJo9MlW826oHYAAAAAFgAU0z+0L2QSLGtyQTn8FhbCpcI7jbliAQAAAQEfzbqgdgAAAAAWABTTP7QvZBIsa3JBOfwWFsKlwjuNuQEDBCEAAAAiBgITHmebEANk81CraV4xZIpqkNjjw0tIvezl1Ism1NRH3Rg5Su0UVAAAgAEAAIAAAACAAAAAAGMAAAAAIgICuTT7WnuiUTpObjWnZFHzIeEvW9PTB+1LLVFNQJVFeIIYOUrtFFQAAIABAACAAAAAgAEAAAAHAAAAACICAk8f3hpc5C35chgSg+Pe2zZ9IhHREd4aKW2+yAMRIFeqGDlK7RRUAACAAQAAgAAAAIABAAAACQAAAAAAIgIDjt1CjvrnMMnjbmTNKUAYoKEDRbmKjNjbq+6Ppqj3bqQYOUrtFFQAAIABAACAAAAAgAEAAAAIAAAAAA=="

    def _load(self):
        from base64 import b64decode

        from embit.psbt import PSBT

        from seedsigner.controller import Controller

        seed = _seed()
        controller = Controller.get_instance()
        controller.psbt = PSBT.parse(b64decode(self.PSBT_B64))
        controller.psbt_seed = seed
        controller.psbt_parser = PSBTParser(controller.psbt, seed=seed,
                                            network=SettingsConstants.MAINNET)
        return controller

    def test_it_reviews_like_any_other_transaction(self):
        """If it failed at parse time the rest of this class would be vacuous."""
        controller = self._load()
        assert controller.psbt_parser.num_inputs == 2

    def test_signing_it_raises_after_one_input_is_already_signed(self):
        from base64 import b64decode

        from embit.psbt import PSBT, PSBTError

        raw = b64decode(self.PSBT_B64)
        held = PSBT.parse(raw)
        with pytest.raises(PSBTError, match="Derivation path"):
            held.sign_with(_root(), sighash=PSBTParser.sighash_type(held))

        assert PSBTParser.sig_count(held) == 1
        assert held.serialize() != raw

    def test_the_view_refuses_and_leaves_the_scanned_psbt_alone(self):
        from base64 import b64decode
        from unittest.mock import patch

        controller = self._load()
        raw = b64decode(self.PSBT_B64)

        with patch("seedsigner.views.view.View.run_screen") as run_screen:
            run_screen.return_value = 0  # the user approves
            destination = psbt_views.PSBTFinalizeView().run()

        assert destination.View_cls is psbt_views.PSBTUnsignableTransactionView
        assert PSBTParser.sig_count(controller.psbt) == 0, "a signature was left behind"
        assert controller.psbt.serialize() == raw, "the scanned PSBT was mutated"


class TestAPlantedSignatureCannotMaskTheCheck(FlowTest):
    """The post-condition is what stands between a mislabelled screen and a signed QR,
    so it has to see the signature it is meant to check.

    A host controls every field of the PSBT, including partial_sigs. Planting one under
    the pubkey this device is about to sign with leaves the slot already occupied, and a
    check that asked only which slots were filled would read the real signature as
    something that was already there and never look at it. On a one input PSBT that
    silences the check completely.
    """

    @staticmethod
    def _psbt(declared, prefill):
        from embit import bip32, script
        from embit.psbt import PSBT, DerivationPath
        from embit.transaction import Transaction, TransactionInput, TransactionOutput

        root = _root()
        path = "m/84h/1h/0h/0/0"
        pub = root.derive(path).to_public()
        spk = script.p2wpkh(pub)

        psbt = PSBT(Transaction(
            vin=[TransactionInput(bytes(32), 0)],
            vout=[TransactionOutput(90000, spk)],
        ))
        inp = psbt.inputs[0]
        inp.witness_utxo = TransactionOutput(100000, spk)
        inp.bip32_derivations[pub.key] = DerivationPath(
            root.my_fingerprint, bip32.parse_path(path))
        inp.sighash_type = declared
        if prefill:
            inp.partial_sigs[pub.key] = b"\x30\x44" + b"\x00" * 68 + bytes([SIGHASH.NONE])
        return psbt, pub

    def _run_finalize(self, prefill, lie):
        """Drive the real view, so this pins the shipped code and not a copy of it."""
        from unittest.mock import patch

        from seedsigner.controller import Controller

        psbt, _pub = self._psbt(SIGHASH.UNIFIED | SIGHASH.ALL, prefill)
        seed = _seed()
        controller = Controller.get_instance()
        controller.psbt = psbt
        controller.psbt_seed = seed
        controller.psbt_parser = PSBTParser(psbt, seed=seed, network=SettingsConstants.MAINNET)

        with patch("seedsigner.views.view.View.run_screen") as run_screen:
            run_screen.return_value = 0  # the user approves
            if lie:
                with patch.object(PSBTParser, "screen_sighash_type",
                                  staticmethod(lambda *a, **k: (SIGHASH.NONE, None))):
                    return psbt_views.PSBTFinalizeView().run()
            return psbt_views.PSBTFinalizeView().run()

    def test_a_truthful_screen_releases_it(self):
        assert self._run_finalize(False, lie=False).View_cls is psbt_views.PSBTSignedQRDisplayView

    def test_a_planted_signature_is_refused_by_the_count_check_first(self):
        """Not the post-condition, and worth recording so the test below is not read as
        covering this. Success is still decided by the signature count rising, and the
        planted signature is replaced rather than added, so the count does not move and
        the transaction is refused before the hash types are ever compared. That check
        predates this work; the point here is only that planting does not release a QR."""
        assert self._run_finalize(True, lie=False).View_cls is psbt_views.PSBTSigningErrorView

    @pytest.mark.parametrize("prefill", [False, True])
    def test_a_planted_signature_does_not_silence_the_check(self, prefill):
        """With the screen lying, the only thing that can stop the QR is the check
        seeing the signature. Planting one in the slot must not hide it."""
        assert self._run_finalize(prefill, lie=True).View_cls is psbt_views.PSBTUnsignableTransactionView, \
            "a signature whose hash type differs from the screen reached the QR"


class TestWhatTheDeviceRefusesToDescribe(FlowTest):
    """`screen_sighash_type` refuses for two different reasons and the user is told
    which. It also refuses to render a value the device would never sign."""

    NETWORK = SettingsConstants.MAINNET

    @staticmethod
    def _one_input(declared, ours=True):
        from embit import bip32, script
        from embit.psbt import PSBT, DerivationPath
        from embit.transaction import Transaction, TransactionInput, TransactionOutput

        root = _root()
        path = "m/84h/1h/0h/0/0"
        pub = root.derive(path).to_public()
        spk = script.p2wpkh(pub)

        psbt = PSBT(Transaction(
            vin=[TransactionInput(bytes(32), 0)],
            vout=[TransactionOutput(90000, spk)],
        ))
        inp = psbt.inputs[0]
        inp.witness_utxo = TransactionOutput(100000, spk)
        if ours:
            inp.bip32_derivations[pub.key] = DerivationPath(
                root.my_fingerprint, bip32.parse_path(path))
        inp.sighash_type = declared
        return psbt

    def test_an_input_that_would_be_skipped_says_so(self):
        psbt = self._one_input(SIGHASH.NONE)
        shown, reason = PSBTParser.screen_sighash_type(psbt, _seed(), self.NETWORK)
        assert shown is None
        assert reason == PSBTParser.REFUSED_PARTIAL

    def test_types_no_single_label_covers_say_so_instead(self):
        """Every input would be signed here, so telling the user part of it would go
        unsigned would be false."""
        from base64 import b64decode

        from embit.psbt import PSBT

        psbt = PSBT.parse(b64decode(TestMixedSighashFlow.MIXED_PSBT))
        psbt.inputs[0].sighash_type = SIGHASH.UNIFIED | SIGHASH.ALL
        psbt.inputs[1].sighash_type = SIGHASH.ALL

        shown, reason = PSBTParser.screen_sighash_type(psbt, _seed(), self.NETWORK)
        assert shown is None
        assert reason == PSBTParser.REFUSED_MIXED

    def test_a_type_the_device_would_never_sign_is_not_rendered(self):
        """The declared type is four bytes off the wire with no bound. Where no input
        matches this seed the whole transaction decides the label, so without this the
        screen would name a hash type no signature could ever carry."""
        psbt = self._one_input(0xdeadbeef, ours=False)
        shown, reason = PSBTParser.screen_sighash_type(psbt, _seed(), self.NETWORK)
        assert shown is None
        assert reason is not None

    def test_an_empty_signature_value_does_not_crash_the_readback(self):
        """A host can leave any signature slot empty. The readback feeds the check that
        gates the QR, so it has to survive anything that parses."""
        from embit import script

        pub = _root().derive("m/84h/1h/0h/0/0").to_public()
        psbt = self._one_input(SIGHASH.ALL)
        psbt.inputs[0].partial_sigs[pub.key] = b""

        found = PSBTParser.signed_hash_types(psbt)
        assert list(found.values())[0][0] is None, "an empty value has no hash type"
