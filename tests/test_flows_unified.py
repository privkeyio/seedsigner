from base import FlowTest, FlowStep

from seedsigner.controller import Controller
from seedsigner.views.view import MainMenuView
from seedsigner.views import scan_views, seed_views, psbt_views
from seedsigner.models.settings import SettingsConstants
from seedsigner.models.psbt_parser import PSBTParser

from embit.transaction import SIGHASH


class TestUnifiedSighashFlow(FlowTest):
    """The full SeedSigner UI flow, driven with a PSBT that asks for the
    unified opt-in sighash. Same screens as test_flows_psbt, but the signature
    produced must carry hash type 0x21."""

    def test_scan_unified_psbt_and_sign(self):
        def load_psbt_into_decoder(view: scan_views.ScanView):
            view.decoder.add_data("cHNidP8BANgCAAAAAsTXZs3fz/dmGb6M80+jjvJZdYya+cw5bT/dGuhZFdSlAAAAAAD9////qo6xg/UZAvUkcbse1F+C9zbP/FeZNjThx7SCIn6eMCgBAAAAAP3///8EQOIBAAAAAAAWABSkZPM7kLcTRE2En1t33/0RCHgMjQXYnnYAAAAAFgAUKMaPRKXdY4m8iKrE9j+rycskJU1A4gEAAAAAABYAFPYc9wiHRrYKAZYLLztREAwpPBIwipVcAwAAAAAWABSiFuiJIa4NrxLUBVQNS0NIun6DDtoRAABPAQQ1h88DBcQGZIAAAAA+0J+jlNL3dpWwlnBi8Dx+Ipg4e6uvB3HdjzFPX7r9CAOOlAIxgII+/xCcj+XoEenKH7wj5s5wlu7Q7CCZWFLGLhA5Su0UVAAAgAEAAIAAAACAAAEA7QIAAAAEE6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0BAAAAAP3///8TqeNf9+e+fuFuQohFzHM1gU5J9sJ015ad3sV7/VRxDQMAAAAA/f///xOp41/3575+4W5CiEXMczWBTkn2wnTXlp3exXv9VHENBAAAAAD9////E6njX/fnvn7hbkKIRcxzNYFOSfbCdNeWnd7Fe/1UcQ0GAAAAAP3///8CUnheAwAAAAAWABRCfygPJ+Fjsx4BknYvvm3A3qKn2xJ/XQcAAAAAF6kU1I4TAst5nAj15ey7vwe5cM3OFq+HlhEAAAEBH1J4XgMAAAAAFgAUQn8oDyfhY7MeAZJ2L75twN6ip9sBAwQhAAAAIgYCo7sfm78RQY3B5n0ac/QF8VtMAzFnci+h5D1MtpgRY7oYOUrtFFQAAIABAACAAAAAgAEAAAAGAAAAAAEAcQIAAAABxY7wh0nsfJQfzWrD/9rN9BYsM+iOmPaO6I0ANFgO/PcAAAAAAP3///8CptiUAAAAAAAWABRIm4HhQY/TzOjeWSPRrbuJo9MlW826oHYAAAAAFgAU0z+0L2QSLGtyQTn8FhbCpcI7jbliAQAAAQEfzbqgdgAAAAAWABTTP7QvZBIsa3JBOfwWFsKlwjuNuQEDBCEAAAAiBgITHmebEANk81CraV4xZIpqkNjjw0tIvezl1Ism1NRH3Rg5Su0UVAAAgAEAAIAAAACAAQAAAAAAAAAAIgICuTT7WnuiUTpObjWnZFHzIeEvW9PTB+1LLVFNQJVFeIIYOUrtFFQAAIABAACAAAAAgAEAAAAHAAAAACICAk8f3hpc5C35chgSg+Pe2zZ9IhHREd4aKW2+yAMRIFeqGDlK7RRUAACAAQAAgAAAAIABAAAACQAAAAAAIgIDjt1CjvrnMMnjbmTNKUAYoKEDRbmKjNjbq+6Ppqj3bqQYOUrtFFQAAIABAACAAAAAgAEAAAAIAAAAAA==")

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
