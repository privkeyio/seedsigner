#!/usr/bin/env python3
"""Drive SeedSigner's own signing code against Bitcoin Knots.

Uses SeedSigner's Seed/PSBTParser and embit's psbt.sign_with, the same call the
app makes at psbt_views.py:543, and requires Knots to accept the result."""
import os
import sys

# SeedSigner's source, so its own Seed/PSBTParser are exercised rather than a
# reimplementation. embit comes from the environment, i.e. the pinned
# dependency, so this tests what requirements.txt actually installs.
_SS = os.environ.get("SEEDSIGNER_SRC")
if not _SS:
    _SS = os.path.join(os.path.dirname(__file__), "..", "..", "src")
sys.path.insert(0, os.path.abspath(_SS))

from test_framework.test_framework import BitcoinTestFramework
from test_framework.wallet import MiniWallet

from seedsigner.models.seed import Seed
from seedsigner.models.psbt_parser import PSBTParser
from seedsigner.models.settings_definition import SettingsConstants

from embit.psbt import PSBT
from embit.transaction import Transaction, TransactionInput, TransactionOutput, SIGHASH
from embit import bip32, script, ec
from embit.networks import NETWORKS

ACTIVATION_HEIGHT = 150
MNEMONIC = ("abandon abandon abandon abandon abandon abandon "
            "abandon abandon abandon abandon abandon about").split()


class SeedSignerE2E(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=blake2b@{ACTIVATION_HEIGHT}", "-corepolicy=0"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, ACTIVATION_HEIGHT + 10)

        # A real SeedSigner seed object, as the device would hold it.
        seed = Seed(mnemonic=MNEMONIC)
        root = bip32.HDKey.from_seed(seed.seed_bytes, version=NETWORKS["regtest"]["xprv"])
        self.log.info(f"SeedSigner seed loaded, fingerprint {root.child(0).fingerprint.hex()}")

        # single-sig p2wpkh at m/84'/1'/0'/0/0
        path = "m/84h/1h/0h/0/0"
        child = root.derive(path)
        spk = script.p2wpkh(child.key.get_public_key())

        utxo = wallet.send_to(from_node=node, scriptPubKey=bytes(spk.data), amount=100_000_000)
        self.generate(wallet, 1)

        sink = script.p2wpkh(ec.PrivateKey(bytes.fromhex("33" * 32)).get_public_key())
        tx = Transaction(
            vin=[TransactionInput(bytes.fromhex(utxo["txid"]), utxo["sent_vout"], sequence=0xFFFFFFFE)],
            vout=[TransactionOutput(100_000_000 - 10_000, sink)],
        )
        psbt = PSBT(tx)
        psbt.inputs[0].witness_utxo = TransactionOutput(100_000_000, spk)
        psbt.inputs[0].bip32_derivations[child.key.get_public_key()] = \
            __import__('embit.psbt', fromlist=['DerivationPath']).DerivationPath(
                root.child(0).fingerprint, bip32.parse_path(path))
        # Ask for the unified sighash, the way a fork-aware wallet would.
        psbt.inputs[0].sighash_type = SIGHASH.ALL | SIGHASH.UNIFIED

        parser = PSBTParser(psbt, seed=seed, network=SettingsConstants.REGTEST)
        self.log.info(f"PSBTParser: {parser.num_inputs} input(s), spend {parser.spend_amount} sat")

        before = PSBTParser.sig_count(psbt)
        # the exact call psbt_views.py makes: the hash type the PSBT asks for
        psbt.sign_with(root, sighash=PSBTParser.sighash_type(psbt))
        after = PSBTParser.sig_count(psbt)
        assert after > before, "SeedSigner's sign_with produced no signature"
        self.log.info(f"  sign_with added {after - before} signature(s)")

        sig = list(psbt.inputs[0].partial_sigs.values())[0]
        assert sig[-1] == (SIGHASH.ALL | SIGHASH.UNIFIED), f"wrong hash type byte: {hex(sig[-1])}"
        self.log.info(f"  hash type byte is {hex(sig[-1])}: the opt-in bit is set")

        # finalize the p2wpkh input from the partial signature SeedSigner made
        pub, sigbytes = list(psbt.inputs[0].partial_sigs.items())[0]
        tx.vin[0].witness = script.Witness([sigbytes, pub.sec()])
        raw = tx.serialize().hex()
        res = node.testmempoolaccept([raw])[0]
        self.log.info(f"Knots verdict: allowed={res['allowed']} {res.get('reject-reason','')}")
        assert res["allowed"], res
        txid = node.sendrawtransaction(raw)
        blk = self.generate(wallet, 1)[0]
        assert txid in node.getblock(blk)["tx"]
        self.log.info("  SeedSigner's signature was accepted and mined by Bitcoin Knots")

        self.check_screen_matches_the_chain(node, wallet, root, seed, path, child)
        self.check_the_card_path_reaches_consensus(node, wallet, root, seed, path, child)

    def check_screen_matches_the_chain(self, node, wallet, root, seed, path, child):
        """The claim the approval screen makes, carried through to consensus.

        The device tells the user which signature message it is about to produce. That
        is only worth anything if the byte on the screen is the byte in the transaction
        a node accepts. Everything above proves the device signs 0x21 when asked; this
        proves the screen would have said so, and that the two agree for the legacy case
        too, which is the one a hostile host can force by rewriting the declared type.
        """
        from embit.psbt import DerivationPath

        spk = script.p2wpkh(child.key.get_public_key())
        sink = script.p2wpkh(ec.PrivateKey(bytes.fromhex("44" * 32)).get_public_key())

        for declared, expected_byte in ((SIGHASH.ALL | SIGHASH.UNIFIED, 0x21),
                                        (SIGHASH.ALL, 0x01),
                                        (None, 0x01)):
            utxo = wallet.send_to(from_node=node, scriptPubKey=bytes(spk.data), amount=50_000_000)
            self.generate(wallet, 1)

            tx = Transaction(
                vin=[TransactionInput(bytes.fromhex(utxo["txid"]), utxo["sent_vout"], sequence=0xFFFFFFFE)],
                vout=[TransactionOutput(50_000_000 - 10_000, sink)],
            )
            psbt = PSBT(tx)
            psbt.inputs[0].witness_utxo = TransactionOutput(50_000_000, spk)
            psbt.inputs[0].bip32_derivations[child.key.get_public_key()] = DerivationPath(
                root.child(0).fingerprint, bip32.parse_path(path))
            psbt.inputs[0].sighash_type = declared

            # the view's own decision, so this cannot drift from what the device shows
            shown, reason = PSBTParser.screen_sighash_type(psbt, seed, SettingsConstants.REGTEST)
            assert shown is not None, f"declared {declared}: the device would refuse it ({reason})"

            psbt.sign_with(root, sighash=PSBTParser.sighash_type(psbt))
            pub, sigbytes = list(psbt.inputs[0].partial_sigs.items())[0]
            assert sigbytes[-1] == shown, \
                f"screen would say {hex(shown)} but the signature carries {hex(sigbytes[-1])}"
            assert shown == expected_byte, f"expected {hex(expected_byte)}, screen says {hex(shown)}"

            tx.vin[0].witness = script.Witness([sigbytes, pub.sec()])
            raw = tx.serialize().hex()
            res = node.testmempoolaccept([raw])[0]
            assert res["allowed"], (declared, res)
            txid = node.sendrawtransaction(raw)
            blk = self.generate(wallet, 1)[0]
            assert txid in node.getblock(blk)["tx"]

            mined = node.getrawtransaction(txid, True, blk)
            witness_sig = bytes.fromhex(mined["vin"][0]["txinwitness"][0])
            assert witness_sig[-1] == shown, \
                f"mined transaction carries {hex(witness_sig[-1])}, screen said {hex(shown)}"
            self.log.info(
                f"  declared {declared if declared is None else hex(declared)}: screen says "
                f"{hex(shown)}, mined transaction carries {hex(witness_sig[-1])}, Knots accepted it")


    def check_the_card_path_reaches_consensus(self, node, wallet, root, seed, path, child):
        """The card path, through the real signer, ending at a block.

        A Satochip or Keycard is handed 32 bytes and signs them blind, so the digest and
        the byte appended to the signature are both chosen on this side. The card here
        holds the same keys and signs whatever it is given, which is all a real one does
        with the digest; what this proves is the part that is not on the card, that the
        message chosen for the opt-in is the one Knots verifies against.
        """
        from unittest.mock import patch

        from embit.psbt import DerivationPath

        from seedsigner.helpers.satochip_signer import sign_psbt_with_satochip
        from seedsigner.models.settings import Settings

        class NoDummies:
            """Turns the chosen-nonce obfuscation off so only the real signature is made."""

            def get_value(self, setting):
                return 5 if "TIMEOUT" in str(setting).upper() else 0

        class Card:
            """Derives on request and signs with the key it derived last, which is how the
            applet behaves: card_sign_transaction_hash names no key."""

            def __init__(self, root):
                self.root = root
                self.selected = root

            def card_bip32_get_extendedkey(self, path):
                self.selected = self.root.derive(path)
                return _CardKey(self.selected), b""

            def card_sign_transaction_hash(self, keynbr, digest, _pin):
                return (self.selected.key.sign(bytes(digest)).serialize(), 0x90, 0x00)

        class _CardKey:
            def __init__(self, hdkey):
                self.hdkey = hdkey

            def get_public_key_bytes(self, compressed=True):
                return self.hdkey.key.get_public_key().sec()

        spk = script.p2wpkh(child.key.get_public_key())
        sink = script.p2wpkh(ec.PrivateKey(bytes.fromhex("55" * 32)).get_public_key())

        for declared, expected_byte in ((SIGHASH.ALL | SIGHASH.UNIFIED, 0x21), (None, 0x01)):
            utxo = wallet.send_to(from_node=node, scriptPubKey=bytes(spk.data), amount=50_000_000)
            self.generate(wallet, 1)

            tx = Transaction(
                vin=[TransactionInput(bytes.fromhex(utxo["txid"]), utxo["sent_vout"], sequence=0xFFFFFFFE)],
                vout=[TransactionOutput(50_000_000 - 10_000, sink)],
            )
            psbt = PSBT(tx)
            psbt.inputs[0].witness_utxo = TransactionOutput(50_000_000, spk)
            psbt.inputs[0].bip32_derivations[child.key.get_public_key()] = DerivationPath(
                root.child(0).fingerprint, bip32.parse_path(path))
            psbt.inputs[0].sighash_type = declared

            # the card path has no seed on this device, so the screen decides on the
            # whole transaction; the same value is what the card is asked to sign.
            shown, reason = PSBTParser.screen_sighash_type(psbt, None)
            assert shown == expected_byte, f"declared {declared}: screen says {shown} ({reason})"

            with patch.object(Settings, "get_instance", classmethod(lambda cls: NoDummies())):
                result = sign_psbt_with_satochip(psbt, Card(root), sighash=shown)
            assert result.signed_count == 1, "the card signer produced no signature"

            pub, sigbytes = list(psbt.inputs[0].partial_sigs.items())[0]
            assert sigbytes[-1] == shown, \
                f"screen would say {hex(shown)} but the card signature carries {hex(sigbytes[-1])}"

            tx.vin[0].witness = script.Witness([sigbytes, pub.sec()])
            raw = tx.serialize().hex()
            res = node.testmempoolaccept([raw])[0]
            assert res["allowed"], (declared, res)
            txid = node.sendrawtransaction(raw)
            blk = self.generate(wallet, 1)[0]
            assert txid in node.getblock(blk)["tx"]

            mined = node.getrawtransaction(txid, True, blk)
            witness_sig = bytes.fromhex(mined["vin"][0]["txinwitness"][0])
            assert witness_sig[-1] == shown
            self.log.info(
                f"  card path, declared {declared if declared is None else hex(declared)}: "
                f"screen says {hex(shown)}, Knots accepted and mined it")


if __name__ == "__main__":
    SeedSignerE2E(__file__).main()
