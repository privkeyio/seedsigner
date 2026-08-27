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


if __name__ == "__main__":
    SeedSignerE2E(__file__).main()
