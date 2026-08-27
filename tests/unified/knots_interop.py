#!/usr/bin/env python3
"""Cross-implementation check: a signature produced by embit's unified sighash
must be accepted by Bitcoin Knots."""
# embit comes from the environment, i.e. the pinned dependency, so this tests
# what requirements.txt actually installs.

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet import MiniWallet

from embit.psbt import PSBT
from embit.transaction import Transaction, TransactionInput, TransactionOutput, SIGHASH
from embit import ec, script
from embit.networks import NETWORKS

ACTIVATION_HEIGHT = 150


class EmbitInteropTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=blake2b@{ACTIVATION_HEIGHT}", "-corepolicy=0"]]

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)

        self.generate(wallet, ACTIVATION_HEIGHT + 10)
        di = node.getdeploymentinfo()
        info = di.get("blake2b")
        self.log.info(f"hardfork deployment: {info}")

        key = ec.PrivateKey(bytes.fromhex("11" * 32))
        spk = script.p2wpkh(key.get_public_key())
        utxo = wallet.send_to(from_node=node, scriptPubKey=bytes(spk.data), amount=100_000_000)
        self.generate(wallet, 1)
        self.log.info(f"funded a p2wpkh output embit controls: {utxo['txid'][:16]}:{utxo['sent_vout']}")

        sink = script.p2wpkh(ec.PrivateKey(bytes.fromhex("22" * 32)).get_public_key())
        tx = Transaction(
            vin=[TransactionInput(bytes.fromhex(utxo["txid"]), utxo["sent_vout"], sequence=0xFFFFFFFE)],
            vout=[TransactionOutput(100_000_000 - 10_000, sink)],
        )
        psbt = PSBT(tx)
        psbt.inputs[0].witness_utxo = TransactionOutput(100_000_000, spk)

        ht = SIGHASH.ALL | SIGHASH.UNIFIED
        h = psbt.sighash(0, sighash=ht)
        sig = key.sign(h).serialize() + bytes([ht])
        tx.vin[0].witness = script.Witness([sig, key.get_public_key().sec()])
        raw = tx.serialize().hex()
        self.log.info(f"embit signed with hash type {hex(ht)}")

        res = node.testmempoolaccept([raw])[0]
        self.log.info(f"Knots verdict: allowed={res['allowed']} {res.get('reject-reason','')}")
        assert res["allowed"], res
        txid = node.sendrawtransaction(raw)
        blk = self.generate(wallet, 1)[0]
        assert txid in node.getblock(blk)["tx"], "embit's transaction was not mined"
        self.log.info("  embit's unified signature was accepted and mined by Knots")

        # Control, on its own unspent output so the rejection cannot be
        # "missing-inputs": the legacy segwit digest carrying the opt-in byte
        # must fail signature verification.
        utxo2 = wallet.send_to(from_node=node, scriptPubKey=bytes(spk.data), amount=100_000_000)
        self.generate(wallet, 1)
        tx2 = Transaction(
            vin=[TransactionInput(bytes.fromhex(utxo2["txid"]), utxo2["sent_vout"], sequence=0xFFFFFFFE)],
            vout=[TransactionOutput(100_000_000 - 10_000, sink)],
        )
        psbt2 = PSBT(tx2)
        psbt2.inputs[0].witness_utxo = TransactionOutput(100_000_000, spk)

        # first prove this output IS spendable with a correct unified signature
        good2 = key.sign(psbt2.sighash(0, sighash=ht)).serialize() + bytes([ht])
        tx2.vin[0].witness = script.Witness([good2, key.get_public_key().sec()])
        ok2 = node.testmempoolaccept([tx2.serialize().hex()])[0]
        assert ok2["allowed"], ("control output must be spendable", ok2)

        # now the same output with the legacy digest under the opt-in byte
        sig_bad = key.sign(psbt2.sighash(0, sighash=SIGHASH.ALL)).serialize() + bytes([ht])
        tx2.vin[0].witness = script.Witness([sig_bad, key.get_public_key().sec()])
        bad = node.testmempoolaccept([tx2.serialize().hex()])[0]
        assert not bad["allowed"], "a legacy digest with the opt-in byte must not verify"
        assert "missing-inputs" not in bad.get("reject-reason", ""), ("wrong rejection reason", bad)
        self.log.info(f"  control: same unspent output, legacy digest rejected ({bad.get('reject-reason','')})")


if __name__ == "__main__":
    EmbitInteropTest(__file__).main()
