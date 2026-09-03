import logging
from binascii import hexlify
from embit import psbt, script, ec, bip32
from embit.descriptor import Descriptor
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath, InputScope, OutputScope
from embit.ec import PublicKey
from embit.transaction import SIGHASH
from io import BytesIO
from typing import List

from seedsigner.models.seed import Seed
from seedsigner.models.settings import SettingsConstants

logger = logging.getLogger(__name__)

class OPCODES:
    OP_RETURN = 106
    OP_PUSHDATA1 = 76



class PSBTParser():
    def __init__(self, p: PSBT, seed: Seed, network: str = SettingsConstants.MAINNET):
        self.psbt: PSBT = p
        self.seed = seed
        self.network = network

        self.policy = None
        self.spend_amount = 0
        self.change_amount = 0
        self.change_data = []
        self.fee_amount = 0
        self.input_amount = 0
        self.num_inputs = 0
        self.destination_addresses = []
        self.destination_amounts = []
        self.op_return_data: bytes = None

        self.root = None

        if self.seed is not None:
            self.parse()


    def get_change_data(self, change_num: int) -> dict:
        if change_num < len(self.change_data):
            return self.change_data[change_num]


    @property
    def num_change_outputs(self):
        return len(self.change_data)


    @property
    def is_multisig(self):
        """
            Multisig psbts will have "m" and "n" defined in policy
        """
        return "m" in self.policy


    @property
    def num_destinations(self):
        return len(self.destination_addresses)


    def _set_root(self):
        self.root = bip32.HDKey.from_seed(self.seed.seed_bytes, version=NETWORKS[SettingsConstants.map_network_to_embit(self.network)]["xprv"])


    def parse(self):
        if self.psbt is None:
            logger.info(f"self.psbt is None!!")
            return False

        if not self.seed:
            logger.info("self.seed is None!")
            return False

        self._set_root()

        # Try to fix missing fingerprints before parsing
        self._fill_missing_fingerprints()

        rt = self._parse_inputs()
        if rt == False:
            return False

        rt = self._parse_outputs()
        if rt == False:
            return False

        return True


    def _parse_inputs(self):
        self.input_amount = 0
        self.num_inputs = len(self.psbt.inputs)
        for inp in self.psbt.inputs:
            if inp.witness_utxo:
                self.input_amount += inp.witness_utxo.value
                script_pubkey = inp.witness_utxo.script_pubkey
            elif inp.non_witness_utxo:
                self.input_amount += inp.utxo.value
                script_pubkey = inp.script_pubkey

            inp_policy = PSBTParser._get_policy(inp, script_pubkey, self.psbt.xpubs)
            if self.policy == None:
                self.policy = inp_policy
            else:
                if self.policy != inp_policy:
                    raise RuntimeError("Mixed inputs in the transaction")

    def _parse_outputs(self):
        self.spend_amount = 0
        self.change_amount = 0
        self.change_data = []
        self.fee_amount = 0
        self.destination_addresses = []
        self.destination_amounts = []
        for i, out in enumerate(self.psbt.outputs):
            out_policy = PSBTParser._get_policy(out, self.psbt.tx.vout[i].script_pubkey, self.psbt.xpubs)
            is_change = False

            # if policy is the same - probably change
            if out_policy == self.policy:
                # double-check that it's change
                # we already checked in get_cosigners and parse_multisig
                # that pubkeys are generated from cosigners,
                # and witness script is corresponding multisig
                # so we only need to check that scriptpubkey is generated from
                # witness script

                # empty script by default
                sc = script.Script(b"")

                # if older multisig, just use existing script
                if self.policy["type"] == "p2sh":
                    sc = script.p2sh(out.redeem_script)

                # multisig, we know witness script
                if self.policy["type"] == "p2wsh":
                    sc = script.p2wsh(out.witness_script)

                elif self.policy["type"] == "p2sh-p2wsh":
                    sc = script.p2sh(script.p2wsh(out.witness_script))
                
                # Arbitrary p2sh; includes pre-segwit multisig (m/45')
                elif self.policy["type"] == "p2sh":
                    sc = script.p2sh(out.redeem_script)

                # single-sig
                elif "pkh" in self.policy["type"]:
                    my_pubkey = None

                    # should be one or zero for single-key addresses
                    if len(out.bip32_derivations.values()) > 0:
                        der = list(out.bip32_derivations.values())[0].derivation
                        my_pubkey = self.root.derive(der)

                    if self.policy["type"] == "p2pkh" and my_pubkey is not None:
                        sc = script.p2pkh(my_pubkey)

                    elif self.policy["type"] == "p2sh-p2wpkh" and my_pubkey is not None:
                        sc = script.p2sh(script.p2wpkh(my_pubkey))

                    elif self.policy["type"] == "p2wpkh" and my_pubkey is not None:
                        sc = script.p2wpkh(my_pubkey)

                    if sc.data == self.psbt.tx.vout[i].script_pubkey.data:
                        is_change = True

                elif "p2tr" in self.policy["type"]:
                    my_pubkey = None
                    # should have one or zero derivations for single-key addresses
                    if len(out.taproot_bip32_derivations.values()) > 0:
                        # TODO: Support keys in taptree leaves
                        leaf_hashes, derivation = list(out.taproot_bip32_derivations.values())[0]
                        der = derivation.derivation
                        my_pubkey = self.root.derive(der)
                        sc = script.p2tr(my_pubkey)

                    if sc.data == self.psbt.tx.vout[i].script_pubkey.data:
                        is_change = True

                if sc.data == self.psbt.tx.vout[i].script_pubkey.data:
                    is_change = True

            if self.psbt.tx.vout[i].script_pubkey.data[0] == OPCODES.OP_RETURN:
                # The data is written as: OP_RETURN + OP_PUSHDATA1 + len(payload) + payload
                self.op_return_data = self.psbt.tx.vout[i].script_pubkey.data[3:]

            elif is_change:
                addr = self.psbt.tx.vout[i].script_pubkey.address(NETWORKS[SettingsConstants.map_network_to_embit(self.network)])
                fingerprints = []
                derivation_paths = []

                # extract info from non-taproot outputs
                if len(self.psbt.outputs[i].bip32_derivations) > 0:
                    for d, derivation_path in self.psbt.outputs[i].bip32_derivations.items():
                        fingerprints.append(hexlify(derivation_path.fingerprint).decode())
                        derivation_paths.append(bip32.path_to_str(derivation_path.derivation))

                # extract info from taproot outputs
                if len(self.psbt.outputs[i].taproot_bip32_derivations) > 0:
                    for d, (leaf_hashes, derivation) in self.psbt.outputs[i].taproot_bip32_derivations.items():
                        fingerprints.append(hexlify(derivation.fingerprint).decode())
                        derivation_paths.append(bip32.path_to_str(derivation.derivation))

                self.change_data.append({
                    "output_index": i,
                    "address": addr,
                    "amount": self.psbt.tx.vout[i].value,
                    "fingerprint": fingerprints,
                    "derivation_path": derivation_paths,
                })
                self.change_amount += self.psbt.tx.vout[i].value

            else:
                addr = self.psbt.tx.vout[i].script_pubkey.address(NETWORKS[SettingsConstants.map_network_to_embit(self.network)])
                self.destination_addresses.append(addr)
                self.destination_amounts.append(self.psbt.tx.vout[i].value)
                self.spend_amount += self.psbt.tx.vout[i].value

        self.fee_amount = self.psbt.fee()
        return True


    @staticmethod
    def trim(tx):
        trimmed_psbt = psbt.PSBT(tx.tx)
        for i, inp in enumerate(tx.inputs):
            if inp.final_scriptwitness:
                # Taproot sign; trim to only final_scriptwitness
                # From BIP-371 and BIP-174, once final script witness is populated
                # it contains all necessary signatures
                trimmed_psbt.inputs[i].final_scriptwitness = inp.final_scriptwitness
            else:
                trimmed_psbt.inputs[i].partial_sigs = inp.partial_sigs

                # The declared hash type travels with an input that is not finished. A
                # signature carries its own in its last byte, so a lone signer never
                # needed this, but a co-signer reading the trimmed PSBT does: without it
                # the next one is not told the opt-in was asked for and signs the legacy
                # message instead, and the two signatures then cover different messages.
                # BIP-174 has a finalizer strip everything but the final fields, so the
                # branch above is left alone: its witness already carries the type.
                trimmed_psbt.inputs[i].sighash_type = inp.sighash_type

        return trimmed_psbt


    # The hash types this device will ask sign_with for. Everything else falls back to
    # SIGHASH.DEFAULT, which is what sign_with was called with before any hash type was
    # passed at all, and under which it signs the inputs asking for ALL and skips the rest.
    #
    # An allowlist rather than a blocklist, because the value comes off the wire from a host
    # this device does not trust, and it decides what the signature commits to. SIGHASH_NONE
    # commits to no outputs, so its signature lets anyone redirect what the input spends.
    # SIGHASH_SINGLE with no output at the input's index does the same, and on a legacy input
    # signs a constant that is reusable against any transaction spending that key.
    # ANYONECANPAY leaves the other inputs uncommitted. None of these are shown to the user,
    # so a transaction asking for one reviews as an ordinary send.
    #
    # This bounds what is asked for, not what can come back. Under DEFAULT, sign_with still
    # honours an input's own opt-in bit, so a PSBT declaring 0x21 is signed as 0x21 without
    # this device naming it. That commits to every output and every input, which is the
    # property being protected here. A bare 0x20 is not signed under DEFAULT by either
    # side: it is not on this list, and embit refuses it against the type asked for.
    SIGNABLE_SIGHASH_TYPES = frozenset({
        None,                               # the PSBT does not say
        SIGHASH.DEFAULT,                    # taproot, commits to everything
        SIGHASH.ALL,
        SIGHASH.UNIFIED | SIGHASH.ALL,      # the unified opt-in
    })

    @staticmethod
    def _derivation_matches_seed(public_key, derivation_path_obj, seed, network, fingerprint=None):
        """Whether one derivation on an input or output belongs to the given seed.

        A coordinator given only an xpub omits the fingerprint, which arrives as four
        zero bytes, so an exact comparison alone would answer False for inputs that are
        this seed's. The fallback derives the key the PSBT names and compares it, which
        is what PSBTParser does elsewhere before parsing.
        """
        if fingerprint is None:
            fingerprint = seed.get_fingerprint(network)
        if hexlify(derivation_path_obj.fingerprint).decode() == fingerprint:
            return True

        if derivation_path_obj.fingerprint == b"\x00\x00\x00\x00":
            root = bip32.HDKey.from_seed(
                seed.seed_bytes,
                version=NETWORKS[SettingsConstants.map_network_to_embit(network)]["xprv"],
            )
            try:
                return root.derive(derivation_path_obj.derivation).key.sec() == public_key.sec()
            except Exception as e:
                logger.debug("Fingerprint fallback derive failed: %s", e, exc_info=True)
        return False


    @staticmethod
    def _input_is_ours(inp, seed, network, fingerprint=None):
        """Whether any derivation on this input belongs to the given seed."""
        derivations = list(inp.bip32_derivations.items()) + [
            (pub, derivation) for pub, (_leaves, derivation) in inp.taproot_bip32_derivations.items()
        ]
        return any(
            PSBTParser._derivation_matches_seed(pub, derivation, seed, network, fingerprint)
            for pub, derivation in derivations
        )


    @staticmethod
    def effective_sighash_type(inp, requested):
        """The hash type this input will actually be signed with.

        Mirrors what sign_with resolves before it builds the digest: an input that
        declares nothing takes the requested type, and DEFAULT means ALL for anything
        that is not taproot, because the byte has to name an output type there. A caller
        naming a type owns the opt-in bit, so the request wins where that bit is in play.

        The screen shows this rather than the requested type: they differ for the two
        commonest PSBTs, and a screen that names a type no signature carries is worse
        than one that says nothing.
        """
        declared = inp.sighash_type
        effective = requested if declared is None else declared
        if not inp.is_taproot and effective == SIGHASH.DEFAULT:
            effective = SIGHASH.ALL
        # Kept so this stays a faithful mirror of sign_with rather than a shortcut that
        # happens to agree. It cannot fire today: sighash_type only returns something
        # other than DEFAULT when every input already declares that same value, so the
        # request and the effective type are equal before reaching here. It would start
        # mattering the moment sighash_type is allowed to ask for something an input did
        # not declare.
        if (
            requested is not None
            and requested != SIGHASH.DEFAULT
            and (effective | requested) & SIGHASH.UNIFIED
        ):
            effective = requested
        return effective


    @staticmethod
    def unsignable_inputs(tx, seed=None, network=SettingsConstants.MAINNET, fingerprint=None):
        """Inputs belonging to this seed that the signer will skip because the hash type
        they declare is not the one this device is about to ask for.

        Scoped to this seed's own inputs. An input the device holds no key for yields no
        signature whatever its hash type, and a co-signer finishes it, so counting those
        would refuse the collaborative transactions this device exists to take part in.

        An input declaring nothing takes whatever is asked for, and DEFAULT and ALL are
        the same request, so neither is skipped. The comparison is embit's own, so this
        cannot drift from what sign_with actually does.

        Signing past one of these produces a transaction signed less completely than the
        device reports, because the signature count still rises.
        """
        from embit.psbt import sighash_types_agree

        requested = PSBTParser.sighash_type(tx)
        return [
            i for i, inp in enumerate(tx.inputs)
            if inp.sighash_type is not None
            and not sighash_types_agree(inp.sighash_type, requested)
            and (seed is None or PSBTParser._input_is_ours(inp, seed, network, fingerprint))
        ]


    # Why a transaction cannot be described by one hash type on the approval screen.
    REFUSED_PARTIAL = "partial"   # an input this seed holds would be skipped
    REFUSED_MIXED = "mixed"       # all would be signed, with types no one label covers


    @staticmethod
    def screen_sighash_type(tx, seed, network=SettingsConstants.MAINNET):
        """The hash type to name on the approval screen, and why not where there is none.

        Returns (hash_type, None) when there is one honest thing to show, and
        (None, reason) otherwise. The two reasons are different situations and the user
        is told different things: one means part of the transaction would go unsigned,
        the other that every part would be signed but with types no single label
        describes.

        One place, so the view and the tests cannot describe different behaviour.

        Inputs this seed holds decide it where there are any. Where there are none the
        whole transaction does, because sign_with also matches the root key inside a
        script with no derivation present, and those inputs still get signed.
        """
        requested = PSBTParser.sighash_type(tx)
        fingerprint = seed.get_fingerprint(network)

        if PSBTParser.unsignable_inputs(tx, seed=seed, network=network, fingerprint=fingerprint):
            return None, PSBTParser.REFUSED_PARTIAL

        ours = [
            inp for inp in tx.inputs
            if PSBTParser._input_is_ours(inp, seed, network, fingerprint)
        ]
        effective = {
            PSBTParser.effective_sighash_type(inp, requested) for inp in (ours or tx.inputs)
        }
        if len(effective) != 1:
            return None, PSBTParser.REFUSED_MIXED

        # The declared type comes off the wire as four little endian bytes with no
        # bound, so where no input matches this seed the fallback above can carry a
        # value the device would never sign. Naming it on the approval screen would
        # describe a signature that cannot exist.
        shown = effective.pop()
        if shown not in PSBTParser.SIGNABLE_SIGHASH_TYPES:
            return None, PSBTParser.REFUSED_MIXED
        return shown, None


    @staticmethod
    def signed_hash_types(tx):
        """Every signature on this PSBT: where it sits, the hash type it carries, and
        the signature itself.

        Read back off the signatures rather than predicted, so it says what was actually
        produced however the signer decided to produce it. The raw bytes are returned
        alongside the hash type because a host can pre-populate any of these slots: a
        caller comparing only which slots are occupied would take a signature that
        replaced planted junk for one that was already there.
        """
        def hash_type(raw):
            # a taproot key path signature is 64 bytes and carries no trailing byte,
            # which is SIGHASH_DEFAULT rather than an absent hash type. A value the host
            # left empty has no hash type at all; it is reported as one nothing matches
            # so it can never be mistaken for the type on the screen.
            if not raw:
                return None
            return raw[-1] if len(raw) != 64 else SIGHASH.DEFAULT

        found = {}
        for i, inp in enumerate(tx.inputs):
            for key, sig in inp.partial_sigs.items():
                raw = bytes(sig)
                found[(i, "partial", bytes(key.sec()))] = (hash_type(raw), raw)
            for key, sig in inp.taproot_sigs.items():
                raw = bytes(sig)
                found[(i, "taproot", str(key))] = (hash_type(raw), raw)
            # Two separate reads, not one chained pair. The pinned embit puts a taproot
            # key path signature in final_scriptwitness and has no taproot_key_sig at
            # all; an embit that adds one while still writing the witness would, under
            # an elif, silently stop this from reading the witness, and a signature
            # would escape the check that this whole function exists to feed.
            key_sig = getattr(inp, "taproot_key_sig", None)
            if key_sig is not None:
                raw = bytes(key_sig)
                found[(i, "taproot_key", b"")] = (hash_type(raw), raw)
            if inp.final_scriptwitness and inp.final_scriptwitness.items:
                raw = bytes(inp.final_scriptwitness.items[0])
                found[(i, "witness", b"")] = (hash_type(raw), raw)
        return found


    @staticmethod
    def sighash_type(tx):
        """The hash type to pass to sign_with for this PSBT.

        The inputs' own type where they all ask for the same signable one, and
        SIGHASH.DEFAULT otherwise. Under DEFAULT embit signs the inputs asking for ALL and
        skips the rest, which is what this did before a hash type was passed at all.
        """
        declared = {inp.sighash_type for inp in tx.inputs}
        if len(declared) != 1 or not declared <= PSBTParser.SIGNABLE_SIGHASH_TYPES:
            return SIGHASH.DEFAULT
        return declared.pop() or SIGHASH.DEFAULT

    @staticmethod
    def sig_count(tx):
        cnt = 0
        for i, inp in enumerate(tx.inputs):
            if inp.final_scriptwitness is not None:
                # Taproot sign
                cnt += 1
            else:
                cnt += len(list(inp.partial_sigs.keys()))

        return cnt


    @staticmethod
    def _get_policy(scope, scriptpubkey, xpubs):
        """Parse scope and get policy"""
        # we don't know the policy yet, let's parse it
        script_type = scriptpubkey.script_type()
        # p2sh can be either legacy multisig, or nested segwit multisig
        # or nested segwit singlesig
        if script_type == "p2sh":
            if scope.witness_script is not None:
                script_type = "p2sh-p2wsh"
            elif (
                scope.redeem_script is not None
                and scope.redeem_script.script_type() == "p2wpkh"
            ):
                script_type = "p2sh-p2wpkh"
        policy = {"type": script_type}

        # expected multisig
        script = None
        if script_type:
            if "p2wsh" in script_type and scope.witness_script is not None:
                script = scope.witness_script

            elif "p2sh" == script_type and scope.redeem_script is not None:
                script = scope.redeem_script

            if script is not None:
                m, n, pubkeys = PSBTParser._parse_multisig(script)
            
                # check pubkeys are derived from cosigners
                try:
                    cosigners = PSBTParser._get_cosigners(pubkeys, scope.bip32_derivations, xpubs)
                    policy.update({"m": m, "n": n, "cosigners": cosigners})
                except:
                    policy.update({"m": m, "n": n})
        
        return policy


    @staticmethod
    def _parse_multisig(sc):
        """Takes a script and extracts m,n and pubkeys from it"""
        # OP_m <len:pubkey> ... <len:pubkey> OP_n OP_CHECKMULTISIG
        # check min size
        if len(sc.data) < 37 or sc.data[-1] != 0xAE:
            raise ValueError("Not a multisig script")
        m = sc.data[0] - 0x50
        if m < 1 or m > 16:
            raise ValueError("Invalid multisig script")
        n = sc.data[-2] - 0x50
        if n < m or n > 16:
            raise ValueError("Invalid multisig script")
        s = BytesIO(sc.data)
        # drop first byte
        s.read(1)
        # read pubkeys
        pubkeys = []
        for i in range(n):
            char = s.read(1)
            if char != b"\x21":
                raise ValueError("Invlid pubkey")
            pubkeys.append(ec.PublicKey.parse(s.read(33)))
        # check that nothing left
        if s.read() != sc.data[-2:]:
            raise ValueError("Invalid multisig script")
        return m, n, pubkeys


    @staticmethod
    def _get_cosigners(pubkeys, derivations, xpubs):
        """Returns xpubs used to derive pubkeys using global xpub field from psbt"""
        cosigners = []
        for i, pubkey in enumerate(pubkeys):
            if pubkey not in derivations:
                raise ValueError("Missing derivation")
            der = derivations[pubkey]
            for xpub in xpubs:
                origin_der = xpubs[xpub]
                # check fingerprint
                if origin_der.fingerprint == der.fingerprint:
                    # check derivation - last two indexes give pub from xpub
                    if origin_der.derivation == der.derivation[:-2]:
                        # check that it derives to pubkey actually
                        if xpub.derive(der.derivation[-2:]).key == pubkey:
                            # append strings so they can be sorted and compared
                            cosigners.append(xpub.to_base58())
                            break
        if len(cosigners) != len(pubkeys):
            raise RuntimeError("Can't get all cosigners")
        return sorted(cosigners)


    @staticmethod
    def get_input_fingerprints(psbt: PSBT) -> List[str]:
        """
            Exctracts the fingerprint from each input's derivation path.

            TODO: It's unclear if these derivations/fingerprints would ever be missing.
            Research on PSBT standard and known wallet coordinator implementations
            needed.
        """
        fingerprints = set()
        for input in psbt.inputs:
            for pub, derivation_path in input.bip32_derivations.items():
                fingerprints.add(hexlify(derivation_path.fingerprint).decode())

            for pub, (leaf_hashes, derivation_path) in input.taproot_bip32_derivations.items():
                # TODO: Support spends from leaves; depends on support in embit
                if len(leaf_hashes) > 0:
                    raise Exception("Signing keyspends from within a taptree not yet implemented")
                fingerprints.add(hexlify(derivation_path.fingerprint).decode())
        return list(fingerprints)


    @staticmethod
    def has_matching_input_fingerprint(psbt: PSBT, seed: Seed, network: str = SettingsConstants.MAINNET):
        """
            Extracts the fingerprint from each psbt input utxo. Returns True if any match
            the current seed.
        """
        # Derived once. This runs for every stored seed on the seed-select screen, over
        # every derivation of every input, and each call is an EC point multiply.
        seed_fingerprint = seed.get_fingerprint(network)

        def check_fingerprint_match(public_key: PublicKey, derivation_path_obj: DerivationPath):
            return PSBTParser._derivation_matches_seed(
                public_key, derivation_path_obj, seed, network, seed_fingerprint)

        # Check all derivations in all inputs
        for input in psbt.inputs:
            # Check regular BIP32 derivations
            for public_key, derivation_path_obj in input.bip32_derivations.items():
                if check_fingerprint_match(public_key, derivation_path_obj):
                    return True
            
            # Check Taproot derivations
            for public_key, (leaf_hashes, derivation_path_obj) in input.taproot_bip32_derivations.items():
                if check_fingerprint_match(public_key, derivation_path_obj):
                    return True
        
        return False


    def verify_multisig_output(self, descriptor: Descriptor, change_num: int) -> bool:
        change_data = self.get_change_data(change_num)
        i = change_data["output_index"]
        output = self.psbt.outputs[i]
        is_owner = descriptor.owns(output)
        # print(f"{self.psbt.tx.vout[i].script_pubkey.address()} | {output.value} | {is_owner}")
        return is_owner


    def _fill_missing_fingerprints(self):
        """
        Fix for when fingerprint is missing (defaults to all zeros). Happens when the user
        creates a new wallet in an external coordinator but only provides the xpub
        (fingerprint and derivation path are omitted).

        Filling the missing fingerprints allows SeedSigner to correctly identify inputs /
        outputs that belong to the signing seed.

        see: https://github.com/SeedSigner/seedsigner/issues/359
        """
        if not self.root:
            return 0
        
        def _fill_scope(scope: InputScope | OutputScope):
            """Helper function to fill missing fingerprints in a scope (input/output)"""
            signing_seed_fingerprint = self.root.child(0).fingerprint
            
            # Helper function to check and fix fingerprint
            def _get_updated_fingerprint(public_key: PublicKey, derivation_path_obj: DerivationPath) -> DerivationPath | None:
                if derivation_path_obj.fingerprint != b"\x00\x00\x00\x00":
                    return None
                
                # Derive the public key from the currently loaded seed using the derivation 
                # contained in the PSBT. If the derived public key exactly matches 
                # the PSBT-provided public key, we can be confident that this input/output 
                # is owned by the signing seed. In that case we populate the missing (zero) 
                # fingerprint with the signing seed's master fingerprint so downstream 
                # parsing/signing can treat it as owned by this seed.
                derived_key = self.root.derive(derivation_path_obj.derivation)
                if derived_key.key.sec() == public_key.sec():
                    return DerivationPath(signing_seed_fingerprint, derivation_path_obj.derivation)
                return None
            
            # Handle regular BIP32 derivations
            for public_key, derivation_path_obj in list(scope.bip32_derivations.items()):
                new_derivation = _get_updated_fingerprint(public_key, derivation_path_obj)
                if new_derivation:
                    scope.bip32_derivations[public_key] = new_derivation
                    logger.debug(f"Filled missing fingerprint for pubkey {public_key.sec().hex()} derivation {bip32.path_to_str(derivation_path_obj.derivation)}")
            
            # Handle Taproot derivations  
            for public_key, (leaf_hashes, derivation_path_obj) in list(scope.taproot_bip32_derivations.items()):
                new_derivation = _get_updated_fingerprint(public_key, derivation_path_obj)
                if new_derivation:
                    scope.taproot_bip32_derivations[public_key] = (leaf_hashes, new_derivation)
                    logger.debug(f"Filled missing fingerprint for pubkey {public_key.sec().hex()} derivation {bip32.path_to_str(derivation_path_obj.derivation)}")

        for inp in self.psbt.inputs:
            _fill_scope(inp)

        for out in self.psbt.outputs:
            _fill_scope(out)