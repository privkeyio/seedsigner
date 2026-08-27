# Unified opt-in sighash: verification

Checks that this fork's signing produces Bitcoin Knots' unified opt-in
signature hash, and that Knots accepts the result.

`embit` is pinned to `privkeyio/embit@unified-sighash-v0.8.0`, which implements the
algorithm for all four script types.

It is based on embit **v0.8.0**, the release this repo pins, not on embit
master. Master carries PSBT version validation added after v0.8.0 that rejects
this repo's test fixtures, failing 14 tests before any sighash work is
involved. If the suite suddenly shows those failures, check which embit is
actually installed.

## test_vectors.py

Runs with the ordinary suite (`pytest tests/`). Checks the pinned embit against
Knots' 166 cross-implementation vectors, vendored in `data/`, covering
bare/P2SH, segwit v0, taproot key path and tapscript.

It imports embit normally, with no `sys.path` manipulation, so it exercises the
dependency `requirements.txt` installs rather than a working tree that happens
to sit beside it. Pointed at an embit without the feature, 167 of its 168 cases
fail, which is what makes a pass meaningful.

## knots_interop.py

Drives a Knots regtest node, signs with embit and requires the node to accept
and mine the transaction. The control spends a separate unspent output with
the legacy segwit digest under the opt-in byte and requires rejection for
signature verification failure, not `missing-inputs`.

## seedsigner_knots_e2e.py

The same, through SeedSigner's own code: its `Seed` and `PSBTParser`, and the
exact `psbt.sign_with(root)` call the app makes in `psbt_views.py`. Asserts the
hash type byte is `0x21` and that Knots mines the result.

The node-driven scripts need a Knots build and run from its functional test
directory, which supplies the framework and `config.ini`. Copy them there and
set `SEEDSIGNER_SRC` to this repo's `src/` if it is not two levels up:

    cp tests/unified/*.py <knots-build>/test/functional/
    SEEDSIGNER_SRC=$PWD/src python3 <knots-build>/test/functional/seedsigner_knots_e2e.py

They take embit from the environment, so they too test the pinned dependency.

## cve_2020_14199.py

Builds the attack the CVE describes and runs it against a Knots node. A signer
is shown one input understated, displays a fee of 0.0001 BTC, and signs; the
real transaction pays 9.9901 BTC.

    BIP143 segwit v0   signature valid in the real transaction: True   attack succeeds
    unified opt-in     signature valid in the real transaction: False  attack blocked

Same transaction, same keys, same signer; only the hash type byte differs.

Note the fee cap is disabled (`testmempoolaccept(..., 0)`) so the result
reflects signature validity rather than relay policy. Left enabled, the attack
is stopped by `max-fee-exceeded`, which is mempool policy a miner can ignore,
not consensus.

## ../test_flows_unified.py

The complete UI flow, driven through SeedSigner's own `FlowTest` harness with a
two-input PSBT that requests the unified sighash:

    MainMenu -> Scan -> ScanView(PSBT) -> PSBTSelectSeed -> ScanSeedQR
      -> SeedFinalize -> SeedOptions -> PSBTOverview -> PSBTMath
      -> PSBTAddressDetails -> PSBTChangeDetails x3 -> PSBTFinalize
      -> PSBTSignedQRDisplay -> MainMenu

Every screen a user touches. Asserts both signatures carry hash type `0x21`.
The signed PSBT is captured at the signed-QR screen because the controller
clears its state on returning to the main menu.

It lives in `tests/` rather than here so it runs with the normal suite.

## Emulator

Verified running under the SeedSigner emulator with this embit: the PSBT
scanned in as an animated UR QR, the seed as a SeedQR, every review screen
walked and approved, and both signatures carrying hash type `0x21`. Repeated
against a Knots regtest chain past the activation height, where the transaction
the emulator signed was accepted and mined.

The emulator predates `Renderer.is_screenshot_generator`, so a one-line property
has to be added to its `gui/renderer.py` when overlaying onto current `dev`. Its
camera opens a real webcam, so driving it without one means standing in for
`emulator/webcamvideostream.py`.
