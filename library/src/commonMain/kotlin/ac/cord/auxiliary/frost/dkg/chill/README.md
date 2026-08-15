# ChillDKG (Kotlin port)

Kotlin Multiplatform port of the ChillDKG Python reference implementation from
[BlockstreamResearch/bip-frost-dkg](https://github.com/BlockstreamResearch/bip-frost-dkg)
@ `a91896883f85b159415ecf298d5e844879af112d` (BIP draft version 0.3.0-dev).

ChillDKG is a distributed key generation (DKG) protocol for FROST: it lets `n` participants
jointly generate a FROST threshold public key and secret shares without a trusted dealer,
so it removes the single point of failure of the trusted-dealer keygen in
`ac.cord.auxiliary.frost.trusted_dealer_keygen`. Its output plugs directly into the FROST
signing implementation in `ac.cord.auxiliary.frost` (BIP-445).

> **WARNING**: like the Python reference, this code is slow and trivially vulnerable to
> side-channel attacks (all arithmetic is variable-time pure-Kotlin bignum). Do not use
> for anything but tests.

## Module map

| File | Contents |
|---|---|
| `ChillDkg.kt` | The full public API (participant/coordinator steps, recovery, exceptions, session/message types) |
| `EncPedPop.kt` | EncPedPop: SimplPedPop with ECDH-encrypted share distribution (internal) |
| `SimplPedPop.kt` | SimplPedPop: Pedersen DKG with proofs of possession (internal); defines `DkgOutput` |
| `Vss.kt` | Feldman VSS commitments: generation, verification, serialization (internal) |
| `ChillDkgCrypto.kt` | secp256k1lab primitives not exposed by the secp256k1-kmp bindings: Schnorr with custom tag prefixes (e.g. `"BIP DKG/pop message"`), `pubkeyGenPlain`, libsecp256k1-semantics ECDH |
| `ChillDkgErrors.kt` | `BIP DKG/` tagged hashing and the `ProtocolError` exception hierarchy |

Only the types and functions in `ChillDkg.kt` (plus the exception classes in
`ChillDkgErrors.kt`) are the supported public API, mirroring the `__all__` list of the
Python reference. Everything else is internal protocol machinery.

## Protocol overview

ChillDKG involves `n` participants and an untrusted coordinator (which may be one of the
participants). The coordinator relays messages but cannot learn secrets or bias the key;
faulty participants or a faulty coordinator are detected and blamed via exceptions.

1. **Setup** — each participant picks a long-term host key pair (`hostpubkeyGen`) and
   shares the host public key with the group. Everyone agrees on `SessionParams(t, hostpubkeys)`
   and can check agreement out-of-band via `paramsHash`. The host secret key must be
   cryptographically secure randomness; **back it up** — together with the per-session
   recovery data it is sufficient to recover all session outputs.
2. **Round 1** — each participant runs `participantStep1` and sends the resulting message
   to the coordinator; the coordinator aggregates with `coordinatorStep1`.
3. **Round 2** — each participant runs `participantStep2` on the coordinator's first
   message; the coordinator runs `coordinatorFinalize` to produce the certificate.
4. **Finalize** — each participant runs `participantFinalize` on the certificate to obtain
   the `DkgOutput` (own secret share, threshold public key, all public shares) and the
   recovery data to store.
5. **Investigation** — if a step raises `FaultyParticipantOrCoordinatorError`, the
   coordinator runs `coordinatorInvestigate` and each honest participant runs
   `participantInvestigate` to identify the faulty party (`FaultyParticipantError` or
   `FaultyCoordinatorError`).
6. **Recovery** — a participant who lost its session state can recompute its outputs from
   the backed-up host secret key and recovery data (`participantRecover`,
   `coordinatorRecover`), and the group acknowledges recovered shares
   (`participantRecoveryAckSign`, `participantRecoveryAcksVerify`).

The `DkgOutput` maps onto FROST signing as follows: `threshPk`/`pubshares` form the
`FrostSignersContext`, and `secshare` is the signer's secret share for
`Frost.nonceGen` / `FrostSessionContext.sign`.

## Exceptions

Ported from the reference (Python class → Kotlin equivalent):

- `SessionParamsError` (base) → `InvalidHostPubkeyError`, `DuplicateHostPubkeyError`,
  `ThresholdOrCountError`
- `HostSeckeyError`, `RandomnessError`
- `ProtocolError` (base) → `FaultyParticipantError`, `FaultyCoordinatorError`,
  `FaultyParticipantOrCoordinatorError`, `UnknownFaultyParticipantOrCoordinatorError`
- `RecoveryDataError`, `InvalidRecoveryAckError`
- `MsgParseError` (extends `IllegalArgumentException`, as Python's extends `ValueError`)

Python built-in exceptions map as: `ValueError` → `IllegalArgumentException`,
`IndexError` → `IndexOutOfBoundsException`, `RuntimeError` → `IllegalStateException`,
`assert` → `require`/`check`.

## Testing

- All 10 official vector files are copied to
  `library/src/commonTest/resources/vectors/chilldkg/` and exercised by
  `ChillDkgVectorTests` (249 vector cases, including error cases with exact exception
  types and messages).
- `ChillDkgCorrectnessTests` mirrors `python/tests.py`: protocol simulations over the
  `(t, n)` grid `{(1,1), (1,2), (2,2), (2,3), (2,5)}`, investigation mode, secret
  recovery, and recovery acknowledgments.
- Run with `JAVA_HOME=<jdk-21> ./gradlew :library:jvmTest` (the build does not work on
  JDK 25).

## Deviations from the Python reference

- `tests.py`'s `simulate_chilldkg_full` (asyncio network plumbing) is not ported; the
  identical API flow is covered by `ChillDkgSimulation.simulateChilldkg`.
- Python's three structurally identical `DkgOutput` NamedTuples are a single shared
  Kotlin `DkgOutput` type.
- `EncPedPop.coordinatorStep` returns a small data class instead of a 4-tuple.
- `paramsValidate` catches any `Exception` from pubkey parsing (Python catches only
  `ValueError`); unobservable for length-checked inputs.
- Like the reference, secrets are not zeroized; they are held in immutable `ByteArray`s
  passed by value.

## Keeping in sync with upstream

When re-syncing with a newer upstream commit:

1. Diff `python/chilldkg_ref/` against the pinned commit and port the changes module by
   module (`vss.py` → `Vss.kt`, `simplpedpop.py` → `SimplPedPop.kt`,
   `encpedpop.py` → `EncPedPop.kt`, `chilldkg.py` → `ChillDkg.kt`,
   `util.py` → `ChillDkgErrors.kt`).
2. Overwrite the vector files in `library/src/commonTest/resources/vectors/chilldkg/`
   from upstream `vectors/`.
3. Update the commit reference at the top of this file and in the root README.
