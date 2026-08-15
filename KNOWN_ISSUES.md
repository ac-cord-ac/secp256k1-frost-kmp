# Known issues and future work

Outstanding security and code-health items identified during the 2026-08 review and the
re-sync with [siv2r/bip-frost-signing](https://github.com/siv2r/bip-frost-signing) @
`4b566d5e03e84e318c60bbead5e9b21fedad09fc`. Items are grouped by theme and roughly ordered
by priority within each section.

## Security

### 1. Variable-time arithmetic (documented limitation, not fixed)

All scalar, field, and elliptic-curve arithmetic is pure-Kotlin
[ionspin bignum](https://github.com/ionspin/kotlin-multiplatform-bignum) with data-dependent
branches on secret values:

- `library/src/commonMain/kotlin/ac/cord/auxiliary/cryptography/GroupElement.kt` —
  `batchMul` branches on scalar bits.
- `library/src/commonMain/kotlin/ac/cord/auxiliary/cryptography/FastGroupElementMultipication.kt` —
  `mul` early-terminates at `bitLength`, leaking scalar length.
- `library/src/commonMain/kotlin/ac/cord/auxiliary/cryptography/APrimeFieldElement.kt` —
  `toBigInteger()` performs a variable-time modular inversion for any non-normalized value.

This is acceptable for a reference implementation but dangerous wherever timing/cache side
channels matter (e.g. a signing server, or on-device signing with long-lived keys). The
constant-time libsecp256k1 backing `fr.acinq.secp256k1` is currently only used for hashing
and final Schnorr verification.

**Future work:** route secret-dependent operations (scalar multiplication, inversion)
through `fr.acinq.secp256k1` bindings, or implement constant-time field/scalar arithmetic.
As a side benefit this should also fix the performance problem noted under Code health.

### 2. Trusted-dealer keygen only

Key generation is trusted-dealer only (`frost/dkg/trusted/FrostTrustedDealer.kt`),
matching the upstream reference — whose own header warns it is insecure and not for
production use. A single party knows the full threshold secret and all shares.

**Future work:** if real deployment is planned, evaluate
[bip-frost-dkg](https://github.com/BlockstreamResearch/bip-frost-dkg) or another DKG, and
surface the trusted-dealer warning in the KMP API documentation (KDoc), not just the README.

### 3. Aggregation API makes it easy to skip verification

`FrostSessionContext.partialSignatureAggregate` never verifies the individual partial
signatures or the final aggregate signature. This matches the BIP (verification is a
separate step), but nothing in the API enforces or loudly documents it, so callers can
aggregate unverified contributions.

**Future work:** add a `verifyAndAggregate` convenience that runs `partialSignatureVerify`
on every contribution (attributing blame via `InvalidContributionException`) and
`Secp256k1.verifySchnorr` on the aggregate before returning it.

### 4. Residual secret-material hygiene gaps

`FrostSecretNonce.clear()` zero-fills the raw nonce array, but material derived from it
during signing is not zeroized:

- `k1_`/`k2_` `Scalar`s (and their internal ionspin `BigInteger`s) in
  `FrostSessionContext.sign` remain on the heap until GC.
- `FrostTrustedDealership` holds all secret shares as `ByteVector32`s with no wipe
  mechanism.
- ionspin `BigInteger` is immutable and heap-allocated, so full zeroization is not
  achievable without changing the arithmetic backend — another argument for item 1.

**Future work:** document the residual lifetime of derived secrets in KDoc; add a `wipe()`
to `FrostTrustedDealership`; reconsider the arithmetic backend.

### 5. Logging on attacker-controlled input

`FrostSessionContext.partialSignatureVerify` logs parse failures of peer-supplied public
nonces via `logger.e` before returning `false`. In a server loop processing untrusted
contributions this is a log-spam / log-injection vector.

**Future work:** remove or downgrade these log statements; return structured failure
information instead.

## Code health

### 6. Performance of the common bignum path

The common-code square-and-multiply `pow` (`cryptography/Math.kt`) is much slower than the
old JVM `java.math.BigInteger.modPow` actual it replaced — the full JVM test suite takes
~2 minutes. `FastGroupElementMultiplication.FAST_G` also pays ~255 point-doublings lazily
per process.

**Future work:** batch inversions (Montgomery trick), a proper fixed-window or wNAF scalar
multiplication, or delegating to libsecp256k1 (see Security item 1). Also make the
precomputed table an immutable `List` built once.

### 7. Dependency weight and ABI coupling

`lightning-kmp-core` is pulled in only for `Random.secure()` (CSPRNG) and bitcoin-kmp
types. It is a heavy dependency, and its published native klibs are coupled to a specific
Kotlin ABI — this is what currently breaks iOS compilation (see CI/build item 10).

**Future work:** inline a small expect/actual CSPRNG (`SecureRandom` on JVM/Android,
`SecRandomCopyBytes` on Apple, `/dev/urandom` on native Linux) and depend on bitcoin-kmp /
secp256k1-kmp directly.

### 8. Incomplete input validation

`Frost.deriveInterpolatingValue` range-checks only `my_id`, not the other identifiers in
the list (ids >= 2^32 would overflow the 4-byte serialization used elsewhere). Flows that
matter currently bound all ids via `FrostSignersContext.validateSignersContext`, but the
function is public and can be called directly.

**Future work:** validate every id in the list, or make the function internal.

### 9. Test infrastructure

- `TestHelpers` reads vector resources via a relative path (`src/commonTest/resources`),
  tying tests to the Gradle working directory — brittle if the test task's working dir
  changes.
- `JsonExtensions.getValueOrNull` still uses `catch (Throwable)` (test-only).
- `androidHostTest` exists but does not run the crypto suite; wiring commonTest into it
  would have caught the broken Android `pow` actual removed in the re-sync.
- No platform test coverage for iOS at all.

**Future work:** load resources through the classpath/compose-resources mechanism, narrow
the catch, run the full suite on `androidHostTest`, and add iOS simulator tests once the
toolchain is fixed.

## CI / build

### 10. CI is currently broken

- `.github/workflows/gradle.yml` triggers on branch `main`, but the default branch is
  `master` — CI never runs.
- The CI matrix includes `linuxX64Test`, but the linuxX64 target is commented out in
  `library/build.gradle.kts` — the job will fail once the trigger is fixed.
- `iosSimulatorArm64Test` fails on a klib ABI mismatch: the published
  `lightning-kmp-core-iosx64:1.11.5` klib was built with a newer Kotlin than this
  project's 2.2.20 toolchain. Fix by upgrading the project's Kotlin/AGP/Gradle, or by
  removing the lightning-kmp dependency (Code health item 7).

### 11. Toolchain age

- The build fails on JDK 25 (`JavaVersion.parse` chokes on "25.0.3"); JDK 21 works. A
  Gradle wrapper upgrade should fix this.
- Publishing metadata is still template placeholder: the Android `namespace` in
  `library/build.gradle.kts` is `org.jetbrains.kotlinx.multiplatform.library.template`,
  and the POM says "My library" with license "XXX". `publish.yml` publishes on GitHub
  release, so this would ship as-is.

**Future work:** upgrade Gradle/AGP/Kotlin together, fix the CI branch trigger and matrix,
and fill in real publishing metadata before the first release.

## Process

### 12. Upstream drift detection

The README pins the tracked upstream commit and documents the re-sync procedure, but
nothing enforces it.

**Future work:** add a CI job or script that diffs
`library/src/commonTest/resources/vectors/` against `python/vectors/` of
siv2r/bip-frost-signing at the pinned commit, so silent vector drift fails the build.
