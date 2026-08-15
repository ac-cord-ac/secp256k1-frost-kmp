# Secp256k1 Frost KMP

Experimental + Unsafe Kotlin Multiplatform implementation of FROST threshold signing and the ChillDKG distributed key generation protocol:

- **FROST signing** (`ac.cord.auxiliary.frost`): rewrite of [bip-frost-signing](https://github.com/siv2r/bip-frost-signing.git) (BIP-445).
- **ChillDKG** (`ac.cord.auxiliary.frost.dkg.chill`): rewrite of [bip-frost-dkg](https://github.com/BlockstreamResearch/bip-frost-dkg.git) — see its [package README](library/src/commonMain/kotlin/ac/cord/auxiliary/frost/dkg/chill/README.md).

## FROST signing

This implementation tracks the upstream Python reference at commit `4b566d5e03e84e318c60bbead5e9b21fedad09fc`
(BIP-0445 hash tags: `BIP0445/aux`, `BIP0445/nonce`, `BIP0445/noncecoef`, `BIP0445/deterministic/nonce`,
`BIP0445/trusted/keygen`). The test vectors under `library/src/commonTest/resources/vectors/` are copied from that
commit, and the tests mirror `python/tests.py` from the reference.

### Intentional deviations from the reference

- Kotlin/JVM bignum arithmetic (ionspin bignum) is variable-time, not constant-time: do not use this library where
  timing side channels matter.
- Errors are Kotlin exceptions: the reference's `ValueError` maps to `IllegalArgumentException`, and
  `InvalidContributionError` maps to `InvalidContributionException` (which extends `Exception`, not `Throwable`).
- Tweaks are passed as `List<ByteArray>` and length-checked at runtime, mirroring the reference's
  "The tweak must be a 32-byte array." error.

## ChillDKG

The ChillDKG port tracks the upstream reference at commit `a91896883f85b159415ecf298d5e844879af112d`
(BIP draft version 0.3.0-dev). Its test vectors live under
`library/src/commonTest/resources/vectors/chilldkg/`, and the tests mirror the upstream `python/tests.py`
(249 vector cases plus protocol simulations). See the
[package README](library/src/commonMain/kotlin/ac/cord/auxiliary/frost/dkg/chill/README.md) for the module map,
protocol flow, API, and deviations.

## Supported targets

- **JVM** and **Android**: fully supported; the JVM test suite (`./gradlew :library:jvmTest`) covers the complete
  upstream test vectors plus regression tests.
- **iOS** (iosX64, iosArm64, iosSimulatorArm64): builds against the same common Kotlin implementation of modular
  arithmetic (the platform-specific `pow` actuals were removed), but is currently not covered by automated tests.
- The linuxX64 target is disabled (commented out in `library/build.gradle.kts`).

## Keeping in sync with upstream

When re-syncing the FROST signing code with a newer upstream commit:

1. Update the hash tags in `Frost.kt` / `FrostSessionContext.kt` if they changed.
2. Copy the vector files from `python/vectors/` into `library/src/commonTest/resources/vectors/` (overwrite;
   `extra_vectors.json` is local and can be regenerated with the reference's deterministic trusted dealer).
3. Update the commit reference in this README.

For ChillDKG, follow the re-sync procedure in its
[package README](library/src/commonMain/kotlin/ac/cord/auxiliary/frost/dkg/chill/README.md).

## Known issues

Outstanding security and code-health items are tracked in [KNOWN_ISSUES.md](KNOWN_ISSUES.md).
