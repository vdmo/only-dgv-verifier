# Build Provenance

This document records the build chain for the DGV verifier binaries, providing transparency about how the binaries were produced without revealing the source code.

## Binaries

| Binary | Purpose | Architecture |
|---|---|---|
| `bin/dgv-verifier` | Native Rust engine — evaluates state, scripts, and governance constraints | x86_64-unknown-linux-gnu |
| `bin/only-gate` | Native Rust engine — validates hardware/crypto constraints (ML-KEM-768, SHAKE-256, GPU TEE) | x86_64-unknown-linux-gnu |

## Build Environment

| Component | Value |
|---|---|
| Language | Rust |
| Toolchain | stable (latest as of build date) |
| Target | x86_64-unknown-linux-gnu |
| Linker | system ld |
| Optimization | release profile (opt-level=3, lto=true) |

## Dependencies

The verifier engines depend on the following Rust crates (from crates.io):

- `serde` / `serde_json` — serialization
- `sha2` — SHA-256 hashing
- `clap` — command-line argument parsing
- `rayon` — parallel computation

No external C dependencies. No network calls at runtime. No dynamic linking beyond libc.

## Reproducibility

The binaries are deterministic: given the same source and the same build environment, the output binary is byte-identical. This is verified by comparing SHA-256 checksums across builds.

## Checksums

Checksums are computed and published with every release. See `CHECKSUMS.txt` in the release artifacts.

Checksums are GPG-signed with the DGV Release Signing key (Ed25519). The signature is in `CHECKSUMS.txt.sig` and the public key is in `RELEASE_SIGNING_KEY.asc`.

To verify a binary:

```bash
# 1. Import the release signing key
gpg --import RELEASE_SIGNING_KEY.asc

# 2. Verify the checksums file signature
gpg --verify CHECKSUMS.txt.sig CHECKSUMS.txt

# 3. Verify the binary checksum
sha256sum bin/dgv-verifier
# Compare against the checksum in CHECKSUMS.txt
```

## Release Signing Key

| Property | Value |
|---|---|
| Algorithm | EdDSA (Ed25519) |
| Key ID | A2BE0CF8812FF724BD38A3730B349D7F61A16EF4 |
| Identity | DGV Release Signing <release@only.institute> |
| Expires | 2027-12-31 |
| Public key | `RELEASE_SIGNING_KEY.asc` |

## SLSA Provenance Level

Current: **SLSA Level 2** (signed build provenance, GPG-signed checksums, documented build environment)

Planned for v0.3.0: **SLSA Level 3** (reproducible builds from source, isolated build environment verified under NDA)

## Source Access

The verifier source code is not publicly available due to IP protection (see `TRUST_ROOT.md`).

For NDA-gated source review:
- Contact: trust@only.institute
- Review paths: Attestation Review or Sandbox Review (see `TRUST_ROOT.md`)
- Review scope: verifier source, build system, dependency versions, test coverage

## Build Verification Under NDA

Organizations requiring build verification can:

1. Sign an NDA with Only Institute
2. Receive access to the source repository (read-only)
3. Build the binary themselves using the documented build environment
4. Compare their build output checksum against the published checksum
5. Issue an attestation if the checksums match

This proves that the published binary was built from the reviewed source, closing the source-to-binary gap without making the source public.

## Contact

For build provenance questions or build verification requests:

- **Email:** trust@only.institute
- **Repository:** https://github.com/vdmo/only-dgv-verifier
