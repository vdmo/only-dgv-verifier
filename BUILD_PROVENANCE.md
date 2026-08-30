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

To verify a binary:

```bash
sha256sum bin/dgv-verifier
# Compare against the published checksum
```

## SLSA Provenance Level

Current: **SLSA Level 1** (build documented, source available to NDA reviewers)

Planned for v0.2.0: **SLSA Level 2** (signed build provenance, isolated build environment)

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
