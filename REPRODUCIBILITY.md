# Reproducibility & Substrate Documentation

DGV v1.0.0 is designed for full deterministic reproducibility. Any third party
should be able to rebuild the environment, re-run the suite, and get identical
results. This document specifies the exact substrate assumptions.

---

## Container Substrate (Recommended)

The easiest path to reproducibility is the included Dockerfile:

```bash
docker build -t dgv-verifier .
docker run --rm dgv-verifier
```

### Container Specification

| Property | Value |
|---|---|
| Base image | `python:3.10-slim-bookworm` |
| OS | Debian 12 (Bookworm) |
| Python | 3.10.x |
| Architecture | `linux/amd64` |
| Network | Not required after build |
| Dependencies | `jsonschema` (Python), `ca-certificates` (system) |

The pre-compiled binaries in `bin/` are ELF 64-bit LSB executables targeting
`x86-64` Linux. They are statically linked where possible and have no external
library dependencies beyond the standard C library.

---

## Native Substrate (Without Docker)

If you prefer to run without Docker, the following must match:

### Binary Requirements

| Property | Value |
|---|---|
| Architecture | x86-64 (amd64) |
| OS | Linux (kernel 5.x+) |
| Binary format | ELF 64-bit LSB |
| Linked libraries | libc (glibc 2.31+) |

### Python Requirements

| Property | Value |
|---|---|
| Python | 3.8+ |
| Packages | `jsonschema` (for registry verification only) |

### Verification

```bash
# Check binary architecture
file bin/dgv-verifier
file bin/only-gate

# Check Python version
python3 --version

# Run the suite
python3 dgv_runner.py

# Verify the registry
pip install jsonschema
python3 verify_registry.py
```

---

## Build From Source (Advanced)

The `dgv-verifier` and `only-gate` binaries are built from the `only-engine`
Rust workspace. To rebuild from source:

### Prerequisites

| Tool | Version |
|---|---|
| Rust | 1.70+ (stable channel) |
| Cargo | 1.70+ |
| Target | `x86-64-unknown-linux-gnu` |

### Build Steps

```bash
# Clone the only-engine repository
git clone <only-engine-repo>
cd only-engine

# Build release binaries
cargo build --release -p dgv-verifier
cargo build --release -p only-gate

# Copy to the verifier directory
cp target/release/dgv-verifier ../only-dgv-verifier/bin/
cp target/release/only-gate ../only-dgv-verifier/bin/
```

### Reproducible Build Notes

For bit-for-bit reproducible builds:

1. Use the exact Rust toolchain version specified in `rust-toolchain.toml`.
2. Set `SOURCE_DATE_EPOCH` to a fixed timestamp.
3. Use `RUSTFLAGS="-C strip=symbols"` for consistent symbol tables.
4. Build on the same OS/architecture as the release target.

Future releases will include a Nix flake for fully deterministic builds.

---

## Determinism Guarantees

The DGV test suite is designed to produce identical results across runs on the
same substrate:

1. **Mathematical determinism**: The `dgv-verifier` engine evaluates
   arithmetic equilibrium (Σ sᵢvᵢ = 0) using fixed-precision floating point.
   Identical inputs always yield identical outputs.

2. **No external dependencies at runtime**: The test cards are self-contained
   JSON files. No network calls are made during the standard suite (except
   TC-012 LLM testing, which requires an API key and is optional).

3. **Stable binary behavior**: The pre-compiled binaries produce deterministic
   JSON output for the same inputs. The `dgv_runner.py` harness runs each
   deterministic card 5 times and verifies identical results across runs.

4. **Content-addressed evidence**: Every evidence package is hashed with
   SHA-256 over its canonical JSON form (excluding the receipt itself). The
   hash is the receipt. Any tampering with evidence changes the hash.

---

## Cross-Platform Notes

- **Windows**: The binaries are Linux ELF executables. On Windows, use WSL2
  or Docker Desktop.
- **macOS (Intel)**: Use Docker with `--platform linux/amd64`.
- **macOS (Apple Silicon)**: Use Docker with `--platform linux/amd64`
  (emulation via Rosetta).
- **ARM64 Linux**: Native ARM64 binaries are not yet provided. Use Docker with
  `--platform linux/amd64` (emulation via QEMU).

---

## Verification Checklist for Third-Party Auditors

1. [ ] Build or pull the Docker image
2. [ ] Run `python3 dgv_runner.py` — all 60 cards must pass
3. [ ] Run `python3 verify_registry.py` — all receipts must verify
4. [ ] Inspect `evidence/` — each file contains inputs, outputs, and receipt
5. [ ] Read `spec.md` — understand what each claim means
6. [ ] Verify receipt procedure in `RECEIPT_VERIFICATION.md`
7. [ ] Confirm binary integrity: `sha256sum bin/dgv-verifier bin/only-gate`
8. [ ] Re-run on a different machine — results must be identical
