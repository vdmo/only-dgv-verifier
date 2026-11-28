# Testing the gate

```
cd native && cargo build --release -p dgv-gate && cargo test --release -p dgv-gate -p dgv-storage && cd ..
pip install "cryptography>=50"
python run_tests.py
```

`run_tests.py` runs the CI set on temporary SQLite files and prints one table. GitHub runs the same on every pull request (`.github/workflows/gate-tests.yml`).

## Postgres

```
python run_tests.py --postgres postgres://USER@127.0.0.1:5432/postgres --psql psql
```

Use a **throwaway** server: the runner creates a new database for every test file and does not delete them. Needs Postgres 9.6 or newer (CI and local checks use 16).

## Settings

| Variable | Effect |
|---|---|
| `DGV_GATE_BIN` | gate binary to test (default: `native/target/release`, then `debug`) |
| `DGV_TEST_DATABASE_URL` | set by the runner for Postgres; honoured by the A2A tests, the demo, `test_gate_v4.py` and `test_concurrent_multi_instance.py` |
| `DGV_RELAY_BIN` | a built `onlystate-relay` for `test_a2a_transport.py`; without it an in-memory stand-in is used |
| `DGV_TEST_GATE_PORT`, `DGV_TEST_RELAY_PORT` | ports for the transport test (default 7910, 7911) |

## What CI does not cover

- `onlystate-relay` itself (it lives in another repository): CI uses the stand-in.
- JWKS and OIDC discovery in the A2A access tests (`test_a2a_jwt.py` covers HS256 and a pinned RS256 key).
- `test_dgv_python.py` (needs the Python bindings built) and `test_real_verification.py` (needs `dgv-verifier` built).
- The LangChain part of `test_sdk_langchain.py` and the real-package parts of other adapters, unless those packages are installed.
- `test_gate_v5.py` is skipped on Windows.
- Passing tests are not a security review.
