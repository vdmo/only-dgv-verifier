# DGV agent-to-agent demo

Three made-up agents (Alice, Bob, Mallory) talk through a real DGV gate. You watch what is delivered, what is refused, and one thing this setup does not stop.

## Run

```
cd native && cargo build -p dgv-gate && cd ..
pip install "cryptography>=50"          # needs HPKE support; tested with 50.0.2
python demo/a2a_demo.py
```

It starts a throwaway gate (temporary SQLite, random admin key, `127.0.0.1`) and a relay, prints each scene, writes `demo/out/report.html`, and stops everything. The exit status is 1 if any scene did not behave as described.

By default the relay is a small stand-in inside the script. To use the real one:

```
python demo/a2a_demo.py --relay-bin /path/to/onlystate-relay
```

`onlystate-relay` listens on **all network interfaces** (`0.0.0.0`), so other machines on your network can reach it while the demo runs.

## Scenes

1. A signed, encrypted message is delivered; the gate stores only a hash.
2. The receipt verifies offline against keys known beforehand, and fails if altered. The evidence is saved to `demo/out/evidence.json` for `dgv_a2a_v2.py`.
3. A forged sender is refused.
4. An altered transport reference and an over-long lifetime are refused.
5. A swapped message is refused and not acknowledged; the genuine one then arrives.
6. A replayed envelope is refused.
7. Another agent cannot acknowledge Bob's message.
8. An expired envelope is refused.
9. The withdrawn encryption formats cannot be used to send.
10. A revoked agent is cut off.
11. **Known limit:** without JWT, anyone who can reach the gate can claim to be Bob.

## Limits

- This is the `dgv` protocol, **not** Google's Agent2Agent (A2A) protocol.
- Runs on one machine, with development settings (no JWT, no TLS, rate limiting off). Not a deployment example.
- A receipt shows the gate accepted an envelope, not that the recipient received or read it. Refusals are not signed.
- Encryption is not post-quantum, has no forward secrecy if the recipient's key is stolen, and has not been independently reviewed.
- A passing run shows these scenes behaved as described. It is not a security audit.
