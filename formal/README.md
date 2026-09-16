# Formal models — DGV quorum revocation (T0/T1)

Two independent models of `check_revocation_with_quorum`
(`native/dgv-gate/src/main.rs`), checked 2026-09-17:

- `tla/DgvQuorum.tla` — TLA+/TLC, exhaustive state-space exploration
- `alloy/DgvQuorum.als` — Alloy 6, bounded SAT checking

## What is modeled

The quorum path exactly as implemented:

1. Local revocation storage check first (self counts as a voter).
2. Gate polls **all** configured peers.
3. Any reachable peer answering `revoked` → deny **and** auto-replicate
   the record locally (`LearnViaQuorum` / `learnViaQuorum`).
4. `clean_votes >= quorum_size` → `ConfirmedClean`; otherwise
   `PartitionFailure` → deny under `DGV_PARTITION_POLICY=fail_closed`.
5. `Revoke` (admin), `Gossip`/`heal` (propagation + anti-entropy),
   `Partition`/`Heal` (arbitrary symmetric connectivity changes),
   `Grant` (T0 `/govern`), `Execute` (T1 `/execute` — token required and
   revocation re-checked).

Only the **fail-closed** configuration is modeled — that is the deployment
posture being verified.

## Results

### TLC (exhaustive)

| Config | Bound | States | Result |
|---|---|---|---|
| `DgvQuorumMesh.cfg` — no partitions | N=3, A=2, Q=2 | 46,656 | All invariants + `Convergence` liveness hold |
| `DgvQuorumPartitionSafety.cfg` — arbitrary partitions | N=3, A=1, Q=2 | 13,280 | `ExecHadCleanQuorum`, `NoReachableRevAtExec` hold |
| `DgvQuorumBoundary.cfg` — arbitrary partitions | N=3, A=1, Q=2 | — | `NoRevAnywhereAtExec` violated: 5-step counterexample |

### Alloy (bounded, SAT4J)

| Check | Scope | Result |
|---|---|---|
| `ExecHadCleanQuorum` | 3 Node, 2 Actor, 6 steps | UNSAT — valid |
| `NoReachableRevAtExec` | 3 Node, 2 Actor, 6 steps | UNSAT — valid |
| `ConvergedBlocks` | 3 Node, 2 Actor, 6 steps | UNSAT — valid |
| `NoRevAnywhereAtExec` | 3 Node, 1 Actor, 6 steps | SAT — counterexample |

## Proven properties (within model + bounds)

- **I1 — fail-closed quorum:** every execution was authorized by ≥Q
  reachable clean voters. An isolated gate cannot execute — under any
  partition sequence.
- **I2 — quorum knowledge safety:** at execution time no node reachable
  by the gate held the revocation. A revocation known to *any* reachable
  node denies execution.
- **I3 — full-mesh revocation safety:** with all nodes mutually reachable,
  no execution occurs for an actor revoked anywhere at or before
  execution time.
- **Convergence (liveness):** under weak fairness on gossip/anti-entropy,
  a revocation existing anywhere eventually reaches every node — after
  which no quorum check for that actor can ever return clean.

## Residual boundary — confirmed by both tools

`NoRevAnywhereAtExec` is **not** true under partitions. TLC trace
(5 steps): `Revoke(g2,a1)` → `Partition(g1,g2)` → `Grant(g1,a1)` →
`Execute(g1,a1)` — g1 assembles a clean quorum {g1,g3} while the
revocation lives only on unreachable g2.

In plain terms: **a revocation held exclusively by partitioned-away nodes
cannot be discovered, and the remaining majority will authorize
execution.** Both the T0 grant and the T1 execute paths share this
boundary.

Mitigations (documented, not yet implemented):

- Anti-entropy reconciliation shrinks the window after healing.
- A stricter posture: require revocations to be acknowledged by a quorum
  before taking effect (quorum-write), or deny T0/T1 whenever fewer than
  *all* peers respond (N-of-N instead of Q-of-N — trades availability).

## Reproduce

```bash
# TLA+ (needs Java 11+ and tla2tools.jar)
java -jar tla2tools.jar -deadlock -config tla/DgvQuorumMesh.cfg            tla/DgvQuorum.tla
java -jar tla2tools.jar -deadlock -config tla/DgvQuorumPartitionSafety.cfg tla/DgvQuorum.tla
java -jar tla2tools.jar -deadlock -config tla/DgvQuorumBoundary.cfg        tla/DgvQuorum.tla

# Alloy (needs Java 11+ and org.alloytools.alloy.dist.jar)
java -jar alloy.jar exec -f -c ExecHadCleanQuorum    -o out alloy/DgvQuorum.als
java -jar alloy.jar exec -f -c NoReachableRevAtExec  -o out alloy/DgvQuorum.als
java -jar alloy.jar exec -f -c NoRevAnywhereAtExec   -o out alloy/DgvQuorum.als
java -jar alloy.jar exec -f -c ConvergedBlocks       -o out alloy/DgvQuorum.als
```

## Honest limits

- This is **bounded/exhaustive model checking of an abstraction**, not a
  proof about the Rust binary. The model is manually derived from
  `main.rs`; divergences are possible.
- Out of scope: signature verification, nonce/timestamp freshness,
  Byzantine (lying) peers — peers answer truthfully or not at all.
  Byzantine quorum behavior remains an open item.
- N=3, A≤2, Q=2 bounds are small; they exhibit the boundary but do not
  prove the property for arbitrary cluster sizes. The I1/I2 argument
  generalizes by inspection (guard-based), I3 was also checked at A=2
  under FullMesh.
- "Model-checked" ≠ "formally verified implementation" — no code-level
  verification (e.g., refinement, Coq/Lean extraction) has been done.
