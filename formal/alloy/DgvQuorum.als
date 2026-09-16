/*
 * DGV quorum revocation — bounded model of the T0/T1 safety invariant
 *
 * Mirrors native/dgv-gate/src/main.rs :: check_revocation_with_quorum:
 *   - local check first; gate polls all peers
 *   - any reachable "revoked" answer -> deny + auto-replicate the record
 *   - >= Q reachable clean voters -> ConfirmedClean, else fail-closed deny
 *
 * Q is fixed at 2 (majority of 3 nodes) to match the TLA+ configuration.
 *
 * Assertions:
 *   ExecHadCleanQuorum / NoReachableRevAtExec  -> expected VALID
 *   NoRevAnywhereAtExec                        -> expected COUNTEREXAMPLE
 *     (revocation held only by partitioned-away nodes is undiscoverable)
 */
module DgvQuorum

sig Actor {}

sig Node {
  var knows:    set Actor,   -- localRev
  var tokens:   set Actor,   -- granted at T0
  var executed: set Actor,   -- executed at T1
  var links:    set Node     -- reachability (symmetric, reflexive)
}

fun reachable[g: Node]: set Node { g.links + g }
fun revHolders[a: Actor]: set Node { knows.a }

pred quorumSaysRevoked[g: Node, a: Actor] {
  some revHolders[a] & reachable[g]
}

pred quorumSaysClean[g: Node, a: Actor] {
  not quorumSaysRevoked[g, a]
  #(reachable[g] - revHolders[a]) >= 2
}

pred init {
  no knows and no tokens and no executed
  links = Node -> Node
}

pred revoke[n: Node, a: Actor] {
  a not in n.knows
  knows' = knows + n->a
  tokens' = tokens and executed' = executed and links' = links
}

pred gossip[n, m: Node, a: Actor] {
  m in reachable[n]
  a in n.knows and a not in m.knows
  knows' = knows + m->a
  tokens' = tokens and executed' = executed and links' = links
}

pred learnViaQuorum[g: Node, a: Actor] {
  a not in g.knows
  quorumSaysRevoked[g, a]
  knows' = knows + g->a
  tokens' = tokens and executed' = executed and links' = links
}

pred grant[g: Node, a: Actor] {          -- T0
  a not in g.tokens
  quorumSaysClean[g, a]
  tokens' = tokens + g->a
  knows' = knows and executed' = executed and links' = links
}

pred execute[g: Node, a: Actor] {        -- T1
  a in g.tokens and a not in g.executed
  quorumSaysClean[g, a]
  executed' = executed + g->a
  knows' = knows and tokens' = tokens and links' = links
}

pred partition[g, n: Node] {
  g != n and n in g.links
  links' = links - (g->n) - (n->g)
  knows' = knows and tokens' = tokens and executed' = executed
}

pred heal[g, n: Node] {
  g != n and n not in g.links
  links' = links + (g->n) + (n->g)
  knows' = knows and tokens' = tokens and executed' = executed
}

pred stutter {
  knows' = knows and tokens' = tokens and executed' = executed and links' = links
}

fact traces {
  init
  always (stutter
    or (some n: Node, a: Actor | revoke[n, a])
    or (some n, m: Node, a: Actor | gossip[n, m, a])
    or (some g: Node, a: Actor | learnViaQuorum[g, a])
    or (some g: Node, a: Actor | grant[g, a])
    or (some g: Node, a: Actor | execute[g, a])
    or (some g, n: Node | partition[g, n])
    or (some g, n: Node | heal[g, n]))
}

fact LinksSymmetric { always (links = ~links) }
fact SelfLinked     { always (all n: Node | n in reachable[n]) }

-- I1: an execution step is only ever taken with >= Q reachable clean voters.
assert ExecHadCleanQuorum {
  always all g: Node, a: Actor |
    (a in g.executed' and a not in g.executed)
      implies (#(reachable[g] - revHolders[a]) >= 2)
}

-- I2: no reachable node held the revocation at the moment of execution.
assert NoReachableRevAtExec {
  always all g: Node, a: Actor |
    (a in g.executed' and a not in g.executed)
      implies no (revHolders[a] & reachable[g])
}

-- I3 (strong claim): no node anywhere held the revocation at execution.
-- Expected counterexample under partitions.
assert NoRevAnywhereAtExec {
  always all g: Node, a: Actor |
    (a in g.executed' and a not in g.executed)
      implies no revHolders[a]
}

-- Sanity: once every node knows the revocation, no quorum can say clean.
assert ConvergedBlocks {
  always all a: Actor |
    (all n: Node | a in n.knows)
      implies (no g: Node | quorumSaysClean[g, a])
}

check ExecHadCleanQuorum for 3 Node, 2 Actor, 6 steps
check NoReachableRevAtExec for 3 Node, 2 Actor, 6 steps
check NoRevAnywhereAtExec for 3 Node, 1 Actor, 6 steps
check ConvergedBlocks for 3 Node, 2 Actor, 6 steps
