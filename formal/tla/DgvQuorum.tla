---- MODULE DgvQuorum ----
(***************************************************************************)
(* DGV quorum revocation — formal model of the T0/T1 safety invariant      *)
(*                                                                         *)
(* Models native/dgv-gate/src/main.rs :: check_revocation_with_quorum:     *)
(*   1. Local storage check first.                                         *)
(*   2. Gate polls ALL configured peers concurrently.                      *)
(*   3. Any reachable peer answering "revoked" -> Revoked outcome: deny    *)
(*      AND store the record locally (auto-replication).                   *)
(*   4. clean_votes = self + valid signed "clean" peer responses.          *)
(*   5. clean_votes >= quorum_size -> ConfirmedClean, else PartitionFailure*)
(*      -> deny under DGV_PARTITION_POLICY=fail_closed.                    *)
(*                                                                         *)
(* This model covers the fail-closed configuration only.                   *)
(*                                                                         *)
(* CONSTANT FullMesh:                                                      *)
(*   TRUE  -> no partitions possible; proves the strong invariant.         *)
(*   FALSE -> arbitrary symmetric partition/heal; TLC exhibits the         *)
(*            documented residual boundary as a counterexample.            *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
    Nodes,      \* gate nodes, e.g. {"g1","g2","g3"}
    Actors,     \* agent identities subject to revocation
    Q,          \* quorum size, e.g. 2 for N=3
    FullMesh    \* BOOLEAN: if TRUE, partitions are disabled

VARIABLES
    localRev,   \* localRev[n] \subseteq Actors : revocations known to node n
    tokens,     \* \subseteq Nodes \X Actors : (gate, actor) granted at T0
    executed,   \* \subseteq Nodes \X Actors : (gate, actor) executed at T1
    connected,  \* \subseteq Nodes \X Nodes : symmetric reachability
    execWitness \* execWitness[g][a] = quorum state recorded at execution

vars == <<localRev, tokens, executed, connected, execWitness>>

NoWitness == [revHolders |-> {}, voters |-> {}]

ReachableFrom(g) == {n \in Nodes : <<g, n>> \in connected}

RevHolders(a) == {n \in Nodes : a \in localRev[n]}

\* Any reachable node (incl. self — local check runs first) holds the
\* revocation -> the quorum check returns Revoked and the gate denies.
QuorumSaysRevoked(g, a) == RevHolders(a) \cap ReachableFrom(g) # {}

\* Clean quorum: enough reachable voters, none holding the revocation.
CleanVoters(g, a) == ReachableFrom(g) \ RevHolders(a)
QuorumSaysClean(g, a) ==
    /\ ~QuorumSaysRevoked(g, a)
    /\ Cardinality(CleanVoters(g, a)) >= Q

Init ==
    /\ localRev = [n \in Nodes |-> {}]
    /\ tokens = {}
    /\ executed = {}
    /\ connected = Nodes \X Nodes
    /\ execWitness = [g \in Nodes |-> [a \in Actors |-> NoWitness]]

(***************************************************************************)
(* Admin revokes actor a at node n.                                        *)
(***************************************************************************)
Revoke(n, a) ==
    /\ a \notin localRev[n]
    /\ localRev' = [localRev EXCEPT ![n] = @ \cup {a}]
    /\ UNCHANGED <<tokens, executed, connected, execWitness>>

(***************************************************************************)
(* Signed gossip / anti-entropy: n propagates a's revocation to peer m.    *)
(***************************************************************************)
Gossip(n, m, a) ==
    /\ <<n, m>> \in connected
    /\ a \in localRev[n]
    /\ a \notin localRev[m]
    /\ localRev' = [localRev EXCEPT ![m] = @ \cup {a}]
    /\ UNCHANGED <<tokens, executed, connected, execWitness>>

(***************************************************************************)
(* Auto-replication: gate g's quorum check found a reachable peer holding  *)
(* a's revocation; the check stores the record locally and denies.         *)
(* (main.rs: store_revocation(rec) before returning QuorumOutcome::Revoked)*)
(***************************************************************************)
LearnViaQuorum(g, a) ==
    /\ a \notin localRev[g]
    /\ QuorumSaysRevoked(g, a)
    /\ localRev' = [localRev EXCEPT ![g] = @ \cup {a}]
    /\ UNCHANGED <<tokens, executed, connected, execWitness>>

(***************************************************************************)
(* T0 (/govern): issue a continuing-authority token only when the quorum   *)
(* check confirms clean. A revoked verdict or insufficient quorum denies.  *)
(***************************************************************************)
Grant(g, a) ==
    /\ <<g, a>> \notin tokens
    /\ QuorumSaysClean(g, a)
    /\ tokens' = tokens \cup {<<g, a>>}
    /\ UNCHANGED <<localRev, executed, connected, execWitness>>

(***************************************************************************)
(* T1 (/execute): the token alone is not sufficient — the revocation check *)
(* runs again. Only a clean quorum authorizes execution.                   *)
(***************************************************************************)
Execute(g, a) ==
    /\ <<g, a>> \in tokens
    /\ <<g, a>> \notin executed
    /\ QuorumSaysClean(g, a)
    /\ executed' = executed \cup {<<g, a>>}
    /\ execWitness' = [execWitness EXCEPT ![g][a] =
                        [revHolders |-> RevHolders(a),
                         voters     |-> ReachableFrom(g)]]
    /\ UNCHANGED <<localRev, tokens, connected>>

(***************************************************************************)
(* Symmetric partition / heal (disabled when FullMesh).                    *)
(***************************************************************************)
Partition(g, n) ==
    /\ ~FullMesh
    /\ g # n
    /\ <<g, n>> \in connected
    /\ connected' = connected \ {<<g, n>>, <<n, g>>}
    /\ UNCHANGED <<localRev, tokens, executed, execWitness>>

Heal(g, n) ==
    /\ g # n
    /\ <<g, n>> \notin connected
    /\ connected' = connected \cup {<<g, n>>, <<n, g>>}
    /\ UNCHANGED <<localRev, tokens, executed, execWitness>>

Next ==
    \/ \E n \in Nodes, a \in Actors : Revoke(n, a)
    \/ \E n, m \in Nodes, a \in Actors : Gossip(n, m, a)
    \/ \E g \in Nodes, a \in Actors : LearnViaQuorum(g, a)
    \/ \E g \in Nodes, a \in Actors : Grant(g, a)
    \/ \E g \in Nodes, a \in Actors : Execute(g, a)
    \/ \E g, n \in Nodes : Partition(g, n)
    \/ \E g, n \in Nodes : Heal(g, n)

GossipAction == \E n, m \in Nodes, a \in Actors : Gossip(n, m, a)

Spec == Init /\ [][Next]_vars /\ WF_vars(GossipAction)

(***************************************************************************)
(* SAFETY INVARIANTS                                                       *)
(***************************************************************************)

TypeInvariant ==
    /\ tokens \subseteq Nodes \X Actors
    /\ executed \subseteq Nodes \X Actors
    /\ \A n \in Nodes : localRev[n] \subseteq Actors
    /\ connected \subseteq Nodes \X Nodes
    /\ \A g \in Nodes : <<g, g>> \in connected

ExecutedImpliesToken == executed \subseteq tokens

\* I1 (fail-closed): every execution was authorized by at least Q reachable
\* clean voters — an isolated gate can never assemble a quorum.
ExecHadCleanQuorum ==
    \A e \in executed :
        LET g == e[1]  a == e[2]
            w == execWitness[g][a]
        IN  Cardinality(w.voters \ w.revHolders) >= Q

\* I2 (quorum knowledge): at execution time, NO node the gate could reach
\* held the revocation — a reachable revocation always denies.
NoReachableRevAtExec ==
    \A e \in executed :
        LET g == e[1]  a == e[2]
            w == execWitness[g][a]
        IN  w.revHolders \cap w.voters = {}

\* I3 (STRONG — the claim we wish were true): no node ANYWHERE held the
\* revocation at execution time. Holds under FullMesh; under partitions TLC
\* produces the documented residual-boundary counterexample: a revocation
\* known only to partitioned-away nodes cannot be discovered, and a clean
\* quorum assembled from the remaining nodes authorizes execution.
NoRevAnywhereAtExec ==
    \A e \in executed : execWitness[e[1]][e[2]].revHolders = {}

(***************************************************************************)
(* LIVENESS (checked under FullMesh + weak fairness on gossip):            *)
(* once a revocation exists anywhere, every node eventually learns it,     *)
(* after which no quorum check for that actor can ever return clean.       *)
(***************************************************************************)
Convergence ==
    \A a \in Actors :
        (\E n \in Nodes : a \in localRev[n])
            ~> (\A m \in Nodes : a \in localRev[m])

====
