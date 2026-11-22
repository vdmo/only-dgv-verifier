import Lake
open Lake DSL

require aeneas from "/home/visuals/toolchain/aeneas/backends/lean"

package «quorum_proof»

@[default_target] lean_lib «QuorumProof» {
  roots := #[`JsonSubsetModel, `OnlyDelegationCore, `DelegationProofs, `OnlyQuorumCore, `Proofs, `Refinement, `TlaBridge, `TlaSystem]
}
