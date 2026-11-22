import OnlyDelegationCore
open Aeneas Aeneas.Std Result ControlFlow
namespace only_delegation_core

theorem parent_live_spec (pe now : Std.I64) :
    parent_live pe now ⦃ r => r = true ↔ pe.val > now.val ⦄ := by
  unfold parent_live
  simp [WP.spec_ok]

/-- Depth bound: never errors (no i64 overflow, even at i64::MAX), succeeds exactly
    when parent_depth < max_depth, and then the child depth is parent+1 ≤ max. -/
theorem child_depth_spec (p m : Std.I64) :
    child_depth p m ⦃ r =>
      (∀ d, r = some d → p.val < m.val ∧ d.val = p.val + 1 ∧ d.val ≤ m.val) ∧
      (r = none → ¬ p.val < m.val) ⦄ := by
  unfold child_depth
  split
  · rename_i h
    have hp : p.val < m.val := by scalar_tac
    step*
    simp
    scalar_tac
  · rename_i h
    simp
    scalar_tac

/-- Expiry rule: exact characterisation. -/
theorem child_expiry_spec (pe : Std.I64) (r : Option Std.I64) (now : Std.I64) :
    child_expiry pe r now ⦃ x =>
      (∀ e, x = Expiry.Ok e →
          e.val ≤ pe.val ∧ now.val < e.val ∧ (r = none ∨ r = some e)) ∧
      (x = Expiry.ExceedsParent → ∃ e, (r = none ∨ r = some e) ∧ e.val > pe.val) ⦄ := by
  unfold child_expiry
  cases r with
  | none =>
    simp only [gt_iff_lt]
    step*
    all_goals (try simp)
    all_goals (try scalar_tac)
  | some e =>
    simp only [gt_iff_lt]
    step*
    all_goals (try simp)
    all_goals (try scalar_tac)

/-- Reachable delegation depths: a chain of `n` successful `child_depth` steps. -/
inductive DChain (m : Std.I64) : Nat → Std.I64 → Std.I64 → Prop
  | base (d : Std.I64) : DChain m 0 d d
  | step {n : Nat} {d0 d e : Std.I64} :
      DChain m n d0 d → child_depth d m = ok (some e) → DChain m (n+1) d0 e

/-- Authority decays: any chain of n ≥ 1 delegations ends at depth start+n, and never
    exceeds the configured maximum, so chains are at most `max - start` long. -/
theorem dchain_bound (m d0 d : Std.I64) (n : Nat) (h : DChain m n d0 d) :
    d.val = d0.val + n ∧ (1 ≤ n → d.val ≤ m.val) := by
  induction h with
  | base d => simp
  | step hc hs ih =>
    rename_i n d0 d e
    have := child_depth_spec d m
    rw [hs] at this
    simp [WP.spec_ok] at this
    obtain ⟨h1, h2, h3⟩ := this
    refine ⟨?_, fun _ => h3⟩
    push_cast
    omega

end only_delegation_core
