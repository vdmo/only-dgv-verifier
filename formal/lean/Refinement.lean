import Proofs
open Aeneas Aeneas.Std Result ControlFlow
namespace only_quorum_core

theorem sat_add_one_val (n : Std.Usize) :
    (core.num.Usize.saturating_add n 1#usize).val = min Std.Usize.max (n.val + 1) := by
  unfold core.num.Usize.saturating_add UScalar.saturating_add
  simp only [UScalar.val, BitVec.toNat_ofNat]
  have h1 : UScalar.max UScalarTy.Usize = 2 ^ System.Platform.numBits - 1 := by
    rw [UScalar.max_def]; rfl
  have h2 : Std.Usize.max = 2 ^ System.Platform.numBits - 1 := by
    rw [Std.Usize.max_def]; simp [Std.Usize.numBits]
  have h3 : (1#usize).bv.toNat = 1 := by simp
  have hp : 0 < 2 ^ System.Platform.numBits := by positivity
  rw [h1, h2, h3]
  show min (2 ^ System.Platform.numBits - 1) (n.bv.toNat + 1) % 2 ^ System.Platform.numBits = _
  rw [Nat.mod_eq_of_lt (by omega)]

theorem clean_votes_loop_exact (votes : Slice Vote) (n i : Std.Usize)
    (hi : i.val ≤ votes.length)
    (hn : n.val = min (1 + ((votes.val.take i.val).countP isClean)) Std.Usize.max) :
    clean_votes_loop votes n i ⦃ r => r.val = min (1 + votes.val.countP isClean) Std.Usize.max ⦄ := by
  unfold clean_votes_loop
  apply loop.spec_decr_nat
    (measure := fun ((_, i) : Std.Usize × Std.Usize) => votes.length - i.val)
    (inv := fun ((n, i) : Std.Usize × Std.Usize) =>
       i.val ≤ votes.length ∧ n.val = min (1 + ((votes.val.take i.val).countP isClean)) Std.Usize.max)
  · intro ⟨n1, i1⟩ hinv
    obtain ⟨hi1, hn1⟩ := hinv
    unfold clean_votes_loop.body
    step*
    · rename_i hlt
      have hlt' : i1.val < votes.length := by scalar_tac
      have htake : votes.val.take (i1.val + 1) = votes.val.take i1.val ++ [votes.val[i1.val]] := by
        rw [List.take_add_one]; simp [List.getElem?_eq_getElem hlt']
      cases v
      · simp [Vote.Insts.CoreCmpPartialEqVote.eq, Vote.read_discriminant]
        step*
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        have := sat_add_one_val n1
        rw [i2_post, htake, ← v_post]
        simp only [List.countP_append]
        simp [isClean]
        omega
      · simp [Vote.Insts.CoreCmpPartialEqVote.eq, Vote.read_discriminant]
        step*
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [i2_post, htake, ← v_post]
        simp only [List.countP_append]
        simp [isClean]
        omega
      · simp [Vote.Insts.CoreCmpPartialEqVote.eq, Vote.read_discriminant]
        step*
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [i2_post, htake, ← v_post]
        simp only [List.countP_append]
        simp [isClean]
        omega
    · rename_i hge
      have : votes.val.take i1.val = votes.val := List.take_of_length_le (by scalar_tac)
      rw [this] at hn1; exact hn1
  · exact ⟨hi, hn⟩

theorem clean_votes_exact (votes : Slice Vote) :
    clean_votes votes ⦃ r => r.val = min (1 + votes.val.countP isClean) Std.Usize.max ⦄ := by
  unfold clean_votes
  have hm : 1 ≤ Std.Usize.max := by scalar_tac
  have hinit : (1#usize).val = min (1 + ((votes.val.take (0#usize).val).countP isClean)) Std.Usize.max := by
    simp
    omega
  exact clean_votes_loop_exact votes 1#usize 0#usize (by scalar_tac) hinit

/-- COMPLETE SPECIFICATION of the Rust `decide`, for a vote slice of any length:
    it never fails and returns exactly
      Revoked            if the local check or any peer vote is a revocation,
      ConfirmedClean     if there is none and q ≤ 1 + #Clean,
      PartitionFailure   otherwise. -/
theorem decide_spec (local_revoked : Bool) (votes : Slice Vote) (q : Std.Usize) :
    «decide» local_revoked votes q ⦃ r =>
      ((local_revoked = true ∨ ∃ j, RevAt votes j) → r = Outcome.Revoked) ∧
      (¬(local_revoked = true ∨ ∃ j, RevAt votes j) → q.val ≤ 1 + votes.val.countP isClean →
          r = Outcome.ConfirmedClean) ∧
      (¬(local_revoked = true ∨ ∃ j, RevAt votes j) → ¬ q.val ≤ 1 + votes.val.countP isClean →
          r = Outcome.PartitionFailure) ⦄ := by
  unfold «decide»
  split
  · rename_i hl
    rw [WP.spec_ok]
    refine ⟨fun _ => rfl, fun h => ?_, fun h => ?_⟩
    · exact absurd (Or.inl hl) h
    · exact absurd (Or.inl hl) h
  · rename_i hloc
    step with any_revoked_spec votes as ⟨b, hb⟩
    split
    · rename_i hb1
      rw [WP.spec_ok]
      refine ⟨fun _ => rfl, fun h => ?_, fun h => ?_⟩
      · exact absurd (Or.inr (hb.mp hb1)) h
      · exact absurd (Or.inr (hb.mp hb1)) h
    · rename_i hb0
      step with clean_votes_exact votes as ⟨cv, hcv⟩
      have hq : q.val ≤ Std.Usize.max := by scalar_tac
      have hnorev : ¬(local_revoked = true ∨ ∃ j, RevAt votes j) := by
        rintro (h | h)
        · exact hloc h
        · exact hb0 (hb.mpr h)
      split
      · rename_i hge
        rw [WP.spec_ok]
        refine ⟨fun h => absurd h hnorev, fun _ _ => rfl, fun _ hn => ?_⟩
        exfalso; apply hn; scalar_tac
      · rename_i hlt
        rw [WP.spec_ok]
        refine ⟨fun h => absurd h hnorev, fun _ hq' => ?_, fun _ _ => rfl⟩
        exfalso; apply hlt; scalar_tac

end only_quorum_core
