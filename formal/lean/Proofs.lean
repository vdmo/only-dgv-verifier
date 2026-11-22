import OnlyQuorumCore
open Aeneas Aeneas.Std Result ControlFlow
namespace only_quorum_core

def RevAt (votes : Slice Vote) (j : Nat) : Prop :=
  ∃ h : j < votes.length, votes.val[j] = Vote.Revoked

/-- `any_revoked_loop` returns `true` iff a `Revoked` vote occurs at an index ≥ `i0`.
    Slice of ANY length. -/
theorem any_revoked_loop_spec (votes : Slice Vote) (i0 : Std.Usize) :
    any_revoked_loop votes i0 ⦃ r => (r = true ↔ ∃ j, i0.val ≤ j ∧ RevAt votes j) ⦄ := by
  unfold any_revoked_loop
  apply loop.spec_decr_nat
    (measure := fun (i : Std.Usize) => votes.length - i.val)
    (inv := fun (i : Std.Usize) => i0.val ≤ i.val ∧ ∀ j, i0.val ≤ j → j < i.val → ¬ RevAt votes j)
  · intro i hinv0
    obtain ⟨hi0, hinv⟩ := hinv0
    unfold any_revoked_loop.body
    step*
    · rename_i hlt
      have hlt' : i.val < votes.length := by scalar_tac
      have hrev : RevAt votes i.val ↔ v = Vote.Revoked := by
        constructor
        · rintro ⟨_, h⟩; rw [v_post]; exact h
        · intro h; exact ⟨hlt', by rw [← v_post]; exact h⟩
      cases v
      · simp [Vote.Insts.CoreCmpPartialEqVote.eq, Vote.read_discriminant] at hrev ⊢
        step*
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        intro j h1 h2
        by_cases hj : j = i.val
        · subst hj; exact hrev
        · exact hinv j h1 (by scalar_tac)
      · simp [Vote.Insts.CoreCmpPartialEqVote.eq, Vote.read_discriminant] at hrev ⊢
        exact ⟨i.val, hi0, hrev⟩
      · simp [Vote.Insts.CoreCmpPartialEqVote.eq, Vote.read_discriminant] at hrev ⊢
        step*
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        intro j h1 h2
        by_cases hj : j = i.val
        · subst hj; exact hrev
        · exact hinv j h1 (by scalar_tac)
    · rename_i hge
      have hge' : ¬ i.val < votes.length := by scalar_tac
      simp only [Bool.false_eq_true, false_iff, not_exists, not_and]
      intro j hj hr
      by_cases hji : j < i.val
      · exact hinv j hj hji hr
      · obtain ⟨hjl, _⟩ := hr
        omega
  · exact ⟨le_refl _, fun j h1 h2 => by omega⟩

theorem any_revoked_spec (votes : Slice Vote) :
    any_revoked votes ⦃ r => (r = true ↔ ∃ j, RevAt votes j) ⦄ := by
  unfold any_revoked
  have := any_revoked_loop_spec votes 0#usize
  simpa using this

/-- `clean_votes` never fails (no overflow / out-of-bounds), any length. -/
theorem clean_votes_loop_spec (votes : Slice Vote) (n i : Std.Usize) (hi : i.val ≤ votes.length) :
    clean_votes_loop votes n i ⦃ _ => True ⦄ := by
  unfold clean_votes_loop
  apply loop.spec_decr_nat
    (measure := fun ((_, i) : Std.Usize × Std.Usize) => votes.length - i.val)
    (inv := fun ((_, i) : Std.Usize × Std.Usize) => i.val ≤ votes.length)
  · intro ⟨n1, i1⟩ hinv
    unfold clean_votes_loop.body
    step*
    simp only at hinv
    have hlt : i1.val < votes.length := by scalar_tac
    cases v <;> simp [Vote.Insts.CoreCmpPartialEqVote.eq, Vote.read_discriminant] <;> step*
  · exact hi

theorem clean_votes_spec_trivial (votes : Slice Vote) : clean_votes votes ⦃ _ => True ⦄ := by
  unfold clean_votes
  exact clean_votes_loop_spec votes 1#usize 0#usize (by scalar_tac)

def isClean : Vote → Bool
  | Vote.Clean => true
  | _ => false

theorem sat_add_one_le (n : Std.Usize) :
    (core.num.Usize.saturating_add n 1#usize).val ≤ n.val + 1 := by
  unfold core.num.Usize.saturating_add UScalar.saturating_add
  simp only [UScalar.val, BitVec.toNat_ofNat]
  have h1 := Nat.mod_le (Min.min (UScalar.max UScalarTy.Usize) (n.val + (1#usize).val)) (2 ^ System.Platform.numBits)
  have h2 : Min.min (UScalar.max UScalarTy.Usize) (n.val + (1#usize).val) ≤ n.val + 1 := by
    have := Nat.min_le_right (UScalar.max UScalarTy.Usize) (n.val + (1#usize).val)
    simp at this ⊢
  exact le_trans h1 h2

/-- The returned tally never exceeds `1 + (number of Clean votes)`. -/
theorem clean_votes_loop_count (votes : Slice Vote) (n i : Std.Usize)
    (hi : i.val ≤ votes.length)
    (hn : n.val ≤ 1 + ((votes.val.take i.val).countP isClean)) :
    clean_votes_loop votes n i ⦃ r => r.val ≤ 1 + votes.val.countP isClean ⦄ := by
  unfold clean_votes_loop
  apply loop.spec_decr_nat
    (measure := fun ((_, i) : Std.Usize × Std.Usize) => votes.length - i.val)
    (inv := fun ((n, i) : Std.Usize × Std.Usize) =>
       i.val ≤ votes.length ∧ n.val ≤ 1 + ((votes.val.take i.val).countP isClean))
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
        have := sat_add_one_le n1
        rw [i2_post, htake, ← v_post]
        simp [List.countP_append, isClean]
        omega
      · simp [Vote.Insts.CoreCmpPartialEqVote.eq, Vote.read_discriminant]
        step*
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [i2_post, htake, ← v_post]
        simp [List.countP_append, isClean]
        omega
      · simp [Vote.Insts.CoreCmpPartialEqVote.eq, Vote.read_discriminant]
        step*
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [i2_post, htake, ← v_post]
        simp [List.countP_append, isClean]
        omega
    · rename_i hge
      have : votes.val.take i1.val = votes.val := List.take_of_length_le (by scalar_tac)
      rw [this] at hn1; exact hn1
  · exact ⟨hi, hn⟩

theorem clean_votes_spec (votes : Slice Vote) :
    clean_votes votes ⦃ r => r.val ≤ 1 + votes.val.countP isClean ⦄ := by
  unfold clean_votes
  exact clean_votes_loop_count votes 1#usize 0#usize (by scalar_tac) (by simp)

/-- MAIN THEOREM (NoReachableRevAtExec for the real Rust `decide`):
    for any local flag, any quorum size and a vote slice of ANY length,
    `decide` terminates without error, and if it answers `ConfirmedClean`
    then the local check was clean and NO vote was `Revoked`. -/
theorem decide_no_reachable_rev (local_revoked : Bool) (votes : Slice Vote) (q : Std.Usize) :
    «decide» local_revoked votes q ⦃ r =>
      r = Outcome.ConfirmedClean →
        local_revoked = false ∧ (¬ ∃ j, RevAt votes j) ∧
        q.val ≤ 1 + votes.val.countP isClean ⦄ := by
  unfold «decide»
  split
  · simp
  · rename_i hloc
    step with any_revoked_spec votes as ⟨b, hb⟩
    split
    · simp
    · rename_i hb0
      step with clean_votes_spec votes as ⟨cv, hcv⟩
      split
      · simp
        rename_i hge
        refine ⟨by simpa using hloc, ?_, ?_⟩
        · intro j hj
          exact hb0 (hb.mpr ⟨j, hj⟩)
        · scalar_tac
      · simp

end only_quorum_core
