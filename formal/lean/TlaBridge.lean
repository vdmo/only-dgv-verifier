import Refinement
open Aeneas Aeneas.Std Result
namespace only_quorum_core

/-! ## Abstract TLA+ model of DgvQuorum (formal/tla/DgvQuorum.tla), any N, any Q

`nodes` is the node set (any length); `conn g m` is symmetric reachability (reflexive: a gate
always reaches itself); `rev m a` = node m holds a's revocation. -/

/-- TLA: QuorumSaysRevoked(g,a) = RevHolders(a) ∩ ReachableFrom(g) ≠ ∅ -/
def QRevoked (nodes : List Nat) (conn : Nat → Nat → Bool) (rev : Nat → Nat → Bool) (g a : Nat) : Prop :=
  ∃ m ∈ nodes, conn g m = true ∧ rev m a = true

/-- TLA: Cardinality(CleanVoters(g,a)) -/
def CleanVoters (nodes : List Nat) (conn : Nat → Nat → Bool) (rev : Nat → Nat → Bool) (g a : Nat) : Nat :=
  nodes.countP (fun m => conn g m && !rev m a)

/-- TLA: QuorumSaysClean(g,a) = ¬QuorumSaysRevoked ∧ |CleanVoters| ≥ Q -/
def QClean (Q : Nat) (nodes : List Nat) (conn : Nat → Nat → Bool) (rev : Nat → Nat → Bool) (g a : Nat) : Prop :=
  ¬ QRevoked nodes conn rev g a ∧ Q ≤ CleanVoters nodes conn rev g a

/-- The votes the real gate collects from its peers (everyone but itself). -/
def voteOf (conn : Nat → Nat → Bool) (rev : Nat → Nat → Bool) (g a : Nat) (m : Nat) : Vote :=
  if conn g m = false then Vote.Abstain else if rev m a = true then Vote.Revoked else Vote.Clean

def votesOf (nodes : List Nat) (conn : Nat → Nat → Bool) (rev : Nat → Nat → Bool) (g a : Nat) : List Vote :=
  (nodes.erase g).map (voteOf conn rev g a)

theorem revAt_votes_iff (peers : List Nat) (conn : Nat → Nat → Bool) (rev : Nat → Nat → Bool) (g a : Nat) :
    (Vote.Revoked ∈ peers.map (voteOf conn rev g a)) ↔ ∃ m ∈ peers, conn g m = true ∧ rev m a = true := by
  induction peers with
  | nil => simp
  | cons x xs ih =>
    simp only [List.map_cons, List.mem_cons, ih]
    constructor
    · rintro (h | ⟨m, hm, h⟩)
      · refine ⟨x, Or.inl rfl, ?_⟩
        unfold voteOf at h
        by_cases h1 : conn g x = false
        · simp [h1] at h
        · by_cases h2 : rev x a = true
          · simp [h1, h2]
          · simp [h1, h2] at h
            
      · exact ⟨m, Or.inr hm, h⟩
    · rintro ⟨m, hm | hm, h⟩
      · subst hm; left; unfold voteOf; simp [h.1, h.2]
      · exact Or.inr ⟨m, hm, h⟩

theorem cleanVoters_split (nodes : List Nat) (conn : Nat → Nat → Bool) (rev : Nat → Nat → Bool)
    (g a : Nat) (hg : g ∈ nodes) :
    CleanVoters nodes conn rev g a =
      (if (conn g g && !rev g a) = true then 1 else 0) +
        (votesOf nodes conn rev g a).countP isClean := by
  unfold CleanVoters votesOf
  rw [(List.perm_cons_erase hg).countP_eq]
  rw [List.countP_cons, List.countP_map]
  have : ((fun m => conn g m && !rev m a) : Nat → Bool) = (isClean ∘ voteOf conn rev g a) := by
    funext m
    unfold voteOf isClean
    by_cases h1 : conn g m = false <;> by_cases h2 : rev m a = true <;> simp [h1, h2]
  rw [this]
  split <;> simp [Nat.add_comm]

theorem qrevoked_split (nodes : List Nat) (conn : Nat → Nat → Bool) (rev : Nat → Nat → Bool)
    (g a : Nat) (hg : g ∈ nodes) (hself : conn g g = true) :
    QRevoked nodes conn rev g a ↔
      (rev g a = true ∨ Vote.Revoked ∈ votesOf nodes conn rev g a) := by
  unfold QRevoked votesOf
  rw [revAt_votes_iff]
  have hp := List.perm_cons_erase hg
  constructor
  · rintro ⟨m, hm, h1, h2⟩
    have hm' := hp.mem_iff.mp hm
    rcases List.mem_cons.mp hm' with rfl | hm''
    · exact Or.inl h2
    · exact Or.inr ⟨m, hm'', h1, h2⟩
  · rintro (h | ⟨m, hm, h1, h2⟩)
    · exact ⟨g, hg, hself, h⟩
    · exact ⟨m, hp.mem_iff.mpr (List.mem_cons_of_mem _ hm), h1, h2⟩

/-- REFINEMENT (bridge to formal/tla/DgvQuorum.tla), for ANY node set and ANY quorum size Q:
    the real Rust `decide`, fed the votes a gate g collects for actor a, never fails and
      returns ConfirmedClean  ⇔ TLA `QuorumSaysClean(g,a)`
      returns Revoked         ⇔ TLA `QuorumSaysRevoked(g,a)`.
    Hypotheses: g is one of the nodes and reaches itself; the peer vote list fits in a usize. -/
theorem decide_refines_tla (Q : Nat) (nodes : List Nat) (conn : Nat → Nat → Bool)
    (rev : Nat → Nat → Bool) (g a : Nat) (hg : g ∈ nodes) (hself : conn g g = true)
    (hlen : (votesOf nodes conn rev g a).length ≤ Std.Usize.max) (q : Std.Usize) (hq : q.val = Q) :
    «decide» (rev g a) (Slice.from (votesOf nodes conn rev g a) hlen) q ⦃ r =>
      (r = Outcome.ConfirmedClean ↔ QClean Q nodes conn rev g a) ∧
      (r = Outcome.Revoked ↔ QRevoked nodes conn rev g a) ⦄ := by
  refine WP.spec_mono (decide_spec (rev g a) (Slice.from (votesOf nodes conn rev g a) hlen) q) ?_
  rintro r ⟨h1, h2, h3⟩
  have hval : (Slice.from (votesOf nodes conn rev g a) hlen).val = votesOf nodes conn rev g a := by
    simp [Slice.from, Slice.val]
    exact Data.ListN.ListN.from_to_inverse
  have hrevat : (∃ j, RevAt (Slice.from (votesOf nodes conn rev g a) hlen) j) ↔
      Vote.Revoked ∈ votesOf nodes conn rev g a := by
    unfold RevAt
    rw [List.mem_iff_getElem]
    simp only [Slice.length, hval]
  have hqr := qrevoked_split nodes conn rev g a hg hself
  have hcv := cleanVoters_split nodes conn rev g a hg
  rw [hval] at h2 h3
  by_cases hR : QRevoked nodes conn rev g a
  · have hr : r = Outcome.Revoked := h1 (by
      rcases hqr.mp hR with h | h
      · exact Or.inl h
      · exact Or.inr (hrevat.mpr h))
    subst hr
    exact ⟨⟨(fun h => nomatch h), fun h => absurd hR h.1⟩, ⟨fun _ => hR, fun _ => rfl⟩⟩
  · have hno : ¬((rev g a = true) ∨ ∃ j, RevAt (Slice.from (votesOf nodes conn rev g a) hlen) j) := by
      rintro (h | h)
      · exact hR (hqr.mpr (Or.inl h))
      · exact hR (hqr.mpr (Or.inr (hrevat.mp h)))
    have hnoG : (rev g a = true) → False := fun h => hno (Or.inl h)
    have hself' : (if (conn g g && !rev g a) = true then 1 else 0) = 1 := by
      have : rev g a = false := by simpa using hnoG
      simp [hself, this]
    by_cases hQ : Q ≤ CleanVoters nodes conn rev g a
    · have hr := h2 hno (by rw [hq]; omega)
      subst hr
      exact ⟨⟨fun _ => ⟨hR, hQ⟩, fun _ => rfl⟩, ⟨(fun h => nomatch h), fun h => absurd h hR⟩⟩
    · have hr := h3 hno (by rw [hq]; omega)
      subst hr
      exact ⟨⟨(fun h => nomatch h), fun h => absurd h.2 hQ⟩, ⟨(fun h => nomatch h), fun h => absurd h hR⟩⟩

end only_quorum_core
