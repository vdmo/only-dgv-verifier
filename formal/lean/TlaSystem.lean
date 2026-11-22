import TlaBridge
namespace only_quorum_core

/-! TLA+ `DgvQuorum` transition system (formal/tla/DgvQuorum.tla), any node set, any Q.
    Safety invariants proved inductively for ALL reachable states (not just N=3). -/

structure Wit where
  rev : Nat → Bool     -- RevHolders(a) at execution time
  vot : Nat → Bool     -- ReachableFrom(g) at execution time

structure TState where
  localRev : Nat → Nat → Bool
  conn : Nat → Nat → Bool
  tokens : Nat → Nat → Bool
  executed : Nat → Nat → Bool
  wit : Nat → Nat → Option Wit

def upd2 {β : Type} (f : Nat → Nat → β) (n a : Nat) (v : β) : Nat → Nat → β :=
  fun x y => if x = n ∧ y = a then v else f x y

def updSym (f : Nat → Nat → Bool) (g n : Nat) (v : Bool) : Nat → Nat → Bool :=
  fun x y => if (x = g ∧ y = n) ∨ (x = n ∧ y = g) then v else f x y

def TInit (s : TState) : Prop :=
  (∀ n a, s.localRev n a = false) ∧ (∀ x y, s.conn x y = true) ∧
  (∀ g a, s.tokens g a = false) ∧ (∀ g a, s.executed g a = false) ∧ (∀ g a, s.wit g a = none)

inductive TStep (Q : Nat) (nodes : List Nat) : TState → TState → Prop
  | revoke (s : TState) (n a : Nat) :
      s.localRev n a = false →
      TStep Q nodes s { s with localRev := upd2 s.localRev n a true }
  | gossip (s : TState) (n m a : Nat) :
      s.conn n m = true → s.localRev n a = true → s.localRev m a = false →
      TStep Q nodes s { s with localRev := upd2 s.localRev m a true }
  | learn (s : TState) (g a : Nat) :
      s.localRev g a = false → QRevoked nodes s.conn s.localRev g a →
      TStep Q nodes s { s with localRev := upd2 s.localRev g a true }
  | grant (s : TState) (g a : Nat) :
      s.tokens g a = false → QClean Q nodes s.conn s.localRev g a →
      TStep Q nodes s { s with tokens := upd2 s.tokens g a true }
  | execute (s : TState) (g a : Nat) :
      s.tokens g a = true → s.executed g a = false → QClean Q nodes s.conn s.localRev g a →
      TStep Q nodes s { s with executed := upd2 s.executed g a true,
                               wit := upd2 s.wit g a (some ⟨fun m => s.localRev m a, fun m => s.conn g m⟩) }
  | partition (s : TState) (g n : Nat) :
      g ≠ n → s.conn g n = true →
      TStep Q nodes s { s with conn := updSym s.conn g n false }
  | heal (s : TState) (g n : Nat) :
      g ≠ n → s.conn g n = false →
      TStep Q nodes s { s with conn := updSym s.conn g n true }

inductive TReach (Q : Nat) (nodes : List Nat) : TState → Prop
  | init (s : TState) : TInit s → TReach Q nodes s
  | step (s s' : TState) : TReach Q nodes s → TStep Q nodes s s' → TReach Q nodes s'

/-- I0 ExecutedImpliesToken, I1 ExecHadCleanQuorum, I2 NoReachableRevAtExec. -/
def TInv (Q : Nat) (nodes : List Nat) (s : TState) : Prop :=
  ∀ g a, s.executed g a = true →
    s.tokens g a = true ∧
    ∃ w : Wit, s.wit g a = some w ∧
      Q ≤ nodes.countP (fun m => w.vot m && !w.rev m) ∧
      ∀ m ∈ nodes, ¬ (w.vot m = true ∧ w.rev m = true)

theorem tinv_init (Q : Nat) (nodes : List Nat) (s : TState) (h : TInit s) : TInv Q nodes s := by
  intro g a he
  have := h.2.2.2.1 g a
  rw [this] at he; exact absurd he (by decide)

theorem tinv_step (Q : Nat) (nodes : List Nat) (s s' : TState)
    (hinv : TInv Q nodes s) (hs : TStep Q nodes s s') : TInv Q nodes s' := by
  cases hs with
  | revoke n a _ => simpa [TInv] using hinv
  | gossip n m a _ _ _ => simpa [TInv] using hinv
  | learn g a _ _ => simpa [TInv] using hinv
  | partition g n _ _ => simpa [TInv] using hinv
  | heal g n _ _ => simpa [TInv] using hinv
  | grant g a _ _ =>
    intro g' a' he
    obtain ⟨ht, w, hw, h1, h2⟩ := hinv g' a' he
    refine ⟨?_, w, hw, h1, h2⟩
    simp only [upd2]; split <;> simp_all
  | execute g a ht hne hq =>
    intro g' a' he
    by_cases hga : g' = g ∧ a' = a
    · obtain ⟨rfl, rfl⟩ := hga
      refine ⟨by simpa using ht, ⟨fun m => s.localRev m a', fun m => s.conn g' m⟩, by simp [upd2], ?_, ?_⟩
      · exact hq.2
      · intro m hm ⟨hv, hr⟩
        exact hq.1 ⟨m, hm, hv, hr⟩
    · have he' : s.executed g' a' = true := by
        simpa [upd2, hga] using he
      obtain ⟨ht', w, hw, h1, h2⟩ := hinv g' a' he'
      refine ⟨by simpa using ht', w, ?_, h1, h2⟩
      simpa [upd2, hga] using hw

theorem tla_safety_all_N (Q : Nat) (nodes : List Nat) (s : TState) (h : TReach Q nodes s) :
    TInv Q nodes s := by
  induction h with
  | init s hi => exact tinv_init Q nodes s hi
  | step s s' _ hs ih => exact tinv_step Q nodes s s' ih hs

/-- Non-vacuity: executions DO occur. 3 nodes, Q = 2: grant then execute at gate 0 for actor 0. -/
theorem execution_is_reachable :
    ∃ s, TReach 2 [0, 1, 2] s ∧ s.executed 0 0 = true := by
  let s0 : TState := ⟨fun _ _ => false, fun _ _ => true, fun _ _ => false, fun _ _ => false, fun _ _ => none⟩
  have h0 : TReach 2 [0, 1, 2] s0 := TReach.init _ ⟨fun _ _ => rfl, fun _ _ => rfl, fun _ _ => rfl, fun _ _ => rfl, fun _ _ => rfl⟩
  have hq : QClean 2 [0, 1, 2] s0.conn s0.localRev 0 0 := by
    refine ⟨?_, ?_⟩
    · rintro ⟨m, _, _, h⟩; simp [s0] at h
    · simp [CleanVoters, s0]
  have h1 := TReach.step _ _ h0 (TStep.grant s0 0 0 rfl hq)
  refine ⟨_, TReach.step _ _ h1 (TStep.execute _ 0 0 ?_ rfl ?_), by simp [upd2]⟩
  · simp [upd2]
  · simpa [s0] using hq

end only_quorum_core
