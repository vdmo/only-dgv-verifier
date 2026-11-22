import Mathlib
/-!
# MODEL of `json_subset` (dgv-gate scope narrowing)

This is a hand-written Lean MODEL of `json_subset` in `native/dgv-gate/src/main.rs`.
It is NOT extracted from the Rust and nothing here proves the Rust matches it.
Modelling choices: numbers are `Int` (the gate compares serde `Number`s exactly, so
`1` vs `1.0` are distinct there; a distinct scalar tag would behave the same), objects
are association lists whose keys are assumed unique (serde_json's `Map` guarantees it),
and the relation is defined by recursion on fuel because Lean cannot accept the
nested-inductive form directly.
-/
namespace JsonModel

inductive Json where
  | null | bool (b : Bool) | num (n : Int) | str (s : String)
  | arr (xs : List Json) | obj (kvs : List (String × Json))

/-- `subN n child parent`: child is a subset of parent, checked to nesting depth `n`. -/
def subN : Nat → Json → Json → Prop
  | 0, _, _ => False
  | _+1, .null, .null => True
  | _+1, .bool a, .bool b => a = b
  | _+1, .num a, .num b => a = b
  | _+1, .str a, .str b => a = b
  | n+1, .arr c, .arr p => ∀ x ∈ c, ∃ y ∈ p, subN n x y
  | n+1, .obj c, .obj p => ∀ k v, (k, v) ∈ c → ∃ w, (k, w) ∈ p ∧ subN n v w
  | _+1, _, _ => False

def JSub (a b : Json) : Prop := ∃ n, subN n a b

theorem subN_mono : ∀ (n : Nat) (a b : Json), subN n a b → subN (n+1) a b := by
  intro n
  induction n with
  | zero => intro a b h; exact absurd h (by simp [subN])
  | succ n ih =>
    intro a b h
    cases a <;> cases b <;> simp only [subN] at h ⊢ <;> try exact h
    · intro x hx; obtain ⟨y, hy, h'⟩ := h x hx; exact ⟨y, hy, ih _ _ h'⟩
    · intro k v hkv; obtain ⟨w, hw, h'⟩ := h k v hkv; exact ⟨w, hw, ih _ _ h'⟩

theorem subN_mono_le {n m : Nat} (h : n ≤ m) {a b : Json} (hs : subN n a b) : subN m a b := by
  induction h with
  | refl => exact hs
  | step _ ih => exact subN_mono _ _ _ ih

theorem subN_refl : ∀ (k : Nat) (a : Json), sizeOf a ≤ k → subN k a a := by
  intro k
  induction k with
  | zero =>
    intro a h
    cases a <;> simp at h
  | succ k ih =>
    intro a h
    cases a <;> simp only [subN]
    · intro x hx
      refine ⟨x, hx, ih x ?_⟩
      have := List.sizeOf_lt_of_mem hx
      simp at h; omega
    · intro key v hkv
      refine ⟨v, hkv, ih v ?_⟩
      have := List.sizeOf_lt_of_mem hkv
      simp at h this; omega

/-- Reflexive: a delegation that does not narrow is accepted. -/
theorem jsub_refl (a : Json) : JSub a a := ⟨sizeOf a, subN_refl _ a le_rfl⟩

theorem subN_trans : ∀ (n m : Nat) (a b c : Json), subN n a b → subN m b c → subN (min n m) a c := by
  intro n
  induction n with
  | zero => intro m a b c h; exact absurd h (by simp [subN])
  | succ n ih =>
    intro m a b c h1 h2
    cases m with
    | zero => exact absurd h2 (by simp [subN])
    | succ m =>
      have : min (n+1) (m+1) = min n m + 1 := by omega
      rw [this]
      cases a <;> cases b <;> cases c <;> simp only [subN] at h1 h2 ⊢ <;>
        first | exact h1.trans h2 | skip
      · intro x hx
        obtain ⟨y, hy, h1'⟩ := h1 x hx
        obtain ⟨z, hz, h2'⟩ := h2 y hy
        exact ⟨z, hz, ih m _ _ _ h1' h2'⟩
      · intro k v hkv
        obtain ⟨w, hw, h1'⟩ := h1 k v hkv
        obtain ⟨u, hu, h2'⟩ := h2 k w hw
        exact ⟨u, hu, ih m _ _ _ h1' h2'⟩

/-- Transitive: so in a delegation chain every descendant's scope is a subset of the
    root's scope, however many hops (authority never widens). -/
theorem jsub_trans {a b c : Json} (h1 : JSub a b) (h2 : JSub b c) : JSub a c := by
  obtain ⟨n, hn⟩ := h1; obtain ⟨m, hm⟩ := h2
  exact ⟨_, subN_trans n m a b c hn hm⟩

/-- Chain of narrowing steps stays inside the root. -/
theorem chain_within_root {root : Json} {l : List Json}
    (h : List.IsChain (fun x y => JSub y x) (root :: l)) : ∀ x ∈ l, JSub x root := by
  induction l generalizing root with
  | nil => simp
  | cons y ys ih =>
    intro x hx
    rw [List.isChain_cons_cons] at h
    obtain ⟨h1, h2⟩ := h
    rcases List.mem_cons.mp hx with rfl | hx
    · exact h1
    · exact jsub_trans (ih h2 x hx) h1

/-- Non-vacuity: adding a key (widening scope) is rejected. -/
theorem extra_key_rejected :
    ¬ JSub (.obj [("a", .num 1), ("extra", .num 1)]) (.obj [("a", .num 1)]) := by
  rintro ⟨n, h⟩
  cases n with
  | zero => exact h
  | succ n =>
    simp only [subN] at h
    obtain ⟨w, hw, _⟩ := h "extra" (.num 1) (by simp)
    simp at hw

/-- Non-vacuity: changing a scalar value (e.g. widening to a wildcard) is rejected. -/
theorem changed_scalar_rejected :
    ¬ JSub (.obj [("to", .str "*")]) (.obj [("to", .str "a@x.com")]) := by
  rintro ⟨n, h⟩
  cases n with
  | zero => exact h
  | succ n =>
    simp only [subN] at h
    obtain ⟨w, hw, h2⟩ := h "to" (.str "*") (by simp)
    simp at hw; subst hw
    cases n with
    | zero => exact h2
    | succ n => simp only [subN] at h2; exact absurd h2 (by decide)

end JsonModel
