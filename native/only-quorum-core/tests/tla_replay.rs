//! Differential trace-replay against formal/tla/DgvQuorum.tla.
//!
//! `Model` re-implements the TLA+ state machine (Revoke, Gossip, LearnViaQuorum,
//! Grant, Execute, Partition, Heal) with the SAME definitions of
//! ReachableFrom / RevHolders / QuorumSaysRevoked / QuorumSaysClean. At every
//! step, for every (gate, actor), the model's verdict is compared with the real
//! `decide` fed the votes the gate would collect. Sizes go beyond TLC's N=3.
use only_quorum_core::*;

struct Model {
    n: usize,
    q: usize,
    local_rev: Vec<Vec<bool>>,    // [node][actor]
    connected: Vec<Vec<bool>>,    // symmetric, reflexive
    tokens: Vec<Vec<bool>>,       // [gate][actor]
    executed: Vec<Vec<bool>>,
    witness: Vec<Vec<Option<(Vec<bool>, Vec<bool>)>>>, // (rev_holders, voters)
}

impl Model {
    fn new(n: usize, actors: usize, q: usize) -> Self {
        Model {
            n, q,
            local_rev: vec![vec![false; actors]; n],
            connected: vec![vec![true; n]; n],
            tokens: vec![vec![false; actors]; n],
            executed: vec![vec![false; actors]; n],
            witness: vec![vec![None; actors]; n],
        }
    }
    fn reachable(&self, g: usize) -> Vec<bool> { self.connected[g].clone() }
    fn rev_holders(&self, a: usize) -> Vec<bool> { (0..self.n).map(|m| self.local_rev[m][a]).collect() }
    // TLA: QuorumSaysRevoked / QuorumSaysClean
    fn tla_revoked(&self, g: usize, a: usize) -> bool {
        let (r, h) = (self.reachable(g), self.rev_holders(a));
        (0..self.n).any(|m| r[m] && h[m])
    }
    fn tla_clean(&self, g: usize, a: usize) -> bool {
        let (r, h) = (self.reachable(g), self.rev_holders(a));
        let clean_voters = (0..self.n).filter(|&m| r[m] && !h[m]).count();
        !self.tla_revoked(g, a) && clean_voters >= self.q
    }
    // What the gate actually does: local check, then votes from peers.
    fn real_outcome(&self, g: usize, a: usize) -> Outcome {
        let votes: Vec<Vote> = (0..self.n).filter(|&m| m != g).map(|m| {
            if !self.connected[g][m] { Vote::Abstain }
            else if self.local_rev[m][a] { Vote::Revoked }
            else { Vote::Clean }
        }).collect();
        decide(self.local_rev[g][a], &votes, self.q)
    }
    fn check_agreement(&self) {
        for g in 0..self.n { for a in 0..self.local_rev[0].len() {
            let o = self.real_outcome(g, a);
            assert_eq!(o == Outcome::ConfirmedClean, self.tla_clean(g, a), "clean mismatch g={g} a={a}");
            assert_eq!(o == Outcome::Revoked, self.tla_revoked(g, a), "revoked mismatch g={g} a={a}");
        }}
    }
    // Actions (guards as in the TLA+ spec). Return whether the action fired.
    fn revoke(&mut self, n: usize, a: usize) -> bool { if self.local_rev[n][a] { return false } self.local_rev[n][a] = true; true }
    fn gossip(&mut self, n: usize, m: usize, a: usize) -> bool {
        if !(self.connected[n][m] && self.local_rev[n][a] && !self.local_rev[m][a]) { return false }
        self.local_rev[m][a] = true; true
    }
    fn learn(&mut self, g: usize, a: usize) -> bool {
        if self.local_rev[g][a] || !self.tla_revoked(g, a) { return false }
        self.local_rev[g][a] = true; true
    }
    fn grant(&mut self, g: usize, a: usize) -> bool {
        if self.tokens[g][a] || !self.tla_clean(g, a) { return false }
        // the real gate must agree on the guard
        assert_eq!(self.real_outcome(g, a), Outcome::ConfirmedClean);
        self.tokens[g][a] = true; true
    }
    fn execute(&mut self, g: usize, a: usize) -> bool {
        if !self.tokens[g][a] || self.executed[g][a] || !self.tla_clean(g, a) { return false }
        assert_eq!(self.real_outcome(g, a), Outcome::ConfirmedClean);
        self.witness[g][a] = Some((self.rev_holders(a), self.reachable(g)));
        self.executed[g][a] = true; true
    }
    fn partition(&mut self, g: usize, n: usize) -> bool {
        if g == n || !self.connected[g][n] { return false }
        self.connected[g][n] = false; self.connected[n][g] = false; true
    }
    fn heal(&mut self, g: usize, n: usize) -> bool {
        if g == n || self.connected[g][n] { return false }
        self.connected[g][n] = true; self.connected[n][g] = true; true
    }
    /// TLA invariants I1 (ExecHadCleanQuorum) and I2 (NoReachableRevAtExec).
    fn check_invariants(&self) {
        for g in 0..self.n { for a in 0..self.local_rev[0].len() {
            if self.executed[g][a] {
                assert!(self.tokens[g][a], "ExecutedImpliesToken");
                let (h, v) = self.witness[g][a].as_ref().unwrap();
                let clean = (0..self.n).filter(|&m| v[m] && !h[m]).count();
                assert!(clean >= self.q, "I1 ExecHadCleanQuorum");
                assert!(!(0..self.n).any(|m| v[m] && h[m]), "I2 NoReachableRevAtExec");
            }
        }}
    }
}

#[test]
fn tla_replay_nominal_t0_to_t1_commit() {
    let mut m = Model::new(3, 1, 2);
    m.check_agreement();
    assert!(m.grant(0, 0));
    m.check_agreement();
    assert!(m.execute(0, 0));
    m.check_invariants();
}

#[test]
fn tla_replay_revocation_aborts_pending_t1() {
    for n in 3..=9 {
        let q = n / 2 + 1;
        let mut m = Model::new(n, 1, q);
        assert!(m.grant(0, 0));
        // revocation lands on a reachable peer between T0 and T1 (TOCTOU)
        assert!(m.revoke(n - 1, 0));
        m.check_agreement();
        assert!(!m.execute(0, 0), "n={n}: T1 must refuse after revocation");
        assert_eq!(m.real_outcome(0, 0), Outcome::Revoked);
        m.check_invariants();
    }
}

#[test]
fn tla_replay_partition_forces_fail_closed() {
    for n in 3..=9 {
        let q = n / 2 + 1;
        let mut m = Model::new(n, 1, q);
        assert!(m.grant(0, 0));
        for p in 1..n { assert!(m.partition(0, p)); }   // isolate gate 0
        m.check_agreement();
        assert!(!m.execute(0, 0), "n={n}: isolated gate must not execute");
        assert_eq!(m.real_outcome(0, 0), Outcome::PartitionFailure);
        // heal exactly enough peers to reach quorum
        for p in 1..q { assert!(m.heal(0, p)); }
        m.check_agreement();
        assert!(m.execute(0, 0), "n={n}: quorum reachable again");
        m.check_invariants();
    }
}

/// The documented residual boundary (TLC counterexample for I3): a revocation
/// held ONLY by a partitioned-away node is invisible, so a clean quorum forms.
#[test]
fn tla_replay_documented_boundary_partitioned_revoker_is_invisible() {
    let mut m = Model::new(3, 1, 2);
    assert!(m.revoke(2, 0));
    assert!(m.partition(0, 2));
    m.check_agreement();
    assert!(m.grant(0, 0));
    assert!(m.execute(0, 0));        // allowed — by design, NoRevAnywhereAtExec fails
    m.check_invariants();            // I1 and I2 still hold
}

fn rng(s: &mut u64) -> u64 { *s ^= *s << 13; *s ^= *s >> 7; *s ^= *s << 17; *s }

#[test]
fn tla_replay_random_10k_traces() {
    let mut seed = 0x9E3779B97F4A7C15u64;
    for _ in 0..10_000 {
        let n = 1 + (rng(&mut seed) % 9) as usize;           // N = 1..=9 (TLC checked 3)
        let actors = 1 + (rng(&mut seed) % 3) as usize;
        let q = 1 + (rng(&mut seed) % n as u64) as usize;
        let mut m = Model::new(n, actors, q);
        for _ in 0..40 {
            let (a, b, x) = ((rng(&mut seed) % n as u64) as usize,
                             (rng(&mut seed) % n as u64) as usize,
                             (rng(&mut seed) % actors as u64) as usize);
            match rng(&mut seed) % 7 {
                0 => { m.revoke(a, x); }
                1 => { m.gossip(a, b, x); }
                2 => { m.learn(a, x); }
                3 => { m.grant(a, x); }
                4 => { m.execute(a, x); }
                5 => { m.partition(a, b); }
                _ => { m.heal(a, b); }
            }
            m.check_agreement();
            m.check_invariants();
        }
    }
}
