//! Property tests for `decide` over arbitrary cluster sizes (1..=256 peers).
//! The Lean proof (formal/lean/Proofs.lean) covers all N; these check the same
//! properties dynamically and guard against the Rust and Lean drifting apart.
use only_quorum_core::*;
use proptest::prelude::*;

fn vote() -> impl Strategy<Value = Vote> {
    prop_oneof![Just(Vote::Clean), Just(Vote::Revoked), Just(Vote::Abstain)]
}

fn no_revoked_vote() -> impl Strategy<Value = Vote> {
    prop_oneof![Just(Vote::Clean), Just(Vote::Abstain)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    /// Threshold is exact: with no revocation, Clean <=> 1 + #Clean >= q.
    #[test]
    fn prop_quorum_threshold_arbitrary_n_1_to_256(
        votes in prop::collection::vec(no_revoked_vote(), 1..=256),
        q in 0usize..=300,
    ) {
        let clean = votes.iter().filter(|v| **v == Vote::Clean).count();
        let out = decide(false, &votes, q);
        prop_assert_eq!(out == Outcome::ConfirmedClean, 1 + clean >= q);
        if out != Outcome::ConfirmedClean { prop_assert_eq!(out, Outcome::PartitionFailure); }
    }

    /// Any revocation (local or from one peer) always wins, whatever q is.
    #[test]
    fn prop_revocation_always_wins(
        votes in prop::collection::vec(vote(), 0..=256),
        q in 0usize..=300,
        local in any::<bool>(),
    ) {
        let rev = local || votes.contains(&Vote::Revoked);
        let out = decide(local, &votes, q);
        prop_assert_eq!(out == Outcome::Revoked, rev);
        if out == Outcome::ConfirmedClean { prop_assert!(!rev); }
    }

    /// Abstentions (timeouts, bad signatures) can never help reach quorum.
    #[test]
    fn prop_abstain_never_helps(
        votes in prop::collection::vec(no_revoked_vote(), 0..=256),
        q in 0usize..=300,
    ) {
        let mut stripped = votes.clone();
        stripped.retain(|v| *v == Vote::Clean);
        if decide(false, &votes, q) == Outcome::ConfirmedClean {
            prop_assert_eq!(decide(false, &stripped, q), Outcome::ConfirmedClean);
        }
        // Turning a Clean into an Abstain never turns a deny into an allow.
        if let Some(i) = votes.iter().position(|v| *v == Vote::Clean) {
            let mut worse = votes.clone();
            worse[i] = Vote::Abstain;
            if decide(false, &worse, q) == Outcome::ConfirmedClean {
                prop_assert_eq!(decide(false, &votes, q), Outcome::ConfirmedClean);
            }
        }
    }

    /// Vote order is irrelevant (no first-responder effects).
    #[test]
    fn prop_vote_order_irrelevant(
        votes in prop::collection::vec(vote(), 0..=64),
        q in 0usize..=70,
        seed in any::<u64>(),
    ) {
        let mut shuffled = votes.clone();
        let mut s = seed | 1;
        for i in (1..shuffled.len()).rev() {
            s ^= s << 13; s ^= s >> 7; s ^= s << 17;
            shuffled.swap(i, (s % (i as u64 + 1)) as usize);
        }
        prop_assert_eq!(decide(false, &votes, q), decide(false, &shuffled, q));
    }
}

#[test]
fn prop_no_peers_fail_closed_for_any_q() {
    for q in 0usize..=1000 {
        let out = decide(false, &[], q);
        assert_eq!(out == Outcome::ConfirmedClean, q <= 1, "q={q}");
    }
}
