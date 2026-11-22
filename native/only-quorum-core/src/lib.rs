//! Pure decision core of `check_revocation_with_quorum` (dgv-gate/src/main.rs).
//!
//! All I/O, crypto, timestamp/nonce checks and signature verification stay in
//! the gate (the *adapter*). The adapter reduces each peer response to a
//! [`Vote`]; this crate only tallies them. No heap, no floats, no unsafe,
//! no panics (no indexing, no unwrap, no arithmetic that can overflow).
//!
//! Written in the Rust subset Charon/Aeneas accepts: plain enums, `&[T]`,
//! a `while` loop with an index, saturating counters.
#![no_std]
#![forbid(unsafe_code)]

/// One peer's contribution, AFTER the adapter has validated nonce, actor id,
/// freshness, signature and trusted key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Vote {
    /// Valid signed response `status == "clean"`.
    Clean,
    /// Valid signed response `status == "revoked"`, WITH or WITHOUT a record.
    /// A reachable peer that says "revoked" always denies; the adapter must
    /// fail closed (deny) even if it cannot produce the record to return.
    Revoked,
    /// Anything else: unreachable, timeout, bad signature, stale, wrong nonce,
    /// untrusted key. Counts for nothing.
    Abstain,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    ConfirmedClean,
    Revoked,
    PartitionFailure,
}

/// Number of `Clean` votes plus one (the gate's own clean local check).
/// Saturates instead of overflowing.
pub fn clean_votes(votes: &[Vote]) -> usize {
    let mut n: usize = 1;
    let mut i: usize = 0;
    while i < votes.len() {
        if votes[i] == Vote::Clean {
            n = n.saturating_add(1);
        }
        i += 1;
    }
    n
}

/// True iff some vote is `Revoked`.
pub fn any_revoked(votes: &[Vote]) -> bool {
    let mut i: usize = 0;
    while i < votes.len() {
        if votes[i] == Vote::Revoked {
            return true;
        }
        i += 1;
    }
    false
}

/// 1. local revocation -> Revoked
/// 2. any valid peer "revoked" -> Revoked
/// 3. 1 + clean >= quorum_size -> ConfirmedClean, else PartitionFailure
///
/// `quorum_size` is always enforced, including with no peers (empty `votes`):
/// a gate configured with quorum_size > 1 and no reachable peers fails closed.
pub fn decide(local_revoked: bool, votes: &[Vote], quorum_size: usize) -> Outcome {
    if local_revoked {
        return Outcome::Revoked;
    }
    if any_revoked(votes) {
        return Outcome::Revoked;
    }
    if clean_votes(votes) >= quorum_size {
        Outcome::ConfirmedClean
    } else {
        Outcome::PartitionFailure
    }
}
