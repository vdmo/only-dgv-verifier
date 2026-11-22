use only_quorum_core::*;

/// Enumerate every vote vector up to length 8 (3^0+..+3^8 = 9841) x local x quorum 0..=10.
#[test]
fn exhaustive_small() {
    let all = [Vote::Clean, Vote::Revoked, Vote::Abstain];
    for len in 0..=8usize {
        let total = 3usize.pow(len as u32);
        for code in 0..total {
            let mut c = code;
            let mut v = [Vote::Abstain; 8];
            for i in 0..len { v[i] = all[c % 3]; c /= 3; }
            let votes = &v[..len];
            for local in [false, true] {
                for q in 0..=10usize {
                    let out = decide(local, votes, q);
                    let rev_seen = local || votes.contains(&Vote::Revoked);
                    // NoReachableRevAtExec (core form)
                    if out == Outcome::ConfirmedClean { assert!(!rev_seen); }
                    // Revocation always wins
                    if rev_seen { assert_eq!(out, Outcome::Revoked); }
                    // Fail-closed quorum (only when peers are configured)
                    if out == Outcome::ConfirmedClean {
                        let clean = votes.iter().filter(|x| **x == Vote::Clean).count() + 1;
                        assert!(clean >= q);
                    }
                }
            }
        }
    }
}

#[test]
fn no_peers_still_enforces_quorum() {
    assert_eq!(decide(false, &[], 1), Outcome::ConfirmedClean);
    assert_eq!(decide(false, &[], 2), Outcome::PartitionFailure);
}
