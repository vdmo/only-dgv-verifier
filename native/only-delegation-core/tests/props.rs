use only_delegation_core::*;
use proptest::prelude::*;

proptest! {
    #[test]
    fn depth_never_exceeds_max(p in any::<i64>(), m in any::<i64>()) {
        match child_depth(p, m) {
            Some(d) => { prop_assert!(d <= m); prop_assert_eq!(d as i128, p as i128 + 1); }
            None => prop_assert!(p as i128 + 1 > m as i128),
        }
    }
    #[test]
    fn expiry_never_widens(pe in any::<i64>(), r in proptest::option::of(any::<i64>()), now in any::<i64>()) {
        match child_expiry(pe, r, now) {
            Expiry::Ok(e) => { prop_assert!(e <= pe && e > now); }
            Expiry::ExceedsParent => prop_assert!(r.unwrap_or(pe) > pe),
            Expiry::InPast => prop_assert!(r.unwrap_or(pe) <= now),
        }
    }
}
#[test]
fn max_boundary_no_overflow() {
    assert_eq!(child_depth(i64::MAX, i64::MAX), None);
    assert_eq!(child_depth(i64::MAX - 1, i64::MAX), Some(i64::MAX));
}
