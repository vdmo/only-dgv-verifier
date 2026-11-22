//! Pure decision core for dgv-gate `/delegate` (depth bound and expiry rules).
//! Integer-only, no allocation, no unsafe: translatable by Charon/Aeneas.
#![no_std]
#![forbid(unsafe_code)]

/// Parent token is still live at `now` (gate: `parent.expires_unix_ms <= now` => expired).
pub fn parent_live(parent_expiry: i64, now: i64) -> bool {
    parent_expiry > now
}

/// Depth of the child, or `None` if it would exceed `max_depth`.
/// Equivalent to `parent_depth + 1 <= max_depth` but cannot overflow:
/// the addition only happens once `parent_depth < max_depth`.
pub fn child_depth(parent_depth: i64, max_depth: i64) -> Option<i64> {
    if parent_depth < max_depth {
        Some(parent_depth + 1)
    } else {
        None
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Expiry {
    /// Child expiry accepted.
    Ok(i64),
    /// Requested expiry is later than the parent's.
    ExceedsParent,
    /// Child expiry is not in the future.
    InPast,
}

/// Child expiry: defaults to the parent's; may only tighten; must be in the future.
pub fn child_expiry(parent_expiry: i64, requested: Option<i64>, now: i64) -> Expiry {
    let e = match requested {
        Some(r) => r,
        None => parent_expiry,
    };
    if e > parent_expiry {
        Expiry::ExceedsParent
    } else if e <= now {
        Expiry::InPast
    } else {
        Expiry::Ok(e)
    }
}
