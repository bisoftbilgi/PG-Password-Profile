//! Blacklist lookups against `password_profile.blacklist`.
//!
//! The blacklist is held only in that table. An earlier design also kept a
//! fixed-size shared-memory array of SipHash digests guarded by a raw
//! PostgreSQL spinlock, but nothing ever populated it: its entry count was only
//! ever assigned zero, so the binary search always missed and the cache could
//! only ever answer "not blacklisted". It has been removed along with its
//! spinlock, which was the last raw spinlock in the extension.

use crate::sql::text_arg;
use pgrx::spi::Spi;
use std::error::Error;

/// Returns `true` when `password` appears in `password_profile.blacklist`.
///
/// # Failure is not "allowed"
/// The lookup is fallible on purpose. If the table cannot be read -- it does not
/// exist, permissions were revoked, the transaction is aborted -- the error is
/// returned to the caller so password validation fails and the password is
/// rejected. The previous implementation discarded such errors and fell through
/// to the empty shared-memory cache, which reported "not blacklisted" and
/// silently accepted a password the policy was meant to refuse.
///
/// An empty blacklist table is not an error: `EXISTS` yields `false` and the
/// password is accepted by this check.
///
/// The password is used only as a bound query parameter and is never logged.
pub(crate) fn contains(password: &str) -> Result<bool, Box<dyn Error>> {
    let found = Spi::get_one_with_args::<bool>(
        "SELECT EXISTS(SELECT 1 FROM password_profile.blacklist WHERE password = $1)",
        &[text_arg(password)],
    )?;

    // `EXISTS` always produces exactly one non-NULL row; the default is
    // defensive only and keeps an unexpected NULL from being treated as a hit.
    Ok(found.unwrap_or(false))
}
