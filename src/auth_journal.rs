//! Durable authentication-event journal.
//!
//! Authentication hooks cannot use SPI, so events are appended to a small
//! fixed-record file in `PGDATA` before the hook returns.  The worker rotates
//! the active file, replays it in order, and removes the rotated file only
//! after every database transaction has committed.  A receipt table makes a
//! replay after a crash idempotent.

use crate::{
    auth_event::{EventFlags, EventKind, SharedAuthEvent},
    LOCK_USERNAME_BYTES,
};
use pgrx::pg_sys;
use siphasher::sip::SipHasher13;
use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::hash::Hasher;
use std::io::{self, BufReader, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const ACTIVE_FILE: &str = "password_profile_auth_events.active";
const PROCESSING_FILE: &str = "password_profile_auth_events.processing";
const MAGIC: [u8; 4] = *b"PPJ1";
const RECORD_SIZE: usize = 112;
const CHECKSUM_OFFSET: usize = RECORD_SIZE - 8;
const HASH_KEY_0: u64 = 0x7061_7373_776f_7264;
const HASH_KEY_1: u64 = 0x7072_6f66_696c_6531;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EventId(pub(crate) [u8; 16]);

#[derive(Debug)]
pub(crate) enum JournalError {
    Io(io::Error),
    Corrupt(&'static str),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Io(e) => write!(f, "{}", e),
            JournalError::Corrupt(reason) => write!(f, "{}", reason),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<io::Error> for JournalError {
    fn from(value: io::Error) -> Self {
        JournalError::Io(value)
    }
}

fn data_dir() -> Result<PathBuf, JournalError> {
    unsafe {
        if pg_sys::DataDir.is_null() {
            return Err(JournalError::Corrupt(
                "PostgreSQL data directory is unavailable",
            ));
        }
        Ok(PathBuf::from(
            CStr::from_ptr(pg_sys::DataDir).to_string_lossy().as_ref(),
        ))
    }
}

fn active_path() -> Result<PathBuf, JournalError> {
    Ok(data_dir()?.join(ACTIVE_FILE))
}

fn processing_path() -> Result<PathBuf, JournalError> {
    Ok(data_dir()?.join(PROCESSING_FILE))
}

fn checksum(bytes: &[u8]) -> u64 {
    let mut hasher = SipHasher13::new_with_keys(HASH_KEY_0, HASH_KEY_1);
    hasher.write(bytes);
    hasher.finish()
}

fn encode(event: &SharedAuthEvent) -> [u8; RECORD_SIZE] {
    let mut out = [0u8; RECORD_SIZE];
    out[0..4].copy_from_slice(&MAGIC);
    out[4..20].copy_from_slice(&event.event_id);
    out[20..20 + LOCK_USERNAME_BYTES].copy_from_slice(&event.username);
    out[84..92].copy_from_slice(&event.timestamp.to_le_bytes());
    out[92..100].copy_from_slice(&event.generation.to_le_bytes());
    out[100] = event.kind;
    out[101] = event.flags;
    let sum = checksum(&out[..CHECKSUM_OFFSET]);
    out[CHECKSUM_OFFSET..].copy_from_slice(&sum.to_le_bytes());
    out
}

fn decode(bytes: &[u8; RECORD_SIZE]) -> Result<SharedAuthEvent, JournalError> {
    if bytes[0..4] != MAGIC {
        return Err(JournalError::Corrupt(
            "auth journal record has an invalid header",
        ));
    }
    let expected = u64::from_le_bytes(bytes[CHECKSUM_OFFSET..].try_into().unwrap());
    if checksum(&bytes[..CHECKSUM_OFFSET]) != expected {
        return Err(JournalError::Corrupt(
            "auth journal record checksum mismatch",
        ));
    }

    let mut event_id = [0u8; 16];
    event_id.copy_from_slice(&bytes[4..20]);
    let mut username = [0u8; LOCK_USERNAME_BYTES];
    username.copy_from_slice(&bytes[20..20 + LOCK_USERNAME_BYTES]);

    let event = SharedAuthEvent {
        event_id,
        username,
        timestamp: i64::from_le_bytes(bytes[84..92].try_into().unwrap()),
        seq: 0,
        kind: bytes[100],
        generation: i64::from_le_bytes(bytes[92..100].try_into().unwrap()),
        flags: bytes[101],
    };
    let username_end = event
        .username
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(event.username.len());
    if username_end == 0 || std::str::from_utf8(&event.username[..username_end]).is_err() {
        return Err(JournalError::Corrupt(
            "auth journal record has an invalid username",
        ));
    }
    if EventKind::from_raw(event.kind).is_none() {
        return Err(JournalError::Corrupt(
            "auth journal record has an unknown event kind",
        ));
    }
    if EventFlags::from_raw(event.flags).is_none() {
        return Err(JournalError::Corrupt(
            "auth journal record has unknown event flags",
        ));
    }
    Ok(event)
}

/// Generates a process-independent event identifier using PostgreSQL's strong
/// random source.  Failure is reported to the hook; an event without a unique
/// identity is never admitted as durable.
pub(crate) fn new_event_id() -> Option<EventId> {
    let mut id = [0u8; 16];
    let ok = unsafe { pg_sys::pg_strong_random(id.as_mut_ptr().cast(), id.len()) };
    ok.then_some(EventId(id))
}

/// Appends and fsyncs one fixed-size record.  The caller serializes this with
/// journal rotation using `AUTH_EVENT_LWLOCK`.
pub(crate) fn append(event: &SharedAuthEvent) -> Result<(), JournalError> {
    let path = active_path()?;
    let new_file = !path.exists();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    if file.metadata()?.permissions().mode() & 0o077 != 0 {
        return Err(JournalError::Corrupt(
            "auth journal permissions must not grant group or other access",
        ));
    }
    file.write_all(&encode(event))?;
    file.sync_data()?;
    if new_file {
        File::open(data_dir()?)?.sync_all()?;
    }
    Ok(())
}

/// Returns the existing processing file, or atomically rotates a non-empty
/// active journal into place.  The caller holds `AUTH_EVENT_LWLOCK` so no
/// producer can append across the rename.
pub(crate) fn rotate() -> Result<Option<PathBuf>, JournalError> {
    let processing = processing_path()?;
    if processing.exists() {
        return Ok(Some(processing));
    }

    let active = active_path()?;
    match fs::metadata(&active) {
        Ok(metadata) if metadata.len() > 0 => {
            fs::rename(&active, &processing)?;
            File::open(data_dir()?)?.sync_all()?;
            Ok(Some(processing))
        }
        Ok(_) => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub(crate) struct JournalReader {
    inner: BufReader<File>,
    complete_records: u64,
    read_records: u64,
}

impl JournalReader {
    pub(crate) fn open(path: &Path) -> Result<Self, JournalError> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        let complete_len = len - len % RECORD_SIZE as u64;
        if complete_len != len {
            // A torn final append was never acknowledged to its producer.  It
            // is safe to discard only that incomplete tail.
            file.set_len(complete_len)?;
            file.sync_data()?;
        }
        Ok(Self {
            inner: BufReader::new(file),
            complete_records: complete_len / RECORD_SIZE as u64,
            read_records: 0,
        })
    }

    pub(crate) fn next_event(&mut self) -> Result<Option<SharedAuthEvent>, JournalError> {
        if self.read_records == self.complete_records {
            return Ok(None);
        }
        let mut bytes = [0u8; RECORD_SIZE];
        self.inner.read_exact(&mut bytes)?;
        self.read_records += 1;
        decode(&bytes).map(Some)
    }
}

/// Deletes a completely processed batch and makes the directory update
/// durable before receipt rows are cleaned up.
pub(crate) fn remove_processing(path: &Path) -> Result<(), JournalError> {
    fs::remove_file(path)?;
    File::open(data_dir()?)?.sync_all()?;
    Ok(())
}

/// Verifies both journal files. A torn final record is truncated because its
/// producer never completed a durable append; complete records are never
/// changed or discarded. Used by the explicit administrative recovery path.
pub(crate) fn verify_pending() -> Result<(), JournalError> {
    for path in [processing_path()?, active_path()?] {
        if !path.exists() {
            continue;
        }
        let mut reader = JournalReader::open(&path)?;
        while reader.next_event()?.is_some() {}
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct JournalStats {
    pub(crate) pending_bytes: i64,
    pub(crate) pending_records: i64,
}

/// Best-effort operational snapshot. Files can rotate between the two metadata
/// reads, so these are monitoring values rather than correctness inputs.
pub(crate) fn stats() -> JournalStats {
    let mut result = JournalStats::default();
    let Ok(paths) = processing_path().and_then(|processing| Ok([processing, active_path()?]))
    else {
        return result;
    };
    for path in paths {
        if let Ok(metadata) = fs::metadata(path) {
            let len = metadata.len().min(i64::MAX as u64) as i64;
            result.pending_bytes = result.pending_bytes.saturating_add(len);
            result.pending_records = result
                .pending_records
                .saturating_add(len / RECORD_SIZE as i64);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_event::{EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS, EVENT_KIND_GRACE_CONSUMED};

    fn event() -> SharedAuthEvent {
        let mut username = [0u8; LOCK_USERNAME_BYTES];
        username[..5].copy_from_slice(b"alice");
        SharedAuthEvent {
            event_id: [7; 16],
            username,
            timestamp: 123,
            seq: 42,
            kind: EVENT_KIND_GRACE_CONSUMED,
            generation: 99,
            flags: EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS,
        }
    }

    #[test]
    fn fixed_record_round_trip_preserves_durable_fields() {
        let decoded = decode(&encode(&event())).unwrap();
        assert_eq!(decoded.event_id, [7; 16]);
        assert_eq!(&decoded.username[..5], b"alice");
        assert_eq!(decoded.timestamp, 123);
        assert_eq!(decoded.generation, 99);
        assert_eq!(decoded.kind, EVENT_KIND_GRACE_CONSUMED);
        assert_eq!(decoded.flags, EVENT_FLAG_CLEAR_LOGIN_ATTEMPTS);
        assert_eq!(decoded.seq, 0);
    }

    #[test]
    fn checksum_rejects_modified_record() {
        let mut bytes = encode(&event());
        bytes[25] ^= 0x40;
        assert!(matches!(decode(&bytes), Err(JournalError::Corrupt(_))));
    }
}
