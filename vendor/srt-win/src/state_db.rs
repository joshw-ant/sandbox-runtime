//! Cross-broker state DB for `srt-win acl` — refcount stamped paths
//! and store original SDs so the LAST broker to release a path can
//! restore it.
//!
//! Lives at `%LOCALAPPDATA%\sandbox-runtime\state.db` (rusqlite,
//! WAL). The directory is ACL-stamped broker-only `(OI)(CI)` on
//! every open so the sandbox child cannot tamper with the
//! refcount or wipe snapshot rows.
//!
//! Every `acl stamp|restore|recover` runs under a single named
//! mutex `Local\sandbox-runtime-acl-init` (broker-only DACL). The
//! mutex — NOT a DB transaction — serializes whole operations
//! across brokers; `WAIT_ABANDONED` from `WaitForSingleObject`
//! tells us the previous holder died mid-op (crash-recovery already
//! runs unconditionally so there's no extra action).
//!
//! There is deliberately NO single enclosing transaction. Ops
//! interleave FS mutations (`acl::restore_sd` / `stamp_file`) with
//! DB row changes; one big tx would roll back the rows on a
//! late-path failure while the FS mutations already executed —
//! divergence. Instead each path's (FS mutation + its row change)
//! commits independently (rusqlite autocommits a lone `execute`;
//! multi-statement ops use their own short tx), so a failure on
//! path Y can't revert path X.
//!
//! Crash safety in BOTH directions follows the rule "the row that
//! preserves `original_sd` outlives the FS mutation". Stamp:
//! `INSERT (original_sd, stamped_sd=NULL)` → `SetNamedSecurityInfoW`
//! → `UPDATE stamped_sd`. A crash before the write leaves a row
//! with cur==original (Case A in [`try_restore_snapshot`]: dropped);
//! a crash after leaves a row with cur==stamp and original recorded
//! (recoverable). Restore: `restore_sd` → `DELETE`. A crash after
//! the write leaves a stale row whose cur==original (Case A again);
//! a crash before leaves the row intact for the next attempt.
//!
//! Crash recovery: at the top of every locked operation, prune
//! `brokers` rows whose process is gone (PID doesn't exist or
//! CreationTime differs → recycled). CASCADE drops their `holders`
//! rows. Any `acl_snapshots` row left with zero holders is then
//! restored (only if the file's CURRENT SD still matches what we
//! stamped — if a third party has since edited it, we leave it
//! and log).

use anyhow::{anyhow, bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::mem::size_of;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use windows::Win32::Foundation::{
    CloseHandle, FILETIME, HANDLE, WAIT_ABANDONED, WAIT_OBJECT_0,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::System::Threading::{
    CreateMutexExW, GetCurrentProcess, GetProcessTimes, OpenProcess,
    ReleaseMutex, WaitForSingleObject, INFINITE, MUTEX_ALL_ACCESS,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::acl::{self, AclMask, CapturedSd};
use crate::util::{pcwstr, wstr, OwnedSd};

/// Holder PID — the LONG-LIVED process that owns a set of stamps
/// (the Node host in production), NOT the ephemeral `srt-win acl`
/// CLI process. Newtype to avoid confusing it with arbitrary PIDs
/// at call sites; the SQLite `brokers.pid` column stores the bare
/// `u32`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HolderPid(pub u32);

impl std::str::FromStr for HolderPid {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<u32>().map(HolderPid)
    }
}

/// `Local\` = per–Terminal-Services-session namespace. Brokers for
/// the SAME user in DIFFERENT TS sessions share the state DB
/// (`%LOCALAPPDATA%`) but NOT this mutex — they would not exclude
/// each other. `Global\` would, but creating it requires
/// `SeCreateGlobalPrivilege`, which an unelevated broker may lack.
/// The cross-session same-user case is rare enough that we accept
/// the limitation for v1; revisit if a real use case appears.
const MUTEX_NAME: &str = r"Local\sandbox-runtime-acl-init";
const SCHEMA_VERSION: i64 = 2;

const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS brokers (
  pid                 INTEGER PRIMARY KEY,
  process_create_time INTEGER NOT NULL,
  started_at          INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS holders (
  canonical_path TEXT    NOT NULL,
  pid            INTEGER NOT NULL REFERENCES brokers(pid) ON DELETE CASCADE,
  PRIMARY KEY (canonical_path, pid)
);
CREATE TABLE IF NOT EXISTS acl_snapshots (
  canonical_path TEXT    PRIMARY KEY,
  is_dir         INTEGER NOT NULL,
  mask           TEXT    NOT NULL CHECK(mask IN ('read','write')),
  original_sd    BLOB    NOT NULL,
  -- NULL while the stamp is in flight: the row is inserted (with the
  -- captured original_sd) BEFORE SetNamedSecurityInfoW runs, then
  -- this column is filled in afterwards. A crash in between leaves
  -- a row whose cur == original_sd (Case A in recovery: dropped
  -- safely) so the original is never lost.
  stamped_sd     BLOB,
  -- 24-byte stable identity captured at stamp time: 8-byte volume
  -- serial + 16-byte FILE_ID_128. Survives rename. Restore validates
  -- (path, file_id) and FAILS-CLOSED on mismatch (leaves the stamp).
  file_id        BLOB    NOT NULL,
  -- Immediate parent directory's canonical path. NULL only when
  -- the file is at a volume root (no parent).
  parent_path    TEXT,
  -- 1 when the parent directory could NOT be stamped (no
  -- WRITE_DAC, capture failed, or no parent). Such a file has no
  -- parent-side delete/rename protection and falls back to the
  -- per-exec no-FILE_SHARE_DELETE handle fence.
  parent_stamp_failed INTEGER NOT NULL DEFAULT 0
);
-- One row per parent directory that carries the FDC-removing
-- allow-list. Refcounted by the number of acl_snapshots rows
-- pointing at it (parent_path = canonical_parent_path); restored
-- + dropped when that count falls to zero.
CREATE TABLE IF NOT EXISTS parent_stamps (
  canonical_parent_path TEXT PRIMARY KEY,
  original_sd           BLOB NOT NULL,
  stamped_sd            BLOB
);
CREATE INDEX IF NOT EXISTS holders_by_pid ON holders (pid);
CREATE INDEX IF NOT EXISTS snapshots_by_parent
  ON acl_snapshots (parent_path);
"#;

/// One stored snapshot. `stamped_sd` is `None` only between the
/// pre-flight `INSERT` and the post-stamp `UPDATE` (see
/// `set_stamped`); a crash in that window leaves a row whose file
/// is still at `original_sd` and is harmlessly dropped by
/// crash-recovery's Case A.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub canonical_path: String,
    pub is_dir: bool,
    pub mask: AclMask,
    pub original_sd: CapturedSd,
    pub stamped_sd: Option<CapturedSd>,
    /// Stable identity captured at stamp time
    /// (`FILE_ID_INFO`). Restore validates `(path, file_id)` and
    /// FAILS-CLOSED on mismatch.
    pub file_id: acl::FileId,
    /// Immediate parent directory (canonical), or `None` for a
    /// file at a volume root.
    pub parent_path: Option<String>,
    /// True when the parent directory could not be stamped — this
    /// file falls back to the per-exec handle fence for
    /// delete/rename protection.
    pub parent_stamp_failed: bool,
}

/// One stamped parent directory (the FDC-removing allow-list).
#[derive(Debug, Clone)]
pub struct ParentStamp {
    pub canonical_parent_path: String,
    pub original_sd: CapturedSd,
    pub stamped_sd: Option<CapturedSd>,
}

/// Outcome of a crash-recovery pass.
#[derive(Debug, Default)]
pub struct RecoveryReport {
    pub dead_brokers: u32,
    pub restored: u32,
    pub left_changed: u32,
    /// Snapshots whose `(path, file_id)` no longer match — the
    /// stamped file was moved (located elsewhere by ID) or is
    /// gone. Row KEPT (fail-closed); reported, not restored.
    pub relocated: u32,
    pub missing: u32,
    /// Parent directories whose allow-list was restored on this
    /// pass (`parent_refcount` reached zero AND `restore_sd`
    /// succeeded).
    pub parents_restored: u32,
    /// Parent directories whose allow-list could NOT be restored
    /// (refcount zero but `restore_sd` failed); the
    /// `parent_stamps` row is kept and the next pass retries.
    pub parents_left: u32,
    /// Per-orphan detail — the structured-result output is
    /// derived from this.
    pub entries: Vec<(Snapshot, RestoreOutcome)>,
    /// Per-parent restore detail (path, ok-or-error-string).
    pub parent_entries: Vec<(String, std::result::Result<(), String>)>,
}

/// RAII guard for the init mutex. Releases on drop. The mutex
/// HANDLE itself is closed too — `CreateMutexExW` returns a fresh
/// handle every call (with `ERROR_ALREADY_EXISTS` set if the kernel
/// object already existed), so each `acquire` owns its own handle.
struct InitMutex {
    h: HANDLE,
}
impl Drop for InitMutex {
    fn drop(&mut self) {
        unsafe {
            let _ = ReleaseMutex(self.h);
            let _ = CloseHandle(self.h);
        }
    }
}

impl InitMutex {
    /// Create-or-open and acquire the init mutex. The mutex carries
    /// a broker-only DACL so a sandbox child cannot open it (and
    /// therefore cannot stall stamps by sitting on the lock).
    fn acquire(group_sid: &str) -> Result<Self> {
        let sddl = acl::sddl_broker_only_object(group_sid);
        let sd = OwnedSd::from_sddl(&sddl)
            .context("build init-mutex SD from SDDL")?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_psd().0,
            bInheritHandle: false.into(),
        };
        let name = wstr(MUTEX_NAME);
        // Don't request CREATE_MUTEX_INITIAL_OWNER — if another
        // broker already created the mutex this call opens it,
        // and INITIAL_OWNER would silently NOT acquire in that
        // case. A separate Wait gives a uniform code path and
        // surfaces WAIT_ABANDONED.
        let h = unsafe {
            CreateMutexExW(
                Some(&sa),
                pcwstr(&name),
                0, // dwFlags — no CREATE_MUTEX_INITIAL_OWNER
                MUTEX_ALL_ACCESS.0,
            )
        }
        .with_context(|| format!("CreateMutexExW({MUTEX_NAME})"))?;
        // `sd` (and `sa`) can drop now — the kernel object owns its SD.

        let r = unsafe { WaitForSingleObject(h, INFINITE) };
        match r {
            WAIT_OBJECT_0 => {}
            WAIT_ABANDONED => {
                // Previous holder died while owning the mutex. We
                // now own it. Crash-recovery (which the caller will
                // run next) handles the cleanup; nothing extra here.
                eprintln!(
                    "srt-win: init-mutex WAIT_ABANDONED — previous \
                     `srt-win acl` died mid-operation; running recovery"
                );
            }
            other => {
                unsafe { let _ = CloseHandle(h); }
                bail!(
                    "WaitForSingleObject({MUTEX_NAME}): unexpected {other:?} \
                     ({})",
                    std::io::Error::last_os_error()
                );
            }
        }
        Ok(Self { h })
    }
}

/// Open (creating if needed) the state DB at the default location.
/// Stamps the parent directory broker-only on EVERY open.
fn open_db(group_sid: &str) -> Result<Connection> {
    let dir = state_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create_dir_all {}", dir.display()))?;
    // Stamp the directory `(OI)(CI)` broker-only so the sandbox
    // child cannot tamper with state.db / -wal / -shm. Done on
    // EVERY open, not just first creation: if the dir already
    // existed (older srt-win, unclean prior run, or a same-user
    // child that pre-seeded it) a first-creation-only stamp would
    // leave the child with write access. `SetNamedSecurityInfoW` is
    // idempotent, so re-stamping an already-correct dir is a no-op.
    // Best-effort: if it fails we proceed (the `%LOCALAPPDATA%`
    // default DACL already excludes OTHER users; this defends
    // against the SAME-USER child) and warn so the test harness can
    // assert.
    if let Err(e) =
        acl::stamp_dir_inheriting(&dir.display().to_string(), group_sid)
    {
        eprintln!(
            "srt-win: WARNING: failed to stamp state-DB dir {} \
             broker-only: {e:#}",
            dir.display()
        );
    }
    open_db_at(&dir.join("state.db"))
}

/// Paths held by `holder_pid` whose **parent directory could not
/// be stamped** (`parent_stamp_failed = 1`) — i.e. the files for
/// which the parent-dir allow-list is NOT providing delete/rename
/// protection and which therefore fall back to the per-exec
/// no-`FILE_SHARE_DELETE` handle fence. Read-only: opens the state
/// DB via [`open_db_ro`] (no init mutex, no dir-stamp, no schema
/// apply, no `create_dir_all` — none of those belong on the
/// per-exec hot path). Returns empty when no `acl stamp` has run
/// yet, OR when every stamped path's parent was successfully
/// stamped (the common case — no fence needed).
pub fn fence_fallback_paths(
    group_sid: &str,
    holder_pid: HolderPid,
) -> Result<Vec<String>> {
    let Some(conn) = open_db_ro(group_sid)? else {
        return Ok(Vec::new());
    };
    let mut s = conn
        .prepare(
            "SELECT s.canonical_path \
             FROM holders h \
             JOIN acl_snapshots s ON h.canonical_path = s.canonical_path \
             WHERE h.pid = ?1 AND s.parent_stamp_failed = 1",
        )
        .context("prepare fence_fallback_paths")?;
    let it = s
        .query_map(params![holder_pid.0 as i64], |r| r.get(0))
        .context("query fence_fallback_paths")?;
    let mut out = Vec::new();
    for r in it {
        out.push(r.context("row fence_fallback_paths")?);
    }
    Ok(out)
}

/// Read-only open of the state DB at the default location. Returns
/// `None` if `state.db` doesn't exist yet. No mutex, no
/// `create_dir_all`, no dir-stamp, no schema apply — for `srt-win
/// exec`'s holder-paths read on the per-Bash-call hot path.
fn open_db_ro(_group_sid: &str) -> Result<Option<Connection>> {
    let path = state_dir()?.join("state.db");
    if !path.exists() {
        return Ok(None);
    }
    let conn = Connection::open_with_flags(
        &path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .with_context(|| format!("sqlite open RO {}", path.display()))?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    // open_db_at can crash between Connection::open (which creates
    // the file) and execute_batch(SCHEMA_SQL), leaving a valid
    // SQLite file with no schema. That state means "no stamps yet"
    // — return None so the caller treats it like a missing DB
    // instead of failing on `no such table: holders`. (A truly
    // CORRUPT DB is intentionally fail-closed: if we can't
    // enumerate the holder's stamps we can't prove the fence is
    // complete.)
    let has_schema: bool = conn
        .query_row(
            "SELECT 1 FROM sqlite_master \
             WHERE type='table' AND name='holders' LIMIT 1",
            [],
            |_| Ok(true),
        )
        .optional()
        .context("probe schema")?
        .unwrap_or(false);
    if !has_schema {
        return Ok(None);
    }
    Ok(Some(conn))
}

fn query_holder_paths(conn: &Connection, pid: HolderPid) -> Result<Vec<String>> {
    let mut s = conn
        .prepare("SELECT canonical_path FROM holders WHERE pid = ?1")
        .context("prepare holder paths")?;
    let it = s
        .query_map(params![pid.0 as i64], |r| r.get(0))
        .context("query holder paths")?;
    let mut out = Vec::new();
    for r in it {
        out.push(r.context("row holder paths")?);
    }
    Ok(out)
}

/// Open at an arbitrary path. Tests use `:memory:` via
/// `open_db_at(Path::new(":memory:"))`.
pub fn open_db_at(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("sqlite open {}", path.display()))?;
    // WAL = concurrent readers + single writer + crash safety.
    // `synchronous=NORMAL` is the recommended companion for WAL and
    // is durable across power loss. busy_timeout is belt-and-braces
    // — the named mutex already serializes whole operations across
    // brokers, but a brief contention inside one process (tests)
    // shouldn't error.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.execute_batch(SCHEMA_SQL).context("apply schema")?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(conn)
}

/// `%LOCALAPPDATA%\sandbox-runtime`.
pub fn state_dir() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("LOCALAPPDATA not set"))?;
    Ok(base.join("sandbox-runtime"))
}

/// Run `f` under the init mutex with the DB open. Crash recovery is
/// run first. `f` receives a `Locked` view whose mutating methods
/// each autocommit (single-statement) or use their own short
/// transaction — there is NO single enclosing transaction.
///
/// See module doc for the no-enclosing-tx and ordering rationale.
pub fn with_init_lock<R>(
    group_sid: &str,
    holder_pid: HolderPid,
    force_recover: bool,
    f: impl FnOnce(&Locked) -> Result<R>,
) -> Result<(R, RecoveryReport)> {
    let _mutex = InitMutex::acquire(group_sid)?;
    let conn = open_db(group_sid)?;
    let report = crash_recovery(&conn, force_recover)?;
    let locked = Locked { conn, holder_pid };
    let out = f(&locked)?;
    Ok((out, report))
}

/// View inside `with_init_lock`. Owns the `Connection`; each method
/// commits independently (rusqlite autocommits a lone `execute`).
///
/// `holder_pid` is the LONG-LIVED owner of the stamps — typically
/// the Node host (sandbox-runtime) process, NOT this ephemeral
/// `srt-win acl` process. The CLI exits immediately; keying holders
/// on its PID would let the next acl op's crash-recovery reap it and
/// tear the stamp down. Keying on the caller-supplied holder PID
/// means a stamp persists until that process exits (or explicitly
/// restores), and refcount / crash-recovery track the real session.
pub struct Locked {
    conn: Connection,
    holder_pid: HolderPid,
}

impl Locked {
    /// Insert (or refresh) the holder's `brokers` row. The stored
    /// `process_create_time` is the HOLDER's, so crash-recovery
    /// checks whether the holder — not this short-lived CLI — is
    /// still alive.
    ///
    /// UPSERT, not `INSERT OR REPLACE`: with `foreign_keys=ON` and
    /// `holders.pid REFERENCES brokers ON DELETE CASCADE`, REPLACE is
    /// a DELETE (cascading away every holder row for this pid) plus a
    /// fresh INSERT — so a holder's *second* `acl stamp` would
    /// silently drop its first stamp's holds, and the next
    /// crash-recovery would restore those files while the holder's
    /// child is still running. `ON CONFLICT DO UPDATE` updates in
    /// place and leaves child rows intact.
    pub fn register_broker(&self) -> Result<()> {
        let ct = pid_create_time(self.holder_pid.0).with_context(|| {
            format!("read create-time of holder pid {}", self.holder_pid.0)
        })?;
        let now = unix_now();
        self.conn
            .execute(
                "INSERT INTO brokers (pid, process_create_time, started_at) \
                 VALUES (?1, ?2, ?3) \
                 ON CONFLICT(pid) DO UPDATE SET \
                   process_create_time = excluded.process_create_time, \
                   started_at          = excluded.started_at",
                params![self.holder_pid.0 as i64, ct, now],
            )
            .context("INSERT brokers")?;
        Ok(())
    }

    /// Remove the holder's `brokers` row. CASCADE drops its
    /// `holders` rows.
    pub fn unregister_broker(&self) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM brokers WHERE pid = ?1",
                params![self.holder_pid.0 as i64],
            )
            .context("DELETE brokers")?;
        Ok(())
    }

    /// Record the holder against `canonical_path`. Idempotent
    /// (`INSERT OR IGNORE`).
    pub fn add_holder(&self, canonical_path: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR IGNORE INTO holders (canonical_path, pid) \
                 VALUES (?1, ?2)",
                params![canonical_path, self.holder_pid.0 as i64],
            )
            .context("INSERT holders")?;
        Ok(())
    }

    /// Remove the holder from `canonical_path`. Returns `true` if the
    /// path's refcount has dropped to zero (caller should restore).
    /// Delete + recount run in one short tx so the returned count
    /// reflects the delete atomically (the mutex already excludes
    /// other writers, but this keeps the read consistent if the
    /// delete partially applied).
    pub fn remove_holder(&self, canonical_path: &str) -> Result<bool> {
        let tx = self
            .conn
            .unchecked_transaction()
            .context("begin remove_holder tx")?;
        tx.execute(
            "DELETE FROM holders WHERE canonical_path = ?1 AND pid = ?2",
            params![canonical_path, self.holder_pid.0 as i64],
        )
        .context("DELETE holders (one)")?;
        let remaining: i64 = tx
            .query_row(
                "SELECT count(*) FROM holders WHERE canonical_path = ?1",
                params![canonical_path],
                |r| r.get(0),
            )
            .context("count remaining holders")?;
        tx.commit().context("commit remove_holder")?;
        Ok(remaining == 0)
    }

    /// All paths currently held by the holder.
    pub fn my_holds(&self) -> Result<Vec<String>> {
        query_holder_paths(&self.conn, self.holder_pid)
    }

    /// Look up a snapshot row.
    pub fn get_snapshot(&self, canonical_path: &str) -> Result<Option<Snapshot>> {
        self.conn
            .query_row(SNAPSHOT_SELECT_BY_PATH, params![canonical_path], snapshot_from_row)
            .optional()
            .context("SELECT acl_snapshots")
    }

    /// Insert a snapshot. Caller is the FIRST stamper of this path
    /// (i.e. `get_snapshot` returned `None`). Called BEFORE the FS
    /// mutation with `stamped_sd = None`; `set_stamped` fills it in
    /// after the kernel-canonical SD is read back.
    pub fn insert_snapshot(&self, s: &Snapshot) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO acl_snapshots \
                 (canonical_path, is_dir, mask, original_sd, stamped_sd, \
                  file_id, parent_path, parent_stamp_failed) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    s.canonical_path,
                    s.is_dir as i64,
                    s.mask.as_str(),
                    s.original_sd.as_bytes(),
                    s.stamped_sd.as_ref().map(CapturedSd::as_bytes),
                    s.file_id.as_bytes().as_slice(),
                    s.parent_path,
                    s.parent_stamp_failed as i64,
                ],
            )
            .context("INSERT acl_snapshots")?;
        Ok(())
    }

    /// Look up a stamped parent directory.
    pub fn get_parent_stamp(
        &self,
        canonical_parent_path: &str,
    ) -> Result<Option<ParentStamp>> {
        self.conn
            .query_row(
                "SELECT canonical_parent_path, original_sd, stamped_sd \
                 FROM parent_stamps WHERE canonical_parent_path = ?1",
                params![canonical_parent_path],
                |r| {
                    Ok(ParentStamp {
                        canonical_parent_path: r.get(0)?,
                        original_sd: CapturedSd::from(r.get::<_, Vec<u8>>(1)?),
                        stamped_sd: r
                            .get::<_, Option<Vec<u8>>>(2)?
                            .map(CapturedSd::from),
                    })
                },
            )
            .optional()
            .context("SELECT parent_stamps")
    }

    /// Insert a parent-directory stamp row (called BEFORE the FS
    /// mutation with `stamped_sd = None`, same ordering invariant
    /// as file snapshots).
    pub fn insert_parent_stamp(&self, p: &ParentStamp) -> Result<()> {
        self.conn
            .execute(
                "INSERT INTO parent_stamps \
                 (canonical_parent_path, original_sd, stamped_sd) \
                 VALUES (?1, ?2, ?3)",
                params![
                    p.canonical_parent_path,
                    p.original_sd.as_bytes(),
                    p.stamped_sd.as_ref().map(CapturedSd::as_bytes),
                ],
            )
            .context("INSERT parent_stamps")?;
        Ok(())
    }

    pub fn set_parent_stamped(
        &self,
        canonical_parent_path: &str,
        stamped_sd: &CapturedSd,
    ) -> Result<()> {
        self.conn
            .execute(
                "UPDATE parent_stamps SET stamped_sd = ?2 \
                 WHERE canonical_parent_path = ?1",
                params![canonical_parent_path, stamped_sd.as_bytes()],
            )
            .context("UPDATE parent_stamps stamped_sd")?;
        Ok(())
    }

    /// Mark a snapshot's `parent_stamp_failed` flag. Called when
    /// the parent directory can't be WRITE_DAC'd (or there is no
    /// parent), so the file falls back to the per-exec handle
    /// fence for delete/rename protection.
    pub fn set_parent_stamp_failed(
        &self,
        canonical_path: &str,
    ) -> Result<()> {
        self.set_parent_stamp_failed_to(canonical_path, true)
    }

    /// Clear the fallback marker after a later parent-stamp
    /// attempt succeeds (mask escalation retries it).
    pub fn clear_parent_stamp_failed(
        &self,
        canonical_path: &str,
    ) -> Result<()> {
        self.set_parent_stamp_failed_to(canonical_path, false)
    }

    fn set_parent_stamp_failed_to(
        &self,
        canonical_path: &str,
        v: bool,
    ) -> Result<()> {
        self.conn
            .execute(
                "UPDATE acl_snapshots SET parent_stamp_failed = ?2 \
                 WHERE canonical_path = ?1",
                params![canonical_path, v as i64],
            )
            .context("UPDATE acl_snapshots parent_stamp_failed")?;
        Ok(())
    }

    pub fn delete_parent_stamp(
        &self,
        canonical_parent_path: &str,
    ) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM parent_stamps WHERE canonical_parent_path = ?1",
                params![canonical_parent_path],
            )
            .context("DELETE parent_stamps")?;
        Ok(())
    }

    /// Number of `acl_snapshots` rows that point at this parent —
    /// the parent stamp's refcount.
    pub fn parent_refcount(
        &self,
        canonical_parent_path: &str,
    ) -> Result<i64> {
        self.conn
            .query_row(
                "SELECT count(*) FROM acl_snapshots WHERE parent_path = ?1",
                params![canonical_parent_path],
                |r| r.get(0),
            )
            .context("count parent_refcount")
    }

    /// Fill in the `stamped_sd` column after the FS mutation has
    /// landed. Also used for mask escalation (a later stamper
    /// requesting a stricter mask re-stamps and updates both
    /// columns; `original_sd` is never touched).
    pub fn set_stamped(
        &self,
        canonical_path: &str,
        mask: AclMask,
        stamped_sd: &CapturedSd,
    ) -> Result<()> {
        self.conn
            .execute(
                "UPDATE acl_snapshots \
                 SET stamped_sd = ?2, mask = ?3 \
                 WHERE canonical_path = ?1",
                params![canonical_path, stamped_sd.as_bytes(), mask.as_str()],
            )
            .context("UPDATE acl_snapshots stamped_sd")?;
        Ok(())
    }

    pub fn delete_snapshot(&self, canonical_path: &str) -> Result<()> {
        self.conn
            .execute(
                "DELETE FROM acl_snapshots WHERE canonical_path = ?1",
                params![canonical_path],
            )
            .context("DELETE acl_snapshots")?;
        Ok(())
    }

    /// Restore-or-drop a zero-refcount snapshot. Shared by the
    /// `acl restore` arm and crash-recovery so the two cannot
    /// diverge in their case analysis (see [`try_restore_snapshot`]).
    pub fn try_restore(
        &self,
        snap: &Snapshot,
        force: bool,
    ) -> Result<RestoreOutcome> {
        try_restore_snapshot(&self.conn, snap, force)
    }
}

const SNAPSHOT_SELECT_BY_PATH: &str = "SELECT canonical_path, is_dir, \
     mask, original_sd, stamped_sd, file_id, parent_path, \
     parent_stamp_failed \
     FROM acl_snapshots WHERE canonical_path = ?1";

fn snapshot_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Snapshot> {
    Ok(Snapshot {
        canonical_path: r.get(0)?,
        is_dir: r.get::<_, i64>(1)? != 0,
        mask: AclMask::parse(&r.get::<_, String>(2)?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                rusqlite::types::Type::Text,
                e.into(),
            )
        })?,
        original_sd: CapturedSd::from(r.get::<_, Vec<u8>>(3)?),
        stamped_sd: r.get::<_, Option<Vec<u8>>>(4)?.map(CapturedSd::from),
        file_id: acl::FileId::from_bytes(&r.get::<_, Vec<u8>>(5)?)
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Blob,
                    e.into(),
                )
            })?,
        parent_path: r.get(6)?,
        parent_stamp_failed: r.get::<_, i64>(7)? != 0,
    })
}

/// Prune dead brokers and restore any snapshots they orphaned.
/// `force` restores even when the current SD ≠ stamped_sd.
///
/// Per-path commit: the dead-broker prune is one short tx (pure DB,
/// CASCADE); then each orphan's (restore_sd FS mutation + snapshot
/// row delete) is committed independently, so a failure restoring
/// path Y leaves path X's restore+delete durable.
fn crash_recovery(conn: &Connection, force: bool) -> Result<RecoveryReport> {
    let mut report = RecoveryReport::default();

    // 1. Find dead brokers.
    let mut dead: Vec<i64> = Vec::new();
    {
        let mut s = conn
            .prepare("SELECT pid, process_create_time FROM brokers")?;
        let it = s.query_map([], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))
        })?;
        for r in it {
            let (pid_i, ct) = r.context("row brokers")?;
            if !is_process_alive(pid_i as u32, ct) {
                dead.push(pid_i);
            }
        }
    }
    // 2. Delete dead brokers in one short tx; CASCADE drops their
    //    holder rows. (No-op if none — but still cheap.)
    if !dead.is_empty() {
        report.dead_brokers = dead.len() as u32;
        let tx = conn
            .unchecked_transaction()
            .context("begin prune-dead tx")?;
        for pid_i in &dead {
            tx.execute("DELETE FROM brokers WHERE pid = ?1", params![pid_i])
                .context("DELETE dead broker")?;
        }
        tx.commit().context("commit prune-dead")?;
    }
    // Even with no dead brokers there can be orphaned snapshots
    // (a broker that unregistered but crashed before restoring), so
    // always run step 3.

    // 3. Any snapshot with zero holders is orphaned → restore, each
    //    path committed independently.
    let orphans: Vec<Snapshot> = {
        let mut s = conn.prepare(
            "SELECT s.canonical_path, s.is_dir, s.mask, s.original_sd, \
                    s.stamped_sd, s.file_id, s.parent_path, \
                    s.parent_stamp_failed \
             FROM acl_snapshots s \
             LEFT JOIN holders h ON h.canonical_path = s.canonical_path \
             WHERE h.canonical_path IS NULL",
        )?;
        let it = s.query_map([], snapshot_from_row)?;
        let mut v = Vec::new();
        for r in it {
            v.push(r.context("row orphan")?);
        }
        v
    };
    for snap in orphans {
        // Each path is processed independently; a failure on
        // one does not abort the batch (the host raises after
        // reading the full structured result, never mid-batch).
        let out = match try_restore_snapshot(conn, &snap, force) {
            Ok(o) => o,
            Err(e) => {
                eprintln!(
                    "srt-win: '{}': restore failed at the DB layer \
                     ({e:#}); leaving snapshot row",
                    snap.canonical_path
                );
                RestoreOutcome::LeftUnreadable
            }
        };
        match &out {
            RestoreOutcome::Restored | RestoreOutcome::AlreadyOriginal => {
                report.restored += 1;
            }
            RestoreOutcome::Relocated { .. } => report.relocated += 1,
            RestoreOutcome::Missing => report.missing += 1,
            RestoreOutcome::LeftChanged | RestoreOutcome::LeftUnreadable => {
                report.left_changed += 1;
            }
        }
        report.entries.push((snap, out));
    }

    // 4. Parent-orphan scan: any `parent_stamps` row with no
    //    remaining child snapshot is one whose `restore_sd` failed
    //    on a previous pass (the row was kept "for a later
    //    attempt"). Retry now. This is the only place the retry
    //    happens — without it a stuck parent would only be
    //    reattempted when a NEW file in that directory is
    //    stamped+restored.
    let parent_orphans: Vec<(String, CapturedSd)> = {
        let mut s = conn.prepare(
            "SELECT p.canonical_parent_path, p.original_sd \
             FROM parent_stamps p \
             WHERE NOT EXISTS (SELECT 1 FROM acl_snapshots s \
                               WHERE s.parent_path = p.canonical_parent_path)",
        )?;
        let it = s.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                CapturedSd::from(r.get::<_, Vec<u8>>(1)?),
            ))
        })?;
        let mut v = Vec::new();
        for r in it {
            v.push(r.context("row parent-orphan")?);
        }
        v
    };
    for (parent, p_orig) in parent_orphans {
        match acl::restore_sd(&parent, &p_orig) {
            Ok(()) => {
                conn.execute(
                    "DELETE FROM parent_stamps \
                     WHERE canonical_parent_path = ?1",
                    params![parent],
                )
                .context("DELETE parent_stamps (orphan)")?;
                report.parents_restored += 1;
                report.parent_entries.push((parent, Ok(())));
            }
            Err(e) => {
                eprintln!(
                    "srt-win: parent restore '{parent}' failed: {e:#}; \
                     leaving parent_stamps row for a later attempt"
                );
                report.parents_left += 1;
                report
                    .parent_entries
                    .push((parent, Err(format!("{e:#}"))));
            }
        }
    }
    Ok(report)
}

/// What `try_restore_snapshot` did with one zero-refcount snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// Wrote `original_sd` back and deleted the row.
    Restored,
    /// File already at `original_sd`; dropped the stale row.
    AlreadyOriginal,
    /// `(path, file_id)` mismatch: the protected file is no longer
    /// at the recorded path (the path is gone or now resolves to a
    /// DIFFERENT inode), but it was found elsewhere on the volume
    /// by `file_id`. Row KEPT, stamp LEFT in place (fail-closed):
    /// the broker-only DACL travels with the inode, so the file
    /// stays read-denied wherever it was moved. We do NOT restore
    /// by inode — chasing the file by ID to remove its stamp would
    /// re-expose a relocated secret.
    Relocated { moved_to: String },
    /// `(path, file_id)` mismatch and the file could not be
    /// located by ID (deleted, or moved off-volume). Row KEPT
    /// (orphan tracking) — the host surfaces this for the user to
    /// resolve (move the file back, or admin-side reset).
    Missing,
    /// Current SD ≠ stamped (third-party edit) and not `--force`;
    /// row kept, file left as-is.
    LeftChanged,
    /// Can't read the current SD (file exists, identity matches)
    /// and not `--force`; row kept for a later attempt.
    LeftUnreadable,
}

/// Restore-or-drop one zero-refcount snapshot. Shared by
/// crash-recovery and the `acl restore` arm so the case analysis
/// cannot diverge.
///
/// **Identity-validated and path-anchored.** We restore ONLY when
/// `canonical_path` still resolves to the same `file_id` we
/// captured at stamp time. If the path is gone, or now points at
/// a different inode, the protected file was relocated or
/// substituted: leave the stamp (it travels with the inode, so
/// the data stays broker-only wherever it went), keep the row as
/// the anomaly record, and best-effort locate the moved file by
/// ID for reporting. We never restore by inode — chasing the file
/// by ID to remove its stamp would re-expose a relocated secret.
///
/// FS mutation FIRST, then delete the row, only on success: if
/// `restore_sd` fails we keep the row (recoverable); if the
/// row-delete fails after a successful restore, the next pass hits
/// Case A (cur == original) and drops the row then.
fn try_restore_snapshot(
    conn: &Connection,
    snap: &Snapshot,
    force: bool,
) -> Result<RestoreOutcome> {
    // Drop the snapshot row, then — if this was the LAST snapshot
    // pointing at the parent — restore the parent directory's
    // original DACL too. (Same record-first FS-then-DB ordering
    // as the file restore: restore_sd first, then delete the
    // parent_stamps row.)
    let drop_row = |ctx: &str| -> Result<()> {
        conn.execute(
            "DELETE FROM acl_snapshots WHERE canonical_path = ?1",
            params![snap.canonical_path],
        )
        .with_context(|| format!("DELETE snapshot ({ctx})"))?;
        if let Some(parent) = snap.parent_path.as_deref() {
            try_restore_parent(conn, parent)?;
        }
        Ok(())
    };

    // Identity gate. Open the path and read its current
    // FILE_ID_INFO. Three cases (the boundary check):
    //
    //   - path gone (ERROR_FILE/PATH_NOT_FOUND) → mismatch.
    //   - path → DIFFERENT file_id → mismatch.
    //   - path → SAME file_id → proceed to the SD case analysis.
    //
    // Any OTHER open error (transient lock, ACCESS_DENIED for a
    // reason other than gone) is `LeftUnreadable` — row kept,
    // retryable, surfaced; NOT treated as a mismatch.
    //
    // On mismatch: row KEPT, stamp LEFT (fail-closed). Locate the
    // file by ID (reporting only; never to restore at).
    use windows::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    };
    let id_match = match acl::capture_file_id(&snap.canonical_path) {
        Ok(cur_id) => cur_id == snap.file_id,
        Err(e) => {
            // Distinguish gone (mismatch) from transiently
            // unreadable (LeftUnreadable, retryable).
            let code = e
                .downcast_ref::<windows::core::Error>()
                .map(|we| we.code());
            let gone = matches!(
                code,
                Some(c) if c == ERROR_FILE_NOT_FOUND.into()
                        || c == ERROR_PATH_NOT_FOUND.into()
            );
            if !gone {
                eprintln!(
                    "srt-win: '{}': cannot read file_id ({e:#}); \
                     leaving snapshot (use `acl recover --force`)",
                    snap.canonical_path
                );
                return Ok(RestoreOutcome::LeftUnreadable);
            }
            false
        }
    };
    if !id_match {
        return Ok(match acl::locate_by_file_id(&snap.file_id) {
            Some(at) => {
                eprintln!(
                    "srt-win: '{}': file_id mismatch — protected file is \
                     now at '{at}'; leaving stamp (fail-closed) and \
                     snapshot row",
                    snap.canonical_path
                );
                RestoreOutcome::Relocated { moved_to: at }
            }
            None => {
                eprintln!(
                    "srt-win: '{}': file_id mismatch — protected file not \
                     found on volume; leaving snapshot row (fail-closed)",
                    snap.canonical_path
                );
                RestoreOutcome::Missing
            }
        });
    }

    let cur = match acl::capture_sd(&snap.canonical_path) {
        Ok(c) => c,
        Err(e) => {
            // Identity matched but the SD read failed (e.g.
            // ACCESS_DENIED, transient lock). Path EXISTS (we just
            // opened it for the file_id read), so this is the
            // unreadable-SD case, not a gone file.
            if force {
                // Best-effort: try the restore anyway.
                if let Err(e2) =
                    acl::restore_sd(&snap.canonical_path, &snap.original_sd)
                {
                    eprintln!(
                        "srt-win: '{}': forced restore after unreadable SD \
                         failed: {e2:#}; leaving snapshot",
                        snap.canonical_path
                    );
                    return Ok(RestoreOutcome::LeftUnreadable);
                }
                drop_row("forced (unreadable)")?;
                return Ok(RestoreOutcome::Restored);
            }
            eprintln!(
                "srt-win: '{}': cannot read current SD ({e:#}); leaving \
                 snapshot (use `acl recover --force`)",
                snap.canonical_path
            );
            return Ok(RestoreOutcome::LeftUnreadable);
        }
    };

    // Case A — already at the original SD. The file is restored and
    // this row is pure stale bookkeeping (a prior restore whose
    // row-delete didn't land, OR a stamp that crashed before the FS
    // mutation — `stamped_sd` is None). Provably safe to drop without
    // --force: cur == original ⇒ nothing to restore.
    if cur.equiv(&snap.original_sd) {
        drop_row("already at original")?;
        return Ok(RestoreOutcome::AlreadyOriginal);
    }

    // Case B — current SD differs from original. Restore only if it
    // still carries OUR stamp (or --force). When `stamped_sd` is
    // None (stamp crashed mid-flight after Case A's check above
    // somehow didn't apply — extremely unlikely since the FS write
    // is atomic) only --force will touch it.
    let still_ours = snap
        .stamped_sd
        .as_ref()
        .map(|s| cur.equiv(s))
        .unwrap_or(false);
    if !force && !still_ours {
        eprintln!(
            "srt-win: '{}': DACL changed since stamp; leaving as-is \
             (snapshot kept; `acl recover --force` to override)",
            snap.canonical_path
        );
        return Ok(RestoreOutcome::LeftChanged);
    }

    match acl::restore_sd(&snap.canonical_path, &snap.original_sd) {
        Ok(()) => {
            drop_row("restored")?;
            Ok(RestoreOutcome::Restored)
        }
        Err(e) => {
            eprintln!(
                "srt-win: '{}': restore failed: {e:#}; leaving snapshot row",
                snap.canonical_path
            );
            Ok(RestoreOutcome::LeftChanged)
        }
    }
}

/// Restore a parent directory's original DACL **iff** no
/// remaining snapshots point at it. Called after a snapshot row
/// is deleted. Best-effort: a failure here is logged and the
/// `parent_stamps` row is kept so a later pass can retry — we do
/// NOT propagate the error to the caller's restore (the file
/// restore already succeeded; failing the whole batch over a
/// stuck parent would block other paths).
fn try_restore_parent(conn: &Connection, parent: &str) -> Result<()> {
    let remaining: i64 = conn
        .query_row(
            "SELECT count(*) FROM acl_snapshots WHERE parent_path = ?1",
            params![parent],
            |r| r.get(0),
        )
        .context("count remaining children of parent")?;
    if remaining > 0 {
        return Ok(());
    }
    let Some(p_orig) = conn
        .query_row(
            "SELECT original_sd FROM parent_stamps \
             WHERE canonical_parent_path = ?1",
            params![parent],
            |r| Ok(CapturedSd::from(r.get::<_, Vec<u8>>(0)?)),
        )
        .optional()
        .context("SELECT parent_stamps original_sd")?
    else {
        // No row — parent was never stamped (parent_stamp_failed
        // case) or already restored. Nothing to do.
        return Ok(());
    };
    if let Err(e) = acl::restore_sd(parent, &p_orig) {
        eprintln!(
            "srt-win: parent restore '{parent}' failed: {e:#}; leaving \
             parent_stamps row for a later attempt"
        );
        return Ok(());
    }
    conn.execute(
        "DELETE FROM parent_stamps WHERE canonical_parent_path = ?1",
        params![parent],
    )
    .context("DELETE parent_stamps after restore")?;
    Ok(())
}

/// True if `pid` refers to a live process whose CreationTime
/// matches `expected_create_filetime`. PID-recycle guard.
fn is_process_alive(pid: u32, expected_create_filetime: i64) -> bool {
    if pid == std::process::id() {
        // Don't reap ourselves even if the stored CreationTime is
        // somehow stale.
        return true;
    }
    // SYNCHRONIZE so the WaitForSingleObject(0) signaled-check works.
    let h = match unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION
                | windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
            false,
            pid,
        )
    } {
        Ok(h) if !h.is_invalid() => h,
        // A spurious `Ok` with an invalid handle is "uncertain" —
        // treat as ALIVE, matching the conservative stance below
        // (better to leave a stale row than reap a live broker and
        // restore a file it still holds).
        Ok(_) => return true,
        // Treat as DEAD only on ERROR_INVALID_PARAMETER (87) — the
        // "no such PID" signal. Every other error (ACCESS_DENIED,
        // transient low-memory, etc.) is uncertain → ALIVE, so we
        // never reap (and restore a file still used by) a holder
        // that's actually running.
        Err(e) => {
            return (e.code().0 as u32 & 0xFFFF) != 87;
        }
    };
    let h = crate::util::OwnedHandle(h);
    match process_create_time(h.raw()) {
        Ok(ct) => {
            ct == expected_create_filetime
                // An exited process whose handle is still held
                // elsewhere remains openable with the same
                // CreationTime — without this check it reads as
                // alive forever and is never reaped. WAIT_TIMEOUT
                // (with a zero wait) means "still running"; any
                // other return (WAIT_OBJECT_0 = signaled = exited,
                // WAIT_FAILED) means not.
                && unsafe { WaitForSingleObject(h.raw(), 0) }
                    == windows::Win32::Foundation::WAIT_TIMEOUT
        }
        // Transient GetProcessTimes failure → uncertain → ALIVE,
        // matching the conservative stance everywhere else (better
        // a stale row than a live holder reaped and its files
        // restored under it).
        Err(_) => true,
    }
}

/// Creation FILETIME (as i64) of an arbitrary PID. Opens the
/// process for limited query; special-cases self to avoid needing
/// OpenProcess rights on our own token.
fn pid_create_time(pid: u32) -> Result<i64> {
    if pid == std::process::id() {
        return process_create_time(unsafe { GetCurrentProcess() });
    }
    let h = unsafe {
        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
    }
    .with_context(|| format!("OpenProcess({pid}) for create-time"))?;
    if h.is_invalid() {
        bail!("OpenProcess({pid}) returned invalid handle");
    }
    let h = crate::util::OwnedHandle(h);
    process_create_time(h.raw())
}

/// FILETIME (100-ns since 1601-01-01) → i64 for storage.
fn process_create_time(h: HANDLE) -> Result<i64> {
    let mut create = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    unsafe {
        GetProcessTimes(h, &mut create, &mut exit, &mut kernel, &mut user)
            .context("GetProcessTimes")?;
    }
    Ok(((create.dwHighDateTime as i64) << 32)
        | (create.dwLowDateTime as i64))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Open an in-memory DB and run `f` against a `Locked` view
    /// (autocommit, like production). Skips the named mutex + dir
    /// stamp (those are integration-tested via smoke-acl.ps1).
    fn with_mem_db<R>(f: impl FnOnce(&Locked) -> R) -> R {
        let conn = open_db_at(std::path::Path::new(":memory:")).unwrap();
        let db = Locked { conn, holder_pid: HolderPid(std::process::id()) };
        f(&db)
    }

    #[test]
    fn schema_applies_in_memory() {
        let conn = open_db_at(std::path::Path::new(":memory:")).unwrap();
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' \
                 AND name IN ('brokers','holders','acl_snapshots')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn refcount_two_holders() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            db.add_holder(r"\\?\C:\f").unwrap();
            // Simulate a second broker by inserting directly.
            db.conn
                .execute(
                    "INSERT INTO brokers \
                     (pid, process_create_time, started_at) \
                     VALUES (999999, 1, 1)",
                    [],
                )
                .unwrap();
            db.conn
                .execute(
                    "INSERT INTO holders (canonical_path, pid) \
                     VALUES (?1, 999999)",
                    params![r"\\?\C:\f"],
                )
                .unwrap();
            // Removing OUR hold leaves the other → not zero.
            assert!(!db.remove_holder(r"\\?\C:\f").unwrap());
            // Drop the other broker (CASCADE removes its holder).
            db.conn
                .execute("DELETE FROM brokers WHERE pid = 999999", [])
                .unwrap();
            let n: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM holders WHERE canonical_path = ?1",
                    params![r"\\?\C:\f"],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 0);
        });
    }

    #[test]
    fn snapshot_round_trip() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            let s = Snapshot {
                canonical_path: r"\\?\C:\f".into(),
                is_dir: false,
                mask: AclMask::WriteDeny,
                original_sd: vec![1, 2, 3].into(),
                // In flight: stamp not yet applied.
                stamped_sd: None,
                file_id: acl::FileId {
                    volume_serial: 0xdead,
                    id128: [7u8; 16],
                },
                parent_path: Some(r"\\?\C:\".into()),
                parent_stamp_failed: false,
            };
            db.insert_snapshot(&s).unwrap();
            let got = db.get_snapshot(r"\\?\C:\f").unwrap().unwrap();
            assert_eq!(got.mask, AclMask::WriteDeny);
            assert_eq!(got.original_sd.as_bytes(), &[1, 2, 3]);
            assert!(got.stamped_sd.is_none());
            // Post-FS-write update fills it in (and can escalate
            // mask).
            db.set_stamped(
                r"\\?\C:\f",
                AclMask::ReadDeny,
                &vec![4, 5, 6].into(),
            )
            .unwrap();
            let got = db.get_snapshot(r"\\?\C:\f").unwrap().unwrap();
            assert_eq!(
                got.stamped_sd.as_ref().map(CapturedSd::as_bytes),
                Some(&[4, 5, 6][..])
            );
            assert_eq!(got.mask, AclMask::ReadDeny);
            // original_sd untouched by set_stamped.
            assert_eq!(got.original_sd.as_bytes(), &[1, 2, 3]);
            db.delete_snapshot(r"\\?\C:\f").unwrap();
            assert!(db.get_snapshot(r"\\?\C:\f").unwrap().is_none());
        });
    }

    /// Regression for the security finding: `register_broker` is an
    /// UPSERT (`ON CONFLICT DO UPDATE`), NOT `INSERT OR REPLACE` —
    /// the latter would CASCADE-delete this holder's existing
    /// `holders` rows on a second stamp.
    #[test]
    fn second_register_broker_keeps_existing_holds() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            db.add_holder(r"\\?\C:\a").unwrap();
            db.add_holder(r"\\?\C:\b").unwrap();
            assert_eq!(db.my_holds().unwrap().len(), 2);
            // Second stamp by the same holder.
            db.register_broker().unwrap();
            // Holds intact (would be 0 with INSERT OR REPLACE).
            assert_eq!(db.my_holds().unwrap().len(), 2);
        });
    }

    #[test]
    fn crash_recovery_reaps_dead_broker_keeps_missing_orphan() {
        // Insert a dead broker + its holder + a snapshot for a path
        // that does NOT exist. Recovery prunes the dead broker
        // (CASCADE drops the holder); `try_restore_snapshot` then
        // hits the identity gate (path gone → file_id mismatch),
        // reports Missing, and KEEPS the row (fail-closed —
        // orphan tracking; the host surfaces it for the user to
        // resolve). The row is NOT silently reaped.
        with_mem_db(|db| {
            db.conn
                .execute(
                    "INSERT INTO brokers \
                     (pid, process_create_time, started_at) \
                     VALUES (999999, 1, 1)",
                    [],
                )
                .unwrap();
            db.conn
                .execute(
                    "INSERT INTO holders (canonical_path, pid) \
                     VALUES (?1, 999999)",
                    params![r"\\?\C:\srt-win-no-such-file"],
                )
                .unwrap();
            db.conn
                .execute(
                    "INSERT INTO acl_snapshots \
                     (canonical_path, is_dir, mask, original_sd, \
                      stamped_sd, file_id, parent_path, \
                      parent_stamp_failed) \
                     VALUES (?1, 0, 'read', x'01', x'02', ?2, NULL, 0)",
                    params![
                        r"\\?\C:\srt-win-no-such-file",
                        [0u8; 24].as_slice(),
                    ],
                )
                .unwrap();
            // PID 999999 with create_time 1 is dead.
            let rep = crash_recovery(&db.conn, false).unwrap();
            assert_eq!(rep.dead_brokers, 1);
            // Path gone → identity-gate mismatch → Missing
            // (locate_by_file_id on an all-zero file_id finds
            // nothing). Row KEPT (fail-closed).
            assert_eq!(rep.restored, 0);
            assert_eq!(rep.missing, 1);
            assert_eq!(rep.relocated, 0);
            assert_eq!(rep.left_changed, 0);
            // CASCADE dropped the holder; broker row gone; snapshot
            // row STAYS (orphan record).
            let h: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM holders", [], |r| r.get(0),
                )
                .unwrap();
            assert_eq!(h, 0);
            let s: i64 = db
                .conn
                .query_row(
                    "SELECT count(*) FROM acl_snapshots", [], |r| r.get(0),
                )
                .unwrap();
            assert_eq!(s, 1, "missing-file orphan row must be kept");
        });
    }

    /// `fence_fallback_paths`'s filter: only paths whose
    /// `parent_stamp_failed = 1` are returned. (Tested in-memory
    /// against the same SQL, since the real function goes through
    /// `open_db_ro` on the production DB path.)
    #[test]
    fn fence_fallback_filter() {
        with_mem_db(|db| {
            db.register_broker().unwrap();
            let mk = |p: &str, failed: bool| Snapshot {
                canonical_path: p.into(),
                is_dir: false,
                mask: AclMask::ReadDeny,
                original_sd: vec![1].into(),
                stamped_sd: None,
                file_id: acl::FileId { volume_serial: 0, id128: [0; 16] },
                parent_path: Some(r"\\?\C:\d".into()),
                parent_stamp_failed: failed,
            };
            db.insert_snapshot(&mk(r"\\?\C:\d\ok", false)).unwrap();
            db.insert_snapshot(&mk(r"\\?\C:\d\fail", true)).unwrap();
            db.add_holder(r"\\?\C:\d\ok").unwrap();
            db.add_holder(r"\\?\C:\d\fail").unwrap();
            // The filter SQL — same as in fence_fallback_paths.
            let rows: Vec<String> = db
                .conn
                .prepare(
                    "SELECT s.canonical_path FROM holders h \
                     JOIN acl_snapshots s \
                       ON h.canonical_path = s.canonical_path \
                     WHERE h.pid = ?1 AND s.parent_stamp_failed = 1",
                )
                .unwrap()
                .query_map(params![db.holder_pid.0 as i64], |r| r.get(0))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            assert_eq!(rows, vec![r"\\?\C:\d\fail".to_string()]);
            // set_parent_stamp_failed flips the flag.
            db.set_parent_stamp_failed(r"\\?\C:\d\ok").unwrap();
            assert!(
                db.get_snapshot(r"\\?\C:\d\ok")
                    .unwrap()
                    .unwrap()
                    .parent_stamp_failed
            );
        });
    }

    #[test]
    fn aliveness_self_is_alive() {
        let ct =
            process_create_time(unsafe { GetCurrentProcess() }).unwrap();
        assert!(is_process_alive(std::process::id(), ct));
        // Same PID, wrong create time would normally be "recycled →
        // dead", but we special-case ourselves.
        assert!(is_process_alive(std::process::id(), ct + 1));
    }

    #[test]
    fn aliveness_bogus_pid_is_dead() {
        // PID 0x7FFF_FFFE is well above any plausible live PID.
        assert!(!is_process_alive(0x7FFF_FFFE, 0));
    }
}
