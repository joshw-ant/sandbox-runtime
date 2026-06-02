//! ACL stamping for filesystem deny — `srt-win acl stamp|restore|recover`.
//!
//! `denyRead` / `denyWrite` paths get their DACL replaced with the
//! broker-only pattern (same shape as `self_protect.rs` applies to
//! the broker process, but file-flavoured):
//!
//! | mask        | ACEs (PROTECTED, in order)                          |
//! |-------------|-----------------------------------------------------|
//! | `ReadDeny`  | `<group>` FILE_ALL · SYSTEM FILE_ALL ·              |
//! |             | Admins FILE_ALL · OWNER_RIGHTS READ_CONTROL         |
//! | `WriteDeny` | as above + Everyone FILE_GENERIC_READ\|EXECUTE       |
//!
//! The OWNER_RIGHTS ACE is load-bearing — without it the sandbox
//! child (running as the same user that owns the file) would walk
//! through the DACL via the kernel's implicit owner
//! `READ_CONTROL|WRITE_DAC` grant. (READ_CONTROL not 0:
//! `SetNamedSecurityInfoW` silently drops a mask-0 ACE — see
//! [`OWNER_RIGHTS_MASK`].)
//!
//! Stamping captures the file's original SD (DACL+Owner+Group,
//! self-relative) so `restore` can put it back exactly. If every
//! ACE in the original was inherited, restore goes back to
//! "no explicit DACL, inheritance on" rather than persisting the
//! inherited ACEs as explicit ones.
//!
//! Directories and globs are **rejected**; the parent-directory
//! allow-list stamp protects an individual file's name, not the
//! directory's own contents.

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::c_void;
use std::mem::size_of;
use windows::Win32::Foundation::{
    INVALID_HANDLE_VALUE,
};
use windows::Win32::Security::Authorization::{
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    AclSizeInformation, AddAccessAllowedAce, AddAccessAllowedAceEx,
    AddAce, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    GetSecurityDescriptorGroup, GetSecurityDescriptorLength,
    GetSecurityDescriptorOwner, InitializeAcl, ACE_HEADER, ACL,
    ACL_REVISION, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE,
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileAttributesW, GetFinalPathNameByHandleW,
    FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
    GETFINALPATHNAMEBYHANDLE_FLAGS, INVALID_FILE_ATTRIBUTES,
    OPEN_EXISTING, VOLUME_NAME_DOS,
};

use crate::sid::LocalPsid;
use crate::util::{local_free, pcwstr, wstr};

/// Owner-Rights well-known SID. ANY ACE for this SID replaces
/// the kernel's implicit `READ_CONTROL|WRITE_DAC` grant to the
/// owner with exactly the ACE's mask.
pub const SID_OWNER_RIGHTS: &str = "S-1-3-4";

/// Mask for the `OWNER_RIGHTS` ACE in both broker-only DACLs.
/// `READ_CONTROL` only — suppresses owner-implicit `WRITE_DAC`
/// (so an owner-child cannot rewrite the DACL) while still
/// letting the owner read it. **The mask must be non-zero**:
/// `SetNamedSecurityInfoW` silently drops a mask-0 ALLOW ACE on
/// write, so the conceptually-purer `OWNER_RIGHTS:0` never
/// reaches disk. The presence of any `OWNER_RIGHTS` ACE is what
/// suppresses the implicit grant; granting `READ_CONTROL` is
/// harmless (the owner could read the DACL anyway via the group
/// ACE on the broker side, and on the child side the discipline
/// is `WRITE_DAC` denial, not DACL secrecy).
pub const OWNER_RIGHTS_MASK: u32 = 0x0002_0000; // READ_CONTROL
pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_BUILTIN_ADMINS: &str = "S-1-5-32-544";
pub const SID_EVERYONE: &str = "S-1-1-0";

/// Stamp shape. `ReadDeny` makes the file broker-only for ALL
/// access via the file's DACL; `WriteDeny` leaves read/execute open
/// to Everyone with content writes (and `WRITE_DAC`) broker-only.
///
/// Note: delete/rename is governed by the PARENT directory's
/// `FILE_DELETE_CHILD`, not the file's DACL — the file DACL alone
/// does NOT prevent it. So `acl stamp` ALSO stamps the file's
/// immediate parent directory with the allow-list from
/// [`build_parent_allow_list_dacl`] (user gets
/// Modify-without-FDC). When the parent can't be
/// stamped (no `WRITE_DAC` on it), the file falls back to the
/// per-exec no-`FILE_SHARE_DELETE` handle fence
/// ([`crate::fence`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMask {
    ReadDeny,
    WriteDeny,
}

impl AclMask {
    pub fn as_str(self) -> &'static str {
        match self {
            AclMask::ReadDeny => "read",
            AclMask::WriteDeny => "write",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "read" => Ok(AclMask::ReadDeny),
            "write" => Ok(AclMask::WriteDeny),
            other => bail!("unknown AclMask {other:?}"),
        }
    }

    /// True if applying `self`'s stamp would deny an access that
    /// `other`'s stamp permits (i.e. self is the stricter mask).
    /// Linear: `ReadDeny` (no Everyone-read ACE) is stricter than
    /// `WriteDeny` (which keeps `GENERIC_READ|EXECUTE`).
    pub fn is_stricter_than(self, other: AclMask) -> bool {
        matches!((self, other), (AclMask::ReadDeny, AclMask::WriteDeny))
    }
}

/// A captured self-relative security-descriptor blob. Cheap newtype
/// over `Vec<u8>` so the byte-offset / bit-mask reads live in one
/// place behind named methods rather than scattered through the
/// state machine. Storage (the SQLite BLOB column) round-trips via
/// `as_bytes()` / `From<Vec<u8>>`.
#[derive(Debug, Clone)]
pub struct CapturedSd(Vec<u8>);

impl CapturedSd {
    /// Borrow as bytes for storage / hashing.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The SD's `SECURITY_DESCRIPTOR_CONTROL` word (LE u16 at
    /// bytes 2–3 of the self-relative header).
    pub fn control(&self) -> u16 {
        if self.0.len() < 4 {
            return 0;
        }
        u16::from_le_bytes([self.0[2], self.0[3]])
    }

    /// Equivalent for our purposes — byte-equal with
    /// `SE_DACL_AUTO_INHERITED` (0x0400) and
    /// `SE_SACL_AUTO_INHERITED` (0x0800) masked out of `control()`.
    /// Those are OS-set markers stamped after auto-inherit
    /// evaluation (any UNPROTECTED `SetNamedSecurityInfoW`, a
    /// parent DACL change, `Set-Acl`, etc.); they don't affect
    /// access and the OS can flip them at any time, so the state
    /// machine's "has this SD changed since we stamped/captured
    /// it?" checks must treat them as noise.
    pub fn equiv(&self, other: &CapturedSd) -> bool {
        const AI: u16 = 0x0C00;
        if self.0.len() != other.0.len() || self.0.len() < 4 {
            return self.0 == other.0;
        }
        (self.control() & !AI) == (other.control() & !AI)
            && self.0[..2] == other.0[..2]
            && self.0[4..] == other.0[4..]
    }
}

impl From<Vec<u8>> for CapturedSd {
    fn from(v: Vec<u8>) -> Self {
        CapturedSd(v)
    }
}

/// Result of `stamp_file_apply` — the kernel-canonical SD after the
/// stamp landed, used by `restore` / recovery to detect "someone
/// else changed it since we stamped". The ORIGINAL SD is captured
/// separately by the caller (via `capture_sd`) BEFORE the FS
/// mutation so it can be persisted to the state DB first — see the
/// ordering invariant in `state_db`'s module doc.
pub struct StampResult {
    pub stamped_sd: CapturedSd,
}

/// Resolve `path` to its kernel-canonical form via
/// `GetFinalPathNameByHandleW` (handles symlinks, junctions, 8.3
/// short names, drive-letter case). Returns the `\\?\`-prefixed
/// path and whether it's a directory.
///
/// `state_db.rs` uses the canonical path as the DB key so a stamp
/// via two equivalent paths (e.g. `C:\PROGRA~1\…` and
/// `C:\Program Files\…`) refcounts correctly.
pub fn canonicalize_path(path: &str) -> Result<(String, bool)> {
    // Glob check on the INPUT, ignoring the `\\?\` extended-path
    // prefix (its `?` is not a wildcard). Without the strip,
    // canonicalize_path would reject its OWN output (which always
    // carries the prefix).
    let glob_in = path.strip_prefix(r"\\?\").unwrap_or(path);
    if glob_in.contains('*') || glob_in.contains('?') {
        bail!(
            "Windows fs deny requires explicit file or directory paths; \
             got glob '{path}'"
        );
    }
    let w = wstr(path);
    // Open without requesting any data access so we don't need read
    // permission on the target. `BACKUP_SEMANTICS` lets directories
    // open too (we need the handle to query the canonical name even
    // though dirs are currently rejected by the caller).
    let h = unsafe {
        CreateFileW(
            pcwstr(&w),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .with_context(|| format!("open '{path}' for canonicalization"))?;
    if h == INVALID_HANDLE_VALUE {
        bail!("CreateFileW('{path}'): INVALID_HANDLE_VALUE");
    }
    // Guard the handle so an error below doesn't leak it.
    let _h = crate::util::OwnedHandle(h);

    // Two-call sizing pattern.
    let need = unsafe {
        GetFinalPathNameByHandleW(
            h, &mut [], GETFINALPATHNAMEBYHANDLE_FLAGS(
                FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0,
            ),
        )
    };
    if need == 0 {
        bail!(
            "GetFinalPathNameByHandleW('{path}') sizing: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut buf = vec![0u16; need as usize + 1];
    let n = unsafe {
        GetFinalPathNameByHandleW(
            h, &mut buf, GETFINALPATHNAMEBYHANDLE_FLAGS(
                FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0,
            ),
        )
    };
    if n == 0 || n as usize >= buf.len() {
        bail!(
            "GetFinalPathNameByHandleW('{path}'): {}",
            std::io::Error::last_os_error()
        );
    }
    buf.truncate(n as usize);
    let canonical = String::from_utf16_lossy(&buf);

    // Directory check on the CANONICAL path so a symlink-to-dir is
    // detected.
    let cw = wstr(&canonical);
    let attrs = unsafe { GetFileAttributesW(pcwstr(&cw)) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        bail!(
            "GetFileAttributesW('{canonical}'): {}",
            std::io::Error::last_os_error()
        );
    }
    let is_dir = attrs & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    Ok((canonical, is_dir))
}

/// Capture DACL+Owner+Group as a self-relative SD blob suitable for
/// storage and round-tripping into `restore_sd`.
pub fn capture_sd(canonical_path: &str) -> Result<CapturedSd> {
    let w = wstr(canonical_path);
    let info = DACL_SECURITY_INFORMATION
        | OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION;
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        let r = GetNamedSecurityInfoW(
            pcwstr(&w),
            SE_FILE_OBJECT,
            info,
            None,
            None,
            None,
            None,
            &mut psd,
        );
        if r.is_err() {
            bail!(
                "GetNamedSecurityInfoW('{canonical_path}'): WIN32_ERROR=0x{:08x}",
                r.0
            );
        }
    }
    // The returned SD is documented self-relative; copy it out so we
    // own the bytes.
    let len = unsafe { GetSecurityDescriptorLength(psd) } as usize;
    if len == 0 {
        local_free(psd.0);
        bail!("GetSecurityDescriptorLength('{canonical_path}') == 0");
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(psd.0 as *const u8, len).to_vec()
    };
    local_free(psd.0);
    Ok(CapturedSd(bytes))
}

/// Restore from a previously-captured SD blob, bit-exact wrt the
/// DACL-protected state:
///
/// - Purely-inherited original (every ACE `INHERITED_ACE`): restore
///   by clearing the explicit DACL with `UNPROTECTED` so the kernel
///   re-derives from the parent. Round-tripping the inherited ACEs
///   would persist them as explicit and decouple the file from
///   future parent-DACL changes.
/// - Original had ≥1 explicit ACE: round-trip the captured DACL and
///   set `PROTECTED` vs `UNPROTECTED` to match the original's
///   `SE_DACL_PROTECTED` control bit (read from the captured SD).
///   Our stamp always sets `PROTECTED`; without restoring the
///   original protected-state, an originally-unprotected file would
///   come back protected and stop auto-inheriting.
pub fn restore_sd(canonical_path: &str, sd: &CapturedSd) -> Result<()> {
    let sd_bytes = sd.as_bytes();
    if sd_bytes.is_empty() {
        bail!("restore_sd('{canonical_path}'): empty SD bytes");
    }
    let psd = PSECURITY_DESCRIPTOR(sd_bytes.as_ptr() as *mut c_void);
    let mut present = windows::core::BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut defaulted = windows::core::BOOL(0);
    let mut owner = PSID::default();
    let mut owner_def = windows::core::BOOL(0);
    let mut group = PSID::default();
    let mut group_def = windows::core::BOOL(0);
    unsafe {
        GetSecurityDescriptorDacl(psd, &mut present, &mut dacl, &mut defaulted)
            .map_err(|e| anyhow!("GetSecurityDescriptorDacl(restore): {e}"))?;
        let _ = GetSecurityDescriptorOwner(psd, &mut owner, &mut owner_def);
        let _ = GetSecurityDescriptorGroup(psd, &mut group, &mut group_def);

        // Read the original's DACL-protected control bit. The
        // windows-0.62 binding types `pcontrol` as `*mut u16`
        // (raw `SECURITY_DESCRIPTOR_CONTROL` value), so compare
        // against `SE_DACL_PROTECTED.0`.
        let mut control: u16 = 0;
        let mut rev = 0u32;
        let was_protected =
            GetSecurityDescriptorControl(psd, &mut control, &mut rev)
                .is_ok()
                && (control & SE_DACL_PROTECTED.0) != 0;

        let mut info = DACL_SECURITY_INFORMATION;
        if !owner.0.is_null() {
            info |= OWNER_SECURITY_INFORMATION;
        }
        if !group.0.is_null() {
            info |= GROUP_SECURITY_INFORMATION;
        }

        // Restore bit-exact wrt the protected-state:
        //
        // - NULL DACL → restore NULL (everyone full access) with
        //   UNPROTECTED. Our stamp set PROTECTED, and
        //   `SetNamedSecurityInfoW` leaves the bit unchanged when
        //   neither flag is given; a true NULL-DACL original is by
        //   construction unprotected (a protected break would have
        //   left an explicit empty ACL, not NULL), so UNPROTECTED
        //   re-couples it to its parent.
        // - Original PROTECTED → a protected DACL has no
        //   INHERITED_ACE ACEs (breaking inheritance copies them to
        //   explicit), so round-trip the whole captured DACL with
        //   PROTECTED.
        // - Original UNPROTECTED → pass ONLY the explicit
        //   (non-INHERITED_ACE) ACEs with UNPROTECTED and let the
        //   kernel re-inherit the rest. Passing the captured
        //   inherited ACEs back verbatim would duplicate them
        //   (our explicit copies + freshly-inherited ones). When
        //   the original was purely inherited this yields an empty
        //   explicit ACL — exactly "no explicit DACL, inheritance
        //   on".
        let explicit_only;
        let dacl_arg: Option<*const ACL> =
            if !present.as_bool() || dacl.is_null() {
                info |= UNPROTECTED_DACL_SECURITY_INFORMATION;
                None
            } else if was_protected {
                info |= PROTECTED_DACL_SECURITY_INFORMATION;
                Some(dacl as *const ACL)
            } else {
                explicit_only = build_explicit_only_acl(dacl)?;
                info |= UNPROTECTED_DACL_SECURITY_INFORMATION;
                Some(explicit_only.as_ptr() as *const ACL)
            };

        let w = wstr(canonical_path);
        let r = SetNamedSecurityInfoW(
            pcwstr(&w),
            SE_FILE_OBJECT,
            info,
            if owner.0.is_null() { None } else { Some(owner) },
            if group.0.is_null() { None } else { Some(group) },
            dacl_arg,
            None,
        );
        if r.is_err() {
            bail!(
                "SetNamedSecurityInfoW(restore '{canonical_path}'): \
                 WIN32_ERROR=0x{:08x}",
                r.0
            );
        }
    }
    Ok(())
}

/// Build the broker-only DACL for the given mask. Returns
/// `(buf, sids)` where `buf` is the heap-owned ACL and `sids` is the
/// set of `LocalPsid`s the ACL points into — caller must keep them
/// alive until after `SetNamedSecurityInfoW` (the kernel copies the
/// ACL on apply, so the buffer can drop immediately afterwards).
///
/// `inherit` adds `(OI)(CI)` to every ACE — used for stamping the
/// state-DB directory and, once supported, directory targets.
pub fn build_broker_only_dacl(
    group_sid: &str,
    mask: AclMask,
    inherit: bool,
) -> Result<(Vec<u8>, Vec<LocalPsid>)> {
    let group = LocalPsid::from_string(group_sid)
        .with_context(|| format!("parse group SID '{group_sid}'"))?;
    let system = LocalPsid::from_string(SID_SYSTEM)?;
    let admins = LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
    let owner_rights = LocalPsid::from_string(SID_OWNER_RIGHTS)?;

    // (sid, mask). `<group>`/SYSTEM/Admins get FILE_ALL_ACCESS;
    // OWNER_RIGHTS gets READ_CONTROL only (see OWNER_RIGHTS_MASK
    // for why not 0). CI passes group_sid == Admins; dedup so we
    // don't write a redundant ACE.
    let mut entries: Vec<(PSID, u32)> = vec![
        (group.as_psid(), FILE_ALL_ACCESS.0),
        (system.as_psid(), FILE_ALL_ACCESS.0),
    ];
    let mut sids = vec![group, system, owner_rights];
    if !group_sid.eq_ignore_ascii_case(SID_BUILTIN_ADMINS) {
        entries.push((admins.as_psid(), FILE_ALL_ACCESS.0));
        sids.push(admins);
    } else {
        // Drop unused parsed SID promptly.
        drop(admins);
    }
    // OWNER_RIGHTS — load-bearing: suppresses owner-implicit
    // WRITE_DAC.
    entries.push((sids[2].as_psid(), OWNER_RIGHTS_MASK));

    // WriteDeny: leave read+execute open to Everyone so the file is
    // still readable / runnable by the sandboxed child; only
    // write/delete/WRITE_DAC are broker-only (because they aren't
    // granted to anyone except the three above).
    if mask == AclMask::WriteDeny {
        let everyone = LocalPsid::from_string(SID_EVERYONE)?;
        entries.push((
            everyone.as_psid(),
            FILE_GENERIC_READ.0 | FILE_GENERIC_EXECUTE.0,
        ));
        sids.push(everyone);
    }

    // ACL header + Σ ACE size. ACCESS_ALLOWED_ACE fixed prefix is 8
    // bytes (Header 4 + Mask 4); `SidStart` is the first DWORD of the
    // SID, so total per-ACE = 8 + GetLengthSid.
    const ACE_FIXED: usize = 8;
    let mut total = size_of::<ACL>();
    for (s, _) in &entries {
        let len = unsafe { GetLengthSid(*s) } as usize;
        if len == 0 {
            bail!("GetLengthSid returned 0");
        }
        total += ACE_FIXED + len;
    }
    total = (total + 3) & !3; // DWORD-align

    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    let flags = if inherit {
        CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE
    } else {
        windows::Win32::Security::ACE_FLAGS(0)
    };
    unsafe {
        InitializeAcl(acl, total as u32, ACL_REVISION)
            .context("InitializeAcl(broker-only DACL)")?;
        for (s, m) in &entries {
            if inherit {
                AddAccessAllowedAceEx(acl, ACL_REVISION, flags, *m, *s)
                    .context("AddAccessAllowedAceEx")?;
            } else {
                AddAccessAllowedAce(acl, ACL_REVISION, *m, *s)
                    .context("AddAccessAllowedAce")?;
            }
        }
    }
    Ok((buf, sids))
}

/// A built DACL ready to apply to one or more paths. Build once
/// per `(mask, inherit)` and reuse across the stamp loop — the
/// SID-parse syscalls inside [`build_broker_only_dacl`] are then
/// done once instead of once per file.
pub struct BrokerDacl {
    acl_buf: Vec<u8>,
    /// Kept alive: the ACL bytes in `acl_buf` point into these.
    _sids: Vec<LocalPsid>,
}

impl BrokerDacl {
    pub fn build(
        group_sid: &str,
        mask: AclMask,
        inherit: bool,
    ) -> Result<Self> {
        let (acl_buf, sids) =
            build_broker_only_dacl(group_sid, mask, inherit)?;
        Ok(Self { acl_buf, _sids: sids })
    }
}

/// Apply a pre-built broker-only DACL to a file and read back the
/// kernel-canonical form. The ORIGINAL SD must already have been
/// captured (and recorded in the state DB) by the caller BEFORE
/// this is called — see the ordering invariant in `state_db`'s
/// module doc. Used both for first-time stamping and for mask
/// escalation (a stricter stamper re-applying with a tighter mask;
/// `original_sd` is unchanged in that case).
pub fn stamp_file_apply(
    canonical_path: &str,
    dacl: &BrokerDacl,
) -> Result<StampResult> {
    apply_broker_only(canonical_path, dacl)?;
    // Read back the canonical form the kernel settled on — this is
    // what `restore` will compare against to detect "someone else
    // changed it since we stamped".
    let stamped_sd = capture_sd(canonical_path)
        .with_context(|| format!("capture stamped SD for '{canonical_path}'"))?;
    Ok(StampResult { stamped_sd })
}

/// Apply the broker-only DACL to a directory with `(OI)(CI)`
/// inheritance. Used by `state_db.rs` to protect
/// `%LOCALAPPDATA%\sandbox-runtime\`. NOT exposed to the CLI —
/// directory targets in `acl stamp` are not yet supported.
pub fn stamp_dir_inheriting(
    canonical_path: &str,
    group_sid: &str,
) -> Result<()> {
    let dacl = BrokerDacl::build(group_sid, AclMask::ReadDeny, true)?;
    apply_broker_only(canonical_path, &dacl)
}

/// `FileSystemRights.Modify` MINUS `FILE_DELETE_CHILD`. Granted
/// to the user SID on a stamped parent directory so the
/// sandboxed child (which shares the user SID with the broker)
/// can still create/write/read/delete non-protected siblings
/// (`DELETE 0x10000` is in there) but cannot delete or
/// rename-over a child of the directory via the parent's
/// `FILE_DELETE_CHILD` — and the protected file's broker-only
/// DACL withholds file-level `DELETE`, so the child has no path
/// to delete/rename it. The broker keeps both via `<group>:FA`.
///
/// Decomposition (the unit test below asserts this so a digit
/// shift cannot recur silently):
///   `0x00100000` SYNCHRONIZE
///   `0x00020000` READ_CONTROL
///   `0x00010000` DELETE                ← the load-bearing bit
///   `0x000001bf` file-specific Modify minus
///                `FILE_DELETE_CHILD (0x40)`
pub const MODIFY_NO_FDC: u32 = 0x0013_01bf;

/// Build the parent-directory allow-list DACL: `PROTECTED`,
/// SYSTEM/Admins/`<group>`: `(OI)(CI)` `FILE_ALL`; `<user>`:
/// `(OI)(CI)` [`MODIFY_NO_FDC`]; `OWNER_RIGHTS`:
/// [`OWNER_RIGHTS_MASK`] (no inherit — applies to the directory
/// itself only, so non-protected children keep implicit owner
/// rights). The `OWNER_RIGHTS` ACE is mandatory: without it an
/// owner-child gets implicit `READ_CONTROL|WRITE_DAC`, can
/// rewrite the directory's DACL, and re-grant itself
/// `FILE_DELETE_CHILD`.
///
/// No DENY ACEs: a deny-only group SID still matches DENY ACEs,
/// so a DENY against the child would also hit the broker —
/// discrimination is via ALLOW + absence-of-grant only.
pub fn build_parent_allow_list_dacl(
    group_sid: &str,
    user_sid: &str,
) -> Result<(Vec<u8>, Vec<LocalPsid>)> {
    let group = LocalPsid::from_string(group_sid)
        .with_context(|| format!("parse group SID '{group_sid}'"))?;
    let user = LocalPsid::from_string(user_sid)
        .with_context(|| format!("parse user SID '{user_sid}'"))?;
    let system = LocalPsid::from_string(SID_SYSTEM)?;
    let admins = LocalPsid::from_string(SID_BUILTIN_ADMINS)?;
    let owner_rights = LocalPsid::from_string(SID_OWNER_RIGHTS)?;

    let oici = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE;
    let no_inherit = windows::Win32::Security::ACE_FLAGS(0);

    // (sid, mask, flags). OWNER_RIGHTS is non-inheriting: it
    // guards the directory itself; non-protected children keep
    // their implicit owner rights.
    let mut entries: Vec<(PSID, u32, _)> = vec![
        (system.as_psid(), FILE_ALL_ACCESS.0, oici),
        (group.as_psid(), FILE_ALL_ACCESS.0, oici),
    ];
    let mut sids = vec![system, group, user, owner_rights];
    if !group_sid.eq_ignore_ascii_case(SID_BUILTIN_ADMINS) {
        entries.push((admins.as_psid(), FILE_ALL_ACCESS.0, oici));
        sids.push(admins);
    } else {
        drop(admins);
    }
    entries.push((sids[2].as_psid(), MODIFY_NO_FDC, oici));
    entries.push((sids[3].as_psid(), OWNER_RIGHTS_MASK, no_inherit));

    const ACE_FIXED: usize = 8;
    let mut total = size_of::<ACL>();
    for (s, _, _) in &entries {
        let len = unsafe { GetLengthSid(*s) } as usize;
        if len == 0 {
            bail!("GetLengthSid returned 0");
        }
        total += ACE_FIXED + len;
    }
    total = (total + 3) & !3;

    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    unsafe {
        InitializeAcl(acl, total as u32, ACL_REVISION)
            .context("InitializeAcl(parent allow-list)")?;
        for (s, m, fl) in &entries {
            AddAccessAllowedAceEx(acl, ACL_REVISION, *fl, *m, *s)
                .context("AddAccessAllowedAceEx(parent)")?;
        }
    }
    Ok((buf, sids))
}

/// Apply the parent allow-list DACL (`PROTECTED`) to a parent
/// directory and read back the kernel-canonical stamped SD.
/// The caller captures (and persists) the ORIGINAL SD separately
/// BEFORE calling this — same record-first ordering invariant as
/// file stamps.
pub fn apply_parent_allow_list(
    canonical_parent_path: &str,
    group_sid: &str,
    user_sid: &str,
) -> Result<CapturedSd> {
    let (buf, _sids) =
        build_parent_allow_list_dacl(group_sid, user_sid)?;
    let w = wstr(canonical_parent_path);
    let r = unsafe {
        SetNamedSecurityInfoW(
            pcwstr(&w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(buf.as_ptr() as *const ACL),
            None,
        )
    };
    if r.is_err() {
        bail!(
            "SetNamedSecurityInfoW(parent allow-list \
             '{canonical_parent_path}'): WIN32_ERROR=0x{:08x}",
            r.0
        );
    }
    capture_sd(canonical_parent_path).with_context(|| {
        format!("capture stamped SD for parent '{canonical_parent_path}'")
    })
}

/// Immediate parent of a `\\?\…` canonical path, as a string.
/// Returns `None` for a root (no parent).
pub fn canonical_parent_of(canonical_path: &str) -> Option<String> {
    std::path::Path::new(canonical_path)
        .parent()
        .map(|p| p.display().to_string())
        .filter(|s| !s.is_empty())
}

// ─── File identity (FILE_ID_INFO) ───────────────────────────────────

/// A file's stable identity on a volume — the
/// `(VolumeSerialNumber, FileId128)` pair from `FILE_ID_INFO`. On
/// NTFS this is the MFT record identity, so it survives rename
/// and lets us both VALIDATE at restore time (the path still
/// resolves to the same file we stamped) and LOCATE a relocated
/// file for reporting. Stored as a 24-byte blob (8 + 16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub volume_serial: u64,
    pub id128: [u8; 16],
}

impl FileId {
    pub fn as_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        out[..8].copy_from_slice(&self.volume_serial.to_le_bytes());
        out[8..].copy_from_slice(&self.id128);
        out
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 24 {
            bail!("FileId::from_bytes: expected 24 bytes, got {}", b.len());
        }
        let mut vs = [0u8; 8];
        vs.copy_from_slice(&b[..8]);
        let mut id = [0u8; 16];
        id.copy_from_slice(&b[8..]);
        Ok(Self { volume_serial: u64::from_le_bytes(vs), id128: id })
    }
    pub fn to_hex(&self) -> String {
        let b = self.as_bytes();
        let mut s = String::with_capacity(48);
        for x in b {
            s.push_str(&format!("{x:02x}"));
        }
        s
    }
}

/// Read the `FILE_ID_INFO` of `canonical_path`. Opens with no data
/// access (just identity query), so the broker-only DACL on the
/// file does not interfere.
pub fn capture_file_id(canonical_path: &str) -> Result<FileId> {
    use windows::Win32::Storage::FileSystem::{
        GetFileInformationByHandleEx, FileIdInfo, FILE_ID_INFO,
    };
    let w = wstr(canonical_path);
    let h = unsafe {
        CreateFileW(
            pcwstr(&w),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .with_context(|| format!("open '{canonical_path}' for file_id"))?;
    let h = crate::util::OwnedHandle(h);
    let mut info = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            h.raw(),
            FileIdInfo,
            (&mut info as *mut FILE_ID_INFO).cast(),
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
        .with_context(|| {
            format!("GetFileInformationByHandleEx(FileIdInfo) '{canonical_path}'")
        })?;
    }
    Ok(FileId {
        volume_serial: info.VolumeSerialNumber,
        id128: info.FileId.Identifier,
    })
}

/// Best-effort: locate the CURRENT path of a file by its captured
/// `(volume_serial, file_id)`. Opens the volume root (`\\?\X:\`),
/// `OpenFileById` with an `ExtendedFileId` descriptor, then
/// `GetFinalPathNameByHandleW`. Returns `None` if the file was
/// deleted or the open fails for any reason. Used ONLY for
/// reporting `movedTo` — restore is path-anchored and never
/// relocates by inode (chasing the file by ID to remove its stamp
/// would re-expose a relocated secret).
pub fn locate_by_file_id(file_id: &FileId) -> Option<String> {
    use windows::Win32::Storage::FileSystem::{
        OpenFileById, ExtendedFileIdType, FILE_ID_128,
        FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0,
    };
    // Open the volume root the file lived on. We need a handle ON
    // the volume to anchor OpenFileById; the captured volume
    // serial doesn't directly map to a drive letter, so try each
    // mounted local drive and match the serial — keeping the
    // locate volume-keyed (a moved file may not be on the drive
    // its canonical_path was recorded under).
    for drive in b'A'..=b'Z' {
        let root = format!(r"\\?\{}:\", drive as char);
        let w = wstr(&root);
        let vh = match unsafe {
            CreateFileW(
                pcwstr(&w),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            )
        } {
            Ok(h) => crate::util::OwnedHandle(h),
            Err(_) => continue,
        };
        // Match the volume by reading FILE_ID_INFO of the root.
        if let Ok(root_id) = capture_file_id(&root) {
            if root_id.volume_serial != file_id.volume_serial {
                continue;
            }
        } else {
            continue;
        }
        let desc = FILE_ID_DESCRIPTOR {
            dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: ExtendedFileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                ExtendedFileId: FILE_ID_128 {
                    Identifier: file_id.id128,
                },
            },
        };
        let fh = match unsafe {
            OpenFileById(
                vh.raw(),
                &desc,
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                None,
                FILE_FLAG_BACKUP_SEMANTICS,
            )
        } {
            Ok(h) => crate::util::OwnedHandle(h),
            Err(_) => return None,
        };
        // Two-call sizing.
        let need = unsafe {
            GetFinalPathNameByHandleW(
                fh.raw(),
                &mut [],
                GETFINALPATHNAMEBYHANDLE_FLAGS(
                    FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0,
                ),
            )
        };
        if need == 0 {
            return None;
        }
        let mut buf = vec![0u16; need as usize + 1];
        let got = unsafe {
            GetFinalPathNameByHandleW(
                fh.raw(),
                &mut buf,
                GETFINALPATHNAMEBYHANDLE_FLAGS(
                    FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0,
                ),
            )
        };
        if got == 0 || got as usize > buf.len() {
            return None;
        }
        return Some(String::from_utf16_lossy(&buf[..got as usize]));
    }
    None
}

fn apply_broker_only(canonical_path: &str, dacl: &BrokerDacl) -> Result<()> {
    let w = wstr(canonical_path);
    let r = unsafe {
        SetNamedSecurityInfoW(
            pcwstr(&w),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl.acl_buf.as_ptr() as *const ACL),
            None,
        )
    };
    if r.is_err() {
        bail!(
            "SetNamedSecurityInfoW(stamp '{canonical_path}'): \
             WIN32_ERROR=0x{:08x}",
            r.0
        );
    }
    Ok(())
}

const INHERITED_ACE: u8 = 0x10;

/// Build a fresh ACL containing only the EXPLICIT (non-`INHERITED_ACE`)
/// ACEs of `src`, preserving their order and bytes. Used by
/// `restore_sd` when the original was unprotected: we pass these as
/// the explicit DACL with `UNPROTECTED` and the kernel re-derives the
/// inherited ACEs. If `src` is purely inherited the result is an
/// empty ACL ("no explicit DACL").
unsafe fn build_explicit_only_acl(src: *mut ACL) -> Result<Vec<u8>> {
    let mut info = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            src,
            &mut info as *mut _ as *mut c_void,
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
        .context("GetAclInformation(src)")?;
    }
    // Collect explicit ACEs (pointer + byte size).
    let mut explicit: Vec<(*const c_void, u16)> = Vec::new();
    let mut total = size_of::<ACL>();
    for i in 0..info.AceCount {
        let mut ace: *mut c_void = std::ptr::null_mut();
        unsafe { GetAce(src, i, &mut ace) }
            .map_err(|e| anyhow!("GetAce({i}): {e}"))?;
        if ace.is_null() {
            bail!("GetAce({i}) returned null");
        }
        let hdr = ace as *const ACE_HEADER;
        let flags = unsafe { (*hdr).AceFlags };
        if flags & INHERITED_ACE != 0 {
            continue; // skip inherited; kernel re-adds them
        }
        let sz = unsafe { (*hdr).AceSize };
        explicit.push((ace as *const c_void, sz));
        total += sz as usize;
    }
    total = (total + 3) & !3; // DWORD-align
    let mut buf = vec![0u8; total];
    let acl = buf.as_mut_ptr() as *mut ACL;
    unsafe {
        InitializeAcl(acl, total as u32, ACL_REVISION)
            .context("InitializeAcl(explicit-only)")?;
        for (ace, sz) in explicit {
            // u32::MAX appends; copy the raw ACE bytes verbatim.
            AddAce(acl, ACL_REVISION, u32::MAX, ace, sz as u32)
                .context("AddAce(explicit)")?;
        }
    }
    Ok(buf)
}

/// SDDL for a SECURITY_ATTRIBUTES that grants `<group>`/SYSTEM/Admins
/// full access only — used for the named init-mutex so the sandbox
/// child cannot open it (and therefore cannot stall stamps by
/// holding the mutex). DACL-only (no `O:`/`G:`): an explicit owner
/// SID at object creation goes through `SeAssignSecurity`, which
/// rejects any owner that isn't the caller's user / an
/// `SE_GROUP_OWNER` group / a `SeRestorePrivilege`-enabled token
/// (`ERROR_INVALID_OWNER`); leaving them unset defaults owner/group
/// to the caller.
pub fn sddl_broker_only_object(group_sid: &str) -> String {
    // OWNER_RIGHTS:READ_CONTROL — same as the file/parent stamps:
    // suppresses owner-implicit WRITE_DAC. (This SDDL goes
    // through `CreateMutexExW`/`SeAssignSecurity`, not
    // `SetNamedSecurityInfoW`, so a mask-0 ACE wouldn't be
    // dropped here; READ_CONTROL is used for consistency.)
    let ow = format!("(A;;0x{OWNER_RIGHTS_MASK:x};;;OW)");
    if group_sid.eq_ignore_ascii_case(SID_BUILTIN_ADMINS) {
        // Dedup the Admins ACE.
        format!("D:P(A;;GA;;;{group_sid})(A;;GA;;;SY){ow}")
    } else {
        format!("D:P(A;;GA;;;{group_sid})(A;;GA;;;SY)(A;;GA;;;BA){ow}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_only_dacl_builds() {
        for mask in [AclMask::ReadDeny, AclMask::WriteDeny] {
            for inherit in [false, true] {
                let (buf, _s) = build_broker_only_dacl(
                    "S-1-5-32-545", // BUILTIN\Users — any valid SID
                    mask,
                    inherit,
                )
                .expect("build");
                // ACL revision is byte 0; should be 2.
                assert_eq!(buf[0], 2, "{mask:?} inherit={inherit}");
                assert!(buf.len() >= size_of::<ACL>());
            }
        }
    }

    #[test]
    fn broker_only_dacl_dedups_admins() {
        // group == Admins → 3 ACEs (group/SYSTEM/OWNER_RIGHTS), not 4.
        let (with, _s1) =
            build_broker_only_dacl(SID_BUILTIN_ADMINS, AclMask::ReadDeny, false)
                .unwrap();
        let (without, _s2) =
            build_broker_only_dacl("S-1-5-32-545", AclMask::ReadDeny, false)
                .unwrap();
        assert!(with.len() < without.len());
    }

    #[test]
    fn aclmask_round_trip() {
        for m in [AclMask::ReadDeny, AclMask::WriteDeny] {
            assert_eq!(AclMask::parse(m.as_str()).unwrap(), m);
        }
        assert!(AclMask::parse("nope").is_err());
    }

    #[test]
    fn canonicalize_rejects_globs() {
        for p in ["C:\\foo\\*.txt", "C:\\foo\\bar?.txt"] {
            let e = canonicalize_path(p).unwrap_err().to_string();
            assert!(e.contains("got glob"), "{p}: {e}");
        }
    }

    #[test]
    fn canonicalize_round_trip_self() {
        // The test binary's own path is a real file we definitely
        // can open.
        let exe = std::env::current_exe().unwrap();
        let (canon, is_dir) =
            canonicalize_path(&exe.display().to_string()).unwrap();
        assert!(canon.starts_with(r"\\?\"), "got {canon}");
        assert!(!is_dir);
        // Round-trip: canonicalizing the canonical path is a no-op.
        let (again, _) = canonicalize_path(&canon).unwrap();
        assert_eq!(canon, again);
    }

    #[test]
    fn sddl_broker_only_parses() {
        use crate::util::OwnedSd;
        for g in [SID_BUILTIN_ADMINS, "S-1-5-21-1-2-3-1004"] {
            let sddl = sddl_broker_only_object(g);
            let _ = OwnedSd::from_sddl(&sddl)
                .unwrap_or_else(|e| panic!("{sddl}: {e:#}"));
        }
    }

    #[test]
    fn capture_restore_round_trip() {
        // Pick a temp file; capture, restore, capture again — the
        // two captures should be byte-identical (we never stamped,
        // so restore is a no-op-of-the-same-bytes). Skip if the
        // host denies SetNamedSecurityInfoW (non-admin without
        // SeRestorePrivilege on someone else's file) — the temp
        // dir is user-owned so this should pass even non-elevated.
        let tmp = std::env::temp_dir().join(format!(
            "srt-win-acl-rt-{}.tmp",
            std::process::id()
        ));
        std::fs::write(&tmp, b"x").unwrap();
        let (canon, _) =
            canonicalize_path(&tmp.display().to_string()).unwrap();
        let before = capture_sd(&canon).unwrap();
        if let Err(e) = restore_sd(&canon, &before) {
            eprintln!("skipping capture_restore_round_trip: {e}");
            let _ = std::fs::remove_file(&tmp);
            return;
        }
        let after = capture_sd(&canon).unwrap();
        let _ = std::fs::remove_file(&tmp);
        // CapturedSd::equiv masks the OS-set AUTO_INHERITED marker
        // bits.
        assert!(
            before.equiv(&after),
            "before/after differ beyond the AI bits:\n  {:02x?}\n  {:02x?}",
            before.as_bytes(),
            after.as_bytes()
        );
    }

    /// `MODIFY_NO_FDC` carries the exact bits the parent
    /// allow-list depends on. Guards against a hex digit shift
    /// (e.g. `0x0130_01bf` vs `0x0013_01bf`) silently dropping
    /// DELETE/READ_CONTROL.
    #[test]
    fn modify_no_fdc_bits() {
        const DELETE: u32 = 0x0001_0000;
        const READ_CONTROL: u32 = 0x0002_0000;
        const SYNCHRONIZE: u32 = 0x0010_0000;
        const FILE_DELETE_CHILD: u32 = 0x40;
        assert_eq!(MODIFY_NO_FDC, 0x1301bf);
        assert_ne!(MODIFY_NO_FDC & DELETE, 0, "must carry DELETE");
        assert_ne!(MODIFY_NO_FDC & READ_CONTROL, 0, "must carry READ_CONTROL");
        assert_ne!(MODIFY_NO_FDC & SYNCHRONIZE, 0, "must carry SYNCHRONIZE");
        assert_eq!(
            MODIFY_NO_FDC & FILE_DELETE_CHILD, 0,
            "must NOT carry FILE_DELETE_CHILD"
        );
        // No bits above SYNCHRONIZE (0x00100000): anything in
        // 0xff000000 / bits 21-23 is meaningless on a file ACE
        // and indicates a digit shift.
        assert_eq!(MODIFY_NO_FDC & 0xffe0_0000, 0, "stray high bits");
    }

    /// `OWNER_RIGHTS_MASK` excludes WRITE_DAC (the whole point)
    /// and is non-zero (so SetNamedSecurityInfoW doesn't drop it).
    #[test]
    fn owner_rights_mask_bits() {
        const WRITE_DAC: u32 = 0x0004_0000;
        assert_ne!(OWNER_RIGHTS_MASK, 0, "must be non-zero");
        assert_eq!(
            OWNER_RIGHTS_MASK & WRITE_DAC, 0,
            "must NOT grant WRITE_DAC"
        );
    }

    /// `build_parent_allow_list_dacl` includes the
    /// `OWNER_RIGHTS` ACE. Regression: the SDDL → DACL path
    /// silently dropped a mask-0 ACE; this builder is
    /// programmatic so it must not.
    #[test]
    fn parent_allow_list_dacl_builds_with_owner_rights() {
        for (group, want_aces) in [
            // group == Admins → BA dedup → 4 ACEs.
            (SID_BUILTIN_ADMINS, 4u16),
            // group ≠ Admins → 5 ACEs.
            ("S-1-5-21-1-2-3-1003", 5),
        ] {
            let (buf, _s) =
                build_parent_allow_list_dacl(group, "S-1-5-21-1-2-3-1000")
                    .expect("build");
            // ACL.AceCount is bytes 4–5 (LE u16).
            let ace_count = u16::from_le_bytes([buf[4], buf[5]]);
            assert_eq!(ace_count, want_aces, "group={group}");
            // S-1-3-4 (OWNER_RIGHTS) in binary: rev=01
            // subauth-count=01 idauth=000000000003
            // subauth[0]=04000000.
            const OW: [u8; 12] = [
                0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x04, 0x00,
                0x00, 0x00,
            ];
            assert!(
                buf.windows(OW.len()).any(|w| w == OW),
                "OWNER_RIGHTS SID missing from parent DACL bytes \
                 (group={group})"
            );
        }
    }

    #[test]
    fn captured_sd_equiv_masks_auto_inherited_only() {
        let sd = |v: &[u8]| CapturedSd::from(v.to_vec());
        // Identical → equiv.
        let a = sd(&[1, 0, 0x04, 0x80, 9, 9]);
        assert!(a.equiv(&a));
        assert_eq!(a.control(), 0x8004);
        // SE_DACL_AUTO_INHERITED (0x0400 → byte[3] |= 0x04) → equiv.
        let b = sd(&[1, 0, 0x04, 0x84, 9, 9]);
        assert_eq!(b.control(), 0x8404);
        assert!(a.equiv(&b));
        // SE_SACL_AUTO_INHERITED (0x0800 → byte[3] |= 0x08) → equiv.
        assert!(a.equiv(&sd(&[1, 0, 0x04, 0x88, 9, 9])));
        // Any other Control bit (e.g. SE_DACL_PROTECTED 0x1000 →
        // byte[3] |= 0x10) → NOT equiv.
        assert!(!a.equiv(&sd(&[1, 0, 0x04, 0x90, 9, 9])));
        // Body byte differs → NOT equiv.
        assert!(!a.equiv(&sd(&[1, 0, 0x04, 0x80, 9, 0])));
        // Length differs → NOT equiv.
        assert!(!a.equiv(&sd(&[1, 0, 0x04, 0x80, 9])));
    }
}
