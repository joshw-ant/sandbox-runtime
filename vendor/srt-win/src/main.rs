//! `srt-win` — CLI for the sandbox-runtime Windows network fence.
//!
//! Subcommands:
//!   install | uninstall                — convenience: group + WFP in one
//!                                         elevated call (one UAC prompt)
//!   group  create | status | delete    — manage the discriminator local group
//!   wfp    install | status | uninstall — manage the persistent WFP filters
//!   exec   -- <target> [args...]       — spawn under the deny-only-group
//!                                         token + job + hardening stack
//!   acl    stamp | restore | recover   — file-level denyRead/denyWrite via
//!                                         broker-only DACL stamp + state DB
//!
//! `status` subcommands write one line of JSON to stdout and exit 0.
//! Mutating subcommands require elevation and write human-readable
//! progress to stderr. `exec` propagates the child's exit code.

use clap::{Args, Parser, Subcommand};

/// Default group name. Lives here (not in the `#[cfg(windows)]`
/// library crate) so the clap-derive CLI structs compile on
/// non-Windows hosts where the library is empty.
const DEFAULT_GROUP_NAME: &str = "sandbox-runtime-net";

#[derive(Parser)]
#[command(name = "srt-win", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Group create + WFP install in one elevated step.
    ///
    /// Self-elevates via UAC if not already running as admin
    /// (one prompt; the elevated child does the work and the
    /// parent relays its exit code). With the machine-wide
    /// filter design, a token where the group is **absent**
    /// (i.e. this session, before logout) matches filter-0
    /// (PERMIT non-members) — so installing the WFP filters
    /// here does NOT break the user's network. Logout is still
    /// required before `srt-win exec` works (the broker
    /// pre-flight needs the group **enabled** to build a
    /// deny-only child token), but the install itself is one
    /// safe step → one UAC prompt.
    ///
    /// Equivalent to `group create --name <N> --user-sid <U>`
    /// followed by `wfp install --name <N> …`. With `--group-sid`,
    /// the group is assumed to already exist (e.g. provisioned by
    /// domain GPO) and only the filters are installed.
    ///
    /// Exit codes:
    ///   0  — installed (or already installed with the same
    ///        port-range; no changes)
    ///   10 — UAC prompt cancelled by the user
    ///   11 — group create / lookup failed
    ///   12 — WFP filter install failed
    ///   13 — already installed under this sublayer with a
    ///        DIFFERENT port-range; pass `--force` to replace
    ///   1  — other error (parse, elevation check, etc.)
    Install {
        #[command(flatten)]
        group: GroupRef,
        /// User SID to add to the group (default: current user).
        /// Ignored with `--group-sid`.
        #[arg(long)]
        user_sid: Option<String>,
        /// Sublayer GUID (default: compile-time constant).
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Loopback port range (`LOW-HIGH`, default 60080-60089).
        #[arg(long, value_name = "LOW-HIGH")]
        proxy_port_range: Option<String>,
        /// Replace an existing install whose port-range differs
        /// (otherwise exits 13).
        #[arg(long)]
        force: bool,
    },
    /// Remove the srt-win WFP filters under the sublayer.
    ///
    /// Self-elevates via UAC if not already admin. Does NOT
    /// delete the discriminator group — use `srt-win group
    /// delete --name <N>` for that explicitly.
    Uninstall {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Manage the local discriminator group.
    Group {
        #[command(subcommand)]
        sub: GroupCmd,
    },
    /// Manage the persistent WFP filters.
    Wfp {
        #[command(subcommand)]
        sub: WfpCmd,
    },
    /// Stamp/restore broker-only DACLs on file paths so the
    /// sandboxed child cannot read (or write) them. State is
    /// persisted in `%LOCALAPPDATA%\sandbox-runtime\state.db` so
    /// concurrent brokers refcount and a crash mid-session is
    /// recoverable by the next `acl` op.
    Acl {
        #[command(subcommand)]
        sub: AclCmd,
    },
    /// Spawn a process under the deny-only-group sandbox.
    ///
    /// Builds a restricted token (group + Admins flipped deny-only,
    /// LUA, Medium IL, all privs stripped except SeChangeNotify),
    /// self-protects the broker, assigns the child to a
    /// kill-on-close job with full UI lockdown, places it on a
    /// non-interactive desktop, applies process-mitigation
    /// policies + an explicit handle whitelist, and waits for it
    /// to exit. Propagates the child's exit code.
    ///
    /// The child inherits this process's environment verbatim — proxy
    /// configuration is single-sourced by the caller, which sets the
    /// proxy vars (TS `generateProxyEnvVars`) in the environment it
    /// spawns `srt-win exec` with. There are intentionally no
    /// `--http-proxy` / `--socks-proxy` flags and no proxy fallback.
    Exec {
        #[command(flatten)]
        group: GroupRef,
        /// Skip the "is the group enabled in the broker's token"
        /// pre-flight. **Fail-open** — the WFP fence depends on
        /// that membership; with this set the child may run with
        /// weaker isolation if the install was incomplete.
        /// Surfaced as a flag (not an env var) so the bypass is
        /// intentional and not accidentally inherited. Use ONLY
        /// in ephemeral CI runners that create the group in-job
        /// and cannot logout/login mid-run.
        #[arg(long)]
        skip_group_check: bool,
        /// PID of the long-lived host whose `acl stamp` holds this
        /// child should be fenced under. When set, exec opens a
        /// no-`FILE_SHARE_DELETE` handle on every file that holder
        /// has stamped and keeps it open until the child exits — the
        /// OS then refuses delete/rename of those files, which the
        /// file's DACL alone cannot prevent (delete is authorized by
        /// the parent directory). When omitted, exec runs with no
        /// state-DB dependency (current standalone behaviour).
        #[arg(long)]
        holder_pid: Option<u32>,
        /// Target executable followed by its arguments. Use `--`
        /// to terminate srt-win's own option parsing.
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            required = true,
            num_args = 1..,
        )]
        target: Vec<String>,
    },
}

/// Group resolution: either by name (looked up via
/// `LookupAccountNameW`) or directly by SID. If both are given the
/// SID wins; `group create`/`delete` always need a name.
#[derive(Args, Clone)]
struct GroupRef {
    /// Group name (local or `DOMAIN\name`). Default
    /// `sandbox-runtime-net`.
    #[arg(long, default_value = DEFAULT_GROUP_NAME)]
    name: String,
    /// Group SID (`S-1-…`). Overrides `--name` for SID resolution.
    /// Use when the group is provisioned by external tooling and name
    /// lookup may be unreliable.
    #[arg(long)]
    group_sid: Option<String>,
}

#[derive(Subcommand)]
enum GroupCmd {
    /// Create the local group and add the current (or `--user-sid`)
    /// user to it. Idempotent. Self-elevates via UAC if not already
    /// admin.
    Create {
        #[command(flatten)]
        group: GroupRef,
        /// User SID to add (default: current user).
        #[arg(long)]
        user_sid: Option<String>,
    },
    /// Print group state as JSON: `{state, sid?, warning?}`.
    Status {
        #[command(flatten)]
        group: GroupRef,
    },
    /// Delete the local group. Idempotent. Self-elevates via UAC if
    /// not already admin.
    Delete {
        #[command(flatten)]
        group: GroupRef,
    },
}

#[derive(Subcommand)]
enum AclCmd {
    /// Read `{denyRead:[…], denyWrite:[…]}` from stdin, stamp each
    /// path's DACL broker-only, and record this process as a
    /// holder. Idempotent across calls and brokers (refcounted).
    /// Directories and globs are rejected.
    Stamp {
        #[command(flatten)]
        group: GroupRef,
        /// PID of the LONG-LIVED process that owns these stamps —
        /// normally the Node host (sandbox-runtime), which calls
        /// `acl stamp` at initialize() and `acl restore` at reset()
        /// from a SEPARATE short-lived `srt-win` process. The stamp
        /// persists until this PID exits or restores. Required:
        /// the `srt-win acl` process exits immediately, so keying
        /// on its own PID would orphan the stamp instantly.
        #[arg(long)]
        holder_pid: u32,
    },
    /// Drop the holder's claim on every path it stamped; restore the
    /// original DACL on any path whose refcount falls to zero.
    Restore {
        #[command(flatten)]
        group: GroupRef,
        /// Holder PID whose stamps to release (see `acl stamp`).
        /// Must match the value passed at stamp time.
        #[arg(long)]
        holder_pid: u32,
        /// Emit a single JSON array of per-path
        /// `{path, status, expectedFileId?, movedTo?, leftStamped?}`
        /// objects on stdout (exit 0 always); the host raises any
        /// error AFTER reading the array. Without this flag, the
        /// existing human-readable summary goes to stderr.
        #[arg(long)]
        json: bool,
    },
    /// Run crash-recovery only: prune dead holders, restore any
    /// orphaned stamps. `--force` restores even when the file's
    /// current DACL no longer matches what we stamped (overwrites
    /// third-party edits — use with care).
    Recover {
        #[command(flatten)]
        group: GroupRef,
        #[arg(long)]
        force: bool,
        /// Emit a single JSON array of per-path outcomes on stdout
        /// (see `acl restore --json`).
        #[arg(long)]
        json: bool,
    },
}

/// One per-path entry of the structured `acl restore --json` /
/// `acl recover --json` result. The host reads the full array,
/// then raises if any entry is not `restored` — restore
/// processes ALL paths first; errors are surfaced afterward,
/// never mid-batch.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(windows), allow(dead_code))]
struct RestoreEntry {
    path: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    moved_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    left_stamped: Option<bool>,
}

/// A parent directory's restore outcome in the structured
/// `--json` result. `status: "leftStamped"` means the directory's
/// allow-list could NOT be removed (`restore_sd` failed) and the
/// `parent_stamps` row was kept for the next pass to retry.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(windows), allow(dead_code))]
struct ParentEntry {
    path: String,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Top-level shape of `acl restore --json` / `acl recover --json`.
#[derive(serde::Serialize)]
#[cfg_attr(not(windows), allow(dead_code))]
struct RestoreResult {
    paths: Vec<RestoreEntry>,
    parents: Vec<ParentEntry>,
}

#[cfg(windows)]
fn parent_entries_from(
    report: &srt_win::state_db::RecoveryReport,
) -> Vec<ParentEntry> {
    report
        .parent_entries
        .iter()
        .map(|(p, r)| ParentEntry {
            path: p.clone(),
            status: if r.is_ok() { "restored" } else { "leftStamped" },
            error: r.as_ref().err().cloned(),
        })
        .collect()
}

#[cfg(windows)]
fn restore_entry(
    snap: &srt_win::state_db::Snapshot,
    out: &srt_win::state_db::RestoreOutcome,
) -> RestoreEntry {
    use srt_win::state_db::RestoreOutcome;
    let (status, moved_to, left_stamped) = match out {
        RestoreOutcome::Restored | RestoreOutcome::AlreadyOriginal => {
            ("restored", None, None)
        }
        RestoreOutcome::Relocated { moved_to } => {
            ("relocated", Some(moved_to.clone()), Some(true))
        }
        RestoreOutcome::Missing => ("missing", None, Some(true)),
        RestoreOutcome::LeftChanged => ("leftChanged", None, Some(true)),
        RestoreOutcome::LeftUnreadable => {
            ("leftUnreadable", None, Some(true))
        }
    };
    RestoreEntry {
        path: snap.canonical_path.clone(),
        status,
        expected_file_id: if status == "restored" {
            None
        } else {
            Some(snap.file_id.to_hex())
        },
        moved_to,
        left_stamped,
    }
}

/// Stamp `canon`'s parent directory with the FDC-removing
/// allow-list (record-first, refcounted via the `parent_stamps`
/// table). Returns `true` if the parent is now (or was already)
/// stamped; `false` if it could NOT be stamped — in which case the
/// snapshot row is marked `parent_stamp_failed` and the file falls
/// back to the per-exec handle fence.
///
/// Failure to stamp the parent never aborts the file stamp: the
/// file's broker-only DACL already gives the content guarantee
/// (read deny, write-content deny), and the per-exec handle fence
/// covers delete/rename for the fallback set.
#[cfg(windows)]
fn stamp_parent_for(
    db: &srt_win::state_db::Locked,
    canon: &str,
    parent_path: Option<&str>,
    group_sid: &str,
    user_sid: &str,
) -> anyhow::Result<bool> {
    use srt_win::{acl, state_db};
    let Some(parent) = parent_path else {
        // File at a volume root — no parent to stamp.
        db.set_parent_stamp_failed(canon)?;
        return Ok(false);
    };
    // Test hook: forcing the fallback lets the smoke suite
    // exercise the handle-fence path on hosts where the broker
    // can ALWAYS stamp the parent (an elevated token's
    // SeRestorePrivilege lets SetNamedSecurityInfoW succeed
    // regardless of any DACL deny on the directory). Active in
    // release because the smoke suite runs the release binary,
    // but it removes the primary delete/rename protection — so
    // emit a loud one-shot warning if it leaks into a non-test
    // environment.
    if std::env::var_os("SRT_WIN_TEST_SKIP_PARENT_STAMP").is_some() {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            eprintln!(
                "srt-win: WARNING: SRT_WIN_TEST_SKIP_PARENT_STAMP is set — \
                 parent-directory stamping is DISABLED for ALL files; \
                 this removes the primary delete/rename protection. \
                 Test setups only."
            );
        });
        eprintln!(
            "srt-win: parent stamp '{parent}' skipped \
             (SRT_WIN_TEST_SKIP_PARENT_STAMP); '{canon}' falls back \
             to the per-exec handle fence"
        );
        db.set_parent_stamp_failed(canon)?;
        return Ok(false);
    }
    if db.get_parent_stamp(parent)?.is_some() {
        // Already stamped (by an earlier file in this batch or a
        // prior session). Refcount is structural via
        // `acl_snapshots.parent_path` so there is nothing to do.
        return Ok(true);
    }
    // Record-first: persist the original SD BEFORE the FS
    // mutation, same invariant as file snapshots.
    let p_orig = match acl::capture_sd(parent) {
        Ok(sd) => sd,
        Err(e) => {
            eprintln!(
                "srt-win: parent stamp: capture SD '{parent}' failed \
                 ({e:#}); '{canon}' falls back to the per-exec handle fence"
            );
            db.set_parent_stamp_failed(canon)?;
            return Ok(false);
        }
    };
    db.insert_parent_stamp(&state_db::ParentStamp {
        canonical_parent_path: parent.to_string(),
        original_sd: p_orig,
        stamped_sd: None,
    })?;
    match acl::apply_parent_allow_list(parent, group_sid, user_sid) {
        Ok(p_stamped) => {
            db.set_parent_stamped(parent, &p_stamped)?;
            Ok(true)
        }
        Err(e) => {
            eprintln!(
                "srt-win: parent stamp '{parent}' failed ({e:#}); \
                 '{canon}' falls back to the per-exec handle fence"
            );
            // Roll back the in-flight row so the next file in this
            // parent retries (and so restore doesn't try to put back
            // an SD that was never replaced).
            db.delete_parent_stamp(parent)?;
            db.set_parent_stamp_failed(canon)?;
            Ok(false)
        }
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(not(windows), allow(dead_code))]
struct AclStampInput {
    #[serde(default)]
    deny_read: Vec<String>,
    #[serde(default)]
    deny_write: Vec<String>,
}

#[derive(Subcommand)]
enum WfpCmd {
    /// Install (or refresh) the machine-wide persistent WFP filters
    /// keyed on the group SID. Idempotent. Self-elevates via UAC if
    /// not already admin.
    Install {
        #[command(flatten)]
        group: GroupRef,
        /// Sublayer GUID. Default is the compile-time constant; pass
        /// when integrating with externally-managed WFP state.
        #[arg(long)]
        sublayer_guid: Option<String>,
        /// Loopback port range the sandboxed child may reach
        /// (`LOW-HIGH`, inclusive; default 60080-60089). The host
        /// http/socks proxies bind inside this range on Windows.
        #[arg(long, value_name = "LOW-HIGH")]
        proxy_port_range: Option<String>,
    },
    /// Print WFP fence state as JSON: `{state, filters,
    /// port_range?}`. Filters are identified by their
    /// `providerData` tag, so only `--sublayer-guid` is relevant.
    Status {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
    /// Remove every srt-win-tagged WFP filter under the sublayer.
    /// Self-elevates via UAC if not already admin.
    Uninstall {
        #[arg(long)]
        sublayer_guid: Option<String>,
    },
}

#[cfg(windows)]
fn main() {
    if let Err(e) = run() {
        eprintln!("srt-win: error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};
    use serde_json::json;
    use srt_win::{sid, wfp};

    let cli = Cli::parse();

    // Validate a caller-supplied SID string up front so a typo
    // surfaces as "invalid --<flag>" rather than an SDDL parse
    // error three calls deep. Returns the CANONICAL `S-1-…` form
    // (round-tripped through ConvertSidToStringSidW) so SDDL
    // shorthands like `BA` or lower-case `s-1-…` collapse to a
    // single comparable representation; downstream
    // `eq_ignore_ascii_case("S-1-5-32-544")` dedup checks rely on
    // that.
    let canonicalize_sid =
        |flag: &str, s: &str| -> anyhow::Result<String> {
            let p = sid::LocalPsid::from_string(s)
                .with_context(|| format!("invalid --{flag} '{s}'"))?;
            sid::psid_to_string(p.as_psid())
                .with_context(|| format!("canonicalize --{flag} '{s}'"))
        };
    let resolve_group_sid = |g: &GroupRef| -> anyhow::Result<String> {
        if let Some(s) = &g.group_sid {
            return canonicalize_sid("group-sid", s);
        }
        sid::lookup_account_sid(&g.name)
            .with_context(|| format!("resolve group '{}'", g.name))
    };
    let resolve_sublayer = |s: &Option<String>| -> anyhow::Result<windows::core::GUID> {
        match s {
            Some(g) => wfp::parse_guid(g),
            None => Ok(wfp::DEFAULT_SUBLAYER_GUID),
        }
    };

    match cli.cmd {
        // ─── install / uninstall (convenience) ─────────────────────
        Cmd::Install {
            group,
            user_sid,
            sublayer_guid,
            proxy_port_range,
            force,
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let range = match &proxy_port_range {
                Some(s) => wfp::parse_port_range(s)
                    .with_context(|| format!("invalid --proxy-port-range '{s}'"))?,
                None => wfp::DEFAULT_PROXY_PORT_RANGE,
            };
            // Idempotency / conflict pre-check. If filters are
            // already installed under this sublayer with the SAME
            // port-range, this is a no-op (exit 0). With a
            // DIFFERENT range and no --force, refuse (exit 13) so
            // an unintended config drift surfaces instead of
            // silently overwriting. A pre-existing install whose
            // tags lack a port_range (legacy) is treated as
            // "different" and requires --force.
            if !force
                && let Ok(st) = wfp::filter_status(&sl)
                && st.state == "installed"
            {
                let want = [range.0, range.1];
                if st.port_range == Some(want) {
                    eprintln!(
                        "srt-win: already installed (sublayer={sl:?}, \
                         port_range={}-{}, filters={}); no changes",
                        range.0, range.1, st.filters,
                    );
                    return Ok(());
                }
                let have = st
                    .port_range
                    .map(|[l, h]| format!("{l}-{h}"))
                    .unwrap_or_else(|| "<unknown>".into());
                eprintln!(
                    "srt-win: error: already installed under sublayer \
                     {sl:?} with port_range={have}; pass --force to \
                     replace, or run `srt-win uninstall` first."
                );
                std::process::exit(13);
            }
            // With --group-sid the group is externally managed;
            // just canonicalize. With --name (or the default),
            // create the local group, add the user, then resolve
            // the SID. Failures here exit 11.
            let group_step = || -> anyhow::Result<(String, String)> {
                if let Some(s) = &group.group_sid {
                    let g = canonicalize_sid("group-sid", s)?;
                    Ok((g.clone(), g))
                } else {
                    let user = match &user_sid {
                        Some(s) => canonicalize_sid("user-sid", s)?,
                        None => sid::current_user_sid()
                            .context("resolve current user")?,
                    };
                    wfp::ensure_group(&group.name, &user)?;
                    let g = sid::lookup_account_sid(&group.name)?;
                    Ok((group.name.clone(), g))
                }
            };
            let (label, gsid) = match group_step() {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("srt-win: error: group step: {e:#}");
                    std::process::exit(11);
                }
            };
            if let Err(e) = wfp::install_filters(&sl, &gsid, range) {
                eprintln!("srt-win: error: WFP install: {e:#}");
                std::process::exit(12);
            }
            eprintln!(
                "srt-win: installed (group={label} sid={gsid}, sublayer={sl:?}, \
                 proxy_port_range={}-{}, filters=8)",
                range.0, range.1,
            );
            eprintln!(
                "srt-win: NOTE — log out and back in before running \
                 `srt-win exec` (the group SID enters TokenGroups at \
                 logon; your network is unaffected meanwhile)."
            );
        }
        Cmd::Uninstall { sublayer_guid } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = wfp::uninstall_filters(&sl)?;
            eprintln!(
                "srt-win: uninstalled ({n} filter(s) removed). \
                 Group is left intact — run `srt-win group delete` \
                 to remove it."
            );
        }

        // ─── group ─────────────────────────────────────────────────
        Cmd::Group { sub: GroupCmd::Create { group, user_sid } } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            if group.group_sid.is_some() {
                return Err(anyhow!(
                    "`group create` needs --name; --group-sid is for \
                     referencing an existing group"
                ));
            }
            let user = match &user_sid {
                Some(s) => canonicalize_sid("user-sid", s)?,
                None => sid::current_user_sid()
                    .context("resolve current user")?,
            };
            wfp::ensure_group(&group.name, &user)?;
            let gsid = sid::lookup_account_sid(&group.name)?;
            eprintln!(
                "srt-win: group '{}' present (sid={gsid}); user {user} added",
                group.name
            );
            eprintln!(
                "srt-win: NOTE — the group SID enters TokenGroups at logon. \
                 Log out and back in before running `srt-win exec`."
            );
        }
        Cmd::Group { sub: GroupCmd::Status { group } } => {
            // Resolve SID first; if that fails the group is absent.
            let gsid = match &group.group_sid {
                Some(s) => {
                    // --group-sid bypasses the name lookup, so do a
                    // reverse lookup to distinguish "exists but not on
                    // this token yet" from "no such account at all".
                    // Tolerate transient lookup failure (domain
                    // unreachable) by falling through to the token
                    // check.
                    match sid::sid_account_exists(s) {
                        Ok(sid::SidExistence::Unmapped) => {
                            println!("{}", json!({"state": "absent"}));
                            return Ok(());
                        }
                        Ok(_) => {}
                        Err(e) => {
                            // Malformed SID string.
                            println!(
                                "{}",
                                json!({"state": "absent", "error": e.to_string()})
                            );
                            return Ok(());
                        }
                    }
                    s.clone()
                }
                None => match sid::lookup_account_sid(&group.name) {
                    Ok(s) => s,
                    Err(_) => {
                        println!("{}", json!({"state": "absent"}));
                        return Ok(());
                    }
                },
            };
            let out = match sid::group_state_for_self(&gsid)? {
                sid::GroupState::Enabled => {
                    json!({"state": "ready", "sid": gsid})
                }
                sid::GroupState::Absent => {
                    json!({"state": "created-not-on-token", "sid": gsid})
                }
                sid::GroupState::DenyOnly => json!({
                    "state": "created-not-on-token",
                    "sid": gsid,
                    "warning": "group is deny-only in this token — running \
                                inside a sandbox child?"
                }),
                sid::GroupState::Present => json!({
                    "state": "created-not-on-token",
                    "sid": gsid,
                    "warning": "group present but neither enabled nor \
                                deny-only (unexpected)"
                }),
            };
            println!("{out}");
        }
        Cmd::Group { sub: GroupCmd::Delete { group } } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            if group.group_sid.is_some() {
                return Err(anyhow!(
                    "`group delete` needs --name; cannot delete by SID"
                ));
            }
            wfp::delete_group(&group.name)?;
            eprintln!("srt-win: group '{}' deleted (if it existed)", group.name);
        }

        // ─── wfp ───────────────────────────────────────────────────
        Cmd::Wfp {
            sub:
                WfpCmd::Install {
                    group,
                    sublayer_guid,
                    proxy_port_range,
                },
        } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let gsid = resolve_group_sid(&group)?;
            let sl = resolve_sublayer(&sublayer_guid)?;
            let range = match &proxy_port_range {
                Some(s) => wfp::parse_port_range(s)
                    .with_context(|| format!("invalid --proxy-port-range '{s}'"))?,
                None => wfp::DEFAULT_PROXY_PORT_RANGE,
            };
            wfp::install_filters(&sl, &gsid, range)?;
            eprintln!(
                "srt-win: WFP filters installed (group_sid={gsid}, \
                 sublayer={sl:?}, proxy_port_range={}-{})",
                range.0, range.1,
            );
        }
        Cmd::Wfp { sub: WfpCmd::Status { sublayer_guid } } => {
            let sl = resolve_sublayer(&sublayer_guid)?;
            let st = wfp::filter_status(&sl)?;
            println!("{}", serde_json::to_string(&st)?);
        }
        Cmd::Wfp { sub: WfpCmd::Uninstall { sublayer_guid } } => {
            if let Some(code) = maybe_self_elevate()? {
                std::process::exit(code);
            }
            let sl = resolve_sublayer(&sublayer_guid)?;
            let n = wfp::uninstall_filters(&sl)?;
            eprintln!("srt-win: removed {n} WFP filter(s)");
        }

        // ─── acl ───────────────────────────────────────────────────
        Cmd::Acl {
            sub: AclCmd::Stamp { group, holder_pid },
        } => {
            use srt_win::{acl, sid, state_db};
            let gsid = resolve_group_sid(&group)?;
            let user_sid = sid::current_user_sid()?;
            let holder = state_db::HolderPid(holder_pid);
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                .context("read stdin")?;
            let input: AclStampInput = serde_json::from_str(&buf)
                .context("parse stdin JSON {denyRead:[…], denyWrite:[…]}")?;
            // Canonicalize and reject dirs/globs BEFORE taking the
            // mutex so a bad input doesn't hold the lock.
            let mut targets: Vec<(String, acl::AclMask)> = Vec::new();
            for (list, mask) in [
                (&input.deny_read, acl::AclMask::ReadDeny),
                (&input.deny_write, acl::AclMask::WriteDeny),
            ] {
                for p in list {
                    let (canon, is_dir) = acl::canonicalize_path(p)?;
                    if is_dir {
                        return Err(anyhow!(
                            "Windows fs deny requires explicit file paths; \
                             got directory '{p}' (canonical '{canon}')."
                        ));
                    }
                    targets.push((canon, mask));
                }
            }
            let ((newly, escalated, parent_fallback), report) =
                state_db::with_init_lock(&gsid, holder, false, |db| {
                    db.register_broker()?;
                    // Build the DACL once per mask, not per file.
                    let read_d = acl::BrokerDacl::build(
                        &gsid, acl::AclMask::ReadDeny, false,
                    )?;
                    let write_d = acl::BrokerDacl::build(
                        &gsid, acl::AclMask::WriteDeny, false,
                    )?;
                    let dacl_for = |m: acl::AclMask| match m {
                        acl::AclMask::ReadDeny => &read_d,
                        acl::AclMask::WriteDeny => &write_d,
                    };
                    let mut newly = 0u32;
                    let mut escalated = 0u32;
                    let mut parent_fallback = 0u32;
                    for (canon, mask) in &targets {
                        match db.get_snapshot(canon)? {
                            None => {
                                // First stamper. Persist the original
                                // SD BEFORE the FS mutation so a
                                // crash mid-stamp can't lose it (see
                                // state_db module doc).
                                let original = acl::capture_sd(canon)
                                    .with_context(|| {
                                        format!(
                                            "capture original SD for '{canon}'"
                                        )
                                    })?;
                                let file_id = acl::capture_file_id(canon)
                                    .with_context(|| {
                                        format!("capture file_id for '{canon}'")
                                    })?;
                                let parent_path =
                                    acl::canonical_parent_of(canon);
                                db.insert_snapshot(&state_db::Snapshot {
                                    canonical_path: canon.clone(),
                                    is_dir: false,
                                    mask: *mask,
                                    original_sd: original,
                                    stamped_sd: None,
                                    file_id,
                                    parent_path: parent_path.clone(),
                                    parent_stamp_failed: false,
                                })?;
                                let r = acl::stamp_file_apply(
                                    canon,
                                    dacl_for(*mask),
                                )
                                .with_context(|| {
                                    format!("stamp '{canon}' ({mask:?})")
                                })?;
                                db.set_stamped(canon, *mask, &r.stamped_sd)?;
                                newly += 1;

                                // Stamp the IMMEDIATE PARENT directory
                                // with the FDC-removing allow-list
                                // (refcounted, record-first). The file
                                // DACL alone does not prevent
                                // delete/rename (the parent's
                                // FILE_DELETE_CHILD authorizes it
                                // regardless), so the parent stamp is
                                // what closes that gap. When the parent
                                // can't be WRITE_DAC'd (system dir,
                                // protected by something else, or the
                                // file is at a volume root), mark this
                                // file for the per-exec handle-fence
                                // fallback instead.
                                if !stamp_parent_for(
                                    db, canon, parent_path.as_deref(),
                                    &gsid, &user_sid,
                                )? {
                                    parent_fallback += 1;
                                }
                            }
                            Some(existing)
                                if mask.is_stricter_than(existing.mask) =>
                            {
                                // Already held under a looser mask
                                // (e.g. WriteDeny while we want
                                // ReadDeny). Re-stamp with the
                                // stricter mask; original_sd stays
                                // as recorded by the first stamper.
                                let r = acl::stamp_file_apply(
                                    canon,
                                    dacl_for(*mask),
                                )
                                .with_context(|| {
                                    format!(
                                        "escalate stamp '{canon}' ({:?}→{mask:?})",
                                        existing.mask
                                    )
                                })?;
                                db.set_stamped(canon, *mask, &r.stamped_sd)?;
                                // The first stamper may have
                                // recorded `parent_stamp_failed`;
                                // retry the parent stamp now
                                // (idempotent-cheap: early-returns
                                // if the parent_stamps row exists).
                                if existing.parent_stamp_failed
                                    && stamp_parent_for(
                                        db,
                                        canon,
                                        existing.parent_path.as_deref(),
                                        &gsid,
                                        &user_sid,
                                    )?
                                {
                                    db.clear_parent_stamp_failed(canon)?;
                                } else if existing.parent_stamp_failed {
                                    parent_fallback += 1;
                                }
                                escalated += 1;
                            }
                            Some(existing) if existing.mask != *mask => {
                                // The path is already stamped at the
                                // stricter level; the looser request
                                // is satisfied by it. Hold only.
                                eprintln!(
                                    "srt-win: '{canon}': requested \
                                     {mask:?} subsumed by existing \
                                     {:?}; holding",
                                    existing.mask
                                );
                            }
                            Some(_) => {} // identical mask — hold only
                        }
                        db.add_holder(canon)?;
                    }
                    Ok((newly, escalated, parent_fallback))
                })?;
            eprintln!(
                "srt-win: acl stamp — {} path(s) ({} newly stamped, \
                 {} escalated, {} already held, {} parent-stamp \
                 fallback); recovery pruned {} dead broker(s), \
                 restored {} orphan(s)",
                targets.len(),
                newly,
                escalated,
                targets.len() as u32 - newly - escalated,
                parent_fallback,
                report.dead_brokers,
                report.restored,
            );
        }
        Cmd::Acl {
            sub: AclCmd::Restore { group, holder_pid, json },
        } => {
            use srt_win::state_db;
            let gsid = resolve_group_sid(&group)?;
            let holder = state_db::HolderPid(holder_pid);
            let (entries, report) =
                state_db::with_init_lock(&gsid, holder, false, |db| {
                    let holds = db.my_holds()?;
                    let mut entries: Vec<RestoreEntry> = Vec::new();
                    for canon in &holds {
                        let now_zero = db.remove_holder(canon)?;
                        if !now_zero {
                            // Another holder still has it — released
                            // our claim, file stays stamped. Not
                            // reported (the LAST holder to release
                            // does).
                            continue;
                        }
                        let Some(snap) = db.get_snapshot(canon)? else {
                            eprintln!(
                                "srt-win: WARNING: '{canon}' had a holder \
                                 row but no snapshot — skipping"
                            );
                            continue;
                        };
                        // Same case analysis as crash-recovery so
                        // the two cannot diverge. A mismatch on one
                        // path does NOT abort the batch — every
                        // other path is still processed.
                        let out = db.try_restore(&snap, false)?;
                        entries.push(restore_entry(&snap, &out));
                    }
                    db.unregister_broker()?;
                    Ok(entries)
                })?;
            let restored =
                entries.iter().filter(|e| e.status == "restored").count();
            let left = entries.len() - restored;
            eprintln!(
                "srt-win: acl restore — {} restored, {} left \
                 (relocated/missing/changed){}",
                restored,
                left,
                if report.parents_left > 0 {
                    format!("; {} parent dir(s) left stamped", report.parents_left)
                } else {
                    String::new()
                },
            );
            if json {
                let result = RestoreResult {
                    paths: entries,
                    parents: parent_entries_from(&report),
                };
                serde_json::to_writer(std::io::stdout(), &result)
                    .context("write --json restore result")?;
                println!();
            }
        }
        Cmd::Acl { sub: AclCmd::Recover { group, force, json } } => {
            use srt_win::state_db;
            let gsid = resolve_group_sid(&group)?;
            // recover only runs crash-recovery (holder-agnostic); the
            // holder PID is irrelevant, pass our own.
            let ((), report) = state_db::with_init_lock(
                &gsid,
                state_db::HolderPid(std::process::id()),
                force,
                |_db| Ok(()),
            )?;
            eprintln!(
                "srt-win: acl recover — pruned {} dead broker(s), \
                 restored {} orphan(s), {} relocated, {} missing, \
                 left {} (changed since stamp{})",
                report.dead_brokers,
                report.restored,
                report.relocated,
                report.missing,
                report.left_changed,
                if force { "; --force applied" } else { "" },
            );
            if json {
                let result = RestoreResult {
                    paths: report
                        .entries
                        .iter()
                        .map(|(s, o)| restore_entry(s, o))
                        .collect(),
                    parents: parent_entries_from(&report),
                };
                serde_json::to_writer(std::io::stdout(), &result)
                    .context("write --json recover result")?;
                println!();
            }
        }

        // ─── exec ──────────────────────────────────────────────────
        Cmd::Exec {
            group,
            skip_group_check,
            holder_pid,
            target,
        } => {
            use srt_win::{fence, launch, state_db};
            let gsid = resolve_group_sid(&group)?;
            // `target` is `required, num_args=1..` so non-empty.
            let exe = std::path::PathBuf::from(&target[0]);
            let args = &target[1..];

            // Delete/rename fence — FALLBACK only. The primary
            // delete/rename protection is the parent-directory
            // allow-list stamp (`acl stamp` strips the user's
            // FILE_DELETE_CHILD on each protected file's parent).
            // The fence is held only on files whose parent could
            // NOT be stamped (`parent_stamp_failed = 1` — no
            // WRITE_DAC on the parent, or no parent). For that
            // subset the fence is LOAD-BEARING: if any such path
            // can't be opened (after a short retry) the deny
            // guarantee would be incomplete and exec must not run —
            // `?` propagates. With --holder-pid omitted, exec has
            // no state-DB dependency. Logged on the no-flag and
            // success paths; on failure the error names the cause
            // directly.
            let delete_fence = match holder_pid {
                None => {
                    eprintln!(
                        "srt-win: handle fence: skipped (no --holder-pid)"
                    );
                    None
                }
                Some(pid) => {
                    let paths = state_db::fence_fallback_paths(
                        &gsid,
                        state_db::HolderPid(pid),
                    )
                        .with_context(|| {
                            format!(
                                "handle fence: state-DB fallback lookup \
                                 for holder {pid}"
                            )
                        })?;
                    let f = fence::open_delete_fence(&paths)?;
                    if paths.is_empty() {
                        eprintln!(
                            "srt-win: handle fence: holder_pid={pid} → \
                             0 path(s) (parent stamps cover all)"
                        );
                    } else {
                        eprintln!(
                            "srt-win: handle fence (fallback): \
                             holder_pid={pid} → {} parent-stamp-failed \
                             path(s) fenced",
                            paths.len()
                        );
                    }
                    Some(f)
                }
            };

            let spec = launch::ExecSpec {
                group_sid: &gsid,
                skip_group_check,
                target_exe: &exe,
                target_args: args,
            };
            let code = launch::run(&spec)?;
            // `delete_fence` drops here → handles closed → fence
            // lifted. process::exit skips destructors, so explicitly
            // drop anything that needs cleanup BEFORE it. Propagate
            // the child's exit code verbatim.
            drop(delete_fence);
            std::process::exit(code as i32);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_elevated() -> anyhow::Result<bool> {
    use anyhow::Context;
    use std::ffi::c_void;
    use std::mem::size_of;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcessToken,
    };
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok)
            .context("OpenProcessToken")?;
        let mut elev = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let r = GetTokenInformation(
            tok,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        );
        let _ = CloseHandle(tok);
        r.context("GetTokenInformation(TokenElevation)")?;
        Ok(elev.TokenIsElevated != 0)
    }
}

/// Hard elevation gate: returns an error (no UAC relaunch) when not
/// admin. The granular admin mutators self-elevate via
/// [`maybe_self_elevate`], so this currently has no caller — it's
/// retained as the non-interactive counterpart for code paths that
/// must NOT pop a UAC prompt, hence `allow(dead_code)`.
#[cfg(windows)]
#[allow(dead_code)]
fn require_elevated() -> anyhow::Result<()> {
    if is_elevated()? {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "this command requires elevation — run from an \
             administrator prompt"
        ))
    }
}

/// If not already elevated, re-launch ourselves with the same
/// argv via `ShellExecuteExW(verb="runas")` — one UAC prompt —
/// wait for the elevated child, and return its exit code. If
/// already elevated, returns `Ok(None)` and the caller proceeds
/// in-process. If the user cancels the UAC dialog
/// (`ERROR_CANCELLED`), exits with code **10** so the caller's
/// exit-code contract holds without the caller needing a
/// separate match.
///
/// The elevated child runs in its own (hidden) console, so its
/// stdout/stderr are NOT relayed to the parent. For
/// `install`/`uninstall` that's acceptable: the exit code is the
/// contract; the convenience commands' stderr is informational
/// only. The granular `group create|delete` and `wfp
/// install|uninstall` admin mutators call this too; their stderr is
/// likewise informational. Read-only subcommands (`group status`,
/// `wfp status`, `exec`) run as the broker and never self-elevate.
#[cfg(windows)]
fn maybe_self_elevate() -> anyhow::Result<Option<i32>> {
    use anyhow::Context;
    use srt_win::launch::quote_arg;
    use srt_win::util::wstr;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_CANCELLED, GetLastError,
    };
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, WaitForSingleObject, INFINITE,
    };
    use windows::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SEE_MASK_NO_CONSOLE,
        SHELLEXECUTEINFOW,
    };
    use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

    if is_elevated()? {
        return Ok(None);
    }

    let exe = std::env::current_exe().context("current_exe")?;
    let exe_w = wstr(&exe.to_string_lossy());
    // Rebuild the original argv (minus argv[0]) using
    // CommandLineToArgvW-compatible quoting so the elevated
    // child parses identically.
    let params: String = std::env::args()
        .skip(1)
        .map(|a| quote_arg(&a))
        .collect::<Vec<_>>()
        .join(" ");
    let params_w = wstr(&params);
    let verb_w = wstr("runas");

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(exe_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: sei is fully initialized; the wide-string buffers
    // outlive the call.
    let ok = unsafe { ShellExecuteExW(&mut sei) };
    if ok.is_err() {
        let err = unsafe { GetLastError() };
        if err == ERROR_CANCELLED {
            eprintln!("srt-win: UAC prompt cancelled by user");
            std::process::exit(10);
        }
        return Err(anyhow::anyhow!(
            "ShellExecuteExW(runas): {} ({}",
            std::io::Error::from_raw_os_error(err.0 as i32),
            err.0,
        ));
    }
    let h = sei.hProcess;
    if h.is_invalid() {
        return Err(anyhow::anyhow!(
            "ShellExecuteExW returned no process handle"
        ));
    }
    unsafe { WaitForSingleObject(h, INFINITE) };
    let mut code: u32 = 1;
    unsafe {
        GetExitCodeProcess(h, &mut code)
            .context("GetExitCodeProcess(elevated child)")?;
        let _ = CloseHandle(h);
    }
    Ok(Some(code as i32))
}

#[cfg(not(windows))]
fn main() {
    // The clap-derived structs above keep `clap` referenced; just
    // print the platform error.
    let _ = <Cli as clap::CommandFactory>::command();
    eprintln!("srt-win: Windows only");
    std::process::exit(2);
}
