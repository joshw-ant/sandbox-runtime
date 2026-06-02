<#
  Smoke test for `srt-win acl stamp|restore|recover`.

  Self-contained: creates temp files under a per-run scratch dir,
  stamps/restores them, and verifies access from both the broker
  side (this process — group enabled) and the sandboxed-child side
  (`srt-win exec --group-sid S-1-5-32-544 -- …` — group deny-only).

  Why `BUILTIN\Administrators` as the group: same reason as
  smoke-exec.ps1 — it's already on the runner token, so the child
  genuinely has it deny-only and the broker-only DACL actually
  excludes it. See that script's header.

  WFP filters are NOT installed by this script — `srt-win exec`
  works without them (the network fence is orthogonal to the FS
  stamp). The state DB and init-mutex DO use the production paths
  (`%LOCALAPPDATA%\sandbox-runtime\state.db`,
  `Local\sandbox-runtime-acl-init`), so the always-cleanup step
  runs `acl recover --force` to clear any leaked stamps.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Exe
)

$ErrorActionPreference = 'Stop'

$GroupSid = 'S-1-5-32-544'   # BUILTIN\Administrators
$cmd      = Join-Path $env:SystemRoot 'System32\cmd.exe'
$pwsh     = Join-Path $env:SystemRoot `
  'System32\WindowsPowerShell\v1.0\powershell.exe'

# Per-run scratch dir for the files we stamp.
$Scratch = Join-Path $env:TEMP "srt-acl-$([guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Path $Scratch | Out-Null
Write-Host "smoke-acl: group_sid=$GroupSid  exe=$Exe  scratch=$Scratch"

# Enable srt-win's per-exec stderr diagnostics (self-protect SDDL
# etc.). The Exec helper's .out filter strips them.
$env:SANDBOX_RUNTIME_WIN_DEBUG = '1'

function Run {
  param([string[]] $argv)
  & $Exe @argv
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited $LASTEXITCODE"
  }
}

# Like Run, but captures and returns the merged stdout+stderr
# (also echoed to the host) so a row can assert on srt-win's
# diagnostic messages.
function RunCapture {
  param([string[]] $argv)
  $raw = & $Exe @argv 2>&1 | Out-String
  Write-Host -NoNewline $raw
  if ($LASTEXITCODE -ne 0) {
    throw "srt-win $($argv -join ' ') exited ${LASTEXITCODE}: $raw"
  }
  return [pscustomobject]@{ raw = $raw }
}

# `acl restore --json` / `acl recover --json` — captures stdout
# (the JSON array) separately from stderr (human diagnostics) and
# returns the parsed array.
function RunJson {
  param([string[]] $argv)
  $serr = [IO.Path]::GetTempFileName()
  try {
    $sout = & $Exe @argv 2>$serr | Out-String
    $diag = Get-Content -Path $serr -Raw
    Write-Host -NoNewline $diag
    if ($LASTEXITCODE -ne 0) {
      throw "srt-win $($argv -join ' ') exited ${LASTEXITCODE}: $diag $sout"
    }
    # The result is `{paths:[…], parents:[…]}`. Callers want the
    # per-file `paths` array; `parents` (parent-dir restore
    # outcomes) is available via a direct ConvertFrom-Json if a
    # row needs it.
    if (-not $sout.Trim()) { return @() }
    $obj = $sout | ConvertFrom-Json
    return @($obj.paths)
  } finally { Remove-Item -Force $serr -ErrorAction SilentlyContinue }
}

# Run a command under `srt-win exec` and capture exit + child-only
# output (lines NOT prefixed `srt-win:`). Mirrors smoke-exec.ps1's
# Exec helper.
function ChildExec {
  param([string[]] $tail)
  $argv = @('exec', '--group-sid', $GroupSid) + $tail
  $raw = & $Exe @argv 2>&1 | Out-String
  $exit = $LASTEXITCODE
  $lines = $raw -split "`r?`n"
  $child = ($lines | Where-Object { $_ -notmatch '^srt-win:' }) -join "`n"
  return [pscustomobject]@{ exit = $exit; raw = $raw; out = $child }
}

# This pwsh process is the stable HOLDER: production passes the
# Node-host PID so a stamp persists across the separate `acl stamp`
# and `acl restore` invocations. Here, $PID plays that role.
$Holder = $PID

# `acl stamp` reads JSON from stdin. Each invocation is its own
# short-lived `srt-win` process, but it registers $HolderPid (default
# $Holder) as the owner so the stamp persists after it exits.
function Stamp {
  param([hashtable] $payload, [int] $HolderPid = $Holder)
  $json = $payload | ConvertTo-Json -Compress
  $json | & $Exe acl stamp --group-sid $GroupSid `
    --holder-pid $HolderPid
  if ($LASTEXITCODE -ne 0) {
    throw "acl stamp exited ${LASTEXITCODE}: payload=$json"
  }
}

# Precondition: BUILTIN\Administrators is enabled in this token,
# else the broker-only DACL would deny US too and the rows below
# would false-fail. (Same gate as smoke-exec.ps1.)
$gs = & $Exe group status --group-sid $GroupSid | ConvertFrom-Json
if ($gs.state -ne 'ready') {
  throw "smoke-acl precondition: $GroupSid must be ENABLED in this " +
        "token (got state=$($gs.state)). Run elevated."
}

try {
  # ── A1: denyRead — broker reads, child cannot ─────────────────
  $f1 = Join-Path $Scratch 'a1.txt'
  Set-Content -Path $f1 -Value 'A1-secret' -NoNewline
  Stamp @{ denyRead = @($f1) }

  # Broker (group enabled) can still read.
  $b = Get-Content -Path $f1 -Raw
  if ($b -ne 'A1-secret') { throw "A1: broker read got '$b'" }

  # Child (group deny-only) cannot. `type` fails with "Access is
  # denied" → cmd exits 1.
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f1`"")
  if ($r.exit -eq 0) {
    throw "A1: child read SUCCEEDED (should be denied). out: $($r.out)"
  }
  if ($r.out -notmatch '(?i)access is denied') {
    throw "A1: expected 'Access is denied', got: $($r.out)"
  }
  # The OWNER_RIGHTS ACE actually reached disk on the stamped
  # FILE (SetNamedSecurityInfoW silently drops a mask-0 ACE; the
  # builder uses READ_CONTROL — verify S-1-3-4 is present in the
  # binary SD and its mask excludes WRITE_DAC).
  $a1Acl = Get-Acl -LiteralPath $f1
  $a1Bin = ($a1Acl.GetSecurityDescriptorBinaryForm() |
    ForEach-Object { $_.ToString('x2') }) -join ''
  if ($a1Bin -notmatch '010100000000000304000000') {
    throw "A1(OW): OWNER_RIGHTS S-1-3-4 ACE absent from stamped " +
          "file's binary SD. SDDL: $($a1Acl.Sddl)"
  }
  $a1OwMask = ($a1Acl.Access |
    Where-Object { "$($_.IdentityReference)" -match 'OWNER|S-1-3-4' } |
    ForEach-Object { [int]$_.FileSystemRights })
  if ($a1OwMask -band 0x40000) {
    throw "A1(OW): OWNER_RIGHTS ACE on stamped file grants " +
          "WRITE_DAC (0x40000); mask=0x$($a1OwMask.ToString('x'))"
  }
  Write-Host 'A1 ok: denyRead — broker reads, child denied'

  # ── A2: denyWrite — child reads, cannot write; broker can ─────
  $f2 = Join-Path $Scratch 'a2.txt'
  Set-Content -Path $f2 -Value 'A2-readable' -NoNewline
  Stamp @{ denyWrite = @($f2) }

  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f2`"")
  if ($r.exit -ne 0 -or $r.out.Trim() -ne 'A2-readable') {
    throw "A2: child read failed (denyWrite should leave read open). " +
          "exit=$($r.exit) out=$($r.out)"
  }
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "echo nope > `"$f2`"")
  if ($r.exit -eq 0) {
    throw "A2: child WRITE succeeded (should be denied)"
  }
  # Broker can write.
  Set-Content -Path $f2 -Value 'A2-broker-wrote' -NoNewline
  if ((Get-Content -Path $f2 -Raw) -ne 'A2-broker-wrote') {
    throw 'A2: broker write did not stick'
  }
  Write-Host 'A2 ok: denyWrite — child reads, child denied write, broker writes'

  # Regression: A2's `Stamp` was a SECOND register_broker for the
  # same $Holder; A1's hold on f1 must survive (UPSERT, not REPLACE).
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f1`"")
  if ($r.exit -eq 0) {
    throw "A2(reg): A1's hold on f1 was DROPPED by A2's second " +
          "register_broker (CASCADE) — sandbox escape. out: $($r.out)"
  }
  Write-Host 'A2(reg) ok: second stamp by same holder kept earlier holds'

  # ── A17: parent allow-list — child cannot delete/rename stamped ─
  # The PRIMARY delete/rename protection: `acl stamp` stamped
  # $Scratch (the parent of f1/f2) with the FDC-removing
  # allow-list. The child gets Modify-without-FILE_DELETE_CHILD
  # on the parent, so it cannot delete or rename-over a child of
  # this directory via the parent's FDC; and the protected files'
  # broker-only DACLs withhold file-level DELETE — so the child
  # has no path to delete/rename them. NO --holder-pid here: the
  # parent stamp is on-disk, not a per-exec handle.
  $sib17 = Join-Path $Scratch 'a17-sibling.txt'
  Set-Content -Path $sib17 -Value 'SIB' -NoNewline
  $imp17 = Join-Path $Scratch 'a17-impostor.txt'
  Set-Content -Path $imp17 -Value 'IMPOSTOR' -NoNewline
  # Child tries to delete the denyRead-stamped f1 — must FAIL.
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "del /f /q `"$f1`"")
  if (-not (Test-Path $f1) -or
      (Get-Content -Path $f1 -Raw) -ne 'A1-secret') {
    throw "A17: child del of stamped f1 SUCCEEDED (parent " +
          "allow-list ineffective). raw: $($r.raw)"
  }
  # Child tries to move impostor over the denyWrite-stamped f2 —
  # must FAIL, f2 content unchanged.
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c',
                   "move /y `"$imp17`" `"$f2`"")
  if ((Get-Content -Path $f2 -Raw) -ne 'A2-broker-wrote') {
    throw "A17: child move-over of stamped f2 SUCCEEDED. " +
          "got: '$((Get-Content -Path $f2 -Raw))' raw: $($r.raw)"
  }
  # Child CAN delete its own non-protected sibling: it inherits
  # user:Modify (with file-level DELETE 0x10000) from the parent
  # allow-list, and the sibling has no broker-only DACL.
  #
  # Ground-truth instrumentation — captures everything needed to
  # diagnose if this assertion fails: parent + sibling effective
  # SDDL, sibling owner, the user SID srt-win wrote into the
  # parent allow-list (the 0x1301bf ACE), and the child token's
  # actual user/groups. Printed unconditionally and included in
  # the throw.
  $a17ParentAcl = Get-Acl -LiteralPath $Scratch
  $a17SibAcl    = Get-Acl -LiteralPath $sib17
  $a17UserAce   = ($a17ParentAcl.Sddl |
    Select-String '\(A;OICI;0x[0-9a-fA-F]+;;;[^)]+\)').Matches.Value
  # OWNER_RIGHTS ACE present (regression guard: a mask-0 ACE is
  # silently dropped by SetNamedSecurityInfoW, so the builder
  # uses READ_CONTROL — verify S-1-3-4 is in the binary SD).
  $a17OwAce = ($a17ParentAcl.Access |
    Where-Object { "$($_.IdentityReference)" -match 'OWNER|S-1-3-4' } |
    ForEach-Object {
      "$($_.IdentityReference)=$($_.FileSystemRights)/$($_.AccessControlType)"
    }) -join ', '
  $a17BinSd = ($a17ParentAcl.GetSecurityDescriptorBinaryForm() |
    ForEach-Object { $_.ToString('x2') }) -join ''
  # SID S-1-3-4 in binary: rev=01 subauth-count=01 idauth=000000000003
  # subauth[0]=04000000 → "0101000000000003 04000000".
  $a17OwInBin = $a17BinSd -match '010100000000000304000000'
  $a17Diag = @(
    "parent SDDL:    $($a17ParentAcl.Sddl)"
    "parent user-ACE:$a17UserAce"
    "parent OW-ACE:  $(if ($a17OwAce) { $a17OwAce } else { '<none in .Access>' })"
    "parent binSD has S-1-3-4: $a17OwInBin"
    "sibling SDDL:   $($a17SibAcl.Sddl)"
    "sibling owner:  $($a17SibAcl.Owner)"
  )
  $a17Diag | ForEach-Object { Write-Host "A17 $_" }
  $rWho = ChildExec @('--', $cmd, '/d', '/s', '/c',
                      'whoami /user /groups /fo list')
  Write-Host "A17 child token (whoami):"
  $rWho.out -split "`n" | ForEach-Object { Write-Host "  $_" }
  # Attempt 1 — cmd `del` (DeleteFileW; /f also touches attrs).
  $rDel = ChildExec @('--', $cmd, '/d', '/s', '/c',
    "del /f /q `"$sib17`" 2>&1 & echo DEL_EXIT=%errorlevel%")
  Write-Host "A17 child del:    $($rDel.out.Trim())"
  # Attempt 2 — PowerShell Remove-Item (different open path; if
  # this succeeds where `del` fails, it's the cmd-builtin's
  # access mask, not the DACL).
  $rRm = ChildExec @('--', $pwsh, '-NoProfile', '-Command',
    "try { Remove-Item -LiteralPath '$sib17' -Force -ErrorAction Stop; " +
    "'RM_OK' } catch { 'RM_ERR: ' + `$_.Exception.Message }")
  Write-Host "A17 child Remove-Item: $($rRm.out.Trim())"
  if (Test-Path $sib17) {
    throw ("A17: child could NOT delete its non-protected sibling " +
           "(parent allow-list over-restricted; user should still " +
           "have file-level DELETE on inherited Modify).`n" +
           ($a17Diag -join "`n") +
           "`nchild whoami: $($rWho.out)" +
           "`nchild del:    $($rDel.out.Trim())" +
           "`nchild rm:     $($rRm.out.Trim())")
  }
  # And the file ACL is still doing its job: child read of f1
  # still denied.
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f1`"")
  if ($r.exit -eq 0) {
    throw "A17: child read of f1 allowed after del attempt. out: $($r.out)"
  }
  Remove-Item -Force $imp17 -ErrorAction SilentlyContinue
  Write-Host ('A17 ok: parent allow-list — child denied del/rename of ' +
              'stamped files; CAN delete non-protected sibling')

  # ── A21: parent OWNER_RIGHTS — child cannot WRITE_DAC parent ──
  # The OWNER_RIGHTS ACE on the parent suppresses the implicit
  # READ_CONTROL|WRITE_DAC the kernel grants the owner. Without
  # it, an owner-child could `icacls /grant` itself FDC on the
  # parent and re-open the delete/rename gap A17 just closed.
  if (-not $a17OwInBin) {
    throw "A21: OWNER_RIGHTS S-1-3-4 ACE absent from parent's binary " +
          "SD — the OW guard is not on disk. parent SDDL: " +
          "$($a17ParentAcl.Sddl)"
  }
  # The OW ACE's mask must exclude WRITE_DAC (0x40000) — the
  # whole point of the ACE.
  $a21OwMask = ($a17ParentAcl.Access |
    Where-Object { "$($_.IdentityReference)" -match 'OWNER|S-1-3-4' } |
    ForEach-Object { [int]$_.FileSystemRights })
  Write-Host "A21 parent OW mask: 0x$($a21OwMask.ToString('x'))"
  if ($a21OwMask -band 0x40000) {
    throw "A21: parent OWNER_RIGHTS ACE grants WRITE_DAC " +
          "(mask=0x$($a21OwMask.ToString('x'))). SDDL: $($a17ParentAcl.Sddl)"
  }
  $a21Me = "$env:USERDOMAIN\$env:USERNAME"
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c',
    "icacls `"$Scratch`" /grant `"${a21Me}:(F)`" 2>&1 & " +
    "echo ICACLS_EXIT=%errorlevel%")
  if ($r.out -match 'ICACLS_EXIT=0' -and
      $r.out -notmatch '(?i)access is denied') {
    throw ("A21: child icacls /grant on stamped parent SUCCEEDED — " +
           "OWNER_RIGHTS not suppressing owner WRITE_DAC. " +
           "out: $($r.out)`nparent SDDL: $($a17ParentAcl.Sddl)")
  }
  # And confirm the parent DACL was NOT modified.
  if ((Get-Acl -LiteralPath $Scratch).Sddl -ne $a17ParentAcl.Sddl) {
    throw "A21: parent DACL was modified by child's icacls. " +
          "before: $($a17ParentAcl.Sddl) " +
          "after:  $((Get-Acl -LiteralPath $Scratch).Sddl)"
  }
  Write-Host ('A21 ok: OWNER_RIGHTS on parent — child cannot ' +
              'WRITE_DAC the directory')

  # exec --holder-pid with all parents stamped → fence has nothing
  # to do (0-path fallback).
  $r = ChildExec @('--holder-pid', $Holder, '--', $cmd, '/d', '/s', '/c',
                   'echo NOFENCE')
  if ($r.raw -notmatch 'parent stamps cover all') {
    throw "A17(diag): expected '0 path(s) (parent stamps cover all)'; " +
          "raw: $($r.raw)"
  }
  Write-Host 'A17(diag) ok: fence fallback set is empty when parent stamped'

  # ── A3: restore → child can read again ────────────────────────
  Run @('acl', 'restore', '--group-sid', $GroupSid, 
        '--holder-pid', $Holder)
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f1`"")
  if ($r.exit -ne 0 -or $r.out.Trim() -ne 'A1-secret') {
    throw "A3: child read after restore failed. exit=$($r.exit) out=$($r.out)"
  }
  Write-Host 'A3 ok: restore — child reads denyRead file again'

  # ── A4: refcount — two live holders, two restores ─────────────
  # Two DIFFERENT holder PIDs claim the same path (modelling two
  # concurrent sandbox sessions). Restoring one leaves the file
  # stamped (the other still holds); restoring the second restores.
  # Holder B is a real, still-alive process so crash-recovery does
  # NOT prematurely reap it.
  $f4 = Join-Path $Scratch 'a4.txt'
  Set-Content -Path $f4 -Value 'A4' -NoNewline
  $holderB = Start-Process -FilePath $pwsh `
    -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep 120') `
    -PassThru
  try {
    Stamp @{ denyRead = @($f4) } $Holder        # holder A
    Stamp @{ denyRead = @($f4) } $holderB.Id    # holder B (alive)

    # Restore A → B still holds → file stays stamped → child denied.
    Run @('acl', 'restore', '--group-sid', $GroupSid, 
          '--holder-pid', $Holder)
    $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f4`"")
    if ($r.exit -eq 0) {
      throw "A4: file unstamped after only one of two holders released"
    }
    # Restore B → refcount 0 → restored → child reads.
    Run @('acl', 'restore', '--group-sid', $GroupSid, 
          '--holder-pid', $holderB.Id)
    $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f4`"")
    if ($r.exit -ne 0) {
      throw "A4: file still stamped after both holders released. " +
            "exit=$($r.exit) out=$($r.out)"
    }
    Write-Host 'A4 ok: refcount — two live holders, restore only on last release'
  }
  finally {
    Stop-Process -Id $holderB.Id -Force -ErrorAction SilentlyContinue
  }

  # ── A5: crash recovery via `acl recover` ──────────────────────
  # A holder process stamps then DIES without restoring. `acl
  # recover` from another process prunes the dead holder and
  # restores the orphan.
  $f5 = Join-Path $Scratch 'a5.txt'
  Set-Content -Path $f5 -Value 'A5' -NoNewline
  # Spawn a short-lived holder, capture its PID, let it exit.
  $holderC = Start-Process -FilePath $pwsh `
    -ArgumentList @('-NoProfile', '-Command', 'Start-Sleep 1') -PassThru
  Stamp @{ denyRead = @($f5) } $holderC.Id
  $holderC.WaitForExit()   # holder C is now dead

  # Confirm child IS denied (stamp took effect, holder dead but
  # snapshot persists).
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f5`"")
  if ($r.exit -eq 0) { throw 'A5: stamp did not take effect' }

  Run @('acl', 'recover', '--group-sid', $GroupSid)
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f5`"")
  if ($r.exit -ne 0) {
    throw "A5: still stamped after recover. exit=$($r.exit) out=$($r.out)"
  }
  Write-Host 'A5 ok: acl recover — orphan from dead holder restored'

  # ── A6: state-DB dir is broker-only ──────────────────────
  $stateDb = Join-Path $env:LOCALAPPDATA 'sandbox-runtime\state.db'
  if (-not (Test-Path $stateDb)) {
    throw "A6: state.db not at $stateDb"
  }
  # Child cannot write to the DB file (broker-only DACL on the
  # parent dir inherits via (OI)(CI)).
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "echo x >> `"$stateDb`"")
  if ($r.exit -eq 0) {
    throw 'A6: child WROTE to state.db (S2 dir stamp ineffective)'
  }
  Write-Host 'A6 ok: child denied write to state.db'

  # ── A7: directory in payload → clear error ────────────────────
  $json7 = @{ denyRead = @($Scratch) } | ConvertTo-Json -Compress
  $out7 = $json7 | & $Exe acl stamp --group-sid $GroupSid `
    --holder-pid $Holder 2>&1 | Out-String
  if ($LASTEXITCODE -eq 0) { throw 'A7: directory was accepted' }
  if ($out7 -notmatch '(?i)requires explicit file paths') {
    throw "A7: wrong error message: $out7"
  }
  Write-Host 'A7 ok: directory in payload rejected with clear message'

  # ── A8: glob in payload → clear error ─────────────────────────
  $json8 = @{ denyRead = @("$Scratch\*.txt") } | ConvertTo-Json -Compress
  $out8 = $json8 | & $Exe acl stamp --group-sid $GroupSid `
    --holder-pid $Holder 2>&1 | Out-String
  if ($LASTEXITCODE -eq 0) { throw 'A8: glob was accepted' }
  if ($out8 -notmatch '(?i)got glob') {
    throw "A8: wrong error message: $out8"
  }
  Write-Host 'A8 ok: glob in payload rejected with clear message'

  # ── A9: restore fidelity on an explicit-ACE, UNPROTECTED file ─
  # A1–A3 only touched purely-inherited files. This covers the
  # branch where the original DACL has an explicit ACE but is NOT
  # protected (still auto-inheriting): restore must bring back the
  # explicit ACE AND keep AreAccessRulesProtected = false (our
  # stamp forces PROTECTED; restore must undo that).
  $f9 = Join-Path $Scratch 'a9.txt'
  Set-Content -Path $f9 -Value 'A9' -NoNewline
  # Add an explicit grant for BUILTIN\Users WITHOUT breaking
  # inheritance (no /inheritance:d), so the file stays unprotected.
  & icacls $f9 /grant '*S-1-5-32-545:(R)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'A9: icacls grant failed' }
  $aclBefore = Get-Acl -Path $f9
  if ($aclBefore.AreAccessRulesProtected) {
    throw 'A9: precondition — file should be UNPROTECTED before stamp'
  }
  $sddlBefore = $aclBefore.Sddl

  Stamp @{ denyRead = @($f9) }
  # While stamped it must be protected + child-denied.
  if (-not (Get-Acl -Path $f9).AreAccessRulesProtected) {
    throw 'A9: stamp should have set PROTECTED'
  }
  Run @('acl', 'restore', '--group-sid', $GroupSid, 
        '--holder-pid', $Holder)

  $aclAfter = Get-Acl -Path $f9
  if ($aclAfter.AreAccessRulesProtected) {
    throw 'A9: restore left file PROTECTED (should be unprotected)'
  }
  if ($aclAfter.Sddl -ne $sddlBefore) {
    throw "A9: restored SDDL differs.`n before: $sddlBefore`n after:  $($aclAfter.Sddl)"
  }
  Write-Host 'A9 ok: restore is bit-exact for explicit-unprotected file'

  # ── A10: DACL-changed-since-stamp guard ───────────────────────
  # Stamp a file, then a third party (icacls) rewrites its DACL.
  # `acl restore` must NOT revert (cur != stamped) and must keep
  # the snapshot row; `acl recover --force` then DOES revert.
  $f10 = Join-Path $Scratch 'a10.txt'
  Set-Content -Path $f10 -Value 'A10' -NoNewline
  $sddl10Orig = (Get-Acl -Path $f10).Sddl
  Stamp @{ denyRead = @($f10) }
  # Third-party edit: grant Users full (admin/broker can WRITE_DAC
  # via the Admins ACE in the stamp). This moves the DACL away
  # from stamped_sd.
  & icacls $f10 /grant '*S-1-5-32-545:(F)' | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'A10: icacls edit failed' }
  $sddl10Edited = (Get-Acl -Path $f10).Sddl

  # restore: removes our holder, sees cur != stamped → leaves
  # the file as-is and keeps the snapshot row (now an orphan).
  Run @('acl', 'restore', '--group-sid', $GroupSid, 
        '--holder-pid', $Holder)
  if ((Get-Acl -Path $f10).Sddl -ne $sddl10Edited) {
    throw 'A10: restore reverted a third-party-edited DACL (should leave)'
  }

  # recover --force: now reverts to the captured original.
  Run @('acl', 'recover', '--group-sid', $GroupSid, '--force')
  $sddl10Recovered = (Get-Acl -Path $f10).Sddl
  # An UNPROTECTED restore makes the kernel run inheritance
  # evaluation and stamp the SE_DACL_AUTO_INHERITED marker bit
  # (`AI` in SDDL); the fresh-file original captured above won't
  # have it. Effective access is identical — normalize it out.
  $noAI = { param($s) $s -replace '(?<=D:)(P?)AI', '$1' }
  if ((& $noAI $sddl10Recovered) -ne (& $noAI $sddl10Orig)) {
    throw "A10: --force did not restore original.`n want: $sddl10Orig`n got:  $sddl10Recovered"
  }
  Write-Host 'A10 ok: changed-DACL left by restore, reverted by recover --force'

  # ── A11/A12 use their own fresh subdir, decoupled from $Scratch's
  # parent-stamp lifecycle (A1-A10 stamp/restore $Scratch repeatedly;
  # `icacls /inheritance:r` on a child of a directory that just went
  # PROTECTED→UNPROTECTED can produce an empty DACL — an icacls
  # quirk, not our bug, but it makes A11's setup non-deterministic).
  $d11 = Join-Path $Scratch 'd11'
  New-Item -ItemType Directory -Path $d11 | Out-Null

  # ── A11: PROTECTED original → restore is bit-exact ─────────────
  # Set up a file with an explicit PROTECTED DACL (via .NET
  # SetAccessRuleProtection — copies inherited ACEs to explicit and
  # sets PROTECTED), stamp, restore. The `was_protected=true` arm of
  # restore_sd must round-trip the SDDL exactly — including the
  # PROTECTED bit.
  $f11 = Join-Path $d11 'a11.txt'
  Set-Content -Path $f11 -Value 'A11' -NoNewline
  $sd11 = Get-Acl -LiteralPath $f11
  $sd11.SetAccessRuleProtection($true, $true)
  Set-Acl -LiteralPath $f11 -AclObject $sd11
  $acl11 = Get-Acl -LiteralPath $f11
  if (-not $acl11.AreAccessRulesProtected) {
    throw 'A11 setup: file should be PROTECTED after SetAccessRuleProtection'
  }
  if ($acl11.Access.Count -eq 0) {
    throw "A11 setup: empty DACL after SetAccessRuleProtection " +
          "(d11 SDDL: $((Get-Acl -LiteralPath $d11).Sddl))"
  }
  $sddl11Orig = $acl11.Sddl
  Stamp @{ denyRead = @($f11) }
  Run @('acl', 'restore', '--group-sid', $GroupSid,
        '--holder-pid', $Holder)
  $sddl11After = (Get-Acl -LiteralPath $f11).Sddl
  if (-not (Get-Acl -LiteralPath $f11).AreAccessRulesProtected) {
    throw 'A11: PROTECTED bit lost on restore'
  }
  if ($sddl11After -ne $sddl11Orig) {
    throw "A11: SDDL not bit-exact.`n want: $sddl11Orig`n got:  $sddl11After"
  }
  Write-Host 'A11 ok: PROTECTED original round-trips bit-exact'

  # ── A12: restore-when-already-original drops stale row ─────────
  # Stamp, then manually put the DACL back to the original (Set-Acl
  # with the captured SDDL); `acl restore` should hit Case A
  # (cur == original) — drop the row, no "DACL changed" warning.
  # The file is made PROTECTED (explicit ACEs only) BEFORE
  # capturing the original, so the original is stable regardless
  # of d11's parent-stamp state — otherwise Set-Acl would
  # re-derive inherited ACEs from d11's CURRENT (stamped) state
  # and on-disk would never match the captured original.
  $f12 = Join-Path $d11 'a12.txt'
  Set-Content -Path $f12 -Value 'A12' -NoNewline
  $sd12 = Get-Acl -LiteralPath $f12
  $sd12.SetAccessRuleProtection($true, $true)
  Set-Acl -LiteralPath $f12 -AclObject $sd12
  if ((Get-Acl -LiteralPath $f12).Access.Count -eq 0) {
    throw 'A12 setup: empty DACL after SetAccessRuleProtection'
  }
  $a12Orig = Get-Acl -LiteralPath $f12
  Stamp @{ denyRead = @($f12) }
  Set-Acl -LiteralPath $f12 -AclObject $a12Orig
  $r = RunCapture @('acl', 'restore', '--group-sid', $GroupSid,
                    '--holder-pid', $Holder)
  if ($r.raw -match 'DACL changed since stamp') {
    throw "A12: restore reported 'DACL changed' for a file already " +
          "back at its original (Case A should drop silently). raw: $($r.raw)"
  }
  # Row is gone — `acl recover` should report 0 left.
  $rec = RunCapture @('acl', 'recover', '--group-sid', $GroupSid)
  if ($rec.raw -match 'left ([1-9]\d*)') {
    throw "A12: snapshot row not dropped. raw: $($rec.raw)"
  }
  Write-Host 'A12 ok: cur==original → row dropped, no DACL-changed warning'

  # ── A13: mask escalation (denyWrite then denyRead → read denied) ─
  $f13 = Join-Path $Scratch 'a13.txt'
  Set-Content -Path $f13 -Value 'A13' -NoNewline
  $holderA = Start-Process -PassThru -WindowStyle Hidden cmd `
    -ArgumentList '/c','timeout','/t','120','/nobreak'
  $holderB = Start-Process -PassThru -WindowStyle Hidden cmd `
    -ArgumentList '/c','timeout','/t','120','/nobreak'
  try {
    Stamp @{ denyWrite = @($f13) } -HolderPid $holderA.Id
    # Under WriteDeny, child can read.
    $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f13`"")
    if ($r.exit -ne 0 -or $r.out.Trim() -ne 'A13') {
      throw "A13 setup: child read under denyWrite failed. out=$($r.out)"
    }
    # Holder B requests STRICTER denyRead on the same path → escalate.
    Stamp @{ denyRead = @($f13) } -HolderPid $holderB.Id
    $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f13`"")
    if ($r.exit -eq 0) {
      throw "A13: stricter denyRead NOT applied (mask escalation " +
            "ignored) — child read SUCCEEDED. out: $($r.out)"
    }
  } finally {
    Run @('acl', 'restore', '--group-sid', $GroupSid,
          '--holder-pid', $holderA.Id)
    Run @('acl', 'restore', '--group-sid', $GroupSid,
          '--holder-pid', $holderB.Id)
    $holderA.Kill(); $holderB.Kill()
  }
  Write-Host 'A13 ok: denyWrite then denyRead on same path → read denied'

  # ── A14: deleted-file orphan → status=missing, row KEPT ────────
  # A stamped file is deleted (broker side) and its holder dies.
  # `acl recover --json` reports it as `missing` (file_id not
  # locatable on the volume) and KEEPS the snapshot row
  # (fail-closed orphan tracking) — it does NOT silently reap.
  $f14 = Join-Path $Scratch 'a14.txt'
  Set-Content -Path $f14 -Value 'A14' -NoNewline
  $holderD = Start-Process -PassThru -WindowStyle Hidden cmd `
    -ArgumentList '/c','timeout','/t','120','/nobreak'
  Stamp @{ denyRead = @($f14) } -HolderPid $holderD.Id
  Remove-Item -Force $f14
  $holderD.Kill(); $holderD.WaitForExit()
  $j = RunJson @('acl', 'recover', '--group-sid', $GroupSid, '--json')
  $e14 = $j | Where-Object { $_.path -like "*a14.txt" }
  if (-not $e14 -or $e14.status -ne 'missing' -or
      $e14.leftStamped -ne $true) {
    throw "A14: expected status=missing leftStamped=true; got: " +
          "$($j | ConvertTo-Json -Compress)"
  }
  # Row STAYS — a second recover still reports it.
  $j2 = RunJson @('acl', 'recover', '--group-sid', $GroupSid, '--json')
  if (-not ($j2 | Where-Object { $_.path -like "*a14.txt" })) {
    throw "A14: orphan row was DROPPED on a second recover " +
          "(fail-closed: row must persist for the host to surface)"
  }
  Write-Host 'A14 ok: deleted-file orphan → status=missing, row kept'

  # ── A15/A16: fence FALLBACK — parent-stamp-fail file is fenced ─
  # The parent allow-list is the primary delete protection. When
  # a file's parent CAN'T be stamped, that file is marked
  # `parent_stamp_failed` and the per-exec handle fence covers it
  # as the fallback. Force the fallback via the test env hook
  # (an elevated broker's SeRestorePrivilege lets
  # SetNamedSecurityInfoW write any DACL regardless of a WRITE_DAC-deny
  # deny, so DACL-based test setups can't reliably make the
  # parent stamp fail on CI runners).
  $d15 = Join-Path $Scratch 'a15-noparent'
  New-Item -ItemType Directory -Path $d15 | Out-Null
  $f15 = Join-Path $d15 'fb.txt'
  Set-Content -Path $f15 -Value 'A15' -NoNewline
  $env:SRT_WIN_TEST_SKIP_PARENT_STAMP = '1'
  try {
    $stampOut = @{ denyRead = @($f15) } | ConvertTo-Json -Compress |
      & $Exe acl stamp --group-sid $GroupSid --holder-pid $Holder 2>&1 |
      Out-String
  } finally {
    Remove-Item Env:\SRT_WIN_TEST_SKIP_PARENT_STAMP
  }
  Write-Host -NoNewline $stampOut
  if ($LASTEXITCODE -ne 0) { throw "A15: stamp failed: $stampOut" }
  if ($stampOut -notmatch '1 parent-stamp fallback') {
    throw "A15: parent-stamp fallback not engaged. stamp out: $stampOut"
  }
  # exec --holder-pid → fence engages on f15 only.
  $r = ChildExec @('--holder-pid', $Holder, '--', $cmd, '/d', '/s', '/c',
                   "del /f /q `"$f15`"")
  $diag15 = ($r.raw -split "`r?`n" |
             Where-Object {$_ -match 'handle fence'}) -join ' | '
  if ($diag15 -notmatch '[1-9]\d* parent-stamp-failed path\(s\) fenced') {
    throw "A15: fallback fence diag did not report ≥1 fenced. " +
          "raw: $($r.raw)"
  }
  if (-not (Test-Path $f15) -or
      (Get-Content -Path $f15 -Raw) -ne 'A15') {
    throw "A15: child del of fallback-fenced f15 SUCCEEDED. raw: $($r.raw)"
  }
  Write-Host 'A15 ok: parent-stamp-failed file is handle-fenced (fallback)'

  # A16 (load-bearing on the fallback set): hold f15 no-share so
  # the fence open hits SHARING_VIOLATION → retries exhaust →
  # exec refuses; release → exec succeeds.
  $hold = [IO.File]::Open($f15, 'Open', 'Read', 'None')
  try {
    $r = ChildExec @('--holder-pid', $Holder, '--', $cmd, '/d', '/s', '/c',
                     'echo SENTINEL')
    if ($r.exit -eq 0 -or $r.out -match 'SENTINEL' -or
        $r.raw -notmatch 'refusing to run') {
      throw "A16: exec ran with an unfenceable fallback path. " +
            "raw: $($r.raw)"
    }
  } finally { $hold.Close() }
  $r = ChildExec @('--holder-pid', $Holder, '--', $cmd, '/d', '/s', '/c',
                   'echo SENTINEL')
  if ($r.exit -ne 0 -or $r.out -notmatch 'SENTINEL') {
    throw "A16: exec did not succeed after release. raw: $($r.raw)"
  }
  # Restore (clears the fallback row).
  Run @('acl', 'restore', '--group-sid', $GroupSid, '--holder-pid', $Holder)
  Write-Host 'A16 ok: fallback fence load-bearing — refuses on share-fail'

  # ── A18: deep tree — ancestor rmdir cannot remove protected file ─
  $d18 = Join-Path $Scratch 'a18'
  $d18b = Join-Path $d18 'b'
  New-Item -ItemType Directory -Path $d18b -Force | Out-Null
  $f18 = Join-Path $d18b 'prot.txt'
  Set-Content -Path $f18 -Value 'A18' -NoNewline
  Stamp @{ denyRead = @($f18) }
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "rmdir /s /q `"$d18`"")
  if (-not (Test-Path $f18) -or
      (Get-Content -Path $f18 -Raw) -ne 'A18') {
    throw "A18: protected file removed by ancestor rmdir /s. raw: $($r.raw)"
  }
  Run @('acl', 'restore', '--group-sid', $GroupSid, '--holder-pid', $Holder)
  Write-Host 'A18 ok: ancestor rmdir /s cannot remove protected file'

  # ── A19: relocation — DACL travels; restore → relocated ────────
  # Stamp a file in its OWN subdir, then (broker side) MOVE it
  # elsewhere. The broker-only DACL travels with the inode, so
  # the child is still denied at the NEW location — protection
  # is sticky to the data, not the path. `acl restore --json`
  # reports `relocated` with `movedTo`, leaves the stamp, and
  # keeps the row (fail-closed; never restore by inode).
  $d19 = Join-Path $Scratch 'a19'
  New-Item -ItemType Directory -Path $d19 | Out-Null
  $f19 = Join-Path $d19 'cookies.txt'
  Set-Content -Path $f19 -Value 'A19-secret' -NoNewline
  Stamp @{ denyRead = @($f19) }
  $f19m = Join-Path $Scratch 'a19-moved.txt'
  Move-Item -Force -Path $f19 -Destination $f19m
  # Child read at the NEW path → still denied (DACL traveled).
  $r = ChildExec @('--', $cmd, '/d', '/s', '/c', "type `"$f19m`"")
  if ($r.exit -eq 0) {
    throw "A19: child read of relocated file SUCCEEDED — DACL did " +
          "not travel with the inode. out: $($r.out)"
  }
  $j = RunJson @('acl', 'restore', '--group-sid', $GroupSid,
                 '--holder-pid', $Holder, '--json')
  $e19 = $j | Where-Object { $_.path -like "*cookies.txt" }
  if (-not $e19 -or $e19.status -ne 'relocated' -or
      $e19.leftStamped -ne $true -or
      $e19.movedTo -notlike "*a19-moved.txt") {
    throw "A19: expected status=relocated movedTo=*a19-moved.txt " +
          "leftStamped=true; got: $($j | ConvertTo-Json -Compress)"
  }
  # Stamp left in place (fail-closed): file at movedTo is STILL
  # broker-only after restore.
  if (-not (Get-Acl -Path $f19m).AreAccessRulesProtected) {
    throw "A19: relocated file is NOT still protected after restore"
  }
  # Move it back to the recorded path, restore again → restored.
  Move-Item -Force -Path $f19m -Destination $f19
  # The previous restore unregistered $Holder; re-register by
  # The Relocated outcome kept the snapshot row but the previous
  # restore unregistered $Holder — re-stamp to re-add the hold.
  Stamp @{ denyRead = @($f19) }
  $j = RunJson @('acl', 'restore', '--group-sid', $GroupSid,
                 '--holder-pid', $Holder, '--json')
  $e19b = $j | Where-Object { $_.path -like "*cookies.txt" }
  if (-not $e19b -or $e19b.status -ne 'restored') {
    throw "A19: after move-back, expected status=restored; got: " +
          "$($j | ConvertTo-Json -Compress)"
  }
  Write-Host ('A19 ok: relocated file stays denied; restore reports ' +
              'relocated+movedTo, leaves stamp; move-back → restored')

  # ── A20: path substitution — restore does NOT touch impostor ───
  # Stamp a file, then (broker side) DELETE it and create a NEW
  # file at the same path. file_id differs → restore reports
  # `missing` (the original is gone), keeps the row, and does
  # NOT touch the impostor's DACL.
  $d20 = Join-Path $Scratch 'a20'
  New-Item -ItemType Directory -Path $d20 | Out-Null
  $f20 = Join-Path $d20 'sub.txt'
  Set-Content -Path $f20 -Value 'A20-original' -NoNewline
  Stamp @{ denyRead = @($f20) }
  Remove-Item -Force $f20
  Set-Content -Path $f20 -Value 'A20-impostor' -NoNewline
  $sddl20Imp = (Get-Acl -Path $f20).Sddl
  $j = RunJson @('acl', 'restore', '--group-sid', $GroupSid,
                 '--holder-pid', $Holder, '--json')
  $e20 = $j | Where-Object { $_.path -like "*sub.txt" }
  if (-not $e20 -or $e20.status -notin @('missing', 'relocated') -or
      $e20.leftStamped -ne $true) {
    throw "A20: expected status∈{missing,relocated} leftStamped=true; " +
          "got: $($j | ConvertTo-Json -Compress)"
  }
  if ((Get-Acl -Path $f20).Sddl -ne $sddl20Imp) {
    throw "A20: impostor's DACL was modified by restore (must not " +
          "touch a file whose file_id differs from the snapshot)"
  }
  Write-Host ('A20 ok: path-substituted impostor untouched; ' +
              'restore reports missing/relocated, row kept')

  Write-Host 'smoke-acl: OK'
}
finally {
  # Best-effort: restore anything this process still holds, then
  # recover anything the separate-process stampers left, then
  # delete the scratch dir. A14/A19/A20 deliberately leave
  # `missing`/`relocated` orphan rows (fail-closed; no
  # by-inode cleanup by design), so also remove the state DB so
  # the next CI run starts clean. The workflow's `if: always()`
  # cleanup also runs `acl recover --force` for belt-and-braces.
  & $Exe acl restore --group-sid $GroupSid --holder-pid $Holder 2>$null
  & $Exe acl recover --group-sid $GroupSid --force 2>$null
  Remove-Item -Recurse -Force $Scratch -ErrorAction SilentlyContinue
  Remove-Item -Recurse -Force `
    (Join-Path $env:LOCALAPPDATA 'sandbox-runtime') `
    -ErrorAction SilentlyContinue
}
