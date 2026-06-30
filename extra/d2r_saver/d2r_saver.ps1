<#
    D2R Saver - simple backup/restore of offline Diablo II: Resurrected saves
    (vanilla + modded) to/from a local folder such as Google Drive for Desktop.

    Run via D2R-Saver.cmd (double-click) so the execution policy is bypassed.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# --- Paths / config -------------------------------------------------------
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$ConfigPath = Join-Path $ScriptDir 'd2r_saver.config.json'

function Get-DefaultSavePath {
    Join-Path $env:USERPROFILE 'Saved Games\Diablo II Resurrected'
}

function Load-Config {
    if (Test-Path $ConfigPath) {
        try { return Get-Content $ConfigPath -Raw | ConvertFrom-Json } catch {}
    }
    return [pscustomobject]@{ Source = ''; Dest = '' }
}

function Save-Config($source, $dest) {
    [pscustomobject]@{ Source = $source; Dest = $dest } |
        ConvertTo-Json | Set-Content -Path $ConfigPath -Encoding UTF8
}

$cfg = Load-Config

# --- UI -------------------------------------------------------------------
$form               = New-Object System.Windows.Forms.Form
$form.Text          = 'D2R Saver - offline character backup'
$form.Size          = New-Object System.Drawing.Size(640, 500)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox   = $false

function New-Label($text, $x, $y) {
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $text; $l.AutoSize = $true
    $l.Location = New-Object System.Drawing.Point($x, $y)
    $form.Controls.Add($l); return $l
}
function New-TextBox($x, $y, $w, $val) {
    $t = New-Object System.Windows.Forms.TextBox
    $t.Location = New-Object System.Drawing.Point($x, $y)
    $t.Size = New-Object System.Drawing.Size($w, 24)
    $t.Text = $val
    $form.Controls.Add($t); return $t
}
function New-Button($text, $x, $y, $w, $h) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text
    $b.Location = New-Object System.Drawing.Point($x, $y)
    $b.Size = New-Object System.Drawing.Size($w, $h)
    $form.Controls.Add($b); return $b
}

# Source (local game saves)
New-Label 'Local D2R save folder (source):' 12 15 | Out-Null
$txtSource = New-TextBox 12 36 500 ($(if ($cfg.Source) { $cfg.Source } else { Get-DefaultSavePath }))
$btnSrcBrowse = New-Button '...' 520 35 90 26
$btnDetect    = New-Button 'Auto-detect' 520 65 90 26

# Dest (Google Drive backup root)
New-Label 'Backup folder (e.g. Google Drive\D2R-Saves):' 12 105 | Out-Null
$txtDest = New-TextBox 12 126 500 $cfg.Dest
$btnDstBrowse = New-Button '...' 520 125 90 26

# Action buttons
$btnBackup  = New-Button 'BACKUP  ->  Drive'  12 175 295 60
$btnRestore = New-Button 'RESTORE  <-  Drive' 317 175 293 60
$btnBackup.Font  = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$btnRestore.Font = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$btnBackup.BackColor  = [System.Drawing.Color]::FromArgb(218, 240, 218)
$btnRestore.BackColor = [System.Drawing.Color]::FromArgb(240, 228, 218)

# Last-synced status line
$lblSync = New-Object System.Windows.Forms.Label
$lblSync.AutoSize = $false
$lblSync.Location = New-Object System.Drawing.Point(12, 243)
$lblSync.Size = New-Object System.Drawing.Size(598, 20)
$lblSync.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
$lblSync.ForeColor = [System.Drawing.Color]::FromArgb(60, 60, 60)
$form.Controls.Add($lblSync)

# Log
New-Label 'Activity log:' 12 270 | Out-Null
$log = New-Object System.Windows.Forms.TextBox
$log.Multiline = $true; $log.ReadOnly = $true; $log.ScrollBars = 'Vertical'
$log.Location = New-Object System.Drawing.Point(12, 291)
$log.Size = New-Object System.Drawing.Size(598, 150)
$log.Font = New-Object System.Drawing.Font('Consolas', 9)
$form.Controls.Add($log)

function Write-Log($msg) {
    $ts = Get-Date -Format 'HH:mm:ss'
    $log.AppendText("[$ts] $msg`r`n")
    [System.Windows.Forms.Application]::DoEvents()
}

# --- Helpers --------------------------------------------------------------
function Browse-Folder($start) {
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($start -and (Test-Path $start)) { $dlg.SelectedPath = $start }
    if ($dlg.ShowDialog() -eq 'OK') { return $dlg.SelectedPath }
    return $null
}

function Make-Snapshot($localPath, $destRoot, $tag) {
    if (-not (Test-Path $localPath)) { return }
    $snapDir = Join-Path $destRoot 'snapshots'
    if (-not (Test-Path $snapDir)) { New-Item -ItemType Directory -Path $snapDir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $zip   = Join-Path $snapDir ("{0}-{1}-{2}.zip" -f $tag, $env:COMPUTERNAME, $stamp)
    try {
        Compress-Archive -Path (Join-Path $localPath '*') -DestinationPath $zip -Force -ErrorAction Stop
        Write-Log "Snapshot saved: $(Split-Path -Leaf $zip)"
    } catch {
        Write-Log "WARNING: snapshot failed ($($_.Exception.Message)). Continuing."
    }
}

function Prune-Snapshots($destRoot, $keep = 5) {
    $snapDir = Join-Path $destRoot 'snapshots'
    if (-not (Test-Path $snapDir)) { return }
    $zips = @(Get-ChildItem -Path $snapDir -Filter '*.zip' -File | Sort-Object LastWriteTime -Descending)
    if ($zips.Count -le $keep) { return }
    foreach ($old in $zips[$keep..($zips.Count - 1)]) {
        try { Remove-Item $old.FullName -Force; Write-Log "Pruned old snapshot: $($old.Name)" } catch {}
    }
}

# last_sync.json lives in the backup ROOT (outside 'current'), so /MIR never touches it.
function Write-SyncMeta($destRoot, $action) {
    try {
        [pscustomobject]@{
            machine = $env:COMPUTERNAME
            action  = $action
            time    = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
        } | ConvertTo-Json | Set-Content -Path (Join-Path $destRoot 'last_sync.json') -Encoding UTF8
    } catch {}
}

function Refresh-SyncStatus {
    $dst = $txtDest.Text.Trim()
    $metaPath = if ($dst) { Join-Path $dst 'last_sync.json' } else { '' }
    if ($metaPath -and (Test-Path $metaPath)) {
        try {
            $m = Get-Content $metaPath -Raw | ConvertFrom-Json
            $self = if ($m.machine -eq $env:COMPUTERNAME) { ' (this PC)' } else { '' }
            $lblSync.Text = "Backup last updated: $($m.action) by $($m.machine)$self on $($m.time)"
            return
        } catch {}
    }
    $lblSync.Text = 'Backup last updated: (none yet for this folder)'
}

function Run-Mirror($from, $to) {
    if (-not (Test-Path $to)) { New-Item -ItemType Directory -Path $to -Force | Out-Null }
    Write-Log "Mirroring:"
    Write-Log "  from: $from"
    Write-Log "  to:   $to"
    # /MIR mirror, retry lightly, terse output, exclude our own snapshot dir just in case
    $args = @($from, $to, '/MIR', '/R:2', '/W:2', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/XD', 'snapshots')
    & robocopy @args | Out-Null
    $code = $LASTEXITCODE
    # robocopy: 0-7 = success (8+ = error)
    if ($code -lt 8) {
        Write-Log "Done (robocopy code $code). Files synced."
        return $true
    } else {
        Write-Log "ERROR: robocopy failed (code $code). Nothing trusted."
        return $false
    }
}

function Validate-Paths([switch]$needDestContent) {
    $src = $txtSource.Text.Trim()
    $dst = $txtDest.Text.Trim()
    if (-not $src) { [System.Windows.Forms.MessageBox]::Show('Pick the local save folder first.'); return $null }
    if (-not $dst) { [System.Windows.Forms.MessageBox]::Show('Pick the backup folder first.'); return $null }
    return [pscustomobject]@{ Src = $src; Dst = $dst }
}

# --- Events ---------------------------------------------------------------
$btnSrcBrowse.Add_Click({
    $p = Browse-Folder $txtSource.Text
    if ($p) { $txtSource.Text = $p }
})
$btnDstBrowse.Add_Click({
    $p = Browse-Folder $txtDest.Text
    if ($p) { $txtDest.Text = $p }
})
$txtDest.Add_TextChanged({ Refresh-SyncStatus })
$btnDetect.Add_Click({
    $d = Get-DefaultSavePath
    if (Test-Path $d) { $txtSource.Text = $d; Write-Log "Detected save folder: $d" }
    else { Write-Log "Default location not found: $d  (use ... to browse)"; [System.Windows.Forms.MessageBox]::Show("Not found at default location:`n$d`n`nUse the ... button to browse.") }
})

$btnBackup.Add_Click({
    $p = Validate-Paths
    if (-not $p) { return }
    if (-not (Test-Path $p.Src)) { [System.Windows.Forms.MessageBox]::Show("Local folder does not exist:`n$($p.Src)"); return }
    $msg = "BACKUP: copy your local saves UP to the backup folder?`n`nThis makes the backup match your local saves (extra files in the backup will be removed).`n`nMake sure D2R is closed."
    if ([System.Windows.Forms.MessageBox]::Show($msg, 'Confirm Backup', 'OKCancel', 'Question') -ne 'OK') { return }
    $form.Enabled = $false
    try {
        Write-Log '=== BACKUP started ==='
        Make-Snapshot $p.Src $p.Dst 'backup'
        Prune-Snapshots $p.Dst 5
        $target = Join-Path $p.Dst 'current'
        if (Run-Mirror $p.Src $target) {
            Save-Config $p.Src $p.Dst
            Write-SyncMeta $p.Dst 'backup'
            Refresh-SyncStatus
            Write-Log '=== BACKUP complete ==='
        }
    } finally { $form.Enabled = $true }
})

$btnRestore.Add_Click({
    $p = Validate-Paths
    if (-not $p) { return }
    $source = Join-Path $p.Dst 'current'
    if (-not (Test-Path $source)) { [System.Windows.Forms.MessageBox]::Show("No backup found at:`n$source`n`nRun a Backup from another machine first."); return }
    $msg = "RESTORE: copy saves DOWN from the backup to this PC?`n`nThis makes your local saves match the backup (local files not in the backup will be removed). A snapshot of your current local saves is taken first.`n`nMake sure D2R is closed."
    if ([System.Windows.Forms.MessageBox]::Show($msg, 'Confirm Restore', 'OKCancel', 'Warning') -ne 'OK') { return }
    $form.Enabled = $false
    try {
        Write-Log '=== RESTORE started ==='
        Make-Snapshot $p.Src $p.Dst 'prerestore'
        Prune-Snapshots $p.Dst 5
        if (Run-Mirror $source $p.Src) {
            Save-Config $p.Src $p.Dst
            Refresh-SyncStatus
            Write-Log '=== RESTORE complete ==='
        }
    } finally { $form.Enabled = $true }
})

# Initial hint
if (Test-Path $txtSource.Text) { Write-Log "Source folder looks good: $($txtSource.Text)" }
else { Write-Log "Source not found yet - use Auto-detect or the ... button." }
Write-Log 'Tip: set the backup folder to a path inside your Google Drive (e.g. G:\My Drive\D2R-Saves).'
Refresh-SyncStatus

[void]$form.ShowDialog()
