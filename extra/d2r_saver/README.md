# D2R Saver

Tiny, zero-install Windows app to back up and restore your **offline** Diablo II:
Resurrected character saves (vanilla **and** modded) between computers via a shared
folder such as **Google Drive for Desktop**.

No installation, no dependencies — it's a PowerShell script with a small GUI.

## Use it

1. **Close Diablo II: Resurrected** (don't sync while the game is running).
2. Double-click **`D2R-Saver.cmd`**.
3. The **local save folder** auto-fills to
   `%USERPROFILE%\Saved Games\Diablo II Resurrected`. If it's blank or wrong, click
   **Auto-detect** or **`...`** to browse.
4. Set the **backup folder** to a path inside your Google Drive, e.g.
   `G:\My Drive\D2R-Saves`. Use the same path on every machine.
5. Click **BACKUP -> Drive** before you leave a computer.
6. On the other computer, click **RESTORE <- Drive** before you play.

Your paths are remembered in `d2r_saver.config.json` next to the script, so you only
pick them once per machine.

## What it does

- **Backup** mirrors your local saves into `<backup folder>\current`.
- **Restore** mirrors `<backup folder>\current` back onto this PC.
- **Mirror** means the destination is made to *match* the source exactly (files removed
  on one side get removed on the other) — that's what keeps two computers truly in sync.
- **Safety net:** before every backup *and* every restore, it zips your current local
  saves into `<backup folder>\snapshots\` (named by machine + timestamp). These are tiny.
  If a sync ever goes wrong, unzip the latest snapshot to recover.

## Recommended workflow

> Finish playing → **Backup** → switch computers → **Restore** → play.

Always backup on the machine you just finished on, and restore on the machine you're
about to play on. That keeps `current` as the single source of truth and avoids
overwriting newer progress with older saves.

## Notes

- Both vanilla and modded saves live under the one `Diablo II Resurrected` folder
  (mods save into `...\mods\<ModName>\`), so the whole folder is synced together.
- Tip: keep this folder (the `.ps1`, `.cmd`, and config) in Google Drive too, so the
  tool itself travels with your saves.
- `robocopy` (built into Windows) does the copying; exit codes 0–7 are success.
