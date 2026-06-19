---
name: weekly-status
description: "Draft Chris's weekly Lattice status report by pulling the past 7 days of GitHub PR activity (created, merged, reviewed/commented), Linear completed issues, calendar meetings attended, local git commits across ~/poolside/git/*, and major themes from Slack discussions where Chris participated. Writes a plain-text file to ~/Documents/Poolside/weekly-updates/<WEEK_END>.txt covering the four standard Lattice questions, ready to paste into the form."
argument-hint: "[week-ending: YYYY-MM-DD (default: today)]"
context: fork
agent: general-purpose
allowed-tools: Bash, Write, mcp__claude_ai_Linear__list_issues, mcp__claude_ai_Linear__get_issue, mcp__github__search_pull_requests, mcp__github__search_issues, mcp__github__pull_request_read, mcp__claude_ai_Google_Calendar__list_events, mcp__claude_ai_Google_Calendar__list_calendars, mcp__claude_ai_Slack__slack_search_public_and_private, mcp__claude_ai_Slack__slack_read_thread, mcp__claude_ai_Slack__slack_read_channel
---

# /weekly-status — Lattice weekly update draft

## STEP 0 — Resolve the time window (do this FIRST)

Parse `$ARGUMENTS`:
- Empty → `WEEK_END = today` (local TZ).
- `YYYY-MM-DD` → use that as `WEEK_END`.

Compute `WEEK_START = WEEK_END - 7 days` (ISO date). All "past week" queries use `[WEEK_START, WEEK_END]` inclusive.

For "next week" queries (Q2 priorities), use `[WEEK_END, WEEK_END + 7 days]`.

State the window once at the top of the output, then fall silent: `Reporting week: WEEK_START → WEEK_END`.

## About me (Chris)

- Linear identity: `625e27e9-da21-4e44-9a67-aec53ce5d5c6` (email: chris.boyd@poolside.ai, displayName: chris.boyd)
- GitHub identity: `chrisaboyd`
- Slack identity: `U08NJ3Z532T`
- Role: Cleared. Solutions Architect
- Voice: terse, infra-engineer, no marketing fluff. Bullets do the talking; prose is one or two sentences max per section.

## Lattice form constraints — plain text only

Lattice's status form **does not render Markdown formatting characters** when pasted in — verified by Chris on 2026-05-08. The literal `**`, `*`, and `_` characters appear in the saved update unrendered. Therefore:

- **No bold** (`**word**`) — drop entirely.
- **No italics** (`*word*` or `_word_`) — drop entirely.
- **No Markdown headings** (`##`) — use the `#`-separator banners described in the output format below.
- **Bullet lists** with `-` and numbered lists with `1.` are fine — they're plain ASCII.
- **Inline links** `[text](url)` — kept for now (Lattice may auto-detect them on paste). If a future run shows links pasted as raw `[text](url)`, drop them and inline the URL.
- **No tables, no fenced code blocks**.
- **No leading-line indentation**. Every line starts at column 0 — no indented bullets, no indented continuation lines. Use long unwrapped lines instead of hard-wrapping at 80 columns.

Lattice API key generation requires super-admin privileges, so the skill **does not** auto-submit. The skill writes the report to `~/Documents/Poolside/weekly-updates/<WEEK_END>.txt` for the user to open and paste.

## Data gathering

Run all sources in parallel where the tool API allows. Each section below is mandatory — there is no scope filter on this skill.

### 1. GitHub — past 7 days

Owner: `poolsideai`. Repos in scope:
- `tf_aws_reference_architecture`
- `reference_architectures`
- `public-docs`
- `forge`

Two searches via `mcp__github__search_pull_requests` (it all counts — created, merged, and contributed-to):

1. **PRs I authored** — `is:pr author:chrisaboyd created:WEEK_START..WEEK_END` and separately `is:pr author:chrisaboyd merged:WEEK_START..WEEK_END`. Dedupe by URL. Note state (open/merged/closed) and merge date if any.
2. **PRs I contributed to** — `is:pr -author:chrisaboyd involves:chrisaboyd updated:WEEK_START..WEEK_END`. These are PRs where Chris reviewed, commented, was requested as reviewer, or was assigned. Capture repo, number, title, and the nature of the contribution if surfaced (review/comment/co-author).

For each PR, capture: `[repo#N](url) — title (state, action: created/merged/reviewed)`.

### 2. Linear — past 7 days completed

Team key: **`SAS`** (Solutions Architects), team UUID `5700ecb6-3e76-440d-aa22-6ef3b8228d96`.

Use `mcp__claude_ai_Linear__list_issues`:
- `team: "SAS"`
- `assignee: "me"` (literal string `me` — the email form has been observed to silently return zero)
- `orderBy: "updatedAt"`
- `limit: 50`

**Do NOT pass `state` as a comma-separated list.** The `state` parameter accepts a single value only and silently returns `[]` on a list. Omit `state` and filter client-side using `statusType`:
- Keep: `completed` (Done) where `completedAt >= WEEK_START`
- Drop: anything else for the "this week" surface

Sanity check: if the filtered list is empty, fetch one well-known issue (e.g. `mcp__claude_ai_Linear__get_issue id="SAS-78"`) to verify the MCP is returning data at all before reporting "zero issues" — silent zero is almost always a query bug.

### 3. Linear — in progress (for next week's priorities)

Same call as above, but filter `statusType ∈ {started, unstarted}`. Keep top ~5 by `updatedAt` desc — these are the candidates for "what I'm working on next."

### 4. Calendar — past 7 days attended

Use `mcp__claude_ai_Google_Calendar__list_events` against the primary calendar:
- `startTime`: `WEEK_START` (ISO-8601 with TZ)
- `endTime`: `WEEK_END` (ISO-8601 with TZ)
- `orderBy: "startTime"`
- `pageSize: 100`
- `eventTypeFilter: ["default", "outOfOffice", "focusTime"]`

Filter heuristics:
- **Keep**: customer-facing meetings (title or attendee domain matches `rtx.com`, `raytheon.com`, `indigo.*`, `customer-*`, or has "customer", "RTX", "Indigo" in the title), notable internal meetings (interviews, design reviews, leadership syncs), and OOO/focus blocks ≥ half a day.
- **Drop**: recurring 1:1s, internal standups, lunch, daily syncs.

Roll up the result as a count-line: `N customer meetings, M internal/notable, K OOO blocks` plus the customer-meeting list with date and title.

### 5. Calendar — next 7 days (for priorities)

Same call, window `[WEEK_END, WEEK_END + 7 days]`. Surface customer-facing meetings only — those drive Q2 prep.

### 6. Slack — significant discussions where Chris participated

The goal is **major themes**, not a thread-by-thread digest. Lattice readers don't need raw Slack content — they need to know "Chris was deep on X with the RTX customer team this week."

**Priority channels** (customer-facing or directly Chris's domain):
- `#solution-architects` (note: SINGULAR — `solution-architects`, not `solutions-architects`)
- `#customer-rtx`
- `#customer-indigo`
- `#external-rtx-poolside`
- `#docs`
- `#engineering-cloud-backend`

**Secondary channels** (only if first-pass results are thin):
- `#public-sector-sales`
- `#support-poolside`
- `#product`

Search via `mcp__claude_ai_Slack__slack_search_public_and_private`:

1. **Threads Chris participated in this week**: `from:<@U08NJ3Z532T> after:WEEK_START before:WEEK_END` — every message Chris posted in the window.
2. **Threads where Chris was @-mentioned and replied**: `to:<@U08NJ3Z532T> after:WEEK_START before:WEEK_END` — combine with (1) and dedupe by thread `permalink`.

For each candidate thread:
- Skip if Chris posted ≤ 1 message and the thread looks like a reaction or one-line ack.
- Skip standup-bot threads, automated notifications, GitHub/Linear notification mirrors.
- Keep threads where Chris posted ≥ 2 substantive messages OR the thread topic clearly involves Chris's domain (architecture decision, customer ask, doc review).

For kept threads, fetch one with `mcp__claude_ai_Slack__slack_read_thread` only when the thread title/first message is ambiguous — otherwise the search snippet is enough to extract a theme.

**Theme rollup:** group kept threads into 2-4 themes max (e.g., "RTX IRSA verification", "AWS ref-arch GovCloud story", "Docs cert stack rotation"). Each theme gets one bullet in the output with a link to the most representative Slack permalink. Do **not** emit a bullet per thread — Lattice doesn't want a Slack log.

### 7. Local git commits — past 7 days

Catches work-in-progress not yet in a PR (drafts, scratch branches, dotfiles tweaks).

Run via Bash:

```bash
WEEK_START="<ISO date computed in step 0>"
find ~/poolside/git -maxdepth 2 -type d -name .git -prune | while read gitdir; do
  repo="$(dirname "$gitdir")"
  out="$(git -C "$repo" log --author=chrisaboyd --since="$WEEK_START" --pretty=format:'%h %s' 2>/dev/null)"
  if [ -n "$out" ]; then
    echo "=== $(basename "$repo") ==="
    echo "$out"
    echo
  fi
done
```

Also check `~/.dotfiles` (Chris keeps configs there) — these are the most active outside `~/poolside/git`.

For each repo with commits, capture `repo-name: N commits` with up to 3 representative commit subjects. Don't dump every commit — Lattice doesn't need the full git log. Use this primarily as a sanity check against the GitHub PR view: if there are many commits but no corresponding PRs, that's a "still cooking" theme worth surfacing in Q2 priorities.

## Synthesis — drafting the four answers

Once all data is gathered, group findings into **themes** (not sources). Common themes for Chris based on memory:
- Public docs (public-docs Mintlify content, deployment posture rewrites)
- Forge / security (forge repo)
- Customer engagements (RTX, Indigo — Slack threads + customer-domain calendar meetings)
- Internal/team (interviews, design reviews, ECC tooling)

For each theme, draft a one-line bullet summarizing the work, with inline links to the strongest evidence (1-3 PR/issue/Slack links per bullet, not all of them).

### Roadblocks signal detection (for Q3)

Auto-detect candidate roadblocks. Surface up to 5, clearly labeled as "review and edit":
- **Stalled review**: open PR authored by Chris with `requested_reviewers` set and no review activity in ≥ 5 days.
- **Stale issue**: Linear issue assigned to Chris with `statusType=started` and `updatedAt` older than 10 days.
- **Blocked label**: any GitHub PR or Linear issue with a label containing "blocked" or "waiting".
- **Out-of-band ask**: Linear issues created in the past week assigned to Chris with no comment activity from him (suggests he hasn't engaged yet).
- **Unanswered Slack thread**: thread in a priority channel where Chris was @-mentioned this week and posted no reply.

If no signals fire, leave the section as a blank prompt for Chris to fill manually — do not invent roadblocks.

## Output format — plain text, file-first

Compose the report as **plain text only** following the template below, then **write it to a file** at:

`/Users/chris.boyd/Documents/Poolside/weekly-updates/<WEEK_END>.txt`

(Use the literal absolute path. The directory already exists; if it ever doesn't, `mkdir -p` it first via Bash.)

Use the `Write` tool to create the file. Overwrite if it already exists — running the skill twice on the same `WEEK_END` should refresh the contents with the latest data.

### File contents — paste this verbatim structure, populated

Rules:
- **No Markdown bold or italics anywhere** — `**`, `*`, `_` characters render literally in Lattice and look broken. The only allowed `*`/`_`/`#` characters are inside URLs and in the section-banner separators.
- **No leading-line indentation** — every line begins at column 0. Bullets `-` are at column 0. Continuation text for a bullet stays on the same long line; do not soft-wrap into indented runover.
- **Long lines** — let lines run as long as needed. Do not hard-wrap at 80 columns.
- **Inline links** `[text](url)` are kept (Lattice may auto-detect them on paste). If a future run shows them pasted as raw `[text](url)`, switch to inlining the bare URL after the title text and remove the markdown brackets.
- **Theme labels** end with a colon on their own line. No bold, no special chars beyond the colon.
- **Section banners** are three-line `#`-style separators (see template). Use the same banner shape every section so it reads as a deliberate divider, not a typo.

```
Reporting week: <WEEK_START> -> <WEEK_END>


###############################################################################
# Q1  --  WHAT DID I FOCUS ON THIS WEEK?                                      #
###############################################################################

<one or two terse prose sentences naming the 2-3 main themes — no bold, no italics>

<Theme 1 name>:
- <bullet with link>
- <bullet with link>

<Theme 2 name>:
- <bullet with link>

<Theme 3 name (if applicable)>:
- <bullet with link>


###############################################################################
# Q2  --  WHAT ARE MY PLANS AND PRIORITIES FOR NEXT WEEK?                     #
###############################################################################

<one terse prose sentence framing the week ahead>

1. <in-progress Linear issue or open PR with link>
2. <upcoming customer-facing meeting prep>
3. <next theme item>


###############################################################################
# Q3  --  WHAT CHALLENGES OR ROADBLOCKS DO I NEED HELP WITH?                  #
###############################################################################

Auto-detected signals (review, edit, or delete before submitting):

- <signal 1 with link and age>
- <signal 2 with link and age>

(If no signals fire: replace the heading line with "Nothing blocking — fill in if you want to surface anything." and omit the bullet list entirely.)


###############################################################################
# Q4  --  IS THERE ANYTHING ELSE ON MY MIND I'D LIKE TO SHARE?                #
###############################################################################

(blank — fill in if needed)
```

The banner shape is exactly: 79 `#` characters on the top and bottom row, with the middle row reading `# Q<N>  --  <UPPERCASE QUESTION TEXT>` padded with spaces to a `#` at column 79. You don't need to count to the byte — close enough is fine — but keep the shape visually rectangular.

### After writing the file

Print **only this** to the conversation (not the full report content):

```
Wrote: /Users/chris.boyd/Documents/Poolside/weekly-updates/<WEEK_END>.txt

Open and paste into Lattice. Roadblocks section has auto-detected signals — review before submitting.

Detected signals (preview):
- <one-line summary of each signal, max 5>
```

If no roadblock signals fired, replace the "Detected signals (preview)" block with `No roadblocks auto-detected.`

## Output discipline (subagent)

This skill runs in a forked subagent context (`context: fork`). Raw MCP results, git log dumps, Slack thread bodies, and intermediate dedup tables live in the subagent's window and are discarded.

**The file is the deliverable.** Return ONLY the short post-write block (file path + paste reminder + roadblock preview) to the main conversation. Do not include:
- The full report content (it's in the file)
- Raw MCP tool outputs
- "I queried GitHub, then Linear, then..." narration
- Full commit lists (only representative subjects, and only inside the file)
- Full Slack thread transcripts
- Tool-call counts or stats

The user opens the file in their editor and pastes from there. The conversation surface stays clean.

## Notes

- If a Linear issue is referenced from a GitHub PR title (e.g., `[SAS-42]`) or vice versa, link only one of the two — pick whichever surfaces the work more clearly to a non-engineer audience (Lattice readers may not have GitHub access).
- Skip Gmail entirely — it's covered by `/triage` for forward-looking work; weekly-status is about completed and contributed work.
- If any MCP server (GitHub, Linear, Calendar, Slack) is unreachable, note it inline in the output (`_⚠️ Slack MCP unreachable — discussion themes this week may be missing._`) rather than failing the whole skill.
- The `created/merged/reviewed` action label on GitHub bullets is important — it tells Lattice readers whether Chris shipped it or contributed to someone else's work. Don't drop that label.
- Slack themes should never quote raw message text — paraphrase into a one-line theme. Customer-channel content is sensitive.

