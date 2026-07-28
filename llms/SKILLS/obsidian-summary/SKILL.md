---
name: obsidian-summary
description: "Summarize the current troubleshooting/triage conversation into a structured technical note in Chris's Obsidian vault at ~/Documents/Devault/AI Notes/. Produces Summary / Problem / Steps & Commands / Validation / Troubleshooting sections from what actually happened in this session — real commands, real errors, real fixes. Trigger phrases: 'summarize this into notes', 'summarize to obsidian', 'document this', 'write this up'."
argument-hint: "[optional: note title override]"
allowed-tools: Read, Write, Bash
---

# obsidian-summary — triage session → Obsidian technical note

Turns the conversation that just happened into a durable note Chris can find in six months.

## Do NOT fork this skill into a subagent

This skill has no `context: fork` on purpose. **The conversation IS the input.** The note's value is the real commands, real error strings, and real dead ends from this session. A subagent with a summarized or partial view produces a plausible-sounding note describing work that didn't happen that way — which is worse than no note, because it looks authoritative.

If the conversation has already been compacted and the specific commands and errors are no longer available, say so plainly and write the note only from what remains, marking thin sections with `> [!warning] Reconstructed from summary — commands not verbatim.` Do not fill gaps with plausible-looking commands.

## STEP 0 — Vault paths

- Vault root: `/Users/chris.boyd/Documents/Devault`
- **Target folder: `/Users/chris.boyd/Documents/Devault/AI Notes/`** — everything this skill writes goes here, with no exceptions. Do not route to `Documentation/`, `Customers/`, or anywhere else even when the content is clearly customer- or topic-specific. Chris keeps this folder as the single landing zone for agent-authored notes so he can review and file them himself. Obsidian resolves `[[wikilinks]]` across the whole vault regardless of folder, so cross-linking costs nothing.

Create the folder with `mkdir -p` if it's missing.

## STEP 1 — Title and filename

Parse `$ARGUMENTS`. If non-empty, that's the title verbatim. If empty, derive one.

Match the vault's existing naming style — descriptive, human-scannable, no date prefixes, no kebab-case:

- Good: `ACP Troubleshooting 504 Timeout`, `Could not resolve Linux kernel version`, `Helm Release Stuck Pending-Upgrade`
- Bad: `2026-07-28-troubleshooting`, `session-summary`, `notes`, `k8s-debug-writeup`

Lead with the concrete symptom or subject, not the activity. `Karpenter Nodes Not Scaling on GPU Taint` beats `Debugging Karpenter`.

Filename is `<Title>.md`. Check for an existing file at that path first. If one exists, **do not overwrite** — append ` (YYYY-MM-DD)` using today's date and report both paths at the end so Chris can merge them himself.

## STEP 2 — Redaction (do this while drafting, not as a cleanup pass)

Triage conversations are full of credentials. The vault already has live API keys sitting in plaintext in `Research.md`, so treat this as a real failure mode, not a hypothetical.

Replace with `<REDACTED>` — this matches the existing convention in `Documentation/ACP Troubleshooting 504 Timeout.md`:

- Bearer tokens, `ps-*`, `sk-*`, `ghp_*`, `AKIA*`, JWTs
- `kubeconfig` contents, client certs, private keys, `.pem` / `.key` bodies
- Passwords, connection strings with embedded credentials (`postgres://user:pw@...`)
- `--set` Helm values or env vars whose name contains `SECRET`, `TOKEN`, `PASSWORD`, `KEY`, `CREDENTIAL`

Keep — these are what make the note useful later:

- Cluster names, namespaces, service names, pod names
- Internal hostnames and `*.svc.cluster.local` addresses
- Customer names (the vault is already organized by customer)
- Session/request UUIDs, image tags and digests, version numbers

When in doubt on something that isn't clearly a secret, keep it and flag the line. An over-redacted note is useless; a note leaking a live token is a problem.

## STEP 3 — Note structure

Write exactly these sections in this order. Omit a section entirely if there's genuinely nothing for it — do not emit an empty header with "N/A" under it.

````markdown
---
date: <YYYY-MM-DD>
tags: [ai-note, <2-4 topic tags: k8s, helm, tls, ldap, vllm, aws, psql, ...>]
status: <resolved | workaround | unresolved>
---

# <Title>

## Summary

<2-4 sentences. What broke, what the cause turned out to be, what fixed it. Someone
who reads only this paragraph should know whether the note is worth opening further.
Write the resolution here — do not make the reader hunt for it.>

## Problem

<The symptom as first observed, with the actual error text in a fenced block.
Include the context that mattered: cluster, version, what changed just before.
If the initial symptom turned out to be misleading, say so — that's useful signal.>

## Steps / Commands

<The commands actually run, in order, in fenced blocks. Annotate each with what it
was for and what it showed. This is the section Chris will copy from, so it must be
literal and runnable — real flags, real values (redacted), no placeholder pseudo-commands.

Include the diagnostic commands that ruled things out, not just the fix. The
elimination path is most of the value.>

## Validation

<How we confirmed the fix held. The specific command and the expected output.
If it wasn't validated, say exactly that — "not validated, cluster torn down before
retest" — rather than implying it was.>

## Troubleshooting

<Dead ends, wrong hypotheses, and gotchas. What looked like the cause but wasn't.
Error messages that were misleading. Anything that would have saved time if known
up front. If a fix is a workaround rather than a root-cause fix, flag it here with
what the real fix would require.>
````

## STEP 4 — Cross-link

Before writing, list `/Users/chris.boyd/Documents/Devault/Documentation/` and `AI Notes/` and check for notes on the same subject. If there's a clear match, add a `## Related` section at the end with `[[Note Name]]` wikilinks (no `.md` extension, no path — Obsidian resolves by filename).

Only link genuine matches. Two or three real links beat ten speculative ones, and a wrong link sends future-Chris down the wrong path.

## Fidelity rules

These are the difference between a note worth keeping and confident-sounding fiction:

- **Never invent a command that wasn't run.** If the natural next step wasn't actually executed, put it under Troubleshooting as "untested next step," not under Steps / Commands.
- **Quote errors verbatim.** Don't paraphrase a stack trace or tidy up an error string — the exact text is what makes it greppable and searchable later.
- **Preserve the failures.** A note that reads as a clean linear path to the answer is a lie about how the debugging went and strips out the most valuable part.
- **Don't editorialize.** No "successfully resolved!", no "hopefully this helps". Terse infra-engineer voice, matching the rest of the vault.
- **Uncertainty gets marked.** If root cause is a hypothesis rather than a confirmed finding, write it as one.

## Output discipline

After writing, print only:

```
Wrote: /Users/chris.boyd/Documents/Devault/AI Notes/<Title>.md

<one-line summary of the note>
Redacted: <N secrets, or "none">
<"⚠️ <Title>.md already existed — wrote to <Title> (YYYY-MM-DD).md instead" if applicable>
```

Do not echo the note body back into the conversation — Chris opens it in Obsidian. The file is the deliverable.
