# HARNESS-BEHAVIORS — verified `agy` hook and permission behavior

**Build tested:** `agy` 1.1.27 (`~/.local/bin/agy`, Go binary, stripped)
**Host:** Fedora Linux 44, bash 5.3.9 (`/bin/sh` -> bash), Python 3.14.7
**Date:** 2026-09-07
**Model used by agy during checks:** `gemini-3.8-flash-high` (default)

Everything below was observed on the installed build, not taken from docs. Re-run
`tests/verify-harness.sh` after every `agy update` and diff the result against this file.

## Where things live on this machine

| Item | Path | Notes |
|---|---|---|
| Settings | `~/.gemini/antigravity-cli/settings.json` | `toolPermission` key; agy rewrites the file and drops the key when it equals the default `request-review` (`omitempty`). |
| Global hooks | `~/.gemini/config/hooks.json` | Did not exist before this work. Hook commands run via `sh -c` with cwd = this directory. |
| Workspace hooks | `<workspace>/.agents/hooks.json` | Loaded only once the folder is trusted (changelog). `.agents/` is gitignored in this repo. |
| Hook doc | embedded in the binary (`strings agy \| grep -A200 'Lifecycle Hooks'`) and https://antigravity.google/docs/hooks | |
| Changelog | `agy changelog` | |

## Hook surface (from the embedded doc, confirmed by probes)

- Events: `PreToolUse`, `PostToolUse`, `PreInvocation`, `PostInvocation`, `Stop`.
- `hooks.json` shape: `{"<hook-name>": {"enabled": true, "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "<sh command>", "timeout": <seconds, default 30>}]}]}}`.
- Matcher is a regex on the tool name; `*` or `""` matches all tools.
- **Stdin (PreToolUse):** `{"toolCall": {"name": "run_command", "args": {...}}, "stepIdx": 2, "conversationId": "...", "workspacePaths": [...], "transcriptPath": "...", "artifactDirectoryPath": "...", "modelName": "..."}`. Keys are camelCase.
- **Stdout:** `{"decision": "allow|deny|ask|force_ask|deny_unless_prior_grant", "reason": "...", "permissionOverrides": [...], "overwrite": {...}}`. Enum confirmed from the binary's `jsonschema:"required,enum=allow,enum=deny,enum=ask,enum=force_ask,enum=deny_unless_prior_grant"`.
- **Hookable tools** (matcher `*` observed firing for): `run_command`, `write_to_file`, `view_file`, `list_dir`, `read_url_content`. Doc lists additionally: `replace_file_content`, `multi_replace_file_content`, `find_by_name`, `grep_search`, `search_web`, `manage_task`, `schedule`, `list_permissions`, `ask_permission`, `invoke_subagent`, `define_subagent`, `send_message`, `manage_subagents`, `ask_question`, `generate_image`. So file writes and URL reads **are** enforceable, not only shell commands.
- Observed `run_command` args: `{"CommandLine": "touch t2.txt", "Cwd": "~", "WaitMsBeforeAsync": 5000, "toolAction": "...", "toolSummary": "..."}` (`Blocking` absent; `Cwd` was `"."` in one run).
- Observed `write_to_file` args: `{"TargetFile": "~/w8.txt", "CodeContent": "hello", "Overwrite": "true", "Description": "..."}`.
- Observed `view_file` args: `{"AbsolutePath": ..., "StartLine": "1", "EndLine": "50"}`; `list_dir`: `{"DirectoryPath": ...}`; `read_url_content`: `{"Url": "https://example.com/"}`.
- Transcript at `transcriptPath` is JSONL with `type` in `USER_INPUT`, `PLANNER_RESPONSE`, `GENERIC` (tool results). The engine reads only `USER_INPUT` and `PLANNER_RESPONSE` text for classifier context, never `GENERIC`.

## Empirical checks

Harness: probe hook at `probe/probe-hook.sh` (records stdin, returns a decision chosen by a mode file), installed as the only entry in `~/.gemini/config/hooks.json` with matcher `*` and `timeout: 3`. Headless runs used:

```
cd <scratch-ws> && agy --print-timeout 150s --output-format json -p "Run exactly this shell command and nothing else, then stop: touch tN.txt. If the command is blocked or denied, reply with the exact denial reason text you received, verbatim. Do not retry with a different approach."
```

Interactive runs used a pseudo-terminal only to *observe* the TUI (`agy --add-dir <ws> -i "<same prompt>"`), no keystrokes were sent until teardown.

| # | Check | Mode | Hook returned | Result | Verdict |
|---|---|---|---|---|---|
| T1 | Baseline, no hook | request-review, `-p` | n/a | Not executed. JSON `denied_actions: [{"action":"command"}]`, stderr: "a tool required the 'command' permission that headless mode cannot prompt for, so it was auto-denied". | Headless no longer stalls (issue #548 is fixed in 1.1.27); it soft-denies. |
| T2 | (a)(d) hook fires under always-proceed, headless | always-proceed, `-p` | `allow` | Hook received 1 call (`run_command`); command executed. | **(a) PASS, (d) PASS** |
| T4 | (b) deny blocks | always-proceed, `-p` | `deny` + reason | Not executed. Model reply: `tool call denied by pre-tool hook: PROBE-DENY-7731: blocked by policy probe`. | **(b) PASS**, reason is surfaced verbatim to the model. |
| T5 | (c) force_ask | always-proceed, `-p` | `force_ask` | **Executed.** No prompt, no denial. | **force_ask is a no-op under always-proceed (headless).** |
| T5b | ask | always-proceed, `-p` | `ask` | **Executed.** | same |
| T5t | force_ask, trusted ws | always-proceed, `-p` | `force_ask` | Executed. | same |
| PTY-1 | (c) force_ask interactive | always-proceed, TUI | `force_ask` | Hook fired (1 call); file created; TUI showed `Ran touch ...`, no permission prompt appeared. | **force_ask is a no-op under always-proceed in the TUI too.** |
| PTY-2 | deny interactive | always-proceed, TUI | `deny` | File not created; TUI printed `The command was blocked` and the reason. | (b) PASS interactively. |
| R3 | deny_unless_prior_grant, non-allowlisted cmd | always-proceed, `-p` | `deny_unless_prior_grant` | Executed. | No usable human-grant channel under always-proceed. |
| R4 | deny_unless_prior_grant, allowlisted cmd (`echo`) | always-proceed, `-p` | same | Executed. | |
| T6 | hook `allow` grants? | request-review, `-p` | `allow` | Not executed, `denied_actions` set. | **A hook cannot grant.** Same as the 1.1.2 report. |
| T6b | `allow` + `permissionOverrides: ["command(touch)"]` | request-review, `-p` | as stated | Not executed; run status `CANCELED`. | Overrides do not grant either. |
| T6c | deny under request-review | request-review, `-p` | `deny` | Not executed, reason surfaced. | deny works in both modes. |
| T7a | hook prints non-JSON | always-proceed, `-p` | `not json at all` | Not executed. Model saw: `failed to unmarshal result from hook ... via protojson`. | Fail-closed. |
| T7b | hook exits 1, no output | always-proceed, `-p` | exit 1 | Not executed: `JSON hook "..." failed: command failed: exit status 1`. | Fail-closed. |
| T7c | hook exceeds timeout (sleep 8, timeout 3) | always-proceed, `-p` | timeout | Not executed: `command failed: signal: killed`. | Fail-closed; the tool call is aborted, not auto-approved. |
| T8 | file-write hook | always-proceed, `-p` | `allow` | Hook saw `list_dir`, `view_file` x2, `write_to_file` with `TargetFile`/`CodeContent`. | Writes are hookable. |
| T9 | URL-read hook | always-proceed, `-p` | `allow` | Hook saw `read_url_content {"Url": ...}`. | Network reads are hookable. |
| R1 | workspacePaths from a trusted cwd | always-proceed, `-p` from `~/LocalAI` | `allow` | `workspacePaths: []`, `Cwd: "."`. | **Headless runs do not populate the workspace from cwd.** |
| R2 | workspacePaths with `--add-dir` | `-p --add-dir <ws>` | `allow` | `workspacePaths: ["<ws>"]`, `Cwd: "<ws>"`. | Use `--add-dir` for headless runs. |
| (e) | `--dangerously-skip-permissions` suppresses hooks? | CLI flag | `deny` / `allow` | **Hook still fires.** agy treats permissions and `PreToolUse` hooks as separate lifecycle stages. `agy-auto` inspects parent cmdline to detect the flag and auto-allow when `honor_dangerously_skip_permissions = true`. | **PASS** (Verified 2026-09-07) |

## Consequences for the design

1. **Mode:** `toolPermission: always-proceed`. The hook is the only gate; it must return `allow` or `deny`.
2. **`ask` / `force_ask` / `deny_unless_prior_grant` are not blocking under always-proceed on 1.1.27** (headless and TUI). The engine never relies on them. Escalation and every failure path return `deny` with an explicit reason. `escalation.decision` in the policy can be switched to `force_ask` if a future build honors it, and `tests/verify-harness.sh` reports whether it does.
3. **Fail-closed at two levels:** the engine catches everything and emits `deny`; if the engine cannot even start, agy aborts the tool call on non-JSON output, non-zero exit, or timeout (T7a-c).
4. **Headless runs need `--add-dir <workspace>`** or the engine sees no workspace, treats every path as outside it, and routes to the classifier or denies.
5. **Under always-proceed, if the hook is missing or disabled, everything runs.** The installer verifies the hook is listed by `agy -p "/hooks"` and runs a smoke test; the README repeats this warning.
6. Denial reasons are fed back to the model verbatim (T4, T6c), so reasons are written as instructions to the model.
