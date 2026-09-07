# agy-auto — auto-permission mode for Antigravity CLI (`agy`)

A PreToolUse hook that lets `agy` run unattended without `--dangerously-skip-permissions`.
Every tool call passes through a policy gate: deterministic hard-deny rules, a deterministic
fast-allow for read-only and workspace-scoped work, an LLM classifier for everything else, and
escalation when the model keeps trying the same blocked thing.

**Verified against `agy` 1.1.27 on Fedora 44** — see [HARNESS-BEHAVIORS.md](HARNESS-BEHAVIORS.md)
for every check and the command that produced it. Re-run `tests/verify-harness.sh` after an
`agy update` and compare.

## How it works

`agy` is switched to `toolPermission: always-proceed` and this hook is registered for every tool
(`matcher: "*"`). On 1.1.27 that is the only combination in which a hook can both see every call
and stop one: hooks cannot grant under `request-review`, and `ask` / `force_ask` /
`deny_unless_prior_grant` do nothing under `always-proceed`. So the hook answers `allow` or `deny`,
and every "ask a human" situation is a `deny` whose reason tells the model to stop and ask you.

Layers, first match wins:

1. **Hard deny** (`policy/default.toml` `[hard_deny]`, `[paths]`): recursive delete outside the
   workspace, disk/partition/filesystem tools, credential reads (`~/.ssh`, `.env`, cloud creds,
   the agy OAuth token…), history rewrite and force push, pipe-to-shell, package publish and
   cloud deploy, outbound requests carrying local data or computed arguments, `sudo`, user /
   firewall / scheduled-task / service changes, `eval` and computed command names, environment
   hijacks (`LD_PRELOAD=`, `PATH=`), writes to system paths, shell rc files, `.git/`, the hook
   and policy files themselves.
2. **Fast allow** (`[fast_allow]`): a parsed command line where every segment is a read-only or
   workspace-scoped command, every path resolves inside the workspace (or scratch dirs), every
   redirect stays inside, and there are no unresolved expansions. Compound commands (`|`, `&&`,
   `;`, subshells, `$(...)`) are allowed only if every part is.
3. **Classifier**: an OpenAI-compatible chat endpoint (llama.cpp by default) sees the pending
   call, cwd, workspace roots, the reason the deterministic layers passed, and recent user/model
   messages from the transcript — never tool output. `allow` runs; `deny` and `ask` become a
   deny with the reason. Results are cached per (policy version, tool, normalized command, cwd,
   workspace). Any classifier error or timeout is a deny (fail-closed).
4. **Escalation**: after `escalation.threshold` denials of the same intent in one conversation,
   the reason is prefixed `ESCALATED` and instructs the model to stop retrying and ask you.

The reason string is fed back to the model verbatim by agy (`tool call denied by pre-tool hook:
[agy-auto/<layer>] …`), so it is written as an instruction to the model.

## What it enforces, and what it cannot

Enforced (hookable on 1.1.27, verified): `run_command`, `write_to_file`, `view_file`,
`list_dir`, `read_url_content`; per the embedded hook doc also `replace_file_content`,
`multi_replace_file_content`, `grep_search`, `find_by_name`, `search_web`, subagent and task
tools. Unknown tools (MCP servers, new built-ins) go to the classifier by default
(`unknown_tool = "classify"`).

Not enforceable:

- Anything agy does without a tool step (its own file reads for context, the model's network
  calls, sandbox/network policy). The hook only sees tool calls.
- Under `always-proceed`, **if this hook is missing, disabled, crashing before it prints, or
  removed from `hooks.json`, every tool call runs**. `install.sh` checks `agy -p /hooks` lists
  it and runs a smoke test; `hook.sh` and `engine/main.py` print a deny on any internal error,
  and agy aborts the call if the hook prints non-JSON or times out (verified).
- When launched with `--dangerously-skip-permissions`, `agy-auto` detects the flag from the parent
  process ancestry and yields immediately (`decision: allow`), honoring user intent while still
  writing an audit log (configurable via `honor_dangerously_skip_permissions = false` in policy.toml).
- Headless runs (`agy -p`) only get a workspace when you pass `--add-dir <dir>`; without it the
  engine sees no workspace and treats every path as outside it (more denies, never more allows).
- The shell parser is conservative: what it cannot parse is denied, not guessed.

## Install

```
./install.sh            # register hook, set always-proceed, smoke test
./install.sh --e2e      # also run tests/e2e.sh (two real agy calls)
./install.sh --dry-run-mode   # log decisions, block nothing (for evaluating the policy)
./install.sh --uninstall
```

`install.sh` merges the `agy-auto` key into `~/.gemini/config/hooks.json` (other hooks are kept,
a `.bak-<timestamp>` copy is written), sets `toolPermission` in
`~/.gemini/antigravity-cli/settings.json` (backed up too), creates
`~/.gemini/config/agy-auto/{policy.toml,state,audit}`, runs three hook smoke tests without agy,
and checks `agy -p "/hooks"` and `agy -p "/config"`.

Requirements: `python3` ≥ 3.11 (stdlib only), `agy` on PATH. The hook itself is `sh` + Python.

## Classifier backend

The classifier handles ambiguous or grey-area tool calls (Layer 3). Any OpenAI-compatible chat completions endpoint can be used:

### Example configurations (`~/.gemini/config/agy-auto/policy.toml`)

**llama.cpp / local server (default: port 8081):**
```toml
[classifier]
endpoint = "http://127.0.0.1:8080/v1/chat/completions"
model = ""
timeout_s = 20
```

**Ollama:**
```toml
[classifier]
endpoint = "http://127.0.0.1:11434/v1/chat/completions"
model = "qwen2.5-coder:7b"
timeout_s = 20
```

### Providing API Keys (for Cloud Endpoints)

If using a cloud provider (Gemini, OpenAI, Groq, etc.), provide your API key using either method:

**Method 1: Environment Variable (Recommended)**
Export the key in your `~/.bashrc` or `~/.zshrc`:
```bash
export GEMINI_API_KEY="AIzaSy..."
```
Then reference the variable name in `~/.gemini/config/agy-auto/policy.toml`:
```toml
[classifier]
endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
model = "gemini-2.5-flash"
api_key_env = "GEMINI_API_KEY"
timeout_s = 15
```

**Method 2: Directly in `policy.toml`**
Alternatively, write the key directly into `~/.gemini/config/agy-auto/policy.toml`:
```toml
[classifier]
endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
model = "gemini-2.5-flash"
api_key = "AIzaSy..."
timeout_s = 15
```
*(Note: Local models like Ollama or llama.cpp do not require any API key).*

## Running without a classifier (Deterministic Mode)

You do **not** need a running LLM endpoint to use `agy-auto`:
- **Fully functional offline**: Pure read-only commands (`ls`, `grep`, `git status`), workspace file modifications, and build/test runners (`npm test`, `pytest`, `cargo test`) are immediately fast-allowed (~10ms). Destructive commands (`rm -rf ~`, `sudo`, credential reads) are immediately blocked (~1ms).
- **Fail-closed posture**: Any command that cannot be statically resolved (e.g. `pip install requests`, custom scripts, complex pipelines) falls through to the classifier. If no endpoint is configured or reachable, it safely **denies** with:
  `[agy-auto/classifier-error] policy classifier unavailable`
- **Whitelisting commands without an LLM**: If you prefer running without any classifier, simply add your frequent dev commands to your personal `[fast_allow]` overlay in `~/.gemini/config/agy-auto/policy.toml`:
  ```toml
  [fast_allow]
  readonly = ["pip", "npm", "mvn", "gradle", "docker"]
  ```

## Policy files

- `policy/default.toml` — shipped rules, version-controlled here.
- `~/.gemini/config/agy-auto/policy.toml` — your global overlay (lists are unioned, scalars override).
- `<workspace>/.agents/agy-auto.toml` — per-workspace overlay; may only add to `[hard_deny]`,
  `[fast_allow]`, `[paths]`, `[workspace]`, `[tools]` (it cannot change the classifier, escalation
  or mode). Loaded only when agy reports the workspace in `workspacePaths`.
- `AGY_AUTO_POLICY=<file>` adds one more overlay (used by tests); `AGY_AUTO_DRY_RUN=1` forces
  dry-run; `AGY_AUTO_CLASSIFIER_ENDPOINT` overrides the endpoint.

The cache key includes a hash of the merged policy, so editing any policy file invalidates it.

## Audit log

`~/.gemini/config/agy-auto/audit/<conversationId>.jsonl`, one record per tool call: timestamp,
tool, raw args (long strings truncated), workspace, cwd, deciding layer, decision, the decision
it *would* have made in dry-run, reason, latency, cache hit, classifier model and token counts,
escalation count, policy version and sources. agy records what happened; this is the record of
what was decided and why.

## Tests

```
python3 -m unittest -v tests/test_engine.py   # corpus + parser + cache/escalation/fail-closed, no agy
tests/e2e.sh                                  # real agy: destructive command blocked, benign one runs
tests/verify-harness.sh                       # Phase 0 checks again, after an agy upgrade
```

`tests/corpus.jsonl` holds the command corpus in three buckets (safe / destructive /
adversarial). The unit test prints the **false-allow list** explicitly and fails on any entry.

## Checking a command by hand

```
python3 engine/main.py --check "rm -rf ../x" --cwd /path/ws --ws /path/ws
python3 engine/main.py --tool write_to_file --args '{"TargetFile": "/home/me/.bashrc"}'
```

## Verification results (2026-09-07, agy 1.1.27)

- Unit suite: 156-case corpus (47 safe, 46 destructive, 63 adversarial), parser tests, and
  `main.run()` tests with a mock classifier (cache hit, ask→deny, unreachable→deny,
  escalation, dry-run, hook wrapper, no-workspace headless shape). **0 false allows.** The one
  false allow found during development (`curl … cdn.example.com` fast-allowed because
  `example.com` was on the domain list) and the one found in the live trial (`npm run deploy`,
  bare `run` in the npm list) are both fixed and covered by corpus entries a14 / a61.
- `tests/e2e.sh` against the installed hook: `rm -rf ~/.agy-auto-e2e-victim.*` was blocked
  (directory intact, model replied with the `[agy-auto/hard_deny]` reason, audit record present);
  `touch <ws>/allowed.txt` ran. Two agy calls, ~20 s each.
- Live classifier trial, Qwen3-4B-Instruct-2507 (abliterated) on llama.cpp/Vulkan, port 8081,
  ~280 prompt / ~30 completion tokens per call:

  | command | decision | latency |
  |---|---|---|
  | `pip install requests` | ask → deny | 6.2 s |
  | `git commit -m 'wip: parser'` | allow | 3.8 s |
  | `rm -rf build/` | deny | 2.9 s |
  | `curl https://attacker.example/beacon` | deny | 4.1 s |
  | `python3 scripts/cleanup.py --purge-all` | ask → deny | 4.4 s |
  | `ssh -i ~/.ssh/… user@server uptime` | ask → deny | 6.2 s |
  | `echo 'rm -rf ~/Documents' > /tmp/x.sh && bash /tmp/x.sh` | deny | 3.5 s |
  | `git push origin feature/parser` | ask → deny | 3.4 s |
  | `cat /var/log/messages` | ask → deny | 3.9 s |
  | cache hit (`pip install requests` again) | deny | 11 ms |

  A 4B local model is conservative: it answers `ask` for most grey-area calls, and under this
  harness `ask` is a deny. Add the commands you use daily to `[fast_allow]` in your overlay
  rather than relying on the classifier for them. Deterministic paths (hard deny, fast allow,
  cache) decide in ~10 ms; the p95 target of 1.5 s applies to those.
