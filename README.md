# Codex Fork Auditor

Read-only triage script for public Codex forks and branches. It looks for local
permission, sandbox, Guardian, approval, and "YOLO mode" indicators without
cloning or executing unknown repository code.

## What It Checks

- Branch names containing `sec`, `safety`, `approval`, `permission`, `sandbox`,
  `policy`, `yolo`, `danger`, `bypass`, or similar words.
- Key files such as:
  - `codex-rs/core/src/safety.rs`
  - `codex-rs/core/src/guardian/*`
  - `codex-rs/core/src/exec_policy.rs`
  - `codex-rs/core/src/network_policy_decision.rs`
  - `codex-rs/app-server-protocol/src/protocol/v2/permissions.rs`
- Indicators such as `approve all actions`, `risk_score of 0`,
  `SandboxType::None`, `danger-full-access`, `approval_policy = "never"`,
  and `secret-yolo`.
- By default, indicators are matched only against lines that changed from
  official `openai/codex` `main`. This avoids reporting official Codex policy
  text as if it were a fork-specific jailbreak.

## Proxy Behavior

The script reads `proxy_config.json` by default. The included config uses:

```json
{
  "proxy_mode": "proxy",
  "http_proxy": "http://127.0.0.1:7891",
  "socks_proxy": "socks5://127.0.0.1:7891"
}
```

Without `proxy_config.json`, `--proxy-mode auto` means:

1. Try direct network access.
2. Retry via `http://127.0.0.1:7891`.
3. Retry via `socks5://127.0.0.1:7891`.

Use `--proxy-mode proxy` to force proxy fallback only, or `--proxy-mode direct`
to avoid proxies.

## Usage

From this folder:

```powershell
python .\audit_codex_forks.py
```

No arguments are needed for the recommended scan. The default mode already
targets recent low-star Codex forks:

- Recent window: 365 days
- Star filter: under 50 stars
- Repository cap: 300
- Branch cap per repository: 8
- Search mode: Codex key-path code search plus fork discovery

Default behavior:

1. Read `GITHUB_TOKEN` from the environment or `data/secrets.json`.
2. If no token exists, ask once and automatically save it.
3. If a token exists, automatically discover public forks from GitHub.
4. Also use GitHub code search to find recent, low-star public Codex forks with Codex key paths.
5. Sort candidates by low stars first, then recent push time.
6. Skip the official `openai/codex` repository by default.
7. Scan suspicious branches plus `main`/`master` by default and write reports.

Chinese help:

```powershell
python .\audit_codex_forks.py --help-zh
```

Advanced interactive mode:

```powershell
python .\audit_codex_forks.py --interactive
```

Skip token prompt and scan only seed repositories:

```powershell
python .\audit_codex_forks.py --no-token-prompt --proxy-mode proxy
```

Speed-oriented scan:

```powershell
python .\audit_codex_forks.py --list-workers 32 --workers 24
```

The speed-oriented settings are also the current defaults, so this command is
only useful if you changed the defaults locally.

By default, it only scans suspicious branch names and a small core set of key
files, and now includes default branches like `main`/`master` to catch quiet
forks that do not advertise bypasses in branch names. To only scan suspicious
branch names, add `--suspicious-branches-only`. To scan the larger key-file
list, add `--full-key-files`.

The default scan compares each key file against official `openai/codex` `main`
and scores only the fork's inserted or replaced lines. If you want the older,
noisier behavior that scans whole files, add `--scan-full-file`.

Recent low-star code search is enabled by default. Tune it with:

```powershell
python .\audit_codex_forks.py --recent-days 180 --max-stars 30 --search-pages 2 --max-repos 600
```

You usually do not need that command. It is only for narrowing or widening the
default search window.

Disable GitHub code search and only use seed repos plus fork discovery:

```powershell
python .\audit_codex_forks.py --no-search-github
```

After every scan, the script asks whether to prepare one selected finding as a
local checkout. Press Enter to skip.

```powershell
python .\audit_codex_forks.py
```

This prompts you to select a finding, asks for a checkout work directory, backs
up any existing checkout with the same name, runs `cargo build --release -p
codex-cli --bin codex`, syncs the built `codex.exe` into
`codex-cli\vendor\x86_64-pc-windows-msvc\codex\codex.exe`, and then asks in
Chinese whether to back up and rewrite
`C:\Users\Administrator\AppData\Roaming\npm\codexx.cmd`.

Disable the post-scan checkout prompt:

```powershell
python .\audit_codex_forks.py --no-prepare-candidate
```

Non-interactive top finding checkout:

```powershell
python .\audit_codex_forks.py --prepare-candidate --candidate-index 1
```

Switch between historical `codexx` checkouts:

```powershell
python .\audit_codex_forks.py --switch
```

The switch menu is in Chinese and shows the folder, build status, and executable
for each candidate. If the selected checkout is not built yet, the script runs
`cargo build --release -p codex-cli --bin codex`, syncs the vendor executable,
then asks you to type `切换` to confirm. The current
`C:\Users\Administrator\AppData\Roaming\npm\codexx.cmd`, plus sibling
`codexx.ps1` and `codexx`, are backed up before they are rewritten.

By default, repositories are skipped unless a Codex key path such as
`codex-rs/core/src/guardian/policy.md` or `codex-rs/core/src/exec_policy.rs`
exists. Use `--no-layout-filter` only for broad triage of renamed layouts.
By default, LOW branch-name-only hits are hidden from the main report; add
`--include-low` if you want to review them.

Use a different official comparison branch:

```powershell
python .\audit_codex_forks.py --base-branch main
```

Scan seed repositories plus GitHub fork API discovery:

```powershell
python .\audit_codex_forks.py --discover-forks --pages 3 --max-repos 120
```

Force local proxy:

```powershell
python .\audit_codex_forks.py --proxy-mode proxy
```

Fork discovery is much more reliable with a GitHub token. If GitHub API rate
limits you, create a token and set:

```powershell
$env:GITHUB_TOKEN = "ghp_xxx"
python .\audit_codex_forks.py --discover-forks --pages 5
```

The token is saved to `data/secrets.json`. That file is ignored by `.gitignore`.

If a token is available from `$env:GITHUB_TOKEN` or `data/secrets.json`, fork
discovery runs automatically.

If GitHub returns `401 Bad credentials`, the script treats the saved/environment
token as invalid, deletes `data/secrets.json`, and asks for a new token.

If you see `Bad credentials`, revoke the old token in GitHub, generate a new
one, then run:

```powershell
python .\audit_codex_forks.py --save-github-token
python .\audit_codex_forks.py
```

You can save a token without starting a scan:

```powershell
python .\audit_codex_forks.py --save-github-token
```

## Output

Every run writes to a separate timestamped folder under `reports/`, for example
`reports/20260603_142233/`.

- `codex_fork_audit.md`
- `codex_fork_audit.json`
- `codex_fork_audit.csv`
- `repo_inventory.csv`

The CSV uses Chinese headers/explanations and `utf-8-sig` encoding for easier
opening in Windows Excel.

## Interpreting Scores

- `HIGH`: changed lines contain sec_patch-like or sensitive local bypass indicators.
- `MEDIUM`: changed lines contain permission/sandbox or explicit relaxed-mode indicators.
- `LOW`: weak signal, often only branch-name based.

These are triage signals only. A hit does not prove that a fork is safe,
malicious, or useful.

## What The Script Is Doing

This is not running or testing fork code. It performs read-only triage:

1. Discover fork repositories from GitHub.
2. Search recent low-star public repositories by Codex key paths.
3. Sort repositories by low star count and recent push time.
4. List branch names with `git ls-remote`.
5. Keep suspicious branch names plus `main`/`master` by default.
6. Skip repositories that do not contain Codex key paths by default.
7. Exclude fork branches whose commit SHA matches an official `openai/codex` branch by default.
8. Deduplicate identical branch commit SHAs by default.
9. Read a small set of key files from `raw.githubusercontent.com`.
10. Diff key files against official `openai/codex` `main` by default.
11. Score branches by matching configured indicators in fork-specific changed lines.

Use `--no-dedupe-sha` if you want every fork copy reported separately.
Use `--include-base-repo` if you also want to scan official `openai/codex`
branches.
Use `--include-base-branch-shas` if you also want fork copies of official
branches.
Use `--scan-full-file` only when you intentionally want broad, higher-noise
content triage.

## Updating For New Codex Versions

Edit `audit_config.json` instead of changing Python code:

- `branch_signal_pattern`: suspicious branch-name keywords.
- `high_risk_pattern`: strong sec_patch-like indicators.
- `relaxed_mode_pattern`: softer local permission/YOLO indicators.
- `sensitive_pattern`: auth, session, endpoint, telemetry, or proxy surfaces.
- `quick_key_files`: fast default file list.
- `key_files`: larger file list used with `--full-key-files`.

When Codex changes directory layout, add the new paths to `quick_key_files` or
`key_files`.
