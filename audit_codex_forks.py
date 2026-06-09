#!/usr/bin/env python3
"""
Codex fork auditor.

This script performs triage of public Codex forks/branches and looks for local
permission/sandbox/approval changes. By default it can also prepare a selected
candidate checkout, build it, and switch codexx.cmd only after an explicit
interactive confirmation.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import difflib
import functools
import getpass
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict
from dataclasses import dataclass
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from typing import Iterable
from typing import Any


DEFAULT_BASE_REPO = "openai/codex"
DEFAULT_PROXY = "http://127.0.0.1:7891"
DEFAULT_SOCKS_PROXY = "socks5://127.0.0.1:7891"
DEFAULT_SECRETS_FILE = Path("data/secrets.json")
DEFAULT_PROXY_CONFIG_FILE = Path("proxy_config.json")
DEFAULT_CODEXX_CMD = Path(r"C:\Users\Administrator\AppData\Roaming\npm\codexx.cmd")

CATEGORY_ZH = {
    "high_risk_local_bypass": "高风险：变更行疑似本地安全/审批/Guardian 绕过特征",
    "relaxed_permission_mode": "中风险：变更行包含宽松权限、YOLO、danger-full-access 或外部沙箱特征",
    "sensitive_surface_changed_or_present": "提示：变更行涉及认证、会话、endpoint、代理、telemetry 等敏感面",
}

HELP_ZH = r"""
Codex Fork Auditor 中文帮助
==========================

用途
----
筛选公开的 Codex fork / 分支，寻找类似 sec_patch、YOLO、本地审批/沙箱/Guardian
改动的候选分支。默认扫描结束后会询问是否复用缓存、是否选择候选；选择候选后会
checkout 到本地工作目录，默认尝试编译 Rust CLI，并在你中文确认后备份并改写 codexx.cmd。

默认行为
--------
直接运行：

  python .\audit_codex_forks.py

默认会：
1. 读取 data\secrets.json 或环境变量 GITHUB_TOKEN。
2. 没有 token 时只问一次，并自动保存到 data\secrets.json。
3. 有 token 时自动调用 GitHub API 发现 openai/codex 的公开 forks。
4. 默认额外用 GitHub repository search 找近期更新、低 star 的公开 Codex fork。
5. 默认按低 star 优先、最近 pushed 时间排序，更适合发现小众新 fork。
6. 默认跳过官方 openai/codex 本身，只扫 fork。
7. 并发列出各 fork 的分支。
8. 默认扫描可疑分支名，也扫描 main/master，避免漏掉静默发布的默认分支。
9. 默认排除 commit SHA 与官方任意分支相同的 fork 分支。
10. 默认按 commit SHA 去重，避免重复扫描同步官方分支的 fork。
11. 每个候选分支读取少量关键文件并打分。
12. 默认只分析 fork 相对官方 openai/codex main 的新增/修改行，避免把官方原文算作命中。
13. 每次运行输出到独立时间目录，例如 reports\20260603_142233\。
14. 输出 codex_fork_audit.md / .csv / .json，CSV 表头和解释为中文。
15. 同时输出 repo_inventory.csv，记录每个仓库的来源、star、最近推送、分支数和候选分支数。
16. 如果有历史报告缓存，会先询问是否直接使用缓存。
17. 如果选择候选 checkout，会默认运行 cargo build --release -p codex-cli --bin codex。
18. 编译成功后会同步 codex.exe 到 codex-cli\vendor\x86_64-pc-windows-msvc\codex\codex.exe。
19. 最后会询问是否把 codexx.cmd 切换到该候选；切换前自动备份旧 codexx.cmd。

常用命令
--------
普通自动扫描：

  python .\audit_codex_forks.py

高速扫描：

  python .\audit_codex_forks.py

更快但更浅（减少仓库数）：

  python .\audit_codex_forks.py --max-repos 120 --search-pages 1

更全但更慢：

  python .\audit_codex_forks.py --pages 8 --search-pages 3 --max-repos 600 --full-key-files

保存 GitHub token：

  python .\audit_codex_forks.py --save-github-token

高级交互模式：

  python .\audit_codex_forks.py --interactive

跳过 token 提示，只扫 data\repos.txt：

  python .\audit_codex_forks.py --no-token-prompt

如果你也想扫描官方 openai/codex 分支：

  python .\audit_codex_forks.py --include-base-repo

核心参数
--------
--pages N
  GitHub fork API 页数。每页最多 100 个 fork。默认 3。

--search-github / --no-search-github
  默认开启 GitHub repository search，用于补充发现近期低 star 的公开 Codex 仓库。

--search-pages N
  每个搜索查询最多拉取多少页。默认 2。

--recent-days N
  只搜索最近 N 天内 pushed 过的仓库。默认 365。

--max-stars N
  code search 优先搜索 star 小于 N 的仓库。默认 50。

--max-repos N
  最多处理多少个仓库。默认 300。

--max-branches-per-repo N
  每个仓库最多保留多少个候选分支。默认 8。

--list-workers N
  并发列分支的线程数。影响 git ls-remote 阶段速度。默认 32。

--workers N
  并发读取 raw 关键文件的线程数。默认 24。

--full-key-files
  使用 audit_config.json 里的完整 key_files，而不是 quick_key_files。

--no-dedupe-sha
  不按 commit SHA 去重。会更全，但会慢很多，并出现大量同步官方分支的重复结果。

--include-base-repo
  默认跳过官方 openai/codex；加这个参数才扫描官方仓库。

--base-branch NAME
  用于差分的官方基线分支。默认 main。

--scan-full-file
  不做官方基线差分，改为扫描关键文件全文。更容易出结果，但误报明显更多。

--include-base-branch-shas
  默认排除和官方分支 SHA 完全相同的 fork 分支；加这个参数才保留这些同步分支。

--include-default-branch
  默认已经扫描 main/master。

--suspicious-branches-only
  只扫描可疑分支名，不扫描 main/master。速度更快，但更容易漏掉静默默认分支。

--no-build-candidate
  选择候选后不自动编译。

--build-timeout N
  候选 cargo build 超时时间，单位秒。默认 3600。

--switch
  不扫描，直接在本地已编译历史候选之间切换 codexx.cmd。

代理
----
脚本默认读取 proxy_config.json：

  {
    "proxy_mode": "proxy",
    "http_proxy": "http://127.0.0.1:7891",
    "socks_proxy": "socks5://127.0.0.1:7891"
  }

命令行也可以覆盖：

  --proxy-mode proxy
  --proxy-mode direct
  --proxy-url http://127.0.0.1:7891
  --socks-proxy-url socks5://127.0.0.1:7891

配置文件
--------
audit_config.json 可改：
- branch_signal_pattern：分支名关键词
- high_risk_pattern：强 sec_patch 特征
- relaxed_mode_pattern：宽松权限/YOLO 特征
- sensitive_pattern：认证、会话、endpoint、telemetry 等敏感面
- quick_key_files：快速扫描文件列表
- key_files：完整扫描文件列表

输出评分
--------
HIGH:
  变更行里出现类 sec_patch / 明显本地绕过特征，如 approve all actions、risk_score 0。

MEDIUM:
  变更行里出现权限、沙箱、审批、外部 sandbox、YOLO 相关特征。

LOW:
  只有分支名弱信号。

注意
----
这只是预筛选，不代表 fork 安全、可用或恶意。高分候选还需要人工 diff 和安全审计。
CSV 使用 utf-8-sig 编码，方便 Windows Excel 直接打开中文。
"""

BRANCH_SIGNAL_RE = re.compile(
    r"(sec|security|restriction|safety|guardian|approval|permission|sandbox|"
    r"policy|yolo|danger|unrestricted|disable|remove|bypass|trusted)",
    re.IGNORECASE,
)

HIGH_RISK_RE = re.compile(
    r"(approve all actions|risk_score\s+of\s+0|all actions are low risk|"
    r"flagged but approved automatically|Remove all local safety restrictions|"
    r"remove\s+all\s+local\s+safety|remove\s+security\s+restrictions|"
    r"bypass\s+patch\s+safety|disable\s+guardian\s+risk|"
    r"always.*AutoApprove|ReviewDecision::Approved|"
    r"return\s+SafetyCheck::AutoApprove|skip.*guardian|disable.*approval)",
    re.IGNORECASE | re.DOTALL,
)

RELAXED_MODE_RE = re.compile(
    r"(secret-yolo|yolo|danger-full-access|approval_policy\s*=\s*[\"']never[\"']|"
    r"approvalPolicy[\"']?\s*:\s*[\"']never[\"']|externalSandbox|"
    r"PermissionProfile::Disabled)",
    re.IGNORECASE,
)

SENSITIVE_RE = re.compile(
    r"(OPENAI_API_KEY|auth token|session|credential|telemetry|endpoint|base_url|"
    r"api_base|proxy|cookie|history\.jsonl|mcp_servers|Authorization)",
    re.IGNORECASE,
)

KEY_FILES = [
    "codex-rs/core/src/safety.rs",
    "codex-rs/core/src/guardian/policy.md",
    "codex-rs/core/src/guardian/review.rs",
    "codex-rs/core/src/guardian/review_session.rs",
    "codex-rs/core/src/guardian/approval_request.rs",
    "codex-rs/core/src/guardian/prompt.rs",
    "codex-rs/core/src/exec_policy.rs",
    "codex-rs/core/src/network_policy_decision.rs",
    "codex-rs/app-server-protocol/src/protocol/v2/permissions.rs",
    "codex-rs/app-server/README.md",
    "codex-rs/protocol/src/prompts/base_instructions/default.md",
    "codex-rs/config.md",
    ".github/codex/home/config.toml",
]

QUICK_KEY_FILES = [
    "codex-rs/core/src/safety.rs",
    "codex-rs/core/src/guardian/policy.md",
    "codex-rs/core/src/guardian/review.rs",
    "codex-rs/core/src/guardian/review_session.rs",
    "codex-rs/core/src/exec_policy.rs",
    "codex-rs/app-server-protocol/src/protocol/v2/permissions.rs",
]


@dataclass
class BranchRef:
    repo: str
    branch: str
    sha: str
    source: str


@dataclass
class RepoCandidate:
    repo: str
    source: str
    stars: int | None = None
    pushed_at: str | None = None


@dataclass
class FileFinding:
    file: str
    category: str
    excerpts: list[str]


@dataclass
class AuditFinding:
    repo: str
    branch: str
    sha: str
    url: str
    score: int
    rating: str
    branch_signal: bool
    file_findings: list[FileFinding]


@dataclass
class RepoInventory:
    repo: str
    url: str
    source: str
    stars: int | None
    pushed_at: str | None
    status: str
    branch_count: int
    candidate_count: int
    note: str


@dataclass
class AuditConfig:
    branch_signal_pattern: str
    high_risk_pattern: str
    relaxed_mode_pattern: str
    sensitive_pattern: str
    key_files: list[str]
    quick_key_files: list[str]


def log(message: str) -> None:
    print(message, flush=True)


def load_saved_token(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    token = data.get("github_token") if isinstance(data, dict) else None
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None


def save_token(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"github_token": token}, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def delete_saved_token(path: Path) -> None:
    try:
        if path.exists():
            path.unlink()
    except OSError:
        pass


def compile_pattern(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise SystemExit(f"Invalid regex in config: {exc}\nPattern: {pattern}") from exc


def default_config() -> AuditConfig:
    return AuditConfig(
        branch_signal_pattern=BRANCH_SIGNAL_RE.pattern,
        high_risk_pattern=HIGH_RISK_RE.pattern,
        relaxed_mode_pattern=RELAXED_MODE_RE.pattern,
        sensitive_pattern=SENSITIVE_RE.pattern,
        key_files=KEY_FILES,
        quick_key_files=QUICK_KEY_FILES,
    )


def load_audit_config(path: Path) -> AuditConfig:
    config = default_config()
    if not path.exists():
        return config
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON config: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit(f"Config must be a JSON object: {path}")

    for field_name in (
        "branch_signal_pattern",
        "high_risk_pattern",
        "relaxed_mode_pattern",
        "sensitive_pattern",
    ):
        value = data.get(field_name)
        if isinstance(value, str) and value.strip():
            setattr(config, field_name, value)

    for field_name in ("key_files", "quick_key_files"):
        value = data.get(field_name)
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            setattr(config, field_name, value)

    return config


def load_proxy_config(args: argparse.Namespace, root: Path) -> None:
    proxy_config = args.proxy_config
    if not proxy_config.is_absolute():
        proxy_config = root / proxy_config
    if not proxy_config.exists():
        return
    try:
        data = json.loads(proxy_config.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        log(f"Invalid proxy config {proxy_config}: {exc}")
        return
    if not isinstance(data, dict):
        return
    if not args.proxy_mode_set_by_cli and isinstance(data.get("proxy_mode"), str):
        if data["proxy_mode"] in {"auto", "direct", "proxy"}:
            args.proxy_mode = data["proxy_mode"]
    if not args.proxy_url_set_by_cli and isinstance(data.get("http_proxy"), str):
        args.proxy_url = data["http_proxy"]
    if not args.socks_proxy_url_set_by_cli and isinstance(data.get("socks_proxy"), str):
        args.socks_proxy_url = data["socks_proxy"]


def prompt_value(label: str, current: Any, cast: type = str) -> Any:
    raw = input(f"{label} [{current}]: ").strip()
    if not raw:
        return current
    if cast is bool:
        return raw.lower() in {"1", "true", "t", "yes", "y", "on", "是", "对", "好", "启用", "开启"}
    try:
        return cast(raw)
    except ValueError:
        log(f"输入无效，保留当前值: {current}")
        return current


def prompt_yes_no(message: str, default: bool = False) -> bool:
    suffix = "[默认是，输入 n/否 跳过]" if default else "[默认否，输入 y/是 确认]"
    try:
        raw = input(f"{message} {suffix}: ").strip().lower()
    except EOFError:
        log(f"无交互输入，使用默认值: {'是' if default else '否'}")
        return default
    if not raw:
        return default
    if raw in {"0", "n", "no", "否", "不", "不要", "跳过", "取消"}:
        return False
    return raw in {"1", "y", "yes", "是", "对", "好", "使用", "确认", "切换"}


def prompt_text(message: str, default: str = "") -> str:
    try:
        raw = input(message)
    except EOFError:
        if default:
            log(f"无交互输入，使用默认值: {default}")
        else:
            log("无交互输入，按空输入处理。")
        return default
    return raw.strip()


def ensure_token(args: argparse.Namespace, root: Path, *, prompt_if_missing: bool) -> bool:
    secrets_file = args.secrets_file
    if not secrets_file.is_absolute():
        secrets_file = root / secrets_file
    saved_token = load_saved_token(secrets_file)
    if not os.environ.get("GITHUB_TOKEN") and saved_token:
        os.environ["GITHUB_TOKEN"] = saved_token

    if os.environ.get("GITHUB_TOKEN"):
        return True

    if prompt_if_missing:
        print("未设置 GITHUB_TOKEN。有 token 时发现 fork 会更稳定。")
        token = getpass.getpass("现在粘贴 GitHub token，或直接回车跳过: ").strip()
        if token:
            os.environ["GITHUB_TOKEN"] = token
            save_token(secrets_file, token)
            print(f"已保存 token 到: {secrets_file}")
            return True
        else:
            print("未输入 token；仅扫描 data/repos.txt 中的种子仓库。")
    return False


def prompt_and_save_token(args: argparse.Namespace, root: Path, reason: str) -> bool:
    secrets_file = args.secrets_file
    if not secrets_file.is_absolute():
        secrets_file = root / secrets_file
    print(reason)
    token = getpass.getpass("现在粘贴新的 GitHub token，或直接回车跳过: ").strip()
    if not token:
        os.environ.pop("GITHUB_TOKEN", None)
        delete_saved_token(secrets_file)
        print("未输入 token；仅扫描 data/repos.txt 中的种子仓库。")
        return False
    os.environ["GITHUB_TOKEN"] = token
    save_token(secrets_file, token)
    print(f"已保存新 token 到: {secrets_file}")
    return True


def interactive_args(args: argparse.Namespace, root: Path) -> argparse.Namespace:
    print("高级交互设置。直接回车保留默认值。")
    has_token = ensure_token(args, root, prompt_if_missing=True)
    if has_token and not args.discover_forks:
        args.discover_forks = True
    args.discover_forks = prompt_value("是否通过 GitHub API 发现 forks? yes/no", args.discover_forks, bool)
    if args.discover_forks and not os.environ.get("GITHUB_TOKEN"):
        print("提示：未认证 GitHub API 容易限流，结果可能退化为仅使用 repos.txt。")
    args.pages = prompt_value("GitHub fork API 页数", args.pages, int)
    args.max_repos = prompt_value("最多处理仓库数", args.max_repos, int)
    args.max_branches_per_repo = prompt_value(
        "每个仓库最多候选分支数",
        args.max_branches_per_repo,
        int,
    )
    args.include_default_branch = prompt_value(
        "是否包含 main/master 默认分支? yes/no",
        args.include_default_branch,
        bool,
    )
    args.base_branch = prompt_value("官方差分基线分支", args.base_branch, str)
    args.full_key_files = prompt_value("是否扫描完整关键文件列表? yes/no", args.full_key_files, bool)
    args.scan_full_file = prompt_value(
        "是否扫描全文而不是仅扫描变更行? yes/no",
        args.scan_full_file,
        bool,
    )
    args.workers = prompt_value("raw 文件扫描并发数", args.workers, int)
    args.timeout = prompt_value("HTTP 超时秒数", args.timeout, int)
    args.git_timeout = prompt_value("Git ls-remote 超时秒数", args.git_timeout, int)
    proxy_mode = input(f"代理模式 auto/direct/proxy [{args.proxy_mode}]: ").strip()
    if proxy_mode in {"auto", "direct", "proxy"}:
        args.proxy_mode = proxy_mode
    return args


def github_headers() -> dict[str, str]:
    headers = {
        "User-Agent": "codex-fork-auditor",
        "Accept": "application/vnd.github+json",
    }
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def opener_for(proxy: str | None) -> urllib.request.OpenerDirector:
    if not proxy:
        return urllib.request.build_opener()
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )


def request_text_with_error(
    url: str,
    timeout: int,
    proxy_mode: str,
) -> tuple[str | None, str | None, int | None]:
    proxies: list[str | None]
    if proxy_mode == "direct":
        proxies = [None]
    elif proxy_mode == "proxy":
        proxies = [DEFAULT_PROXY, DEFAULT_SOCKS_PROXY]
    else:
        proxies = [None, DEFAULT_PROXY, DEFAULT_SOCKS_PROXY]

    last_error: Exception | None = None
    for proxy in proxies:
        try:
            request = urllib.request.Request(url, headers=github_headers())
            with opener_for(proxy).open(request, timeout=timeout) as response:
                raw = response.read()
            return raw.decode("utf-8", errors="replace"), None, None
        except urllib.error.HTTPError as exc:
            detail = f"HTTP {exc.code}"
            try:
                body = exc.read().decode("utf-8", errors="replace")
                if body:
                    detail = f"{detail}: {body[:300]}"
            except Exception:
                pass
            last_error = RuntimeError(detail)
            if exc.code == 401:
                return None, detail, 401
            continue
        except Exception as exc:  # noqa: BLE001 - surface robust triage errors
            last_error = exc
            continue
    if last_error:
        return None, str(last_error), None
    return None, None, None


def request_text(url: str, timeout: int, proxy_mode: str) -> str | None:
    text, _error, _status = request_text_with_error(url, timeout, proxy_mode)
    return text


def github_api_json(url: str, timeout: int, proxy_mode: str) -> tuple[object | None, int | None]:
    text, error, status = request_text_with_error(url, timeout, proxy_mode)
    if not text:
        log(f"GitHub API request failed or empty: {url} ({error or 'no detail'})")
        return None, status
    try:
        return json.loads(text), None
    except json.JSONDecodeError:
        log(f"GitHub API returned non-JSON: {url}")
        return None, None


def validate_github_token(timeout: int, proxy_mode: str) -> int | None:
    if not os.environ.get("GITHUB_TOKEN"):
        return None
    _data, status = github_api_json(
        "https://api.github.com/rate_limit",
        timeout,
        proxy_mode,
    )
    return status


def git_ls_remote_heads(repo: str, timeout: int, proxy_mode: str) -> list[BranchRef]:
    remote = repo
    if not repo.startswith(("http://", "https://", "git@")):
        remote = f"https://github.com/{repo}.git"

    env = os.environ.copy()
    env.setdefault("GIT_TERMINAL_PROMPT", "0")

    if proxy_mode == "direct":
        proxy_envs = [{}]
    elif proxy_mode == "proxy":
        proxy_envs = [
            {"HTTPS_PROXY": DEFAULT_PROXY, "HTTP_PROXY": DEFAULT_PROXY},
            {"HTTPS_PROXY": DEFAULT_SOCKS_PROXY, "HTTP_PROXY": DEFAULT_SOCKS_PROXY},
        ]
    else:
        proxy_envs = [
            {},
            {"HTTPS_PROXY": DEFAULT_PROXY, "HTTP_PROXY": DEFAULT_PROXY},
            {"HTTPS_PROXY": DEFAULT_SOCKS_PROXY, "HTTP_PROXY": DEFAULT_SOCKS_PROXY},
        ]

    output = ""
    for proxy_env in proxy_envs:
        run_env = env.copy()
        run_env.update(proxy_env)
        try:
            proc = subprocess.run(
                ["git", "ls-remote", "--heads", remote],
                text=True,
                capture_output=True,
                timeout=timeout,
                env=run_env,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                output = proc.stdout
                break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

    refs: list[BranchRef] = []
    repo_name = repo
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    if repo_name.startswith("https://github.com/"):
        repo_name = repo_name.removeprefix("https://github.com/")

    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) != 2:
            continue
        sha, ref = parts
        if not ref.startswith("refs/heads/"):
            continue
        branch = ref.removeprefix("refs/heads/")
        refs.append(BranchRef(repo=repo_name, branch=branch, sha=sha, source="ls-remote"))
    return refs


def load_repos_from_file(path: Path) -> list[str]:
    repos: list[str] = []
    if not path.exists():
        return repos
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "github.com/" in line:
            line = line.split("github.com/", 1)[1]
        line = line.removesuffix(".git").strip("/")
        repos.append(line)
    return repos


def repo_candidates_from_names(names: Iterable[str], source: str) -> list[RepoCandidate]:
    return [RepoCandidate(repo=name, source=source) for name in names]


def parse_github_repo_item(item: object, source: str) -> RepoCandidate | None:
    if not isinstance(item, dict) or not isinstance(item.get("full_name"), str):
        return None
    stars = item.get("stargazers_count")
    pushed_at = item.get("pushed_at")
    return RepoCandidate(
        repo=item["full_name"],
        source=source,
        stars=stars if isinstance(stars, int) else None,
        pushed_at=pushed_at if isinstance(pushed_at, str) else None,
    )


def repo_sort_key(candidate: RepoCandidate) -> tuple[int, int, str]:
    if candidate.source.startswith("repos-file"):
        source_rank = 0
    elif "code-search:" in candidate.source:
        source_rank = 1
    elif "forks:" in candidate.source:
        source_rank = 2
    elif "search:" in candidate.source:
        source_rank = 3
    else:
        source_rank = 4
    pushed_rank = 0
    if candidate.pushed_at:
        try:
            pushed_rank = int(
                datetime.fromisoformat(candidate.pushed_at.replace("Z", "+00:00")).timestamp()
            )
        except ValueError:
            pushed_rank = 0
    return (
        source_rank,
        candidate.stars if candidate.stars is not None else 999999,
        -pushed_rank,
        candidate.repo.lower(),
    )


def discover_forks(
    base_repo: str,
    pages: int,
    timeout: int,
    proxy_mode: str,
) -> tuple[list[RepoCandidate], int | None]:
    repos: list[RepoCandidate] = []
    last_status: int | None = None
    for page in range(1, pages + 1):
        url = (
            f"https://api.github.com/repos/{base_repo}/forks?"
            f"sort=newest&per_page=100&page={page}"
        )
        data, status = github_api_json(url, timeout, proxy_mode)
        last_status = status
        if not isinstance(data, list):
            return repos, last_status
        if not data:
            break
        for item in data:
            candidate = parse_github_repo_item(item, "forks:newest")
            if candidate:
                repos.append(candidate)
        time.sleep(0.25)
    return repos, last_status


def search_github_repos(
    queries: list[str],
    pages: int,
    timeout: int,
    proxy_mode: str,
) -> tuple[list[RepoCandidate], int | None]:
    repos: list[RepoCandidate] = []
    last_status: int | None = None
    for query in queries:
        for page in range(1, pages + 1):
            encoded_query = urllib.parse.quote(query)
            url = (
                "https://api.github.com/search/repositories?"
                f"q={encoded_query}&sort=updated&order=desc&per_page=100&page={page}"
            )
            data, status = github_api_json(url, timeout, proxy_mode)
            last_status = status
            if not isinstance(data, dict):
                break
            items = data.get("items")
            if not isinstance(items, list) or not items:
                break
            for item in items:
                candidate = parse_github_repo_item(item, f"search:{query}")
                if candidate:
                    repos.append(candidate)
            time.sleep(0.25)
    return repos, last_status


def search_github_code_repos(
    queries: list[str],
    pages: int,
    timeout: int,
    proxy_mode: str,
) -> tuple[list[RepoCandidate], int | None]:
    repos: list[RepoCandidate] = []
    last_status: int | None = None
    for query in queries:
        for page in range(1, pages + 1):
            encoded_query = urllib.parse.quote(query)
            url = (
                "https://api.github.com/search/code?"
                f"q={encoded_query}&per_page=100&page={page}"
            )
            data, status = github_api_json(url, timeout, proxy_mode)
            last_status = status
            if not isinstance(data, dict):
                break
            items = data.get("items")
            if not isinstance(items, list) or not items:
                break
            for item in items:
                repo = item.get("repository") if isinstance(item, dict) else None
                candidate = parse_github_repo_item(repo, f"code-search:{query}")
                if candidate:
                    repos.append(candidate)
            time.sleep(0.25)
    return repos, last_status


def default_search_queries(base_repo: str, days: int, max_stars: int) -> list[str]:
    pushed_after = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    owner, _, name = base_repo.partition("/")
    repo_name = name or "codex"
    star_filter = f"stars:<{max_stars}" if max_stars > 0 else ""
    return [
        f"{repo_name} in:name,description,readme fork:true archived:false pushed:>{pushed_after} {star_filter} size:<200000".strip(),
        f"{owner} {repo_name} in:readme fork:true archived:false pushed:>{pushed_after} {star_filter} size:<200000".strip(),
    ]


def default_code_search_queries(days: int, max_stars: int) -> list[str]:
    pushed_after = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    star_filter = f"stars:<{max_stars}" if max_stars > 0 else ""
    return [
        f'"GUARDIAN_REVIEWER_NAME" path:codex-rs/core/src/guardian fork:true pushed:>{pushed_after} {star_filter}'.strip(),
        f'"PermissionProfile::Disabled" path:codex-rs/core/src fork:true pushed:>{pushed_after} {star_filter}'.strip(),
        f'"danger-full-access" path:codex-rs fork:true pushed:>{pushed_after} {star_filter}'.strip(),
    ]


def merge_repo_candidates(candidates: Iterable[RepoCandidate]) -> list[RepoCandidate]:
    merged: dict[str, RepoCandidate] = {}
    for candidate in candidates:
        key = candidate.repo.lower()
        existing = merged.get(key)
        if existing is None:
            merged[key] = candidate
            continue
        if existing.stars is None and candidate.stars is not None:
            existing.stars = candidate.stars
        if existing.pushed_at is None and candidate.pushed_at is not None:
            existing.pushed_at = candidate.pushed_at
        if candidate.source not in existing.source.split(";"):
            existing.source = f"{existing.source};{candidate.source}"
    return sorted(merged.values(), key=repo_sort_key)


def looks_like_codex_repo(repo: str, branch: str, timeout: int, proxy_mode: str) -> bool:
    markers = (
        "codex-rs/core/src/guardian/policy.md",
        "codex-rs/core/src/exec_policy.rs",
        "codex-rs/config.md",
        "codex-rs/Cargo.toml",
    )
    for marker in markers:
        if cached_raw_text(repo, branch, marker, timeout, proxy_mode):
            return True
    return False


def first_likely_default_branch(refs: list[BranchRef]) -> str | None:
    branch_names = {ref.branch for ref in refs}
    for name in ("main", "master"):
        if name in branch_names:
            return name
    return refs[0].branch if refs else None


def candidate_branches(
    refs: list[BranchRef],
    max_per_repo: int,
    include_default: bool,
    branch_signal_re: re.Pattern[str],
) -> list[BranchRef]:
    selected: list[BranchRef] = []
    for ref in refs:
        if branch_signal_re.search(ref.branch) or (
            include_default and ref.branch in {"main", "master"}
        ):
            selected.append(ref)
    return selected[:max_per_repo]


def raw_url(repo: str, branch: str, file_path: str) -> str:
    encoded_branch = urllib.parse.quote(branch, safe="")
    encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in file_path.split("/"))
    return f"https://raw.githubusercontent.com/{repo}/{encoded_branch}/{encoded_path}"


@functools.lru_cache(maxsize=4096)
def cached_raw_text(
    repo: str,
    branch: str,
    file_path: str,
    timeout: int,
    proxy_mode: str,
) -> str | None:
    return request_text(raw_url(repo, branch, file_path), timeout, proxy_mode)


def changed_candidate_lines(base_text: str | None, candidate_text: str) -> str:
    if base_text is None:
        return candidate_text

    base_lines = base_text.splitlines()
    candidate_lines = candidate_text.splitlines()
    changed_lines: list[str] = []
    matcher = difflib.SequenceMatcher(None, base_lines, candidate_lines, autojunk=False)
    for tag, _base_start, _base_end, candidate_start, candidate_end in matcher.get_opcodes():
        if tag in {"insert", "replace"}:
            changed_lines.extend(candidate_lines[candidate_start:candidate_end])
    return "\n".join(changed_lines)


def excerpts_for(pattern: re.Pattern[str], text: str, max_count: int = 3) -> list[str]:
    excerpts: list[str] = []
    for match in pattern.finditer(text):
        start = max(0, match.start() - 80)
        end = min(len(text), match.end() + 120)
        snippet = text[start:end].replace("\r", " ").replace("\n", " ")
        snippet = re.sub(r"\s+", " ", snippet).strip()
        excerpts.append(snippet[:260])
        if len(excerpts) >= max_count:
            break
    return excerpts


def audit_branch(
    ref: BranchRef,
    timeout: int,
    proxy_mode: str,
    key_files: list[str],
    base_repo: str,
    base_branch: str,
    scan_full_file: bool,
    branch_signal_re: re.Pattern[str],
    high_risk_re: re.Pattern[str],
    relaxed_mode_re: re.Pattern[str],
    sensitive_re: re.Pattern[str],
) -> AuditFinding | None:
    file_findings: list[FileFinding] = []
    score = 0
    branch_signal = bool(branch_signal_re.search(ref.branch))
    if branch_signal:
        score += 5

    for file_path in key_files:
        text = cached_raw_text(ref.repo, ref.branch, file_path, timeout, proxy_mode)
        if not text:
            continue
        if scan_full_file:
            scan_text = text
        else:
            base_text = cached_raw_text(base_repo, base_branch, file_path, timeout, proxy_mode)
            scan_text = changed_candidate_lines(base_text, text)
            if not scan_text.strip():
                continue

        high = excerpts_for(high_risk_re, scan_text)
        if high:
            score += 80
            file_findings.append(FileFinding(file_path, "high_risk_local_bypass", high))

        relaxed = excerpts_for(relaxed_mode_re, scan_text)
        if relaxed:
            score += 15
            file_findings.append(FileFinding(file_path, "relaxed_permission_mode", relaxed))

        sensitive = excerpts_for(sensitive_re, scan_text, max_count=2)
        if sensitive:
            file_findings.append(FileFinding(file_path, "sensitive_surface_changed_or_present", sensitive))

    has_high_evidence = any(
        item.category == "high_risk_local_bypass" for item in file_findings
    )
    if has_high_evidence and score >= 70:
        rating = "HIGH: sec_patch-like or sensitive bypass indicators"
    elif score >= 20:
        rating = "MEDIUM: permission/sandbox related"
    elif score > 0:
        rating = "LOW: branch-name or weak signal only"
    else:
        return None

    return AuditFinding(
        repo=ref.repo,
        branch=ref.branch,
        sha=ref.sha,
        url=f"https://github.com/{ref.repo}/tree/{urllib.parse.quote(ref.branch, safe='/')}",
        score=score,
        rating=rating,
        branch_signal=branch_signal,
        file_findings=file_findings,
    )


def unique_refs_by_sha(refs: list[BranchRef]) -> list[BranchRef]:
    seen: set[str] = set()
    unique: list[BranchRef] = []
    for ref in refs:
        if ref.sha in seen:
            continue
        seen.add(ref.sha)
        unique.append(ref)
    return unique


def filter_base_branch_shas(
    refs: list[BranchRef],
    base_repo: str,
    git_timeout: int,
    proxy_mode: str,
) -> tuple[list[BranchRef], int]:
    base_refs = git_ls_remote_heads(base_repo, git_timeout, proxy_mode)
    base_shas = {ref.sha for ref in base_refs}
    if not base_shas:
        return refs, 0
    filtered = [ref for ref in refs if ref.sha not in base_shas]
    return filtered, len(refs) - len(filtered)


def rating_zh(rating: str) -> str:
    if rating.startswith("HIGH"):
        return "高风险"
    if rating.startswith("MEDIUM"):
        return "中风险"
    if rating.startswith("LOW"):
        return "低风险"
    return rating


def rating_explanation_zh(rating: str) -> str:
    if rating.startswith("HIGH"):
        return "疑似 sec_patch 类改动或本地安全/审批绕过特征，建议优先人工 diff 审计"
    if rating.startswith("MEDIUM"):
        return "涉及权限、沙箱、审批、YOLO 或外部沙箱相关改动，适合作为候选继续查看"
    if rating.startswith("LOW"):
        return "主要来自分支名等弱信号，优先级较低"
    return "未分类"


def category_zh(category: str) -> str:
    return CATEGORY_ZH.get(category, category)


def create_run_output_dir(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = out_dir / timestamp
    suffix = 1
    while run_dir.exists():
        suffix += 1
        run_dir = out_dir / f"{timestamp}_{suffix}"
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def write_reports(
    findings: list[AuditFinding],
    repo_inventory: list[RepoInventory],
    out_dir: Path,
) -> Path:
    run_dir = create_run_output_dir(out_dir)
    json_path = run_dir / "codex_fork_audit.json"
    md_path = run_dir / "codex_fork_audit.md"
    csv_path = run_dir / "codex_fork_audit.csv"
    repo_csv_path = run_dir / "repo_inventory.csv"

    json_path.write_text(
        json.dumps([asdict(f) for f in findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "分数",
                "风险等级",
                "风险解释",
                "仓库",
                "分支",
                "提交SHA",
                "链接",
                "命中类别",
                "命中类别中文解释",
                "命中文件数",
                "命中摘要",
            ]
        )
        for finding in findings:
            categories = sorted({item.category for item in finding.file_findings})
            category_explanations = [category_zh(category) for category in categories]
            excerpts: list[str] = []
            for item in finding.file_findings:
                for excerpt in item.excerpts[:1]:
                    excerpts.append(f"{item.file}: {excerpt}")
            summary = " | ".join(excerpts[:3])
            writer.writerow(
                [
                    finding.score,
                    rating_zh(finding.rating),
                    rating_explanation_zh(finding.rating),
                    finding.repo,
                    finding.branch,
                    finding.sha[:12],
                    finding.url,
                    ";".join(categories),
                    "；".join(category_explanations),
                    len(finding.file_findings),
                    summary,
                ]
            )

    with repo_csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "仓库",
                "仓库链接",
                "来源",
                "Star数",
                "最近推送",
                "状态",
                "全部分支数",
                "候选分支数",
                "说明",
            ]
        )
        for item in repo_inventory:
            writer.writerow(
                [
                    item.repo,
                    item.url,
                    item.source,
                    "" if item.stars is None else item.stars,
                    item.pushed_at or "",
                    item.status,
                    item.branch_count,
                    item.candidate_count,
                    item.note,
                ]
            )

    lines = [
        "# Codex Fork Audit",
        "",
        "Read-only triage report. Findings are indicators, not proof of safety or maliciousness.",
        "",
    ]
    for finding in findings:
        lines.extend(
            [
                f"## {finding.score} - {finding.repo} / `{finding.branch}`",
                "",
                f"- Rating: {finding.rating}",
                f"- URL: {finding.url}",
                f"- SHA: `{finding.sha}`",
            ]
        )
        for file_finding in finding.file_findings:
            lines.append(f"- `{file_finding.file}`: {file_finding.category}")
            for excerpt in file_finding.excerpts:
                lines.append(f"  - {excerpt}")
        lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")
    return run_dir


def audit_finding_from_dict(data: dict[str, Any]) -> AuditFinding:
    return AuditFinding(
        repo=str(data.get("repo") or ""),
        branch=str(data.get("branch") or ""),
        sha=str(data.get("sha") or ""),
        url=str(data.get("url") or ""),
        score=int(data.get("score") or 0),
        rating=str(data.get("rating") or ""),
        branch_signal=bool(data.get("branch_signal")),
        file_findings=[
            FileFinding(
                file=str(item.get("file") or ""),
                category=str(item.get("category") or ""),
                excerpts=[str(excerpt) for excerpt in item.get("excerpts", [])],
            )
            for item in data.get("file_findings", [])
            if isinstance(item, dict)
        ],
    )


def latest_report_cache(out_dir: Path) -> tuple[Path, list[AuditFinding]] | None:
    if not out_dir.exists():
        return None
    report_paths = sorted(
        out_dir.glob("*/codex_fork_audit.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for report_path in report_paths:
        try:
            raw = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(raw, list):
            continue
        findings = [
            audit_finding_from_dict(item)
            for item in raw
            if isinstance(item, dict)
        ]
        return report_path, findings
    return None


def safe_path_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return safe.strip("._") or "candidate"


def run_git_command(command: list[str], cwd: Path | None, proxy_mode: str, timeout: int) -> None:
    env = os.environ.copy()
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    if proxy_mode == "proxy":
        env["HTTPS_PROXY"] = DEFAULT_PROXY
        env["HTTP_PROXY"] = DEFAULT_PROXY
    proc = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        timeout=timeout,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise RuntimeError(f"命令执行失败: {' '.join(command)}\n{detail}")


def candidate_target_dir(workdir: Path, finding: AuditFinding) -> Path:
    return workdir / f"{safe_path_name(finding.repo)}__{safe_path_name(finding.branch)}"


def backup_existing_dir(target: Path) -> Path | None:
    if not target.exists():
        return None
    backup_root = target.parent / "_backups"
    backup_root.mkdir(parents=True, exist_ok=True)
    backup = backup_root / f"{target.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    shutil.move(str(target), str(backup))
    return backup


def likely_codex_entry(repo_dir: Path) -> Path | None:
    vendor_exe = codex_cli_vendor_exe(repo_dir)
    candidates = [
        repo_dir / "codex-rs" / "target" / "release" / "codex.exe",
        repo_dir / "codex-rs" / "target" / "debug" / "codex.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    if vendor_exe.exists():
        wrapper = repo_dir / "codex-cli" / "bin" / "codex.js"
        if wrapper.exists():
            return wrapper
    return candidates[0]


def codex_cli_vendor_exe(repo_dir: Path) -> Path:
    return (
        repo_dir
        / "codex-cli"
        / "vendor"
        / "x86_64-pc-windows-msvc"
        / "codex"
        / "codex.exe"
    )


def existing_codex_entry(repo_dir: Path) -> Path | None:
    vendor_exe = codex_cli_vendor_exe(repo_dir)
    candidates = [
        repo_dir / "codex-rs" / "target" / "release" / "codex.exe",
        repo_dir / "codex-rs" / "target" / "debug" / "codex.exe",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    wrapper = repo_dir / "codex-cli" / "bin" / "codex.js"
    if wrapper.exists() and vendor_exe.exists():
        return wrapper
    return None


def sync_codex_vendor_exe(repo_dir: Path) -> Path | None:
    source = repo_dir / "codex-rs" / "target" / "release" / "codex.exe"
    if not source.exists():
        source = repo_dir / "codex-rs" / "target" / "debug" / "codex.exe"
    if not source.exists():
        return None
    target = codex_cli_vendor_exe(repo_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != target.resolve():
        shutil.copy2(source, target)
    return target


def build_codex_candidate(repo_dir: Path, proxy_mode: str, timeout: int) -> Path | None:
    codex_rs = repo_dir / "codex-rs"
    cargo_toml = codex_rs / "Cargo.toml"
    if not cargo_toml.exists():
        log(f"未发现 Rust 工作区，跳过编译: {cargo_toml}")
        return sync_codex_vendor_exe(repo_dir)

    release_exe = codex_rs / "target" / "release" / "codex.exe"
    if release_exe.exists():
        log(f"已存在 release 可执行文件，跳过重复编译: {release_exe}")
        return sync_codex_vendor_exe(repo_dir)

    log("开始编译候选 Codex：cargo build --release -p codex-cli --bin codex")
    run_git_command(
        ["cargo", "build", "--release", "-p", "codex-cli", "--bin", "codex"],
        cwd=codex_rs,
        proxy_mode=proxy_mode,
        timeout=timeout,
    )
    vendor_exe = sync_codex_vendor_exe(repo_dir)
    if vendor_exe:
        log(f"已同步 vendor 可执行文件: {vendor_exe}")
    return vendor_exe


def launcher_content(entry: Path, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    if entry.suffix.lower() == ".js":
        command = f'node "{entry}" %*'
    else:
        command = f'"{entry}" %*'
    lines = [
        "@echo off",
        "SETLOCAL",
        f'rem Managed by codex_fork_auditor at {datetime.now().isoformat(timespec="seconds")}',
    ]
    for key in ("repo", "branch", "sha", "checkout"):
        value = metadata.get(key)
        if value:
            lines.append(f"rem {key}: {value}")
    lines.extend(
        [
            f'SET "CODEXX_BINARY={entry}"',
            "",
            'IF NOT EXIST "%CODEXX_BINARY%" (',
            '  ECHO codexx binary not found: %CODEXX_BINARY% 1>&2',
            "  EXIT /B 1",
            ")",
            "",
            command,
            "",
        ]
    )
    return "\r\n".join(lines)


def powershell_launcher_content(entry: Path, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    lines = [
        "# Managed by codex_fork_auditor",
        f"# generated_at: {datetime.now().isoformat(timespec='seconds')}",
    ]
    for key in ("repo", "branch", "sha", "checkout"):
        value = metadata.get(key)
        if value:
            lines.append(f"# {key}: {value}")
    lines.extend(
        [
            f"$binary = {json.dumps(str(entry), ensure_ascii=False)}",
            "",
            "if (-not (Test-Path $binary)) {",
            '  throw "codexx binary not found: $binary"',
            "}",
            "",
            "if ($MyInvocation.ExpectingInput) {",
            "  $input | & $binary $args",
            "} else {",
            "  & $binary $args",
            "}",
            "",
            "exit $LASTEXITCODE",
            "",
        ]
    )
    return "\r\n".join(lines)


def shell_launcher_content(entry: Path, metadata: dict[str, Any] | None = None) -> str:
    metadata = metadata or {}
    lines = [
        "#!/bin/sh",
        "# Managed by codex_fork_auditor",
        f"# generated_at: {datetime.now().isoformat(timespec='seconds')}",
    ]
    for key in ("repo", "branch", "sha", "checkout"):
        value = metadata.get(key)
        if value:
            lines.append(f"# {key}: {value}")
    quoted_entry = "'" + str(entry).replace("'", "'\"'\"'") + "'"
    lines.extend(
        [
            f"binary={quoted_entry}",
            "",
            'if [ ! -f "$binary" ]; then',
            '  echo "codexx binary not found: $binary" >&2',
            "  exit 1",
            "fi",
            "",
            'exec "$binary" "$@"',
            "",
        ]
    )
    return "\n".join(lines)


def write_codexx_cmd(codexx_cmd: Path, entry: Path, metadata: dict[str, Any]) -> Path | None:
    codexx_cmd.parent.mkdir(parents=True, exist_ok=True)
    backup = backup_file(codexx_cmd)
    codexx_cmd.write_text(launcher_content(entry, metadata), encoding="utf-8")
    ps1_path = codexx_cmd.with_suffix(".ps1")
    sh_path = codexx_cmd.with_suffix("")
    backup_file(ps1_path)
    backup_file(sh_path)
    ps1_path.write_text(powershell_launcher_content(entry, metadata), encoding="utf-8")
    sh_path.write_text(shell_launcher_content(entry, metadata), encoding="utf-8")
    return backup


def backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    backup = path.with_name(f"{path.name}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak")
    shutil.copy2(path, backup)
    return backup


def write_candidate_cmd(
    cmd_path: Path,
    target_dir: Path,
    entry: Path | None,
    finding: AuditFinding,
) -> Path:
    candidate_path = cmd_path.with_name(f"{cmd_path.name}.candidate")
    usable_entry = entry if entry and entry.exists() else None
    entry_text = str(usable_entry) if usable_entry else "<build-first>"
    if usable_entry and usable_entry.suffix.lower() == ".js":
        command = f'node "{usable_entry}" %*'
    elif usable_entry and usable_entry.suffix.lower() == ".exe":
        command = f'"{usable_entry}" %*'
    else:
        command = (
            "echo 候选 checkout 已准备好，但未发现已编译的可执行文件。\r\n"
            f'echo 仓库目录: "{target_dir}"\r\n'
            "echo 请先编译并审计，再手动更新此启动脚本。\r\n"
            "exit /b 1"
        )
    content = (
        "@echo off\r\n"
        "rem 候选启动脚本，仅供人工安全审阅。\r\n"
        f"rem Repo: {finding.repo}\r\n"
        f"rem Branch: {finding.branch}\r\n"
        f"rem SHA: {finding.sha}\r\n"
        f"rem Checkout: {target_dir}\r\n"
        f"rem Entry: {entry_text}\r\n"
        f"{command}\r\n"
    )
    candidate_path.parent.mkdir(parents=True, exist_ok=True)
    candidate_path.write_text(content, encoding="utf-8")
    return candidate_path


def load_codexx_history(workdir: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    seen: set[Path] = set()

    for manifest_path in workdir.rglob("candidate_checkout_manifest.json"):
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        checkout = Path(str(manifest.get("checkout") or manifest_path.parent)).expanduser()
        if not checkout.is_absolute():
            checkout = (manifest_path.parent / checkout).resolve()
        entry = existing_codex_entry(checkout)
        checkout_resolved = checkout.resolve()
        if checkout_resolved in seen:
            continue
        seen.add(checkout_resolved)
        entries.append(
            {
                "entry": entry.resolve() if entry else None,
                "checkout": checkout_resolved,
                "repo": manifest.get("repo") or checkout.name,
                "branch": manifest.get("branch") or "-",
                "sha": str(manifest.get("sha") or "")[:12],
                "source": str(manifest_path),
                "built": entry is not None,
            }
        )

    if workdir.exists():
        for checkout in workdir.iterdir():
            if not checkout.is_dir() or checkout.name == "_backups":
                continue
            if not (checkout / "codex-rs" / "Cargo.toml").exists() and not existing_codex_entry(checkout):
                continue
            entry = existing_codex_entry(checkout)
            checkout_resolved = checkout.resolve()
            if checkout_resolved in seen:
                continue
            seen.add(checkout_resolved)
            entries.append(
                {
                    "entry": entry.resolve() if entry else None,
                    "checkout": checkout_resolved,
                    "repo": checkout.name,
                    "branch": "-",
                    "sha": "",
                    "source": "directory-scan",
                    "built": entry is not None,
                }
            )

    entries.sort(key=lambda item: (str(item["repo"]).lower(), str(item["branch"]).lower()))
    return entries


def switch_codexx_history(
    workdir: Path,
    codexx_cmd: Path,
    index: int | None,
    proxy_mode: str,
    build_timeout: int,
    build_candidate: bool,
) -> None:
    workdir = workdir.resolve()
    entries = load_codexx_history(workdir)
    if not entries:
        log(f"未在目录下找到 codexx 历史候选: {workdir}")
        log("期望存在 candidate_checkout_manifest.json 或 codex-rs\\Cargo.toml。")
        return

    print("\ncodexx 历史候选:")
    for i, item in enumerate(entries, start=1):
        status = "已编译" if item.get("built") else "未编译"
        entry_text = str(item["entry"]) if item.get("entry") else "<选择后自动编译>"
        print(
            f"{i:2d}. [{status}] {item['repo']} / {item['branch']} {item['sha']}\n"
            f"    文件夹: {item['checkout']}\n"
            f"    可执行: {entry_text}"
        )

    selected_index = index
    if selected_index is None:
        raw = prompt_text("请选择要切换到的候选编号，或直接回车取消: ")
        if not raw:
            log("已取消切换。")
            return
        try:
            selected_index = int(raw)
        except ValueError as exc:
            raise SystemExit("选择必须是数字。") from exc
    if selected_index is None or not 1 <= selected_index <= len(entries):
        raise SystemExit(f"切换编号无效；有效范围是 1..{len(entries)}")

    selected = entries[selected_index - 1]
    print("\n已选择:")
    print(f"  文件夹: {selected['checkout']}")
    print(f"  状态: {'已编译' if selected.get('built') else '未编译'}")
    print(f"  可执行: {selected['entry'] or '<选择后自动编译>'}")

    entry = Path(selected["entry"]) if selected.get("entry") else None
    if entry is None or not entry.exists():
        if not build_candidate:
            log("该候选尚未编译，且已关闭自动编译。")
            return
        if index is None and not prompt_yes_no("该候选尚未编译，是否现在自动编译", default=True):
            log("已取消切换。")
            return
        try:
            build_codex_candidate(Path(selected["checkout"]), proxy_mode, build_timeout)
        except RuntimeError as exc:
            log(f"自动编译失败: {exc}")
            return
        entry = existing_codex_entry(Path(selected["checkout"]))
        if entry is None:
            log("编译后仍未找到可执行文件，无法切换。")
            return
        selected["entry"] = entry.resolve()
        selected["built"] = True
        print(f"  编译完成: {selected['entry']}")

    if index is None:
        confirm = prompt_text("输入“切换”以备份并重写 codexx.cmd，或直接回车取消: ")
        if confirm != "切换":
            log("已取消切换。")
            return

    metadata = {
        "repo": selected.get("repo"),
        "branch": selected.get("branch"),
        "sha": selected.get("sha"),
        "checkout": str(selected.get("checkout")),
    }
    backup = write_codexx_cmd(codexx_cmd, Path(selected["entry"]), metadata)
    if backup:
        log(f"旧 codexx.cmd 已备份到: {backup}")
    log(f"codexx.cmd 已切换到: {selected['entry']}")
    log(f"候选文件夹: {selected['checkout']}")


def select_finding_interactively(findings: list[AuditFinding], index: int | None) -> AuditFinding | None:
    if not findings:
        log("没有可用于 checkout 的候选结果。")
        return None
    if index is not None:
        if 1 <= index <= len(findings):
            return findings[index - 1]
        raise SystemExit(f"--candidate-index 无效: {index}；有效范围是 1..{len(findings)}")

    print("\n候选结果:")
    for i, finding in enumerate(findings[:30], start=1):
        print(
            f"{i:2d}. score={finding.score:<3} {rating_zh(finding.rating)} "
            f"{finding.repo} / {finding.branch} @ {finding.sha[:12]}"
        )
    raw = prompt_text("请选择要 checkout 的候选编号，或直接回车跳过: ")
    if not raw:
        return None
    try:
        selected = int(raw)
    except ValueError as exc:
        raise SystemExit("选择必须是数字。") from exc
    if not 1 <= selected <= min(len(findings), 30):
        raise SystemExit("选择超出当前显示范围。")
    return findings[selected - 1]


def prepare_candidate_checkout(
    findings: list[AuditFinding],
    workdir: Path,
    index: int | None,
    codexx_cmd: Path,
    proxy_mode: str,
    git_timeout: int,
    build_timeout: int,
    build_candidate: bool,
) -> None:
    selected = select_finding_interactively(findings, index)
    if selected is None:
        return

    if index is None:
        raw_workdir = prompt_text(f"候选 checkout 工作目录 [{workdir}]: ")
        if raw_workdir:
            workdir = Path(raw_workdir).expanduser()
    workdir = workdir.resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    target = candidate_target_dir(workdir, selected)
    backup = backup_existing_dir(target)
    if backup:
        log(f"已有 checkout 已备份到: {backup}")

    remote = f"https://github.com/{selected.repo}.git"
    log(f"正在拉取候选用于审计: {selected.repo} {selected.branch}")
    run_git_command(
        ["git", "clone", "--branch", selected.branch, "--depth", "1", remote, str(target)],
        cwd=None,
        proxy_mode=proxy_mode,
        timeout=max(git_timeout * 6, 60),
    )
    run_git_command(["git", "checkout", selected.sha], cwd=target, proxy_mode=proxy_mode, timeout=git_timeout)

    if build_candidate:
        try:
            build_codex_candidate(target, proxy_mode, build_timeout)
        except RuntimeError as exc:
            log(f"候选编译失败: {exc}")
            log("已保留 checkout，可手动进入目录排查编译问题。")

    entry = existing_codex_entry(target) or likely_codex_entry(target)
    candidate_cmd = write_candidate_cmd(codexx_cmd, target, entry, selected)
    manifest = {
        "repo": selected.repo,
        "branch": selected.branch,
        "sha": selected.sha,
        "url": selected.url,
        "checkout": str(target),
        "backup": str(backup) if backup else None,
        "candidate_cmd": str(candidate_cmd),
        "entry": str(entry) if entry else None,
        "vendor_exe": str(codex_cli_vendor_exe(target)),
        "note": "Candidate prepared by codex_fork_auditor.",
    }
    (target / "candidate_checkout_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    log(f"候选 checkout 已准备好: {target}")
    log(f"候选启动脚本已写入（仅供审阅）: {candidate_cmd}")
    if entry and entry.exists() and prompt_yes_no(
        f"是否备份并把 codexx.cmd 切换到这个候选可执行文件: {entry}",
        default=True,
    ):
        backup_cmd = write_codexx_cmd(
            codexx_cmd,
            entry,
            {
                "repo": selected.repo,
                "branch": selected.branch,
                "sha": selected.sha,
                "checkout": str(target),
            },
        )
        if backup_cmd:
            log(f"旧 codexx.cmd 已备份到: {backup_cmd}")
        log(f"codexx.cmd 已指向: {entry}")
    else:
        log("全局 codexx.cmd 未修改。可稍后通过 --switch 切换。")


def batched(iterable: Iterable[str], size: int) -> Iterable[list[str]]:
    batch: list[str] = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only auditor for public Codex forks.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=r"""
Recommended default scan
------------------------
No arguments are required:

  python .\audit_codex_forks.py

This default scan targets recent low-star Codex forks:
  recent days          365
  max stars            50
  max repositories     300
  branches per repo    8
  search pages         2
  repository filter    Codex key-path layout required
  report noise         LOW branch-name-only hits hidden

Common examples
---------------
Faster, smaller scan:
  python .\audit_codex_forks.py --max-repos 120 --search-pages 1

Broader scan:
  python .\audit_codex_forks.py --pages 8 --search-pages 3 --max-repos 600 --full-key-files

Only seed repos and fork API, no GitHub code search:
  python .\audit_codex_forks.py --no-search-github

Show LOW branch-name-only hits too:
  python .\audit_codex_forks.py --include-low

Prepare, build, and optionally switch one selected candidate:
  python .\audit_codex_forks.py

Switch between local codexx candidates, building missing ones:
  python .\audit_codex_forks.py --switch

Chinese detailed help:
  python .\audit_codex_forks.py --help-zh
""",
    )
    parser.add_argument("--help-zh", action="store_true", help="Show detailed Chinese help and exit.")
    parser.add_argument("--config", type=Path, default=Path("audit_config.json"), help="Audit regex/path config file. Default: audit_config.json")
    parser.add_argument("--proxy-config", type=Path, default=DEFAULT_PROXY_CONFIG_FILE, help="Proxy config file. Default: proxy_config.json")
    parser.add_argument("--secrets-file", type=Path, default=DEFAULT_SECRETS_FILE, help="Saved GitHub token file. Default: data/secrets.json")
    parser.add_argument(
        "--save-github-token",
        action="store_true",
        help="Prompt for a GitHub token, save it to --secrets-file, then exit.",
    )
    parser.add_argument("--base-repo", default=DEFAULT_BASE_REPO, help=f"Official repo used as baseline. Default: {DEFAULT_BASE_REPO}")
    parser.add_argument(
        "--base-branch",
        default="main",
        help="Official base branch used for per-file diffing. Default: main",
    )
    parser.add_argument("--repos-file", type=Path, default=Path("data/repos.txt"), help="Seed repo list. Default: data/repos.txt")
    parser.add_argument("--discover-forks", action="store_true", help="Use GitHub API to enumerate forks. Auto-enabled when a token exists.")
    parser.add_argument("--pages", type=int, default=3, help="Fork API pages to scan. Default: 3")
    parser.add_argument(
        "--search-github",
        action="store_true",
        default=True,
        help="Use GitHub code search to find recent low-star Codex forks. Default: on",
    )
    parser.add_argument(
        "--no-search-github",
        action="store_false",
        dest="search_github",
        help="Disable GitHub code search.",
    )
    parser.add_argument(
        "--broad-repo-search",
        action="store_true",
        help="Also use broad repository search before Codex layout filtering. Higher noise.",
    )
    parser.add_argument("--search-pages", type=int, default=2, help="Code-search pages per query. Default: 2")
    parser.add_argument("--recent-days", type=int, default=365, help="Only search repos pushed within this many days. Default: 365")
    parser.add_argument("--max-stars", type=int, default=50, help="Prefer searched repos below this star count. Default: 50")
    parser.add_argument("--max-repos", type=int, default=300, help="Maximum repositories to process. Default: 300")
    parser.add_argument("--max-branches-per-repo", type=int, default=8, help="Maximum candidate branches per repo. Default: 8")
    parser.add_argument("--include-default-branch", action="store_true", default=True, help="Scan main/master too. Default: on")
    parser.add_argument(
        "--suspicious-branches-only",
        action="store_false",
        dest="include_default_branch",
        help="Do not scan main/master unless their branch name also matches suspicious keywords.",
    )
    parser.add_argument("--include-base-repo", action="store_true", help="Also scan the official base repo. Default: off")
    parser.add_argument(
        "--full-key-files",
        action="store_true",
        help="Scan all configured key files instead of the faster core subset.",
    )
    parser.add_argument(
        "--scan-full-file",
        action="store_true",
        help="Scan whole files instead of only candidate lines changed from --base-repo/--base-branch.",
    )
    parser.add_argument(
        "--include-low",
        action="store_true",
        help="Include LOW branch-name-only hits in codex_fork_audit reports.",
    )
    parser.add_argument(
        "--no-layout-filter",
        action="store_false",
        dest="layout_filter",
        help="Do not require Codex key files to exist before scanning a repository.",
    )
    parser.add_argument("--workers", type=int, default=24, help="Concurrent raw-file scan workers. Default: 24")
    parser.add_argument("--list-workers", type=int, default=32, help="Concurrent git ls-remote workers. Default: 32")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout seconds. Default: 15")
    parser.add_argument("--git-timeout", type=int, default=12, help="git ls-remote timeout seconds. Default: 12")
    parser.add_argument("--proxy-mode", choices=["auto", "direct", "proxy"], default="auto", help="Network mode. Default: auto, then proxy_config may override.")
    parser.add_argument("--proxy-url", default=DEFAULT_PROXY, help=f"HTTP proxy fallback. Default: {DEFAULT_PROXY}")
    parser.add_argument("--socks-proxy-url", default=DEFAULT_SOCKS_PROXY, help=f"SOCKS proxy fallback. Default: {DEFAULT_SOCKS_PROXY}")
    parser.add_argument("--no-dedupe-sha", action="store_true", help="Do not deduplicate branches by commit SHA.")
    parser.add_argument(
        "--include-base-branch-shas",
        action="store_true",
        help="Keep fork branches whose commit SHA matches an official base-repo branch.",
    )
    parser.add_argument("--out-dir", type=Path, default=Path("reports"), help="Output directory. Default: reports")
    parser.add_argument(
        "--prepare-candidate",
        action="store_true",
        default=True,
        help=(
            "After scanning, choose one finding, clone it, build it, and ask before "
            "switching codexx.cmd. Default: on"
        ),
    )
    parser.add_argument(
        "--no-prepare-candidate",
        action="store_false",
        dest="prepare_candidate",
        help="Disable the post-scan candidate checkout prompt.",
    )
    parser.add_argument(
        "--candidate-index",
        type=int,
        default=None,
        help="Non-interactive finding index for --prepare-candidate. 1 means top finding.",
    )
    parser.add_argument(
        "--candidate-workdir",
        type=Path,
        default=Path("candidate_checkouts"),
        help="Directory for prepared candidate checkouts. Default: candidate_checkouts",
    )
    parser.add_argument(
        "--build-timeout",
        type=int,
        default=3600,
        help="Candidate cargo build timeout seconds. Default: 3600",
    )
    parser.add_argument(
        "--no-build-candidate",
        action="store_false",
        dest="build_candidate",
        help="Do not auto-build the selected candidate checkout.",
    )
    parser.add_argument(
        "--codexx-cmd",
        type=Path,
        default=DEFAULT_CODEXX_CMD,
        help=f"Path to the codexx.cmd launcher to back up and rewrite after confirmation. Default: {DEFAULT_CODEXX_CMD}",
    )
    parser.add_argument(
        "--switch",
        "--switch-codexx",
        dest="switch_codexx",
        action="store_true",
        help=(
            "Switch codexx.cmd between local candidates under --candidate-workdir. "
            "Shows folders and builds missing executables before switching."
        ),
    )
    parser.add_argument(
        "--switch-index",
        type=int,
        default=None,
        help="Non-interactive index for --switch-codexx. 1 means first built candidate.",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        default=False,
        help="Prompt for advanced scan options.",
    )
    parser.add_argument(
        "--no-token-prompt",
        action="store_true",
        help="Do not ask for a GitHub token when none is configured.",
    )
    args = parser.parse_args()
    if args.help_zh:
        print(HELP_ZH)
        raise SystemExit(0)
    argv = set(sys.argv[1:])
    args.proxy_mode_set_by_cli = "--proxy-mode" in argv
    args.proxy_url_set_by_cli = "--proxy-url" in argv
    args.socks_proxy_url_set_by_cli = "--socks-proxy-url" in argv
    return args


def main() -> int:
    global DEFAULT_PROXY, DEFAULT_SOCKS_PROXY
    args = parse_args()
    root = Path(__file__).resolve().parent
    load_proxy_config(args, root)
    DEFAULT_PROXY = args.proxy_url
    DEFAULT_SOCKS_PROXY = args.socks_proxy_url
    out_dir = args.out_dir
    if not out_dir.is_absolute():
        out_dir = root / out_dir
    if args.switch_codexx:
        candidate_workdir = args.candidate_workdir
        if not candidate_workdir.is_absolute():
            candidate_workdir = root / candidate_workdir
        switch_codexx_history(
            workdir=candidate_workdir,
            codexx_cmd=args.codexx_cmd,
            index=args.switch_index,
            proxy_mode=args.proxy_mode,
            build_timeout=args.build_timeout,
            build_candidate=args.build_candidate,
        )
        return 0
    if args.save_github_token:
        secrets_file = args.secrets_file
        if not secrets_file.is_absolute():
            secrets_file = root / secrets_file
        token = getpass.getpass("请输入要保存的 GitHub token，或直接回车取消: ").strip()
        if not token:
            log("未输入 token，未保存。")
            return 1
        save_token(secrets_file, token)
        log(f"已保存 token 到: {secrets_file}")
        return 0
    cache = latest_report_cache(out_dir)
    if cache and args.prepare_candidate:
        cache_path, cached_findings = cache
        if prompt_yes_no(
            f"发现最近一次审计缓存: {cache_path}，共 {len(cached_findings)} 条结果。是否直接使用缓存",
            default=True,
        ):
            log(f"已使用缓存结果: {cache_path}")
            candidate_workdir = args.candidate_workdir
            if not candidate_workdir.is_absolute():
                candidate_workdir = root / candidate_workdir
            prepare_candidate_checkout(
                findings=cached_findings,
                workdir=candidate_workdir,
                index=args.candidate_index,
                codexx_cmd=args.codexx_cmd,
                proxy_mode=args.proxy_mode,
                git_timeout=args.git_timeout,
                build_timeout=args.build_timeout,
                build_candidate=args.build_candidate,
            )
            return 0
    if args.interactive:
        args = interactive_args(args, root)
    else:
        has_token = ensure_token(args, root, prompt_if_missing=not args.no_token_prompt)
        if has_token:
            args.discover_forks = True
    token_status = validate_github_token(args.timeout, args.proxy_mode)
    if token_status == 401:
        secrets_file = args.secrets_file
        if not secrets_file.is_absolute():
            secrets_file = root / secrets_file
        delete_saved_token(secrets_file)
        os.environ.pop("GITHUB_TOKEN", None)
        if args.no_token_prompt:
            log("GitHub token 无效，且已禁用 token 提示；仅扫描种子仓库。")
            args.discover_forks = False
        elif prompt_and_save_token(
            args,
            root,
            "GitHub token 无效（401 Bad credentials）。",
        ):
            args.discover_forks = True
        else:
            args.discover_forks = False
    config_path = args.config
    if not config_path.is_absolute():
        config_path = root / config_path
    audit_config = load_audit_config(config_path)
    branch_signal_re = compile_pattern(audit_config.branch_signal_pattern)
    high_risk_re = compile_pattern(audit_config.high_risk_pattern, re.IGNORECASE | re.DOTALL)
    relaxed_mode_re = compile_pattern(audit_config.relaxed_mode_pattern)
    sensitive_re = compile_pattern(audit_config.sensitive_pattern)
    repos_file = args.repos_file
    if not repos_file.is_absolute():
        repos_file = root / repos_file

    repo_candidates: list[RepoCandidate] = repo_candidates_from_names(
        load_repos_from_file(repos_file),
        "repos-file",
    )
    if args.discover_forks:
        log(f"Discovering forks of {args.base_repo} via GitHub API...")
        discovered, status = discover_forks(
            args.base_repo,
            args.pages,
            args.timeout,
            args.proxy_mode,
        )
        if status == 401:
            secrets_file = args.secrets_file
            if not secrets_file.is_absolute():
                secrets_file = root / secrets_file
            delete_saved_token(secrets_file)
            os.environ.pop("GITHUB_TOKEN", None)
            if args.no_token_prompt:
                log("GitHub token 无效，且已禁用 token 提示；仅扫描种子仓库。")
            elif prompt_and_save_token(
                    args,
                    root,
                    "GitHub 返回 401 Bad credentials，已保存/环境变量中的 token 无效。",
                ):
                discovered, _status = discover_forks(
                    args.base_repo,
                    args.pages,
                    args.timeout,
                    args.proxy_mode,
                )
        repo_candidates.extend(discovered)
    if args.search_github:
        queries = default_code_search_queries(args.recent_days, args.max_stars)
        log(
            "正在通过 GitHub 代码搜索近期低 star Codex 仓库 "
            f"({len(queries)} 个查询，每个 {args.search_pages} 页)..."
        )
        searched, status = search_github_code_repos(
            queries,
            args.search_pages,
            args.timeout,
            args.proxy_mode,
        )
        if status == 401:
            log("GitHub 代码搜索返回 401；继续使用 fork/种子仓库。")
        repo_candidates.extend(searched)
    if args.broad_repo_search:
        queries = default_search_queries(args.base_repo, args.recent_days, args.max_stars)
        log(
            "已启用宽泛 GitHub 仓库搜索 "
            f"({len(queries)} 个查询，每个 {args.search_pages} 页)..."
        )
        searched, status = search_github_repos(
            queries,
            args.search_pages,
            args.timeout,
            args.proxy_mode,
        )
        if status == 401:
            log("GitHub 仓库搜索返回 401；继续使用其他来源。")
        repo_candidates.extend(searched)
    if args.include_base_repo:
        repo_candidates.append(RepoCandidate(args.base_repo, "base-repo"))
    else:
        repo_candidates = [
            candidate
            for candidate in repo_candidates
            if candidate.repo.lower() != args.base_repo.lower()
        ]
    repo_candidates = merge_repo_candidates(repo_candidates)[: args.max_repos]
    repo_by_name = {candidate.repo: candidate for candidate in repo_candidates}
    repos = [candidate.repo for candidate in repo_candidates]
    log(f"已加入队列的仓库数: {len(repos)}")

    refs: list[BranchRef] = []
    repo_inventory: list[RepoInventory] = []
    log(f"正在用 {args.list_workers} 个并发列出分支...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.list_workers) as executor:
        future_to_repo = {
            executor.submit(git_ls_remote_heads, repo, args.git_timeout, args.proxy_mode): repo
            for repo in repos
        }
        completed = 0
        for future in concurrent.futures.as_completed(future_to_repo):
            completed += 1
            repo = future_to_repo[future]
            log(f"[{completed}/{len(repos)}] 已列出分支: {repo}")
            repo_refs = future.result()
            status = "可访问" if repo_refs else "未列出分支"
            note = (
                "git ls-remote 成功"
                if repo_refs
                else "可能仓库不存在、私有、被删除、网络失败，或 git 访问超时"
            )
            if args.layout_filter and repo_refs:
                default_branch = first_likely_default_branch(repo_refs)
                if default_branch and not looks_like_codex_repo(
                    repo,
                    default_branch,
                    args.timeout,
                    args.proxy_mode,
                ):
                    repo_candidate = repo_by_name.get(repo, RepoCandidate(repo, "unknown"))
                    repo_inventory.append(
                        RepoInventory(
                            repo=repo,
                            url=f"https://github.com/{repo}",
                            source=repo_candidate.source,
                            stars=repo_candidate.stars,
                            pushed_at=repo_candidate.pushed_at,
                            status="跳过",
                            branch_count=len(repo_refs),
                            candidate_count=0,
                            note="未发现 Codex 关键路径，已按默认布局过滤跳过",
                        )
                    )
                    continue
            repo_candidates = candidate_branches(
                repo_refs,
                args.max_branches_per_repo,
                args.include_default_branch,
                branch_signal_re,
            )
            refs.extend(repo_candidates)
            repo_candidate = repo_by_name.get(repo, RepoCandidate(repo, "unknown"))
            repo_inventory.append(
                RepoInventory(
                    repo=repo,
                    url=f"https://github.com/{repo}",
                    source=repo_candidate.source,
                    stars=repo_candidate.stars,
                    pushed_at=repo_candidate.pushed_at,
                    status=status,
                    branch_count=len(repo_refs),
                    candidate_count=len(repo_candidates),
                    note=note,
                )
            )
    log(f"候选分支数: {len(refs)}")
    if not args.include_base_branch_shas:
        before = len(refs)
        refs, removed = filter_base_branch_shas(
            refs,
            args.base_repo,
            args.git_timeout,
            args.proxy_mode,
        )
        log(f"官方 SHA 过滤后候选分支数: {len(refs)} (移除 {removed})")
    if not args.no_dedupe_sha:
        before = len(refs)
        refs = unique_refs_by_sha(refs)
        log(f"SHA 去重后候选分支数: {len(refs)} (移除 {before - len(refs)})")

    key_files = audit_config.key_files if args.full_key_files else audit_config.quick_key_files
    log(f"每个分支扫描关键文件数: {len(key_files)}")

    findings: list[AuditFinding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [
            executor.submit(
                audit_branch,
                ref,
                args.timeout,
                args.proxy_mode,
                key_files,
                args.base_repo,
                args.base_branch,
                args.scan_full_file,
                branch_signal_re,
                high_risk_re,
                relaxed_mode_re,
                sensitive_re,
            )
            for ref in refs
        ]
        for future in concurrent.futures.as_completed(futures):
            finding = future.result()
            if finding:
                if finding.rating.startswith("LOW") and not args.include_low:
                    continue
                findings.append(finding)
                log(f"命中 score={finding.score}: {finding.repo} {finding.branch}")

    findings.sort(key=lambda item: item.score, reverse=True)
    repo_inventory.sort(
        key=lambda item: (
            item.status,
            item.stars if item.stars is not None else 999999,
            item.repo.lower(),
        )
    )
    run_out_dir = write_reports(findings, repo_inventory, out_dir)
    log(f"发现结果数: {len(findings)}")
    log(f"报告已写入: {run_out_dir}")
    if args.prepare_candidate:
        candidate_workdir = args.candidate_workdir
        if not candidate_workdir.is_absolute():
            candidate_workdir = root / candidate_workdir
        prepare_candidate_checkout(
            findings=findings,
            workdir=candidate_workdir,
            index=args.candidate_index,
            codexx_cmd=args.codexx_cmd,
            proxy_mode=args.proxy_mode,
            git_timeout=args.git_timeout,
            build_timeout=args.build_timeout,
            build_candidate=args.build_candidate,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
