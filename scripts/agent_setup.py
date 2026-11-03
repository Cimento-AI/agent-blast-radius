#!/usr/bin/env python3
"""The facts behind /blast-radius: what each coding agent on this machine reads,
what it can reach, what it can do without asking, and who else would see it.

Reads Claude Code, Cursor and Codex configuration and prints one JSON object.
`page` reads the write-up the agent built from those facts on stdin, checks
it, and opens it as a page. Secret values never appear in the output:
env vars and headers keep their names only, credential-shaped arguments, URL
parts and rule text become "<redacted>", and credential files are opened only
to answer yes or no to "does this hold a credential?". Nothing is sent anywhere.
Standard library only, Python 3.8+.
"""

import base64
import datetime
import glob
import html
import json
import os
import re
import sqlite3
import subprocess
import sys
import tempfile

VERSION = "0.4.0"
HOME = os.path.expanduser("~")
# Tests point this at a fake filesystem root; real runs leave it empty.
SYSTEM = os.environ.get("BLAST_RADIUS_SYSTEM_ROOT", "")
CWD = os.getcwd()
REDACTED = "<redacted>"
FILES_READ = []

# ---------------------------------------------------------------- redaction

CREDENTIAL_WORDS = {
    "token", "secret", "password", "passwd", "pwd", "apikey", "key", "auth",
    "authorization", "bearer", "basic", "credential", "credentials", "cred", "creds",
    "session", "cookie", "signature", "sig", "private", "pat", "dsn", "jwt",
}
SECRET_SHAPE = re.compile(
    r"(sk-|ghp_|gho_|ghs_|ghu_|github_pat_|xox[abpr]-|glpat-|AKIA|ASIA|AIza|ya29\.|eyJ[\w-]+\.)"
    r"|^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_\-+/=]{20,}$"
)


def clean(text, limit=80):
    """Collapse whitespace, drop control characters, cap length. Every string
    copied from a config file goes through here, so a file cannot smuggle a
    long instruction into the output."""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text))
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def tilde(text):
    return str(text).replace(HOME, "~")


def is_credential_key(key):
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(key)).lower().lstrip("-$")
    segments = set(re.split(r"[-_.\s]+", key))
    # PGPASSWORD, MYAPPTOKEN: long credential words count even inside a word.
    return bool(segments & CREDENTIAL_WORDS) or any(w in key for w in CREDENTIAL_WORDS if len(w) >= 5)


def scrub_url(url):
    url = re.sub(r"(\w[\w+.-]*://)[^@/\s]*@", r"\1", url)
    m = re.match(r"^([a-z][a-z0-9+.-]*://)([^/?#]*)([^?#]*)(\?[^#]*)?", url, re.I)
    if not m:
        return REDACTED
    scheme, host, path, query = m.groups()
    path = "/".join(REDACTED if SECRET_SHAPE.search(seg) else seg for seg in path.split("/"))
    if query:
        keys = [pair.split("=", 1)[0] for pair in query[1:].split("&") if pair]
        path += "?" + "&".join(clean(k, 30) + "=" + REDACTED for k in keys)
    return scheme + host + path


def scrub_word(word, previous=None):
    """Scrub one token of a command line, an argument or a rule."""
    word = str(word)
    if previous is not None and previous.startswith("-") and "=" not in previous \
            and (is_credential_key(previous) or previous in ("-H", "--header", "--headers", "-u", "--user")):
        return REDACTED
    if previous is not None and previous.lower().rstrip(":") in ("bearer", "basic", "token"):
        return REDACTED
    for sep in ("=", ":"):
        key, found, value = word.partition(sep)
        if found and "//" not in key and is_credential_key(key.strip()):
            return key + sep + REDACTED
        if found and sep == "=" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and value:
            return key + "=" + scrub_word(value)
    if "://" in word:
        return scrub_url(word)
    if SECRET_SHAPE.search(word) and not word.startswith(("/", "~", "./", "../")):
        return REDACTED
    return tilde(word)


def scrub_command(text):
    words = str(text).split()
    return " ".join(scrub_word(w, words[i - 1] if i else None) for i, w in enumerate(words))


def scrub_rule(rule):
    """Permission rules can embed whole commands, tokens included:
    Bash(curl -H "Authorization: Bearer ghp_..." ...)."""
    rule = str(rule)
    m = re.match(r"^([\w.]+)\((.*)\)$", rule, re.S)
    if not m:
        return clean(rule)
    return clean(m.group(1) + "(" + scrub_command(m.group(2).replace('"', " ").replace("'", " ")) + ")")


def is_plaintext(value):
    value = str(value).strip()
    return bool(value) and not re.fullmatch(r"\$\{?[\w:.-]+(:-[^}]*)?\}?", value)


# ---------------------------------------------------------------- reading


def read_text(path, limit=2_000_000):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read(limit)
    except OSError:
        return None
    FILES_READ.append(tilde(path))
    return text


def read_json(path):
    text = read_text(path)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def parse_toml(text):
    """tomllib on 3.11+; otherwise enough of TOML for Codex's config."""
    try:
        import tomllib
        return tomllib.loads(text)
    except ImportError:
        pass
    except Exception:
        return {}
    data, table, pending = {}, None, ""
    for raw in text.splitlines():
        line = (pending + " " + raw.strip()) if pending else raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and "=" not in line:
            keys = [k.strip().strip('"') for k in re.findall(r'"[^"]*"|[^.\[\]]+', line.strip("[]"))]
            table = data
            for k in keys:
                table = table.setdefault(k, {}) if isinstance(table.get(k, {}), dict) else {}
            continue
        if line.count("[") > line.count("]") or line.count("{") > line.count("}"):
            pending = line
            continue
        pending = ""
        key, _, value = line.partition("=")
        key, value = key.strip().strip('"'), value.split(" #")[0].strip()
        target = table if table is not None else data
        if value.startswith(("'", '"')):
            target[key] = value[1:-1]
        elif value in ("true", "false"):
            target[key] = value == "true"
        elif value.startswith("["):
            target[key] = [a or b for a, b in re.findall(r'"([^"]*)"|\'([^\']*)\'', value)]
        elif value.startswith("{"):
            target[key] = {k.strip(): v.strip().strip('"\'') for k, v in re.findall(r"([\w-]+)\s*=\s*([^,}]+)", value)}
        else:
            target[key] = value
    return data


def read_toml(path):
    text = read_text(path)
    return None if text is None else parse_toml(text)


# ---------------------------------------------------------------- servers

# What a server touches, judged from its name, URL, command and package.
READS_UNTRUSTED = ("github", "gitlab", "bitbucket", "linear", "jira", "atlassian", "confluence",
                   "slack", "discord", "teams", "gmail", "outlook", "email", "notion", "gdrive", "drive",
                   "sentry", "posthog", "intercom", "zendesk", "hubspot", "salesforce", "figma",
                   "browser", "puppeteer", "playwright", "chrome", "fetch", "firecrawl", "brave",
                   "tavily", "exa", "search", "reddit", "twitter")
HOLDS_PRIVATE = ("github", "gitlab", "bitbucket", "linear", "jira", "atlassian", "confluence", "slack",
                 "discord", "gmail", "outlook", "email", "notion", "gdrive", "drive", "google", "postgres",
                 "mysql", "sqlite", "supabase", "mongo", "redis", "snowflake", "bigquery", "datadog",
                 "sentry", "posthog", "stripe", "aws", "gcp", "azure", "kubernetes", "filesystem",
                 "salesforce", "hubspot", "intercom", "zendesk", "figma", "vercel", "cloudflare")
WRITES_OUT = ("github", "gitlab", "bitbucket", "linear", "jira", "atlassian", "confluence", "notion",
              "slack", "discord", "teams", "gmail", "outlook", "email", "browser", "puppeteer",
              "playwright", "chrome", "fetch")


def touches(text, words):
    tokens = re.split(r"[^a-z0-9]+", text.lower())
    return any(t.startswith(w) for t in tokens if t for w in words)


def server(name, spec, scope):
    spec = spec if isinstance(spec, dict) else {}
    out = {"name": clean(name, 40), "scope": scope}
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
    if url:
        out["url"] = clean(scrub_url(str(url)))
    if spec.get("command"):
        args = spec.get("args") if isinstance(spec.get("args"), list) else []
        out["command"] = clean(os.path.basename(str(spec["command"])) + " " + scrub_command(" ".join(map(str, args))))
    names, plaintext = [], 0
    for field in ("env", "headers", "http_headers", "env_http_headers"):
        if isinstance(spec.get(field), dict):
            names += [clean(k, 40) for k in sorted(spec[field])]
            if field in ("env", "headers", "http_headers"):
                plaintext += sum(1 for k, v in spec[field].items()
                                 if is_plaintext(v) and (is_credential_key(k) or SECRET_SHAPE.search(str(v))))
    if names:
        out["env_names"] = names[:16]
    if plaintext:
        out["plaintext_secrets"] = plaintext
    if spec.get("disabled") is True or spec.get("enabled") is False:
        out["disabled"] = True
    fingerprint = " ".join([str(name), str(url or ""), str(spec.get("command") or ""),
                            " ".join(map(str, spec.get("args") or [] if isinstance(spec.get("args"), list) else []))])
    out["reads_untrusted"] = touches(fingerprint, READS_UNTRUSTED)
    out["holds_private"] = touches(fingerprint, HOLDS_PRIVATE)
    out["writes_out"] = touches(fingerprint, WRITES_OUT)
    out["known"] = out["reads_untrusted"] or out["holds_private"] or out["writes_out"]
    return out


def servers_from(mapping, scope):
    if not isinstance(mapping, dict):
        return []
    return [server(n, s, scope) for n, s in sorted(mapping.items())]


# ---------------------------------------------------------------- credentials

CREDENTIAL_FILES = [
    ("~/.aws/credentials", r"aws_secret_access_key", "AWS keys"),
    ("~/.config/gh/hosts.yml", r"oauth_token", "GitHub login"),
    ("~/.git-credentials", r"://[^:\s/]+:[^@\s]+@", "git credentials"),
    ("~/.docker/config.json", r'"auth"\s*:\s*"', "Docker registry login"),
    ("~/.npmrc", r"_authToken|_auth\s*=", "npm token"),
    ("~/.pypirc", r"\bpassword\b", "PyPI token"),
    ("~/.netrc", r"\bpassword\b", ".netrc passwords"),
    ("~/.kube/config", r"\btoken:|client-key-data", "Kubernetes credentials"),
    ("~/.config/gcloud/application_default_credentials.json", r"refresh_token|private_key", "Google Cloud login"),
    ("~/.codex/auth.json", r"token|api_key", "Codex login"),
    ("~/.claude/.credentials.json", r"accessToken", "Claude login"),
]


def credentials():
    found = []
    for path, pattern, label in CREDENTIAL_FILES:
        full = os.path.expanduser(path)
        if os.path.isfile(full):
            text = read_text(full, 200_000) or ""
            if re.search(pattern, text):
                found.append({"file": path, "label": label})
    for key in sorted(glob.glob(os.path.join(HOME, ".ssh", "id_*"))):
        if key.endswith(".pub"):
            continue
        text = read_text(key, 20_000) or ""
        encrypted = "ENCRYPTED" in text
        if "OPENSSH PRIVATE KEY" in text:
            body = "".join(line for line in text.splitlines() if line and not line.startswith("-----"))
            try:
                encrypted = b"bcrypt" in base64.b64decode(body + "==")[:64]
            except ValueError:
                encrypted = True
        if not encrypted:
            found.append({"file": tilde(key), "label": "SSH key without a passphrase"})
    for name in (".env", ".env.local", ".env.production"):
        text = read_text(os.path.join(CWD, name), 200_000) or ""
        if re.search(r"(?im)^\s*(export\s+)?[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|DSN)[A-Z0-9_]*\s*=\s*\S", text):
            found.append({"file": name, "label": "secrets in " + name, "from_repo": True})
    return found


def shell_flags():
    """Aliases and wrappers in shell startup files that override every config file."""
    flags = {
        "claude_code": ["--dangerously-skip-permissions", "--permission-mode bypassPermissions",
                        "--permission-mode=bypassPermissions"],
        "codex": ["--yolo", "--dangerously-bypass-approvals-and-sandbox", "--full-auto",
                  "-s danger-full-access", "--sandbox danger-full-access"],
    }
    found = {"claude_code": [], "codex": []}
    for rc in ("~/.zshrc", "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zprofile", "~/.config/fish/config.fish"):
        text = read_text(os.path.expanduser(rc), 500_000)
        if not text:
            continue
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue
            for agent, names in flags.items():
                for flag in names:
                    if flag in line and {"flag": flag, "file": rc} not in found[agent]:
                        found[agent].append({"flag": flag, "file": rc})
    return found


# ---------------------------------------------------------------- Claude Code

# Commands that can send data off the machine whatever their arguments.
SENDS_ANYTHING = {"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync", "ftp",
                  "telnet", "http", "https", "xh", "open"}
# Commands that can when allowed with any arguments: interpreters, runners, cloud CLIs.
SENDS_WHEN_UNRESTRICTED = {"node", "deno", "bun", "bunx", "python", "python3", "ruby", "perl", "php", "bash",
                           "sh", "zsh", "npx", "uvx", "docker", "aws", "gcloud", "az", "kubectl", "make"}
# test, start and run execute scripts the repo defines, so whoever wrote the repo decides what they do.
SENDING_SUBCOMMANDS = {"git": {"push", "remote", "send-email"},
                       "gh": {"api", "gist", "issue", "pr", "repo", "release"},
                       "npm": {"run", "exec", "publish", "test", "t", "start"},
                       "pnpm": {"run", "exec", "dlx", "publish", "test", "t", "start"},
                       "yarn": {"run", "exec", "dlx", "publish", "test", "start"}, "uv": {"run"},
                       "pip": {"install"}, "pip3": {"install"}}


def command_words(rule):
    """Bash(curl --silent:*) -> ['curl', '--silent']; Bash -> ['*']; a plain command -> its words."""
    m = re.match(r"^(Bash|Shell)(?:\((.*)\))?$", str(rule), re.S)
    inner = (m.group(2) or "*") if m else str(rule)
    words = [w.rstrip(":*") or "*" for w in inner.split() if not re.fullmatch(r"[A-Za-z_]\w*=\S*", w)]
    if not words:
        return ["*"]
    return [os.path.basename(words[0])] + [w for w in words[1:] if w != "*"]


def can_send(rule):
    words = command_words(rule)
    head, rest = words[0], words[1:]
    if head == "*" or head in SENDS_ANYTHING:
        return True
    if head in SENDS_WHEN_UNRESTRICTED:
        return not rest
    if head in SENDING_SUBCOMMANDS:
        return not rest or rest[0] in SENDING_SUBCOMMANDS[head]
    return False


def rule_command(rule):
    return command_words(rule)[0]


def claude_code(flags):
    managed = SYSTEM + ("/Library/Application Support/ClaudeCode" if sys.platform == "darwin" else "/etc/claude-code")
    layers = [("company", os.path.join(managed, "managed-settings.json"))]
    layers += [("company", p) for p in sorted(glob.glob(os.path.join(managed, "managed-settings.d", "*.json")))]
    layers += [("company", os.path.join(HOME, ".claude", "remote-settings.json")),
               ("user", os.path.join(HOME, ".claude", "settings.json")),
               ("repo", os.path.join(CWD, ".claude", "settings.json")),
               ("repo", os.path.join(CWD, ".claude", "settings.local.json"))]
    user_config = read_json(os.path.join(HOME, ".claude.json"))
    if user_config is None and not os.path.isdir(os.path.join(HOME, ".claude")):
        return None

    r = {"mode": None, "mode_set_by": None, "allow": [], "deny": [], "sandbox": None, "hooks": [],
         "telemetry": None, "mcp_servers": [], "company_keys": [], "shell_flags": flags}
    enabled_mcpjson, all_mcpjson, plugins = set(), False, []
    for scope, path in layers:
        s = read_json(path)
        if s is None:
            continue
        if scope == "company":
            r["company_keys"] += sorted(set(s) | {"permissions." + k for k in (s.get("permissions") or {})})
        perms = s.get("permissions") if isinstance(s.get("permissions"), dict) else {}
        mode = perms.get("defaultMode")
        if mode and not (scope == "repo" and mode in ("auto", "bypassPermissions")) and r["mode_set_by"] != "company":
            r["mode"], r["mode_set_by"] = mode, scope
        for kind in ("allow", "deny"):
            for rule in perms.get(kind) or []:
                r[kind].append({"rule": scrub_rule(rule), "command": rule_command(rule), "sends": can_send(rule),
                                "scope": scope})
        if perms.get("disableBypassPermissionsMode") == "disable":
            r["bypass_disabled_by"] = scope
        sb = s.get("sandbox") if isinstance(s.get("sandbox"), dict) else None
        if sb is not None and "enabled" in sb:
            net = sb.get("network") if isinstance(sb.get("network"), dict) else {}
            r["sandbox"] = {"enabled": bool(sb.get("enabled")), "set_by": scope,
                            "allowed_domains": len(net.get("allowedDomains") or []),
                            "allows_any_domain": "*" in (net.get("allowedDomains") or []),
                            "excluded_commands": [clean(c, 30) for c in (sb.get("excludedCommands") or [])][:10],
                            "unsandboxed_retry": sb.get("allowUnsandboxedCommands", True) is not False}
        for event, groups in (s.get("hooks") or {}).items():
            for group in groups if isinstance(groups, list) else []:
                for hook in (group.get("hooks") or []) if isinstance(group, dict) else []:
                    program = os.path.basename(str(hook.get("command", "")).split()[0]) if hook.get("command") else ""
                    entry = {"event": clean(event, 30), "scope": scope, "program": clean(program, 30)}
                    if entry not in r["hooks"]:
                        r["hooks"].append(entry)
        env = s.get("env") if isinstance(s.get("env"), dict) else {}
        if any(k == "CLAUDE_CODE_ENABLE_TELEMETRY" or k.startswith("OTEL_EXPORTER") for k in env):
            r["telemetry"] = scope
        enabled_mcpjson |= set(s.get("enabledMcpjsonServers") or [])
        all_mcpjson = all_mcpjson or s.get("enableAllProjectMcpServers") is True
        plugins += [p for p, on in (s.get("enabledPlugins") or {}).items() if on]

    if user_config:
        r["mcp_servers"] += servers_from(user_config.get("mcpServers"), "user")
        project = (user_config.get("projects") or {}).get(CWD) or {}
        r["mcp_servers"] += servers_from(project.get("mcpServers"), "repo")
        enabled_mcpjson |= set(project.get("enabledMcpjsonServers") or [])
    project_mcp = read_json(os.path.join(CWD, ".mcp.json"))
    for s in servers_from((project_mcp or {}).get("mcpServers"), "repo"):
        s["approved"] = all_mcpjson or s["name"] in enabled_mcpjson
        r["mcp_servers"].append(s)
    r["mcp_servers"] += servers_from((read_json(os.path.join(managed, "managed-mcp.json")) or {}).get("mcpServers"), "company")

    installed = (read_json(os.path.join(HOME, ".claude", "plugins", "installed_plugins.json")) or {}).get("plugins") or {}
    for plugin in plugins:
        for install in installed.get(plugin) or []:
            root = install.get("installPath") if isinstance(install, dict) else None
            if not root:
                continue
            spec = read_json(os.path.join(root, ".mcp.json")) or {}
            spec = spec.get("mcpServers", spec)
            manifest = read_json(os.path.join(root, ".claude-plugin", "plugin.json")) or {}
            if isinstance(manifest.get("mcpServers"), dict):
                spec = dict(spec, **manifest["mcpServers"])
            r["mcp_servers"] += servers_from(spec, "plugin " + clean(plugin, 40))
            break
    r["company_keys"] = sorted(set(r["company_keys"]))
    return r


# ---------------------------------------------------------------- Codex


def apply_codex_layer(r, cfg, scope):
    for key in ("sandbox_mode", "approval_policy", "web_search"):
        if key in cfg:
            value = cfg[key]
            r[key] = value if isinstance(value, str) else "custom"
            r["set_by"][key] = scope
    ww = cfg.get("sandbox_workspace_write")
    if isinstance(ww, dict) and "network_access" in ww:
        r["network_access"], r["set_by"]["network_access"] = bool(ww["network_access"]), scope
    r["mcp_servers"] += servers_from(cfg.get("mcp_servers"), scope)
    r["hooks"] += [{"event": clean(e, 30), "scope": scope} for e in (cfg.get("hooks") or {})]
    otel = cfg.get("otel")
    if isinstance(otel, dict) and otel.get("exporter") not in (None, "none"):
        r["telemetry"] = scope


def codex(flags):
    home = os.environ.get("CODEX_HOME") or os.path.join(HOME, ".codex")
    layers = [("company", SYSTEM + "/etc/codex/config.toml"), ("user", os.path.join(home, "config.toml"))]
    if not os.path.isdir(home) and not os.path.exists(layers[0][1]):
        return None
    r = {"sandbox_mode": None, "approval_policy": None, "network_access": None, "web_search": None,
         "set_by": {}, "mcp_servers": [], "allow_rules": [], "hooks": [], "telemetry": None, "profiles": [],
         "shell_flags": flags}
    for scope, path in layers:
        cfg = read_toml(path)
        if cfg is None:
            continue
        apply_codex_layer(r, cfg, scope)
        trust = ((cfg.get("projects") or {}).get(CWD) or {}).get("trust_level") if scope == "user" else None
        if trust == "trusted":
            project = read_toml(os.path.join(CWD, ".codex", "config.toml"))
            if project:
                apply_codex_layer(r, project, "repo")

    in_git = os.path.isdir(os.path.join(CWD, ".git"))
    if r["sandbox_mode"] is None:
        r["sandbox_mode"], r["set_by"]["sandbox_mode"] = ("workspace-write" if in_git else "read-only"), "default"
    if r["approval_policy"] is None:
        r["approval_policy"], r["set_by"]["approval_policy"] = "on-request", "default"
    if r["network_access"] is None:
        r["network_access"] = False

    requirements = read_toml(SYSTEM + "/etc/codex/requirements.toml") or {}
    legacy = read_toml(SYSTEM + "/etc/codex/managed_config.toml") or {}
    r["company_keys"] = sorted(set(requirements) | set(legacy))
    allowed_modes = requirements.get("allowed_sandbox_modes") or ([legacy["sandbox_mode"]] if legacy.get("sandbox_mode") else None)
    if allowed_modes and r["sandbox_mode"] not in allowed_modes:
        r["sandbox_mode"], r["set_by"]["sandbox_mode"] = allowed_modes[0], "company"
    allowed_policies = requirements.get("allowed_approval_policies") or ([legacy["approval_policy"]] if legacy.get("approval_policy") else None)
    if allowed_policies and r["approval_policy"] not in allowed_policies:
        r["approval_policy"], r["set_by"]["approval_policy"] = allowed_policies[0], "company"

    for path in sorted(glob.glob(os.path.join(home, "rules", "*.rules"))):
        text = read_text(path) or ""
        for m in re.finditer(r"prefix_rule\((.*?)\)\s*(?:\n|$)", text, re.S):
            body = m.group(1)
            decision = re.search(r'decision\s*=\s*"(\w+)"', body)
            if decision and decision.group(1) != "allow":
                continue
            pattern = re.search(r"pattern\s*=\s*\[(.*?)\]", body, re.S)
            words = re.findall(r'"([^"]*)"', pattern.group(1)) if pattern else []
            if words:
                r["allow_rules"].append({"rule": clean(scrub_command(" ".join(words)), 60),
                                         "sends": can_send(" ".join(words))})
    for path in sorted(glob.glob(os.path.join(home, "*.config.toml"))):
        cfg = read_toml(path) or {}
        if cfg.get("sandbox_mode") or cfg.get("approval_policy"):
            r["profiles"].append({"name": clean(os.path.basename(path)[: -len(".config.toml")], 30),
                                  "sandbox_mode": cfg.get("sandbox_mode"), "approval_policy": cfg.get("approval_policy")})
    hooks_file = read_json(os.path.join(home, "hooks.json")) or {}
    r["hooks"] += [{"event": clean(e, 30), "scope": "user"} for e in (hooks_file.get("hooks") or {})]
    return r


# ---------------------------------------------------------------- Cursor


def cursor_run_mode():
    """Cursor keeps its run mode in a local SQLite store, not a config file.
    Only the named fields below are read; the rest of that record (which also
    holds Cursor's own credentials) is never copied anywhere."""
    base = os.path.join(HOME, "Library", "Application Support", "Cursor") if sys.platform == "darwin" \
        else os.path.join(HOME, ".config", "Cursor")
    path = os.path.join(base, "User", "globalStorage", "state.vscdb")
    if not os.path.exists(path):
        return None
    try:
        con = sqlite3.connect("file:" + path + "?mode=ro&immutable=1", uri=True)
        row = con.execute("SELECT value FROM ItemTable WHERE key = ?", (
            "src.vs.platform.reactivestorage.browser.reactiveStorageServiceImpl.persistentStorage.applicationUser",)).fetchone()
        admin = con.execute("SELECT 1 FROM ItemTable WHERE key = 'autorun.cachedAdminSettings'").fetchone()
        con.close()
        state = json.loads(row[0]).get("composerState", {}) if row else {}
    except (sqlite3.Error, ValueError, TypeError, AttributeError):
        return None
    FILES_READ.append(tilde(path) + " (run mode fields only)")
    agent = next((m for m in state.get("modes4") or [] if isinstance(m, dict) and m.get("id") == "agent"), {})
    allowed_tools = [str(t) for t in state.get("mcpAllowedTools") or []]
    return {
        "run_everything": bool(state.get("yoloEnableRunEverything") or agent.get("fullAutoRun")),
        "auto_run": bool(agent.get("autoRun") or state.get("useYoloMode")),
        "auto_review": bool(state.get("enableSmartAuto")),
        "web_search_unasked": bool(state.get("autoAcceptWebSearchTool")),
        "allowlisted_commands": [{"rule": clean(scrub_command(c), 40), "sends": can_send(c)}
                                 for c in state.get("yoloCommandAllowlist") or [] if str(c).strip()][:80],
        "mcp_tools_auto_allowed": {s: sum(1 for t in allowed_tools if t.split(":")[0] == s)
                                   for s in sorted({t.split(":")[0] for t in allowed_tools})},
        "web_fetch_any_domain": "*" in (state.get("webFetchDomainAllowlist") or []),
        "company_admin_settings": bool(admin),
    }


def cursor():
    base = os.path.join(HOME, ".cursor")
    if not os.path.isdir(base) and not os.path.isdir(SYSTEM + "/Applications/Cursor.app"):
        return None
    r = {"mcp_servers": [], "hooks": [], "run_mode": cursor_run_mode(), "cli": None, "sandbox": None}
    r["mcp_servers"] += servers_from((read_json(os.path.join(base, "mcp.json")) or {}).get("mcpServers"), "user")
    r["mcp_servers"] += servers_from((read_json(os.path.join(CWD, ".cursor", "mcp.json")) or {}).get("mcpServers"), "repo")
    cli = read_json(os.path.join(base, "cli-config.json"))
    if cli:
        perms = cli.get("permissions") if isinstance(cli.get("permissions"), dict) else {}
        r["cli"] = {"approval_mode": clean(cli.get("approvalMode") or "allowlist", 20),
                    "allow": [{"rule": scrub_rule(x), "sends": can_send(x)} for x in perms.get("allow") or []]}
    for scope, path in (("user", os.path.join(base, "sandbox.json")), ("repo", os.path.join(CWD, ".cursor", "sandbox.json"))):
        sb = read_json(path)
        if sb:
            policy = sb.get("networkPolicy") if isinstance(sb.get("networkPolicy"), dict) else {}
            r["sandbox"] = {"type": clean(sb.get("type") or "workspace_readwrite", 30),
                            "network_default": clean(policy.get("default") or "deny", 10), "set_by": scope}
    enterprise = SYSTEM + ("/Library/Application Support/Cursor/hooks.json" if sys.platform == "darwin" else "/etc/cursor/hooks.json")
    for scope, path in (("company", enterprise), ("user", os.path.join(base, "hooks.json")),
                        ("repo", os.path.join(CWD, ".cursor", "hooks.json"))):
        hooks = (read_json(path) or {}).get("hooks")
        if isinstance(hooks, dict):
            r["hooks"] += [{"event": clean(e, 30), "scope": scope} for e in hooks]
    return r


# ---------------------------------------------------------------- verdicts

ASKS_ORDER = {"no": 0, "classifier": 1, "you": 2}


def legs(servers, extra_in, extra_out, data):
    active = [s for s in servers if not s.get("disabled") and s.get("approved", True)]
    out = list(extra_out)
    return {
        "in": extra_in + [s["name"] for s in active if s["reads_untrusted"]],
        "data": data + [s["name"] for s in active if s["holds_private"]],
        "out": out,
        "whole_trifecta_servers": [s["name"] for s in active if s["reads_untrusted"] and s["holds_private"] and s["writes_out"]],
        "unknown_servers": [s["name"] for s in active if not s["known"]],
    }


def finish(v):
    paths = [p for p in v["out"] if p["asks"] in ASKS_ORDER]
    if not paths:
        v["clicks"], v["reviewer"] = None, None
        return v
    worst = min(paths, key=lambda p: ASKS_ORDER[p["asks"]])
    v["clicks"] = 1 if worst["asks"] == "you" else 0
    v["reviewer"] = "classifier" if worst["asks"] == "classifier" else None
    return v


def claude_verdict(c, data):
    mode = c["mode"] or "auto"
    flags = c["shell_flags"]
    if flags and not c.get("bypass_disabled_by"):
        mode = "bypassPermissions"
    ask_any = {"bypassPermissions": "no", "auto": "classifier", "dontAsk": None}.get(mode, "you")
    sandbox = c["sandbox"] if c["sandbox"] and c["sandbox"]["enabled"] else None
    out = []
    if ask_any:
        why = {"no": "any command, mode " + mode + (" (shell alias)" if flags else ""),
               "classifier": "any command, auto mode: a classifier approves, not you",
               "you": "any command, asks you first"}[ask_any]
        out.append({"via": why, "asks": ask_any})
    for rule in c["allow"]:
        cmd = rule["command"]
        if rule["sends"]:
            asks = "no"
            if sandbox and not sandbox["allows_any_domain"] and cmd not in sandbox["excluded_commands"]:
                asks = ask_any or "you"
            out.append({"via": rule["rule"] + " (" + rule["scope"] + " allow rule)", "asks": asks})
        elif rule["rule"].startswith("WebFetch") and rule["rule"] in ("WebFetch", "WebFetch(domain:*)"):
            out.append({"via": rule["rule"] + " (" + rule["scope"] + " allow rule)", "asks": "no"})
    allowed_mcp = {r["rule"][5:].split("__")[0] for r in c["allow"] if r["rule"].startswith("mcp__")}
    for s in c["mcp_servers"]:
        if s["writes_out"] and not s.get("disabled") and s.get("approved", True):
            out.append({"via": s["name"] + " MCP server", "asks": "no" if s["name"] in allowed_mcp else (ask_any or "you")})
    denies_web = any(r["rule"] in ("WebFetch", "WebSearch") for r in c["deny"])
    v = legs(c["mcp_servers"], ([] if denies_web else ["web pages (WebFetch)"]) + ["repos you open"], out, data)
    v["mode"] = mode
    return finish(v)


def codex_verdict(x, data):
    mode, policy, net = x["sandbox_mode"], x["approval_policy"], x["network_access"]
    if x["shell_flags"]:
        mode = "danger-full-access"
        if any(f["flag"] in ("--yolo", "--dangerously-bypass-approvals-and-sandbox") for f in x["shell_flags"]):
            policy = "never"
    out = []
    shell_net = mode == "danger-full-access" or (mode == "workspace-write" and net)
    if shell_net and policy in ("never", "on-request", "on-failure"):
        out.append({"via": "any command: " + mode + (", network on" if mode != "danger-full-access" else "")
                    + ", approval " + policy + ("" if policy == "never" else " (the model decides when to ask)"), "asks": "no"})
    elif policy != "never":
        out.append({"via": "commands that need the network ask you first (" + mode + ")", "asks": "you"})
    for rule in x["allow_rules"]:
        if rule["sends"]:
            out.append({"via": rule["rule"] + " (rules file: runs outside the sandbox, unasked)", "asks": "no"})
    for s in x["mcp_servers"]:
        if s["writes_out"] and not s.get("disabled"):
            out.append({"via": s["name"] + " MCP server (outside Codex's sandbox)", "asks": "unknown"})
    web = [] if x["web_search"] == "disabled" else ["web search"]
    v = legs(x["mcp_servers"], web + ["repos you open"], out, data)
    v["mode"] = mode + " / " + policy
    return finish(v)


def cursor_verdict(c, data):
    rm, out = c["run_mode"], []
    if rm is None:
        terminal = "unknown"
    elif rm["run_everything"]:
        terminal = "no"
    elif rm["auto_run"] and rm["auto_review"]:
        terminal = "classifier"
    else:
        terminal = "you"
    label = {"no": "any command: Run Everything is on", "classifier": "terminal: Auto-review, a model approves",
             "you": "other terminal commands ask you first", "unknown": "terminal: run mode not readable"}[terminal]
    out.append({"via": label, "asks": terminal})
    for rule in (rm or {}).get("allowlisted_commands", []) if (rm or {}).get("auto_run") else []:
        if rule["sends"]:
            out.append({"via": rule["rule"] + " (allowlisted: runs unasked, outside the sandbox)", "asks": "no"})
    for rule in (c["cli"] or {}).get("allow", []):
        if rule["sends"]:
            out.append({"via": rule["rule"] + " (Cursor CLI allow rule)", "asks": "no"})
    auto_tools = (rm or {}).get("mcp_tools_auto_allowed", {})
    for s in c["mcp_servers"]:
        if s["writes_out"] and not s.get("disabled"):
            out.append({"via": s["name"] + " MCP server" + (" (tools auto-allowed)" if auto_tools.get(s["name"]) else ""),
                        "asks": "no" if auto_tools.get(s["name"]) else "you"})
    web = ["web search"] if (rm or {}).get("web_search_unasked") else []
    v = legs(c["mcp_servers"], web + ["repos you open"], out, data)
    v["mode"] = {"no": "Run Everything", "classifier": "Auto-review",
                 "you": "allowlist" if (rm or {}).get("auto_run") else "asks first", "unknown": "unknown"}[terminal]
    return finish(v)


# ---------------------------------------------------------------- the fix


def fix_for(name, a, v):
    """The smallest change that closes this agent's no-approval paths, or None.
    `after` says who approves those paths once it's made: the agent's own
    default, which in auto mode or Auto-review is a model, not the person."""
    if v["clicks"] != 0 or v["reviewer"]:
        return None
    if name == "codex":
        still_open = [s["name"] for s in a["mcp_servers"] if s["writes_out"] and not s.get("disabled")]
        if a["shell_flags"]:
            f = a["shell_flags"][0]
            return {"agent": name, "file": f["file"], "change": "remove " + f["flag"] + " from the codex alias or wrapper",
                    "after": "Codex uses its config again: sandbox %s, approval %s" % (a["sandbox_mode"], a["approval_policy"]),
                    "still_open": still_open}
        if a["set_by"].get("sandbox_mode") == "company":
            return {"agent": name, "file": "/etc/codex/config.toml", "change": "set by your company's Codex config; ask whoever manages it"}
        lines = ['sandbox_mode = "workspace-write"']
        if a["network_access"]:
            lines += ["[sandbox_workspace_write]", "network_access = false"]
        if a["approval_policy"] == "never":
            lines.insert(1, 'approval_policy = "on-request"')
        return {"agent": name, "file": "~/.codex/config.toml", "set": lines,
                "after": "commands that need the network ask you first", "approver_after": "you",
                "still_open": still_open}
    if name == "claude_code":
        if a["shell_flags"]:
            f = a["shell_flags"][0]
            return {"agent": name, "file": f["file"], "change": "remove " + f["flag"] + " from the claude alias or wrapper",
                    "after": "Claude Code uses its settings again: mode " + (a["mode"] or "auto")}
        if a["mode"] == "bypassPermissions" and a["mode_set_by"] == "user":
            return {"agent": name, "file": "~/.claude/settings.json", "set": ['"permissions": { "defaultMode": "default" }'],
                    "after": "commands and MCP tools ask you first; reads and edits you've allowed still don't",
                    "approver_after": "you"}
        rules = [r for r in a["allow"] if r["scope"] != "company" and r["sends"]]
        if rules:
            scope = rules[0]["scope"]
            names = [r["rule"] for r in rules if r["scope"] == scope]
            approver = {"auto": "classifier", "dontAsk": "refused"}.get(v["mode"], "you")
            return {"agent": name, "file": "~/.claude/settings.json" if scope == "user" else ".claude/settings(.local).json in this repo",
                    "change": "remove the allow rule%s %s" % ("s" if len(names) > 1 else "", ", ".join(names)),
                    "after": {"classifier": "those commands go to auto mode's classifier, which approves instead of you",
                              "refused": "those commands are refused"}.get(approver, "those commands ask you first"),
                    "approver_after": approver}
    if name == "cursor" and a["run_mode"]:
        if a["run_mode"]["run_everything"]:
            return {"agent": name, "file": "Cursor Settings > Agents > Approvals & Execution",
                    "change": "switch Run Everything to Auto-review or Allowlist",
                    "after": "Auto-review: a model approves commands; Allowlist: you approve anything not on the list",
                    "approver_after": "classifier or you"}
        sending = [r["rule"] for r in a["run_mode"]["allowlisted_commands"] if r["sends"]]
        if sending:
            approver = "classifier" if a["run_mode"]["auto_review"] else "you"
            return {"agent": name, "file": "Cursor Settings > Agents > Approvals & Execution",
                    "change": "remove " + ", ".join(sending) + " from the command allowlist",
                    "after": "those commands go to Auto-review, where a model approves" if approver == "classifier"
                    else "those commands ask you first", "approver_after": approver}
    return None


def pick_fixes(agents, verdicts):
    """One fix per agent with a no-approval path, worst agent first."""
    def rank(n):
        unasked = [p for p in verdicts[n]["out"] if p["asks"] == "no"]
        return (0 if any(p["via"].startswith("any command") for p in unasked) else 1, -len(unasked))
    fixes = {}
    for name in sorted(verdicts, key=rank):
        fix = fix_for(name, agents[name], verdicts[name])
        if fix:
            fixes[name] = fix
    return fixes


# ---------------------------------------------------------------- main


def plaintext_in_configs(agents):
    counts = {}
    for name, a in agents.items():
        for s in a.get("mcp_servers", []):
            if s.get("plaintext_secrets"):
                key = name + " " + s["scope"] + " config"
                counts[key] = counts.get(key, 0) + s["plaintext_secrets"]
    return [{"where": k, "count": n} for k, n in sorted(counts.items())]


def watching(agents):
    """What would leave a record somewhere other than this laptop: hooks and telemetry."""
    codex_home = os.environ.get("CODEX_HOME") or os.path.join(HOME, ".codex")
    return {
        "agents": {name: {"hooks": sorted({h["scope"] + (" " + h["program"] if h.get("program") else "")
                                           for h in a.get("hooks", [])}),
                          "telemetry": a.get("telemetry")}
                   for name, a in agents.items()},
        "local_transcripts": [tilde(p) for p in (os.path.join(HOME, ".claude", "projects"),
                                                 os.path.join(codex_home, "sessions")) if os.path.isdir(p)],
    }


def build():
    flags = shell_flags()
    agents = {k: v for k, v in (("claude_code", claude_code(flags["claude_code"])), ("codex", codex(flags["codex"])),
                                ("cursor", cursor())) if v is not None}
    creds = credentials()
    data = [c["label"] for c in creds] + ["this repo's code"]
    plain = plaintext_in_configs(agents)
    if plain:
        data.insert(0, "plaintext tokens in agent configs")
    makers = {"claude_code": claude_verdict, "codex": codex_verdict, "cursor": cursor_verdict}
    verdicts = {name: makers[name](a, data) for name, a in agents.items()}
    return {
        "blast_radius": VERSION,
        "project": tilde(CWD),
        "verdicts": verdicts,
        "fixes": pick_fixes(agents, verdicts),
        "credentials": creds,
        "plaintext_secrets_in_agent_configs": plain,
        "company_policy": {
            "claude_code": agents.get("claude_code", {}).get("company_keys"),
            "codex": agents.get("codex", {}).get("company_keys"),
            "cursor": {"hooks": any(h["scope"] == "company" for h in (agents.get("cursor") or {}).get("hooks", [])),
                       "team_admin_settings": "present; contents not read" if ((agents.get("cursor") or {}).get("run_mode")
                                                                               or {}).get("company_admin_settings") else None}
            if "cursor" in agents else None,
        },
        "watching": watching(agents),
        "agents": agents,
        "files_read": FILES_READ,
    }




# ---------------------------------------------------------------- the page
#
# The agent running the skill writes the words from the facts above; this
# checks them and lays them out. The trifecta dots come from the facts, never
# from the words, so a write-up can't make an agent look safer than it is.

NAMES = {"claude_code": "Claude Code", "codex": "Codex", "cursor": "Cursor"}
REACH = ("anyone", "customers", "company", "team")
LIMITS = {"headline": 120, "lead": 320, "unseen": 240, "watched": 300, "fix": 240, "note": 480}
OPTIONAL = {"unseen"}
TEAM_LINK = "https://cimento.ai/blast-radius?ref=page"
INSTALL = "Run it yourself: /plugin marketplace add Cimento-AI/agent-blast-radius"


def looks_secret(word):
    return len(word) >= 16 and bool(SECRET_SHAPE.match(word))


def check_page(content, report):
    """Every problem with the write-up, as lines the agent can act on."""
    if not isinstance(content, dict):
        return ["send one JSON object"]
    problems = []

    def check(label, value, limit, required=True):
        if value in (None, "") and not required:
            return
        if not isinstance(value, str) or not value.strip():
            problems.append(label + ": missing")
        elif len(value) > limit:
            problems.append("%s: %d characters, keep it to %d" % (label, len(value), limit))
        elif any(looks_secret(w) for w in re.split(r"[\s,;()\"'`]+", value)):
            problems.append(label + ": looks like it holds a secret value; name the credential type instead")

    for key, limit in LIMITS.items():
        check(key, content.get(key), limit, required=key not in OPTIONAL)
    agents = list(report["verdicts"])
    sources = content.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 6:
        problems.append("sources: give 1 to 6")
        sources = []
    for i, s in enumerate(sources):
        s = s if isinstance(s, dict) else {}
        check("sources[%d].name" % i, s.get("name"), 40)
        check("sources[%d].who" % i, s.get("who"), 160)
        if s.get("reach") not in REACH:
            problems.append("sources[%d].reach: one of %s" % (i, ", ".join(REACH)))
        if not s.get("agents") or not isinstance(s["agents"], list) or set(s["agents"]) - set(agents):
            problems.append("sources[%d].agents: a list of agent ids from the facts (%s)" % (i, ", ".join(agents)))
    if content.get("fix_agent") not in (list(report["fixes"]) or [None]):
        problems.append("fix_agent: one of %s" % (", ".join(report["fixes"]) or "null (no agent needs a fix)"))
    lines = content.get("agents")
    if not isinstance(lines, dict) or set(lines) != set(agents):
        problems.append("agents: one line for each of %s" % ", ".join(agents))
    else:
        for name in agents:
            check("agents." + name, lines[name], 200)
    if re.search(r"~/|/Users/|/home/|://|\b[\w-]+\.(com|ai|io|dev|net|org|work|app)\b", str(content.get("note") or "")):
        problems.append("note: no paths, hostnames or links; it goes to someone else, and the install line is added for you")
    return problems


def sends(v):
    if v["clicks"] is None:
        return "none", "no way out found"
    if v["reviewer"]:
        return "classifier", "a model approves sends"
    return ("no", "sends without asking") if v["clicks"] == 0 else ("you", "asks before sending")


def render_page(content, report):
    e = html.escape
    sources = "".join(
        '<li><span class="reach r-%s">%s</span><div><b>%s</b>%s<p>%s</p><small>read by %s</small></div></li>' % (
            s["reach"], s["reach"], e(s["name"]),
            '<span class="unseen">connector</span>' if s.get("unseen") else "",
            e(s["who"]), e(", ".join(NAMES[a] for a in s["agents"])))
        for s in content["sources"])
    agents = ""
    for name, v in report["verdicts"].items():
        state, label = sends(v)
        agents += ('<li><div class="row"><b>%s</b><span class="legs"><span class="on">listens to others</span>'
                   '<span class="on">reads private data</span><span class="%s">%s</span></span></div><p>%s</p></li>'
                   % (NAMES[name], state, label, e(content["agents"][name])))
    fix, code = report["fixes"].get(content.get("fix_agent") or ""), ""
    if fix:
        lines = fix.get("set") or [fix.get("change", "")]
        code = '<div class="where">%s</div><pre>%s</pre>' % (e(fix["file"]), e("\n".join(lines)))
    unseen = '<p class="aside">%s</p>' % e(content["unseen"]) if content.get("unseen") else ""
    fill = {
        "@@PROJECT@@": e(report["project"]), "@@DATE@@": datetime.date.today().strftime("%B %-d, %Y"),
        "@@HEADLINE@@": e(content["headline"]), "@@LEAD@@": e(content["lead"]),
        "@@SOURCES@@": sources, "@@UNSEEN@@": unseen, "@@AGENTS@@": agents,
        "@@WATCHED@@": e(content["watched"]), "@@FIX@@": e(content["fix"]), "@@FIXCODE@@": code,
        "@@NOTE@@": e(content["note"].strip() + "\n\n" + INSTALL), "@@TEAMLINK@@": TEAM_LINK,
    }
    page = PAGE
    for key, value in fill.items():
        page = page.replace(key, value)
    return page


def open_page(page):
    path = os.path.join(tempfile.gettempdir(), "blast-radius.html")
    with open(path, "w") as f:
        f.write(page)
    if not os.environ.get("BLAST_RADIUS_NO_OPEN"):
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        try:
            subprocess.Popen([opener, path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass
    return path


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blast radius</title>
<style>
:root{--bg:#f7f5f1;--card:#fffdfa;--ink:#1c1a17;--soft:#47423d;--muted:#857d74;--rule:#e4ded5;
--red:#c4321c;--red-bg:#fbe7e2;--amber:#9e640f;--amber-bg:#f7ecd8;--off:#d2cbc1;--on:#1c1a17}
@media (prefers-color-scheme:dark){:root{--bg:#121110;--card:#1a1917;--ink:#eeeae4;--soft:#c9c3bb;--muted:#8d867e;
--rule:#2c2a27;--red:#ff6a52;--red-bg:#3b1a14;--amber:#f2b552;--amber-bg:#352710;--off:#3f3b37;--on:#eeeae4}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:720px;margin:0 auto;padding:56px 20px 8px}
.kicker{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
h1{font:600 clamp(30px,5.2vw,44px)/1.14 ui-serif,Georgia,"Times New Roman",serif;letter-spacing:-.01em;margin:14px 0 18px;text-wrap:balance}
.lead{font-size:19px;line-height:1.55;color:var(--soft);margin:0}
h2{font:600 23px/1.3 ui-serif,Georgia,serif;margin:56px 0 6px}
.intro{color:var(--muted);margin:0 0 16px;font-size:15px}
.intro a{color:inherit}
ul{list-style:none;margin:0;padding:0}
.sources li{display:grid;grid-template-columns:104px 1fr;gap:14px;padding:14px 0;border-top:1px solid var(--rule)}
.reach{justify-self:start;font-size:11px;font-weight:650;letter-spacing:.07em;text-transform:uppercase;padding:3px 9px;border-radius:99px;margin-top:3px;height:fit-content}
.r-anyone{background:var(--red-bg);color:var(--red)}
.r-customers{background:var(--amber-bg);color:var(--amber)}
.r-company,.r-team{color:var(--muted);box-shadow:inset 0 0 0 1px var(--rule)}
.sources b{font-weight:600}
.sources p{margin:2px 0;color:var(--soft)}
small{color:var(--muted);font-size:13px}
.unseen{font-size:11px;font-weight:650;letter-spacing:.06em;text-transform:uppercase;color:var(--amber);margin-left:10px}
.aside{margin:16px 0 0;padding:14px 16px;border-left:3px solid var(--amber);background:var(--card);color:var(--soft);font-size:15px}
.agents li{padding:16px 0;border-top:1px solid var(--rule)}
.row{display:flex;flex-wrap:wrap;align-items:center;gap:8px 18px}
.row b{font-size:17px;min-width:112px}
.legs{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:12.5px;color:var(--muted)}
.legs span{display:inline-flex;align-items:center;gap:7px}
.legs span::before{content:"";width:10px;height:10px;border-radius:50%;background:var(--off)}
.legs .on::before{background:var(--on)}
.legs .no{color:var(--red);font-weight:600}.legs .no::before{background:var(--red);box-shadow:0 0 0 4px var(--red-bg)}
.legs .classifier{color:var(--amber);font-weight:600}.legs .classifier::before{background:var(--amber)}
.agents p{margin:8px 0 0;color:var(--soft)}
.watched{font-size:17px;color:var(--soft);margin:0}
.fix p{margin:0 0 14px;font-size:17px;color:var(--soft)}
.where{font-size:13px;color:var(--muted);margin-bottom:6px}
pre{margin:0;padding:14px 16px;background:var(--card);border:1px solid var(--rule);border-radius:8px;font:13.5px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-x:auto;white-space:pre-wrap}
.note{margin:56px 0 0;padding:20px;border:1px solid var(--rule);border-radius:12px;background:var(--card)}
.note header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;font-size:13px;color:var(--muted)}
.note button{font:inherit;font-size:13px;color:var(--ink);background:transparent;border:1px solid var(--rule);border-radius:6px;padding:4px 12px;cursor:pointer}
.note pre{border:0;padding:0;background:transparent;font:15px/1.55 -apple-system,system-ui,sans-serif;color:var(--soft)}
footer{max-width:720px;margin:48px auto 0;padding:20px 20px 56px;display:flex;flex-wrap:wrap;justify-content:space-between;gap:8px;font-size:13px;color:var(--muted);border-top:1px solid var(--rule)}
footer a{color:var(--muted)}
@media (max-width:560px){main{padding-top:36px}.sources li{grid-template-columns:1fr;gap:6px}}
</style>
</head>
<body>
<main>
<div class="kicker">Blast radius &middot; @@PROJECT@@ &middot; @@DATE@@</div>
<h1>@@HEADLINE@@</h1>
<p class="lead">@@LEAD@@</p>

<h2>Who can talk to your agents</h2>
<p class="intro">Anything an agent reads can steer it. These are the places your agents read, and who can write there.</p>
<ul class="sources">@@SOURCES@@</ul>
@@UNSEEN@@

<h2>What they do without asking</h2>
<p class="intro">An agent is exposed when three things are true at once: someone else can talk to it, it can read something private, and it can send things out. Simon Willison calls this the <a href="https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/">lethal trifecta</a>. The first two are true of every coding agent. The third is the one you control.</p>
<ul class="agents">@@AGENTS@@</ul>

<h2>Would anyone know?</h2>
<p class="watched">@@WATCHED@@</p>

<h2>The one change</h2>
<div class="fix"><p>@@FIX@@</p>@@FIXCODE@@</div>

<section class="note">
<header><span>For whoever owns security</span><button type="button" onclick="navigator.clipboard.writeText(document.getElementById('note').innerText).then(()=>{this.textContent='Copied'})">Copy</button></header>
<pre id="note">@@NOTE@@</pre>
</section>
</main>
<footer><span>Read from config files on this laptop. Nothing left it.</span><a href="@@TEAMLINK@@">Seeing this across a team &rarr; Agent Hub</a></footer>
</body>
</html>
"""


def main():
    report = build()
    if sys.argv[1:2] == ["page"]:
        try:
            content = json.loads(sys.stdin.read())
        except ValueError as err:
            sys.exit("page: the write-up is not valid JSON (%s)" % err)
        problems = check_page(content, report)
        if problems:
            sys.exit("page: fix these and send it again\n- " + "\n- ".join(problems))
        print(open_page(render_page(content, report)))
    else:
        json.dump(report, sys.stdout, indent=1)
        print()


if __name__ == "__main__":
    main()
