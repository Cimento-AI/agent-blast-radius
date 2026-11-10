#!/usr/bin/env python3
"""The facts behind /blast-radius: what Claude Code on this machine reads, what
it can open, which ways data can leave without anyone approving, who else would
see it, and the smallest change that closes the worst path.

Reads Claude Code's settings layers, MCP servers (including plugins'), shell
startup files and credential files, and prints one JSON object. Secret values
never appear in the output: env vars and headers keep their names only,
credential-shaped arguments, URL parts and rule text become "<redacted>", and
credential files are opened only to answer yes or no to "does this hold a
credential?". Nothing is sent anywhere. Standard library only, Python 3.8+.
"""

import base64
import glob
import json
import os
import re
import shlex
import sys

VERSION = "0.5.4"
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
    # Userinfo runs to the last "@" before the host, since a password can hold "@".
    url = re.sub(r"(\w[\w+.-]*://)[^/?#\s]*@", r"\1", url)
    m = re.match(r"^([a-z][a-z0-9+.-]*://)([^/?#]*)([^?#]*)(\?[^#]*)?", url, re.I)
    if not m:
        return REDACTED
    scheme, host, path, query = m.groups()
    path = "/".join(REDACTED if SECRET_SHAPE.search(seg) else seg for seg in path.split("/"))
    if query:
        keys = [pair.split("=", 1)[0] for pair in query[1:].split("&") if pair]
        path += "?" + "&".join((REDACTED if SECRET_SHAPE.search(k) else clean(k, 30)) + "=" + REDACTED for k in keys)
    return scheme + host + path


# Flags whose value is user:password, so the whole value goes.
USER_FLAGS = ("-u", "--user", "--password", "--pass")
# A NAME=value prefix on a command line. After a shell-style split the value can
# hold spaces (AUTH="Basic abc def" becomes one word), so it may contain anything.
ASSIGNMENT = re.compile(r"[A-Za-z_]\w*=.*", re.S)


def scrub_word(word, previous=None):
    """Scrub one token of a command line, an argument or a rule."""
    word = str(word)
    if previous is not None:
        prev = previous.strip("\"'")
        if prev.startswith("-") and "=" not in prev \
                and (is_credential_key(prev) or prev in ("-H", "--header", "--headers") + USER_FLAGS):
            return REDACTED
        if prev.lower().rstrip(":") in ("bearer", "basic", "token"):
            return REDACTED
        # The value after a header name such as "Authorization:" or "X-Api-Key:".
        if prev.endswith(":") and is_credential_key(prev[:-1]):
            return REDACTED
    if re.match(r"^-u[^-=\s].*:", word):
        return "-u" + REDACTED
    for sep in ("=", ":"):
        key, found, value = word.partition(sep)
        if found and sep == "=" and key in USER_FLAGS and value:
            return key + "=" + REDACTED
        if found and "//" not in key and is_credential_key(key.strip()):
            return key + sep + REDACTED
        if found and sep == "=" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) and value:
            return key + "=" + scrub_word(value)
    if "://" in word:
        return scrub_url(word)
    if SECRET_SHAPE.search(word) and not word.startswith(("/", "~", "./", "../")):
        return REDACTED
    return tilde(word)


def scrub_words(words):
    """Scrub a list of arguments, each as one unit, so "X-Api-Key: value" stays together."""
    words = [str(w) for w in words]
    return " ".join(scrub_word(w, words[i - 1] if i else None) for i, w in enumerate(words))


def scrub_command(text):
    return scrub_words(str(text).split())


def split_command(text):
    """Split like a shell would, so a quoted header stays one word."""
    try:
        return shlex.split(text)
    except ValueError:
        # An unbalanced quote somewhere (don't): still keep each closed "..." or
        # '...' inside its word, so a quoted NAME="a b" value stays one word.
        words = re.findall(r"(?:\"[^\"]*\"|'[^']*'|[^\s\"'])+|\S+", text)
        return [re.sub(r"\"([^\"]*)\"|'([^']*)'", lambda q: q.group(1) or q.group(2) or "", w) for w in words]


def scrub_rule(rule):
    """Permission rules can embed whole commands, tokens included:
    Bash(curl -H "Authorization: Bearer ghp_..." ...)."""
    rule = str(rule)
    m = re.match(r"^([\w.]+)\((.*)\)$", rule, re.S)
    if m:
        return clean(m.group(1) + "(" + scrub_words(split_command(m.group(2))) + ")")
    # Bare tool names (WebFetch, mcp__server__tool) carry no arguments; keep them
    # intact so they still match their server. Anything else, such as a rule left
    # unclosed, is scrubbed like a command line.
    if re.fullmatch(r"[A-Za-z]+|mcp__[\w.*-]*", rule):
        return clean(rule)
    return clean(scrub_command(rule))


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
    FILES_READ.append(clean(tilde(path), 200))
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


def git_pointer(path, prefix=""):
    """The path a .git file or a commondir file points at, or None."""
    m = re.match(re.escape(prefix) + r"\s*([^\x00\r\n]+)", read_text(path, 4096) or "")
    return m.group(1).strip() if m else None


def repo_root():
    """The first folder at or above CWD with a .git entry, or None. In a linked
    worktree, the main checkout's root. Reads files only; never runs git."""
    path = CWD
    while not os.path.lexists(os.path.join(path, ".git")):
        if os.path.dirname(path) == path:
            return None
        path = os.path.dirname(path)
    dot_git = os.path.join(path, ".git")
    gitdir = git_pointer(dot_git, "gitdir:") if os.path.isfile(dot_git) else None
    common = git_pointer(os.path.join(path, gitdir, "commondir")) if gitdir else None
    if common:
        common = os.path.realpath(os.path.join(path, gitdir, common))
        if os.path.basename(common) == ".git" and os.path.isdir(common):
            return os.path.dirname(common)
    return path


def local_settings_root():
    """The repo root whose .claude/settings.local.json Claude Code uses, or None
    when it uses CWD's: no repo, the root is the home folder, or someone else
    owns the root, its .git or its .claude (https://code.claude.com/docs/en/settings)."""
    root = repo_root()
    if root is None or os.path.realpath(root) == os.path.realpath(HOME):
        return None
    for path in (root, os.path.join(root, ".git"), os.path.join(root, ".claude")):
        try:
            if os.lstat(path).st_uid != os.getuid():
                return None
        except OSError:
            pass
    return root


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


def split_program(command):
    """A command line's program, scrubbed and basenamed, after any NAME=value
    prefixes (which are dropped), and the words that follow it, unscrubbed."""
    words = split_command(str(command or ""))
    while words and ASSIGNMENT.fullmatch(words[0]):
        words.pop(0)
    if not words:
        return "", []
    return os.path.basename(scrub_word(words[0])), words[1:]


def server(name, spec, scope):
    spec = spec if isinstance(spec, dict) else {}
    out = {"name": clean(name, 40), "scope": scope}
    url = spec.get("url") or spec.get("serverUrl") or spec.get("httpUrl")
    if url:
        out["url"] = clean(scrub_url(str(url)))
    if spec.get("command"):
        args = spec.get("args") if isinstance(spec.get("args"), list) else []
        # The command string can carry NAME=value prefixes and its own arguments.
        program, rest = split_program(spec["command"])
        out["command"] = clean((program + " " + scrub_words(rest + [str(a) for a in args])).strip())
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
    """Aliases and wrappers in shell startup files that override every settings file."""
    names = ["--dangerously-skip-permissions", "--permission-mode bypassPermissions",
             "--permission-mode=bypassPermissions"]
    found = []
    for rc in ("~/.zshrc", "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zprofile", "~/.config/fish/config.fish"):
        text = read_text(os.path.expanduser(rc), 500_000)
        if not text:
            continue
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue
            for flag in names:
                if flag in line and {"flag": flag, "file": rc} not in found:
                    found.append({"flag": flag, "file": rc})
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
    words = [w.rstrip(":*") or "*" for w in split_command(inner) if not ASSIGNMENT.fullmatch(w)]
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


# Auto mode drops allow rules that grant arbitrary code execution when it starts
# (https://code.claude.com/docs/en/permission-modes): blanket shell, wildcarded
# interpreters, package-manager run commands, Agent and Monitor rules. Those go to
# its classifier instead; narrow rules like Bash(npm test) stay in effect.
INTERPRETERS = {"node", "deno", "bun", "python", "python3", "ruby", "perl", "php", "bash", "sh", "zsh"}
PACKAGE_RUNNERS = {"npx", "bunx", "pnpx", "uvx"}
RUN_SUBCOMMANDS = {"npm": {"run", "exec", "x"}, "pnpm": {"run", "exec", "dlx"}, "yarn": {"run", "exec", "dlx"},
                   "bun": {"run", "x"}, "uv": {"run"}}


def dropped_in_auto(rule):
    rule = str(rule)
    if rule.startswith(("Agent", "Monitor")):
        return True
    if not re.match(r"^(Bash|Shell)\b", rule):
        return False
    words = command_words(rule)
    head, rest = words[0], words[1:]
    return (head == "*" or head in PACKAGE_RUNNERS or (head in INTERPRETERS and "*" in rule)
            or (head in RUN_SUBCOMMANDS and bool(rest) and rest[0] in RUN_SUBCOMMANDS[head]))


def rule_command(rule):
    """The rule's program, scrubbed like the rule itself."""
    return clean(scrub_word(command_words(rule)[0]), 30)


# How the fix names a settings file it points at, for scopes outside the home folder.
REPO_SETTINGS = ".claude/settings.json in this repo"
LOCAL_AT_ROOT = ".claude/settings.local.json at the repo root"
LOCAL_IN_CWD = ".claude/settings.local.json in this folder"


def claude_code(flags):
    root = local_settings_root()
    local_file = {}
    # An earlier version may have left a file in CWD. Rules from both files apply;
    # the root's is read last so its scalar values win.
    if root != CWD:
        local_file[os.path.join(CWD, ".claude", "settings.local.json")] = LOCAL_IN_CWD
    if root:
        local_file[os.path.join(root, ".claude", "settings.local.json")] = LOCAL_AT_ROOT
    managed = SYSTEM + ("/Library/Application Support/ClaudeCode" if sys.platform == "darwin" else "/etc/claude-code")
    layers = [("company", os.path.join(managed, "managed-settings.json"))]
    layers += [("company", p) for p in sorted(glob.glob(os.path.join(managed, "managed-settings.d", "*.json")))]
    layers += [("company", os.path.join(HOME, ".claude", "remote-settings.json")),
               ("user", os.path.join(HOME, ".claude", "settings.json")),
               ("repo", os.path.join(CWD, ".claude", "settings.json"))]
    layers += [("local", p) for p in local_file]
    user_config = read_json(os.path.join(HOME, ".claude.json"))
    if user_config is None and not os.path.isdir(os.path.join(HOME, ".claude")):
        return None

    r = {"project_root": clean(tilde(root), 200) if root else None, "mode": None, "mode_set_by": None,
         "allow": [], "deny": [], "sandbox": None, "hooks": [], "telemetry": None, "mcp_servers": [], "company_keys": [], "shell_flags": flags}
    enabled_mcpjson, all_mcpjson, plugins = set(), False, []
    for scope, path in layers:
        s = read_json(path)
        if s is None:
            continue
        if scope == "company":
            r["company_keys"] += sorted(set(s) | {"permissions." + k for k in (s.get("permissions") or {})})
        perms = s.get("permissions") if isinstance(s.get("permissions"), dict) else {}
        mode = perms.get("defaultMode")
        if mode and not (scope in ("repo", "local") and mode in ("auto", "bypassPermissions")) and r["mode_set_by"] != "company":
            r["mode"], r["mode_set_by"] = mode, scope
        for kind in ("allow", "deny"):
            for rule in perms.get(kind) or []:
                entry = {"rule": scrub_rule(rule), "command": rule_command(rule), "sends": can_send(rule),
                         "dropped_in_auto": dropped_in_auto(rule), "scope": scope}
                if scope == "local":
                    entry["file"] = local_file[path]
                r[kind].append(entry)
        if perms.get("disableBypassPermissionsMode") == "disable":
            r["bypass_disabled_by"] = scope
        sb = s.get("sandbox") if isinstance(s.get("sandbox"), dict) else None
        if sb is not None and "enabled" in sb:
            net = sb.get("network") if isinstance(sb.get("network"), dict) else {}
            r["sandbox"] = {"enabled": bool(sb.get("enabled")), "set_by": scope,
                            "allowed_domains": len(net.get("allowedDomains") or []),
                            "allows_any_domain": "*" in (net.get("allowedDomains") or []),
                            "excluded_commands": [clean(scrub_words(split_command(str(c))), 30)
                                                  for c in (sb.get("excludedCommands") or [])][:10],
                            "unsandboxed_retry": sb.get("allowUnsandboxedCommands", True) is not False}
        for event, groups in (s.get("hooks") or {}).items():
            for group in groups if isinstance(groups, list) else []:
                for hook in (group.get("hooks") or []) if isinstance(group, dict) else []:
                    entry = {"event": clean(event, 30), "scope": scope,
                             "program": clean(split_program(hook.get("command"))[0], 30)}
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
        # Which folder Claude Code keys a project by isn't documented, so read both.
        local_servers = {}
        for key in filter(None, (root, CWD)):
            project = (user_config.get("projects") or {}).get(key) or {}
            if isinstance(project.get("mcpServers"), dict):
                local_servers.update(project["mcpServers"])
            enabled_mcpjson |= set(project.get("enabledMcpjsonServers") or [])
        r["mcp_servers"] += servers_from(local_servers, "local")
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


# ---------------------------------------------------------------- verdicts

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


def claude_verdict(c, data):
    mode = c["mode"] or "auto"
    flags = c["shell_flags"]
    if flags and not c.get("bypass_disabled_by"):
        mode = "bypassPermissions"
    ask_any = {"bypassPermissions": "no", "auto": "classifier", "dontAsk": None}.get(mode, "you")
    sandbox = c["sandbox"] if c["sandbox"] and c["sandbox"]["enabled"] else None
    out = []

    def way_out(via, asks):
        # The same rule can sit in two files; it's still one way out.
        if {"via": via, "asks": asks} not in out:
            out.append({"via": via, "asks": asks})

    if ask_any:
        why = {"no": "any command, mode " + mode + (" (shell alias)" if flags else ""),
               "classifier": "any command, auto mode: a classifier approves, not you",
               "you": "any command, asks you first"}[ask_any]
        out.append({"via": why, "asks": ask_any})
    for rule in c["allow"]:
        cmd = rule["command"]
        if rule["sends"]:
            asks, why = "no", " (" + rule["scope"] + " allow rule)"
            if mode == "auto" and rule["dropped_in_auto"]:
                asks, why = "classifier", " (" + rule["scope"] + " allow rule, dropped in auto mode, so the classifier decides)"
            elif sandbox and not sandbox["allows_any_domain"] and cmd not in sandbox["excluded_commands"]:
                asks = ask_any or "you"
            way_out(rule["rule"] + why, asks)
        elif rule["rule"].startswith("WebFetch") and rule["rule"] in ("WebFetch", "WebFetch(domain:*)"):
            way_out(rule["rule"] + " (" + rule["scope"] + " allow rule)", "no")
    allowed_mcp = {r["rule"][5:].split("__")[0] for r in c["allow"] if r["rule"].startswith("mcp__")}
    for s in c["mcp_servers"]:
        if s["writes_out"] and not s.get("disabled") and s.get("approved", True):
            out.append({"via": s["name"] + " MCP server", "asks": "no" if s["name"] in allowed_mcp else (ask_any or "you")})
    denies_web = any(r["rule"] in ("WebFetch", "WebSearch") for r in c["deny"])
    v = legs(c["mcp_servers"], ([] if denies_web else ["web pages (WebFetch)"]) + ["repos you open"], out, data)
    v["mode"] = mode
    v["mode_from"] = ("shell alias in " + flags[0]["file"]) if mode == "bypassPermissions" and flags and \
        not c.get("bypass_disabled_by") else (c["mode_set_by"] + " settings" if c["mode_set_by"] else "Claude Code's default")
    return v


# ---------------------------------------------------------------- the fix


def pick_fix(c, v):
    """The smallest change that closes the ways out nobody approves, or None.
    `after` says who approves them once it's made: whatever Claude Code's mode
    sends them to, which in auto mode is a classifier, not the person."""
    if not any(p["asks"] == "no" for p in v["out"]):
        return None
    if v["mode_from"].startswith("shell alias"):
        f = c["shell_flags"][0]
        return {"file": f["file"], "change": "remove " + f["flag"] + " from the claude alias or wrapper",
                "after": "Claude Code uses its settings again: mode " + (c["mode"] or "auto")}
    if v["mode"] == "bypassPermissions":
        if c["mode_set_by"] == "company":
            return {"file": "company-managed settings", "change": "set by your company; ask whoever manages it"}
        return {"file": "~/.claude/settings.json" if c["mode_set_by"] == "user" else REPO_SETTINGS,
                "set": ['"permissions": { "defaultMode": "default" }'],
                "after": "commands and MCP tools ask you first; reads and edits you've allowed still don't",
                "approver_after": "you"}
    writers = {s["name"] for s in c["mcp_servers"] if s["writes_out"]}
    rules = [r for r in c["allow"] if r["scope"] != "company" and not (v["mode"] == "auto" and r["dropped_in_auto"]) and
             (r["sends"] or r["rule"] in ("WebFetch", "WebFetch(domain:*)") or
              (r["rule"].startswith("mcp__") and r["rule"][5:].split("__")[0] in writers))]
    if not rules:
        return None
    scope, local = rules[0]["scope"], rules[0].get("file")
    names = [r["rule"] for r in rules if r["scope"] == scope and r.get("file") == local]
    approver = {"auto": "classifier", "dontAsk": "refused"}.get(v["mode"], "you")
    def named(rule):
        return "~/.claude/settings.json" if rule["scope"] == "user" else rule.get("file") or REPO_SETTINGS
    fix_file = named(rules[0])
    # A rule still in another file keeps that way out open after this change.
    also = sorted({named(r) for r in c["allow"] if r["rule"] in names and r["scope"] != "company"} - {fix_file})
    fix = {"file": fix_file,
           "change": "remove the allow rule%s %s" % ("s" if len(names) > 1 else "", ", ".join(names)),
           "after": {"classifier": "those go to auto mode's classifier, which approves instead of you",
                     "refused": "those are refused"}.get(approver, "those ask you first"),
           "approver_after": approver}
    if also:
        fix["also_in"] = also
    return fix


# ---------------------------------------------------------------- main


def build():
    c = claude_code(shell_flags())
    if c is None:
        return {"blast_radius": VERSION, "error": "no Claude Code configuration in this home folder"}
    creds = credentials()
    plain = sum(s.get("plaintext_secrets", 0) for s in c["mcp_servers"])
    data = (["plaintext tokens in your Claude Code config"] if plain else []) + [x["label"] for x in creds] + ["this repo's code"]
    v = claude_verdict(c, data)
    hooks = {}
    for h in c["hooks"]:
        hooks.setdefault((h["scope"], h["program"]), []).append(h["event"])
    transcripts = os.path.join(HOME, ".claude", "projects")
    return {
        "blast_radius": VERSION,
        "project": tilde(CWD),
        "project_root": c["project_root"],
        "mode": v["mode"],
        "mode_from": v["mode_from"],
        "reads": v["in"],
        "can_open": v["data"],
        "ways_out": v["out"],
        "whole_trifecta_servers": v["whole_trifecta_servers"],
        "unknown_servers": v["unknown_servers"],
        "fix": pick_fix(c, v),
        "credentials": creds,
        "plaintext_secrets_in_config": plain,
        "watching": {
            "hooks": [{"scope": k[0], "program": k[1], "events": sorted(set(e))} for k, e in sorted(hooks.items())],
            "telemetry": c["telemetry"],
            "local_transcripts": [tilde(transcripts)] if os.path.isdir(transcripts) else [],
        },
        "company_managed": c["company_keys"],
        "settings": c,
        "files_read": FILES_READ,
    }


def main():
    json.dump(build(), sys.stdout, indent=1)
    print()


if __name__ == "__main__":
    main()
