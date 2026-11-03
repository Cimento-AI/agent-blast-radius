# agent-blast-radius

Who can talk to your coding agents?

Anything an agent reads can steer it. So the useful question about your setup isn't which settings are on. It's who can put words in front of Claude Code, Cursor and Codex on your laptop, and what those agents will do without asking you.

`/blast-radius` answers that for your machine. A script reads how each agent is set up. Then Claude works out what that means for you: where your agents read, who can actually write there, which agent can act on it without anyone approving, whether anyone would know, and the one change that closes the worst of it. The result is a short page in your browser.

The answers are usually not the obvious ones. An analytics or error-tracking connection is a channel anyone who visits your website can write into, because the keys those tools use in the browser are public. A shared Slack channel includes people from other companies. And the services Claude Code is connected to through your claude.ai account don't appear in any config file on your laptop, so most people don't know they're there.

## Install

In Claude Code:

```
/plugin marketplace add Cimento-AI/agent-blast-radius
/plugin install agent-blast-radius@cimento
```

Then type `/blast-radius`, or ask "who can talk to my agents?"

## What you get

In the terminal, one sentence and a page:

```
If your app sends PostHog events from the browser, anyone can talk to
me, and your curl rule skips auto mode's check.

I wrote it up. It's open in your browser.
Want me to make the one change? I'll show you the diff first.
```

The page has five parts:

- **Who can talk to your agents.** Every place your agents read, who can write there, and how wide that is: your team, your company, your customers, or anyone. It also marks the services that are connected but appear in no config file.
- **What they do without asking.** For each agent, the three legs of Simon Willison's [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): it listens to others, it can read private data, it can send things out. The first two are true of every coding agent, so the third is the one you control.
- **Would anyone know?** Whether hooks or telemetry send a record of what your agents do anywhere besides your laptop.
- **The one change.** The smallest config change that closes the worst path, and what you give up for it. If you say yes, Claude makes it and shows you the diff.
- **A note for whoever owns security**, written in your voice, naming products and credential types but no paths, hosts or values.

## How it works

The work is split in two on purpose.

[`scripts/agent_setup.py`](scripts/agent_setup.py) gathers the facts, and it's where every judgment you'd want to audit lives: which config files apply, which allow rules can send data out (curl, ssh, `git push`, a bare `node` or `python`), whether anyone approves them, and what the fix is. It's deterministic, standard-library Python, and covered by tests. You can run it without Claude:

```
python3 scripts/agent_setup.py
```

Claude reads those facts and does the part a script can't: knowing who writes to each service you're connected to, comparing its own live tool list with what your config files say, and picking the true thing about your setup you'd least expect. The skill tells it to describe who can reach what and which setting allows it, never how to exploit it, and to hedge anything it infers.

The script then checks Claude's write-up before showing it. It enforces length limits, rejects anything shaped like a secret, requires every agent and fix to match the facts, and escapes everything. The trifecta dots on the page are drawn from the facts, not from Claude's words, so the write-up can't make an agent look safer than it is.

## What it reads, and what it doesn't

- Claude Code: managed, user, project and local settings; `~/.claude.json`; `.mcp.json`; `managed-mcp.json`; installed plugins' MCP servers.
- Codex: `/etc/codex/config.toml`, `~/.codex/config.toml`, a trusted project's `.codex/config.toml`, `requirements.toml`, `~/.codex/rules/*.rules`, `hooks.json` and profile files.
- Cursor: `mcp.json`, `cli-config.json`, `sandbox.json`, `hooks.json`, and the run-mode fields of Cursor's local settings database (only those fields are read).
- Shell startup files, only to find aliases that add flags such as `--dangerously-skip-permissions` or `--yolo`.
- Credential files such as `~/.aws/credentials` and `~/.ssh/id_*` are opened only to answer "does this hold a credential?" The output says yes or no and never includes their contents.
- Secret values never reach the output. Env vars and headers keep their names only, and credential-shaped arguments, URL parts and rule text become `<redacted>`. The tests cover the cases we know about; please open an issue if you find one we missed.
- Nothing is sent to Cimento. The plugin makes no network calls. Claude sees the facts the way it sees any command you run in a session, and the page is a local file.
- If you say yes to the fix, Claude edits that one setting in that one file in your home folder and shows you the diff. It never edits files inside a repository or company-managed files.

## Limits

- It reads configuration, not behavior. An agent that asks first can still be talked into asking you something misleading.
- What Claude says about who writes to a service is reasoning, not a scan of that service. It says "if" when it's inferring.
- Only Claude Code can report its own live connections. Cursor's and Codex's come from their config files.
- macOS and Linux. Windows paths aren't covered yet.

## For teams

This reads one laptop, once. [Cimento Agent Hub](https://cimento.ai/blast-radius?ref=github) answers the same questions for every engineer's Claude Code, Cursor and Codex, keeps a record of what the agents actually do, and enforces the fix as policy.

## License

Apache-2.0
