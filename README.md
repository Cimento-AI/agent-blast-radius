# agent-blast-radius

How many approval clicks stand between a poisoned README and your keys leaving your laptop?

`/blast-radius` checks how Claude Code, Cursor and Codex are set up on your machine. Every coding agent reads things strangers wrote, and every one can reach your code and keys: two legs of the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/). This finds the third leg, a way to send data out, and counts how many approvals stand in its way. Then it gives you the one-line fix and applies it if you say yes.

## Install

In Claude Code:

```
/plugin marketplace add Cimento-AI/agent-blast-radius
/plugin install agent-blast-radius@cimento
```

Then type `/blast-radius`, or ask "what's my agent blast radius?"

## What you get

```
Anyone who can comment on a Jira ticket could get your AWS keys off
this laptop through Codex, and nothing would ask you first.

Codex        0 clicks  Jira, Linear -> AWS keys, SSH key -> any command
Claude Code  0 clicks  web pages -> same -> curl (your allow rule)
Cursor       1 click   GitHub issues -> same -> terminal, asks first

atlassian is all three legs by itself: it reads what others write,
holds private data, and can post.
3 plaintext tokens sit in your agent configs. This report hid them; a
poisoned README won't.
No company policy reaches any of these agents; every setting above can
be changed from this laptop.

Fix the worst one, in ~/.codex/config.toml:
  sandbox_mode = "workspace-write"
Codex goes from 0 clicks to 1: commands that need the network ask you
first. atlassian and linear can still post; Codex's sandbox doesn't
cover MCP. Claude Code stays at 0 until you remove the curl rule.

That's one laptop. Agent Hub reads every engineer's Claude Code, Cursor
and Codex setup every 5 minutes, so a full-access Codex shows up the
day someone sets it, and it blocks the same MCP servers in all three.
https://cimento.ai/blast-radius?ref=plugin
```

After you answer, it writes a short note you can forward to whoever owns security, with credential types and tool names but no paths or values.

## How it decides

[`scripts/agent_setup.py`](scripts/agent_setup.py) makes every judgment; Claude only writes the sentences around it. You can run it without Claude:

```
python3 scripts/agent_setup.py --text   # the verdicts, in plain text
python3 scripts/agent_setup.py          # everything, as JSON
```

The rules are in the code and the tests (`python3 -m unittest discover tests`). A way out counts as 0 clicks when nothing asks a person first: Codex with `danger-full-access`, or with network on and approval `on-request` (the model decides when to ask); a Claude Code or Cursor allow rule for a command that can send data (curl, ssh, `git push`, a bare `node` or `python`); Cursor's Run Everything; Claude Code's `bypassPermissions`, including shell aliases that add it. Claude Code's auto mode and Cursor's Auto-review are shown as "0 clicks (classifier)": a model approves, not you.

## What it reads, and what it doesn't

- Claude Code: managed, user, project and local settings; `~/.claude.json`; `.mcp.json`; `managed-mcp.json`; installed plugins' MCP servers.
- Codex: `/etc/codex/config.toml`, `~/.codex/config.toml`, a trusted project's `.codex/config.toml`, `requirements.toml`, `~/.codex/rules/*.rules`, `hooks.json` and profile files.
- Cursor: `mcp.json`, `cli-config.json`, `sandbox.json`, `hooks.json`, and the run-mode fields of Cursor's local settings database (only those fields are read).
- Shell startup files, only to find aliases that add flags such as `--dangerously-skip-permissions` or `--yolo`.
- Credential files such as `~/.aws/credentials` and `~/.ssh/id_*` are opened only to answer "does this hold a credential?" The output says yes or no and never includes their contents.
- Secret values never reach the output: env vars and headers keep their names only, and credential-shaped arguments, URL parts and rule text become `<redacted>`. The tests cover the cases we know about; please open an issue if you find one we missed.
- Nothing is sent to Cimento. The plugin makes no network calls. Claude sees the script's output the way it sees any command you run in a session.
- If you say yes to the fix, it edits that one setting in that one file in your home folder, and shows you the diff. It never edits files inside a repository or company-managed files.

## Limits

- It reads configuration, not behavior. "no path" means no way out was found in config, not that the agent can't be fooled.
- MCP servers are judged by name, so an unfamiliar server is listed as unknown rather than guessed at.
- macOS and Linux. Windows paths aren't covered yet.

## For teams

Which of your engineers run Codex with full access, or added an MCP server this week? [Cimento Agent Hub](https://cimento.ai/blast-radius?ref=github) shows that for every laptop within 5 minutes, blocks MCP servers in all three agents before the call, and puts its hooks back if someone removes them.

## License

Apache-2.0
