# agent-blast-radius

Ask Claude Code who can talk to it.

Anything an agent reads can steer it. So the useful question about your Claude Code setup isn't which settings are on. It's who can put words in front of it, and what it will do without anyone approving.

`/blast-radius` answers that for your machine. A script reads how Claude Code is set up. Then Claude Code works out what that means for you: where it reads, who can actually write there, what it can send without anyone approving, whether anyone would know, and the one change that closes the worst of it.

The answers are usually not the obvious ones. An analytics or error-tracking connection is a channel anyone who uses your app can write into, because the keys those tools use in the browser are public. A shared Slack channel includes people from other companies. And the services Claude Code is connected to through your claude.ai account don't appear in any config file on your laptop, so most people don't know they're there.

## Install

In Claude Code:

```
/plugin marketplace add Cimento-AI/agent-blast-radius
/plugin install agent-blast-radius@cimento
```

Then type `/blast-radius`, or ask "who can talk to you?"

## What you get

A short answer in the chat, in Claude Code's own voice. For example:

> **If your app sends PostHog events from the browser, anyone who uses it can talk to me, and your curl rule skips auto mode's check, so nobody approves a curl.**
>
> A model approves my commands, but the allow rule `Bash(curl --silent --show-error --location:*)` in `~/.claude/settings.json` skips that check, and it doesn't limit where curl sends. I can open the AWS keys and the SSH key without a passphrase saved on this laptop.
>
> **Who can talk to me**
> - **PostHog MCP server**: whoever your app records, and if it sends events from the browser, anyone who uses it.
> - **Sentry** (claude.ai connector, in no config file): whoever can make your app throw an error.
> - **Slack** (claude.ai connector, in no config file): your channels, and other companies if you have shared channels.
> - **Jira** (claude.ai connector, in no config file): anyone who can file or comment on a ticket.
>
> **Would anyone know?** Most likely. A company program runs before and after each tool runs, and when a session starts and ends.
>
> **The one change:** remove that rule. Curl then goes to the same model as my other commands. Slack and Jira can still post, with that model approving; you turn them off in your claude.ai connector settings. Want me to make it? I'll show you the diff first. I can also write a note for whoever owns security.

Say yes and it makes the change and shows you the diff. Ask for the note and you get a few sentences, in your voice, for whoever owns security. The note names products and credential types but no paths, hosts or values.

## How it works

The work is split in two on purpose.

[`scripts/agent_setup.py`](scripts/agent_setup.py) gathers the facts, and it's where every judgment you'd want to audit lives: which settings layers apply, which allow rules can send data out (curl, ssh, `git push`, a bare `node` or `python`, and `npm test`, which runs whatever the repo says), whether anyone approves them (auto mode drops the broad ones itself, and the script accounts for that), and what the fix is. It's deterministic, standard-library Python, and covered by tests. You can run it without Claude:

```
python3 scripts/agent_setup.py
```

Claude Code reads those facts and does the part a script can't. It knows who writes to each service you're connected to, compares its own live tool list with what your config files say, and picks the true thing about your setup you'd least expect. The skill tells it to describe who can reach what and which setting allows it, never how to exploit it, and to hedge anything it infers.

## What it reads, and what it doesn't

- Claude Code's managed, user, project and local settings, with local settings read from the repo root (the main checkout's root in a worktree, found through the `.git` and `commondir` files); `~/.claude.json`; `.mcp.json`; `managed-mcp.json`; installed plugins' MCP servers.
- Shell startup files, only to find aliases that add flags such as `--dangerously-skip-permissions`.
- Credential files such as `~/.aws/credentials` and `~/.ssh/id_*` are opened only to answer "does this hold a credential?" The output says yes or no and never includes their contents.
- Secret values never reach the output. Env vars and headers keep their names only, and credential-shaped arguments, URL parts and rule text become `<redacted>`. The tests cover the cases we know about; please open an issue if you find one we missed.
- Nothing is sent to Cimento. The plugin makes no network calls. Claude sees the facts the way it sees any command you run in a session.
- If you say yes to the fix, Claude edits that one setting in that one file in your home folder and shows you the diff. It never edits files inside a repository or company-managed files.

## Limits

- It reads configuration, not behavior. A setup where you approve everything can still be talked into asking you something misleading.
- What Claude says about who writes to a service is reasoning, not a scan of that service. It says "if" when it's inferring.
- macOS and Linux. Windows paths aren't covered yet.

## For teams

This reads one laptop, once. [Cimento Agent Hub](https://cimento.ai/blast-radius?ref=github) answers the same questions for every engineer's coding agents, keeps a record of what they actually do, and enforces the fix as policy.

## License

Apache-2.0
