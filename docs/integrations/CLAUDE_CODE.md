# Claude Code integration

Invock discovers `claude` on `PATH` and uses Claude Code's user MCP configuration at `~/.claude.json`. Installation adds one `mcpServers.invock` entry, creates a timestamped backup, and writes atomically. Uninstall removes only that entry.

Live Claude authentication is environment-dependent. Run `invock verify claude` before `invock wrap claude`.
