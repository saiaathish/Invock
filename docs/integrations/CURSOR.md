# Cursor integration

Invock discovers `cursor` on `PATH` and manages `~/.cursor/mcp.json`. Existing JSON is preserved except for the Invock-owned `mcpServers.invock` entry. Each update creates a timestamped backup and uses an atomic write.
