# neon-guard-mcp 🛡️

Neon's official MCP server is amazing, but giving an LLM full admin access to your infrastructure is terrifying. **neon-guard-mcp** acts as a local security proxy, giving your AI agent the exact tools it needs to branch and test code, while completely air-gapping your production data and master keys.

---

## Features

- **Default-deny whitelist** — only a small set of branch-scoped tools are exposed; there is no tool for deleting projects, managing users, modifying production, or accessing connection strings for branches the proxy did not create.
- **Provenance gating** — authorization to retrieve a connection string, delete, or reset a branch requires that the proxy itself created it (tracked in `.neon-guard-state.json`). A matching name prefix alone is not sufficient.
- **Schema-only branches by default** — new branches are created with `init_source: schema-only`, so no production rows are ever copied into an agent-accessible branch.
- **Short-lived branches** — configurable expiry (default 24 h); Neon deletes the branch automatically, invalidating the embedded credential.
- **Project allowlist** — the proxy refuses to act on any project not explicitly listed in your config, even if the API key has broader access.
- **NEON_API_KEY never leaves the proxy process** — the LLM receives only tool results, never the key itself.
- **Configurable tool disabling** — remove individual tools from the schema if your threat model requires it.

---

## Architecture

```
Claude Code (or any MCP client)
        |
        |  stdio (JSON-RPC)
        v
+---------------------------+
|   neon-guard-mcp proxy    |
|  - holds NEON_API_KEY     |
|  - enforces policy        |
|  - tracks provenance      |
|  - rewrites / filters     |
+---------------------------+
        |
        |  HTTPS (Neon REST API v2)
        v
   console.neon.tech
```

The LLM calls tools. The proxy validates every call against config and provenance state, then translates allowed calls into Neon API requests. The master key is only ever present in the proxy process environment.

---

## Why / threat model

### The official Neon MCP server

Neon's official server maps MCP tools 1:1 to Neon REST API operations. This is intentional and useful — for a human developer who understands what they are authorizing. For an autonomous AI agent, it means the LLM can:

- Delete any branch, including `main` / production.
- Read connection strings for any branch, including production.
- Create branches that copy full production data.
- Manage users, roles, and project settings.

One prompt-injection attack, one confused-deputy mistake, or one overly-helpful model decision is enough to destroy production data or exfiltrate it.

### neon-guard-mcp

This proxy takes the opposite position: **default-deny, least privilege, explicit allowlist**. The agent gets only what it needs to create isolated test branches and run migrations/tests against them. Every other API surface simply does not exist as far as the LLM is concerned.

---

## How the trust boundary works

**Name prefix is NOT a security boundary.**

It would be trivial for an attacker (or a confused model) to supply a branch name that happens to match the configured prefix. Authorization is instead gated on *provenance*: the proxy records every branch it creates in `.neon-guard-state.json`. A branch must appear in that record AND pass live server-side checks (not default, not protected, not the enforced parent branch) before the proxy will issue a connection string, delete it, or reset it.

The provenance store uses atomic file writes (write-then-`os.replace`) with mode `0o600` to prevent partial reads and limit filesystem exposure.

---

## Installation

### Recommended: uvx with a pinned version

```bash
uvx neon-guard-mcp==0.1.0
```

Pinning the version is important for security: it prevents a supply-chain update from silently changing proxy behavior.

### pip

```bash
pip install neon-guard-mcp==0.1.0
```

### From source (before the package is published)

Until `neon-guard-mcp` is published to PyPI, install it from a local checkout:

```bash
git clone https://github.com/your-org/neon-guard-mcp.git
cd neon-guard-mcp
uv sync                      # or: pip install -e .
uv run neon-guard-mcp        # runs the server over stdio
```

In your MCP client config, point `command` at `uv` with `args: ["run", "neon-guard-mcp"]` (or `uvx --from /abs/path/to/neon-guard-mcp neon-guard-mcp`) instead of the published-package form below.

---

## Configuration

Copy the example config and edit it:

```bash
cp neon-guard.json.example neon-guard.json
```

> **Note:** `neon-guard.json` and `.neon-guard-state.json` are in `.gitignore` and must never be committed. The example file (`neon-guard.json.example`) is safe to commit — it contains no secrets.

### Configuration schema

| Field | Type | Default | Description |
|---|---|---|---|
| `allowed_projects` | `list[string]` | required | Neon project IDs the proxy is permitted to act on. Any other project ID is rejected. |
| `branch_naming_prefix` | `string` | required | Prefix applied to all branches the proxy creates (e.g. `"ai-dev-"`). Must match `^[a-z0-9][a-z0-9-]*$`. |
| `enforce_parent_branch` | `string` | required | Name of the branch all agent branches must be parented from (e.g. `"main"`). Prevents branching off an already-modified branch. |
| `branch_data_mode` | `"schema-only"` \| `"full"` | `"schema-only"` | Controls Neon's `init_source`. `"schema-only"` copies only DDL — no rows. **Change to `"full"` only if you have reviewed the security implications.** |
| `branch_expiry_hours` | `integer` \| `null` | `24` | Hours after creation before Neon auto-deletes the branch. `null` disables expiry. Expiry also invalidates the embedded credential in any connection string issued for the branch. |
| `allow_branch_deletion` | `bool` | `false` | If `false`, the `delete_test_branch` and `reset_test_branch` tools are not registered at all. |
| `max_ai_branches` | `integer` | `10` | Maximum number of live agent-created branches per project. Prevents runaway branch creation. |
| `connection.default_database` | `string` | required | Database name used when generating connection strings. |
| `connection.default_role` | `string` | required | Postgres role used when generating connection strings. Should be a dedicated least-privilege role (see Recommended Neon Setup). |
| `connection.pooled` | `bool` | `true` | Whether to request a PgBouncer pooled connection URI. |
| `disabled_tools` | `list[string]` | `[]` | Tool names to omit from the MCP schema entirely. Useful for further restricting the agent's surface. |

---

## Available tools

All tools are read-only or scoped to branches the proxy created. No tool can touch production or untracked branches.

| Tool | What it does | Guard |
|---|---|---|
| `list_safe_projects` | Lists Neon projects filtered to `allowed_projects`. | Intersection with server response; unlisted projects are invisible. |
| `list_safe_branches` | Lists branches for an allowed project, annotated with `created_by_guard`. | Project must be in `allowed_projects`. |
| `create_test_branch` | Creates a new branch from `enforce_parent_branch` using the naming prefix. | Project allowed; parent verified server-side; `max_ai_branches` enforced; name uniqueness checked; `branch_data_mode` and `expires_at` applied. |
| `get_branch_connection_string` | Returns the connection URI for a guard-created branch. | Project allowed; branch must be in provenance store; branch must not be default, protected, or the enforced parent. |
| `get_branch_status` | Returns branch state metadata. | Project allowed; branch must exist in the project. |
| `delete_test_branch` | Deletes a guard-created branch. | Only registered if `allow_branch_deletion: true`; provenance + server-side safety checks; branch must have no children. |
| `reset_test_branch` | Restores a guard-created branch to its parent's current state. | Only registered if `allow_branch_deletion: true`; provenance + server-side safety checks. |

---

## Claude Code `.mcp.json` integration

Add this to your project's `.mcp.json` (or `~/.claude/mcp.json` for global use):

```json
{
  "mcpServers": {
    "neon-guard": {
      "command": "uvx",
      "args": ["neon-guard-mcp==0.1.0"],
      "env": {
        "NEON_API_KEY": "napi_...",
        "NEON_GUARD_CONFIG": "/absolute/path/to/neon-guard.json"
      }
    }
  }
}
```

> **Important:** The `env` block is passed only to the `neon-guard-mcp` subprocess. Claude Code does not forward it to the LLM context. `NEON_API_KEY` never appears in any tool call, tool result, or conversation message.

Use an absolute path for `NEON_GUARD_CONFIG` to avoid ambiguity about the working directory at startup.

---

## Security model and honest boundaries

### What this protects

- **Master API key** — never in LLM context; lives only in the proxy process environment.
- **Production branch** — no tool can retrieve its connection string, delete it, or reset it (enforced server-side by checking the `default` and `protected` flags and matching against `enforce_parent_branch`).
- **Non-allowed projects** — refused at the policy layer before any API call.
- **Untracked branches** — connection strings and destructive operations are refused for any branch not recorded in `.neon-guard-state.json`.

### What this does NOT fully protect

**Connection strings are live credentials.** When you call `get_branch_connection_string`, the returned URI contains a Postgres password. That URI enters the LLM context (it is the tool result). This is a fundamental constraint of how database connections work — the agent needs a credential to connect.

Mitigations applied by default:

- **Schema-only mode** — even if the credential is exfiltrated, the branch contains no production rows.
- **Short expiry** — the default 24 h expiry causes Neon to delete the branch, which invalidates the embedded password.
- **Dedicated non-owner role** — the connection role (`neon_guard_ai` in the example) should have only the privileges needed for migrations and tests, not superuser or `neondb_owner`.

**Operational posture:** treat any branch that an agent has touched as potentially compromised. Deleting the branch (or allowing it to expire) rotates the credential. Do not reuse agent branches for sensitive data.

**Log redaction is a best-effort backstop, not the primary control.** The proxy never passes the master key or a connection URI to a log, an error message, or stdout, and it scrubs known secret shapes (Neon keys, `Bearer` tokens, `postgresql://` credentials, `password=` keyword forms) from every log record as defense-in-depth. Redaction is pattern-based, so the real guarantee is the "never log a secret" discipline above — do not add log lines that interpolate credentials and rely on the scrubber to catch them.

### Prompt injection risk

If your agent processes untrusted input (web pages, user-provided files, database content from a previous branch), an adversary could embed instructions that attempt to exfiltrate the connection string or manipulate the agent into calling `reset_test_branch` on the wrong branch. The schema-only default and provenance gating significantly reduce the blast radius, but they do not eliminate the attack surface entirely. Consider whether your agent's task requires access to `get_branch_connection_string` at all; if not, add it to `disabled_tools`.

---

## Recommended Neon setup

Create a dedicated database role with limited privileges rather than using `neondb_owner`:

```sql
-- Run as neondb_owner on your Neon project
CREATE ROLE neon_guard_ai WITH LOGIN PASSWORD 'choose-a-strong-password';

-- Grant only what your migrations/tests need
GRANT CONNECT ON DATABASE neondb TO neon_guard_ai;
GRANT USAGE ON SCHEMA public TO neon_guard_ai;
GRANT CREATE ON SCHEMA public TO neon_guard_ai;  -- needed for migrations
-- Do NOT grant SUPERUSER, CREATEROLE, or CREATEDB
```

Set `connection.default_role` to `"neon_guard_ai"` in your config. This ensures that even if a connection string is leaked, the role cannot escalate privileges, create new roles, or access other databases.

---

## License

MIT — see [LICENSE](LICENSE).
