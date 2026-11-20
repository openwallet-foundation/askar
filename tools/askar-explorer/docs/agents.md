# Agent API And MCP

Explorer can expose a store to agents through an authenticated HTTP API and an MCP server. The API always applies the configured redacted view; MCP forwards tool calls to that API and holds no database credentials or store keys.

For basic installation and host/devcontainer connectivity, see the [README](../README.md). For SQL details exposed by the query endpoint, see [SQL queries](sql.md).

## Agent API

Run the API where the store credentials and redaction policy are available:

```sh
askar-explorer serve \
  --uri "$ASKAR_EXPLORER_URI" \
  --policy .devcontainer/askar-explorer/policy.toml \
  --agent-listen 0.0.0.0:7071 \
  --token-file /run/explorer/agent.token
```

Requests must include `Authorization: Bearer <token>`. The token is regenerated on startup and written to `--token-file`. In a container without a terminal, provide the store pass key with `ASKAR_EXPLORER_PASS_KEY_FILE`.

| Route | Purpose |
| --- | --- |
| `GET /v1/profiles`, `GET /v1/stats` | Profiles and category statistics. |
| `POST /v1/describe` | Summarize one category's structure. |
| `POST /v1/query` | Read-only SQL over the redacted `items` table. |
| `POST /v1/entries`, `POST /v1/entry` | List or fetch entries. |
| `POST /v1/proposals` | Save a proposal for a person to review. |
| `GET /v1/proposals` | List proposal ids, titles, status, and size. |

Responses use `{ "columns": [...], "rows": [...] }`, except `/v1/entry`, which returns one object. Limits include 1000 SQL rows, 200 listed entries, a 5000-entry sample, 64 KB request bodies, and a 60-second request timeout. Proposals are stored at `--proposals` or `ASKAR_EXPLORER_PROPOSALS`.

The API has no endpoint to apply, reject, read, or delete a proposal. Creating one does not reveal whether guessed data exists or whether an edit would change anything.

## MCP

Run the stdio MCP proxy with the API URL and token file:

```sh
askar-explorer mcp --agent-url http://explorer:7071 --token-file /run/explorer/agent.token
```

It provides `list_profiles`, `category_stats`, `describe_category`, `query`, `list_entries`, `get_entry`, `propose_change`, and `list_proposals`. Read tools return the API's redacted view; `propose_change` only saves a proposal. A person reviews and applies changes with the CLI.

In the devcontainer setup, MCP is already registered for VS Code agent mode. See the isolated service setup below.

## Redacted View

The redacted view preserves structure while hiding values. Text leaves become size markers, equal names and tag values become stable keyed pseudonyms, and identifier-like object keys may also be pseudonymized. Policy-listed fields may be shown or pseudonymized selectively. Review sample output before sharing it; identifier detection is heuristic.

Example policy:

```toml
show_tags = ["state"]
show_paths = ["state", "role"]
pseudonymize_paths = ["owner"]
safe_keys = ["connection_id"]

[category.connections]
show_paths = ["created_at", "items[].status"]
```

Paths are dot-separated, with `[]` for array elements and `*` for object keys treated as data. The pseudonym key is created at `.askar-explorer/pseudonym.key` on first use; keep it private and backed up if stable pseudonyms are needed.

Redaction is a guardrail for API/MCP readers, not a boundary against a process that can read the database, credentials, policy, or pseudonym key, or run Explorer with the pass key and `--reveal`. Do not make the policy or key writable by agents.

## Isolated Devcontainer Setup

For real stores when agents are involved, keep the agent workspace separate from the service holding database credentials and keys. The Compose `explorer` service runs outside the devcontainer; the devcontainer sees only its token and API/MCP access.

On the host, from the repository root, create the ignored config directory and copy the templates:

```sh
mkdir -p .devcontainer/askar-explorer
cp .devcontainer/explorer.env.example .devcontainer/askar-explorer/explorer.env
cp .devcontainer/policy.toml.example .devcontainer/askar-explorer/policy.toml
cp .devcontainer/pass.key.example .devcontainer/askar-explorer/pass.key
```

Set `ASKAR_EXPLORER_URI` in `explorer.env` to a read-only connection to the external store. For a database on the host, use `host.docker.internal`; use `ASKAR_EXPLORER_WRITE_URI` only if you plan to apply reviewed proposals. Replace the pass-key placeholder with the exact key, and follow the trusted-host/permissions warning in the example configuration.

Open the repository with **Dev Containers: Reopen in Container**, then start the service from a host terminal:

```sh
docker compose -f .devcontainer/compose.yaml --profile explorer up -d --build explorer
```

The service publishes its API only on the internal Compose network. The devcontainer is not mounted with the database URI, pass key, policy, pseudonym key, or proposals volume. Directly running the CLI in an agent-accessible devcontainer exposes credentials to that environment; reserve that path for disposable data.

## Reviewing Proposals

A proposal is a request, not a write. Review and apply it from the service that holds the credentials:

```sh
docker compose -f .devcontainer/compose.yaml --profile explorer exec explorer \
  askar-explorer changes list
```

See [Export And Recovery](recovery.md#review-and-apply-changes) for the review, backup, dry-run, and apply procedure. Applying requires a separate write URI, an interactive confirmation, and a backup; changes are written through Askar's encryption.
