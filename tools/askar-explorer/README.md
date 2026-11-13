# Askar Explorer

Askar Explorer is a developer tool for inspecting and troubleshooting Askar SQLite and PostgreSQL stores. Browse a live store from the CLI or browser, query encrypted storage through focused tools, or export a plaintext SQLite copy for recovery work.

Explorer does not initialize or migrate a database. Use a read-only database role for inspection. Exports contain decrypted data; treat them as sensitive.

## Connect To An External Database

Use an Askar connection URI:

```text
postgres://USER:PASSWORD@HOST:PORT/DATABASE?schema=SCHEMA
```

URL-encode reserved password characters. Add `?schema=SCHEMA` when the Askar tables are not in `public`. You need the store pass key if one is configured; commands prompt for it unless you provide a pass-key environment variable.

### Run On The Host

Install stable Rust with Cargo and the native build tools for your platform. The devcontainer installs the build dependencies automatically.

From the repository root, create the ignored Explorer config and edit the sample URI:

```sh
mkdir -p .devcontainer/askar-explorer
cp .devcontainer/explorer.env.example .devcontainer/askar-explorer/explorer.env
```

For a database reachable from your host, set `ASKAR_EXPLORER_URI` to use `127.0.0.1` or `localhost` and the database's host port, for example:

```text
postgres://readonly_user:URL_ENCODED_PASSWORD@127.0.0.1:5432/mediator?schema=public
```

Load the config and try a read:

```sh
set -a
. .devcontainer/askar-explorer/explorer.env
set +a
cargo run -p askar-explorer -- profiles
cargo run -p askar-explorer -- ls --category connections --limit 20
```

### Run The CLI In The Devcontainer

Requires Docker and the VS Code Dev Containers extension. Choose **Dev Containers: Reopen in Container**, then point the CLI at the database. For a PostgreSQL server on the host, use `host.docker.internal` and the host-mapped port, not `localhost`:

```sh
export ASKAR_EXPLORER_URI='postgres://readonly_user:URL_ENCODED_PASSWORD@host.docker.internal:5432/mediator?schema=public'
cargo run -p askar-explorer -- profiles
cargo run -p askar-explorer -- ls --category connections --limit 20
```

The host database must accept Docker TCP connections; configure PostgreSQL's `listen_addresses`, `pg_hba.conf`, and the host firewall as needed. Direct CLI use makes the URI and any supplied pass key available to processes in the devcontainer. Use disposable data there when agents are present; see [Agents And MCP](docs/agents.md) for the isolated service workflow.

## Web UI Quickstart

With `ASKAR_EXPLORER_URI` set in the host shell, start the human-facing UI:

```sh
cargo run -p askar-explorer -- ui
```

Open <http://127.0.0.1:7070> and enter the store pass key in the browser. For a store without a pass key, enter the one-time login code printed by the service. The UI is read-only and shows decrypted ordinary item data after login; key-manager values are never displayed. Press Ctrl-C in the terminal to stop it. The UI needs no Node.js or separate web server.

### Explorer Screenshots

![Store unlock screen](docs/img/askar-explorer-unlock.png)
![Dashboard](docs/img/askar-explorer-dashoard.png)
![Entry List](docs/img/askar-explorer-entries.png)
![Entry Detail](docs/img/askar-explorer-entry-detail.png)

To run the UI as a Compose service instead, configure the ignored `explorer.env` file with a host-reachable database URI (`host.docker.internal` for a database on your machine), then run:

```sh
docker compose -f .devcontainer/compose.yaml --profile explorer-ui up -d --build explorer-ui
```

Open <http://localhost:7070>. The service asks for the pass key in the browser and is published only on host loopback. Stop it with:

```sh
docker compose -f .devcontainer/compose.yaml --profile explorer-ui stop explorer-ui
```

## CLI At A Glance

```sh
cargo run -p askar-explorer -- profiles
cargo run -p askar-explorer -- stats
cargo run -p askar-explorer -- ls --category connections --limit 20
```

Use `get --id ID` to inspect one entry and `describe CATEGORY` to summarize a category's structure. Values are hidden by default; `--reveal` prints real ordinary item values. KMS values remain hidden. See [SQL Queries](docs/sql.md) for advanced querying.

## Configuration

Explorer reads `.env` from the current working directory. `ASKAR_EXPLORER_URI` sets the database URI; pass keys can be entered at the prompt or supplied through `ASKAR_EXPLORER_PASS_KEY` or `ASKAR_EXPLORER_PASS_KEY_FILE`. Explicit command-line flags override environment variables. Keep credentials out of committed files and shell history.

## Further Guides

- [SQL Queries](docs/sql.md): virtual table, filters, performance, visibility, and safeguards.
- [Agents And MCP](docs/agents.md): redacted API/MCP access, policy, isolation, and proposals.
- [Export And Recovery](docs/recovery.md): plaintext export, DBeaver inspection, and guarded apply.
