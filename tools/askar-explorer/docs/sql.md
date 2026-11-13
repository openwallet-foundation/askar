# SQL Queries

Explorer can run one read-only SQL query against a virtual `items` table. The query uses SQLite syntax and reads a live SQLite or PostgreSQL Askar store. See the [README](../README.md) for connection setup.

```sh
askar-explorer sql "SELECT category, count(*) AS entries FROM items GROUP BY category ORDER BY entries DESC"
askar-explorer sql "SELECT name FROM items WHERE ptag = 'state=active' AND etag = 'owner=alice'"
askar-explorer sql --reveal "SELECT name, json_extract(value, '$.state') AS state FROM items WHERE category = 'connections' LIMIT 20"
```

Use `--format jsonl` for JSON Lines output and `--limit` to cap returned rows (default 1000). The store connection is read-only.

## Columns

| Column | Description |
| --- | --- |
| `profile` | Profile name. |
| `id` | Entry id. |
| `kind` | `item` or `kms`. |
| `category`, `name` | Decrypted entry identity. |
| `value` | Decrypted value, hidden unless `--reveal` is set. |
| `value_bytes` | Size of the stored value. |
| `expiry` | Expiry timestamp, if set. |
| `ptags`, `etags` | Plaintext and encrypted tags, represented as JSON objects. Tag values are hidden unless `--reveal` is set. |
| `errors` | Decryption errors for fields that could not be read. |

Key-manager (`kms`) values are always hidden, including when `--reveal` is used.

## Filters And Performance

Equality filters on `profile`, `id`, `kind`, `category`, and `name` are pushed down to the database. `ptag` and `etag` also support exact `name=value` matches. The `expiry_mode` column accepts `any`, `live`, or `expired`; expired rows are included by default.

Other predicates are evaluated after decryption. For example, JSON functions, `LIKE`, ranges, sorting, and grouping on decrypted values can scan many rows. Add a selective equality condition such as `category = 'connections'` when querying a large profile. A `LIMIT` can stop a simple scan early, but sorting or grouping may require reading all matching rows.

## Visibility

By default, `value` and tag values are `NULL`. `--reveal` displays ordinary item values and tag values. For a structural, pseudonymized view instead, use `--redact` and configure a policy; see the [Agent and MCP guide](agents.md#redacted-view). The agent API always uses the redacted view.

## Safeguards

Explorer accepts a single read-only `SELECT`. The query runs against a virtual table on a throwaway in-memory SQLite connection. Its authorizer rejects writes and schema operations such as `CREATE`, `DROP`, `ATTACH`, and `PRAGMA`; the source database is opened read-only as well.
