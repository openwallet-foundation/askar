# Export And Recovery

Explorer can export a decrypted SQLite copy for inspection and can apply reviewed edits from that export. The export is plaintext; protect it like the original secrets. For connecting to a live store, see the [README](../README.md).

## Export

From the repository root:

```sh
cargo run -p askar-explorer -- export \
  --uri 'sqlite:///path/to/store.db' \
  --out ./inspection.db
```

For PostgreSQL, pass an Askar URI such as `postgres://USER:PASSWORD@HOST:PORT/DATABASE?schema=SCHEMA`. Reserved password characters must be URL-encoded. Use `.env` or `ASKAR_EXPLORER_URI` to avoid putting credentials in command history. Explorer prompts for the pass key unless the store uses no pass key or a pass-key environment variable is supplied. The output file must not already exist.

Key-manager material is excluded by default. Add `--include-kms` only when required, and handle the resulting export with particular care.

## Inspect In DBeaver

Connect DBeaver or another SQLite client to the export. The `profiles`, `items`, and `item_tags` tables contain decrypted data. `items.id` is the source Askar id; `items.row_id` is local to the export and is referenced by `item_tags.item_row_id`. `items.value` is a BLOB; `readable_items.value_text` casts text/JSON values to text.

```sql
SELECT p.name AS profile, i.category, i.name, i.value_text, i.expiry
FROM readable_items AS i
JOIN profiles AS p ON p.id = i.profile_id;
```

For decryption problems, inspect `category_error`, `name_error`, and `value_error` in `items`, and `error` in `item_tags`. A profile-key unlock failure stops export and reports an incomplete output file.

## Edit The Export

Back up the encrypted source before applying edits. Do not treat the plaintext export as a backup of the source database. Edit the tables, not the `readable_items` view. For example:

```sql
UPDATE items
SET value = CAST('{"fixed":true}' AS BLOB)
WHERE category = 'records' AND name = 'broken';

UPDATE item_tags
SET value = 'resolved'
WHERE item_row_id = (
  SELECT row_id FROM items WHERE category = 'records' AND name = 'broken'
) AND name = 'status';
```

For tags, `plaintext = 1` means a searchable plaintext value; `0` means the value is encrypted. Tag names are always encrypted in Askar. Set expiry as a UTC timestamp (`YYYY-MM-DD HH:MM:SS`) or `NULL`. Leave `items.row_id`, existing `items.id`, `original_*`, and `export_meta` alone; the latter tables are used to detect edits. New rows need no `id`.

## Review And Apply Changes

First preview the edits without writing to the source:

```sh
cargo run -p askar-explorer -- apply \
  --uri 'sqlite:///path/to/store.db' \
  --edits ./inspection.db
```

After making a recoverable backup, commit the changes through Askar's encrypted storage API:

```sh
cargo run -p askar-explorer -- apply \
  --uri 'sqlite:///path/to/store.db' \
  --edits ./inspection.db \
  --commit --confirm-backup
```

The source is not modified without both `--commit` and `--confirm-backup`. Apply verifies that the source profiles and key match the export and that edited existing values/tags have not changed since export. A conflict rolls back that profile's transaction. Profiles commit separately, so a later failure does not undo earlier profile commits. Re-export after a successful apply.

Rows with decryption errors or expired rows cannot be changed through this API. Apply loads the export into memory to compare it; for very large stores, work from a separate copy and limit its size.
