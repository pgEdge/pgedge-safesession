# pgEdge SafeSession

pgEdge SafeSession is a PostgreSQL extension that enforces
read-only sessions for specified database roles. It provides
defense-in-depth protection using executor and utility hooks
to block all write operations, DDL, and other potentially
dangerous commands.

## Features

- Block DML (INSERT, UPDATE, DELETE, MERGE) for restricted
  roles
- Block DDL (CREATE, ALTER, DROP, TRUNCATE, etc.)
- Block COPY FROM and COPY TO PROGRAM
- Block GRANT/REVOKE, VACUUM/ANALYZE
- Block volatile C-language function execution (which can
  bypass the executor)
- Prevent tampering with read-only GUC settings
- Role membership inheritance: members of restricted roles
  are also restricted
- Superuser exemption: superusers are never restricted, even
  if they are members of restricted roles
- Session-user anchored: SET ROLE cannot escape restrictions
- Configurable protection layers via GUCs

## Requirements

- PostgreSQL 14 or later
- Must be loaded via `shared_preload_libraries`

## Installation

### Build from Source

```bash
make
make install
```

### Configure PostgreSQL

Add the extension to `shared_preload_libraries` in
`postgresql.conf`:

```
shared_preload_libraries = 'pgedge_safesession'
```

Restart PostgreSQL for the change to take effect.

### Create the Extension (Optional)

The extension is fully functional once loaded via
`shared_preload_libraries`. Running `CREATE EXTENSION` is
optional, but registers it in the `pg_extension` catalog
so it appears in `\dx` output:

```sql
CREATE EXTENSION pgedge_safesession;
```

## Configuration

All GUCs are SUSET parameters (only superusers can modify
them).

### `pgedge_safesession.roles`

A comma-separated list of PostgreSQL role names whose
sessions will be restricted to read-only operations.

```sql
ALTER SYSTEM SET pgedge_safesession.roles =
    'readonly_user, reporting_role';
SELECT pg_reload_conf();
```

Any session authenticated as one of these roles, or as a
role that is a member of one of these roles, will be
restricted to read-only operations.

### `pgedge_safesession.block_dml`

Default: `on`

Block INSERT, UPDATE, DELETE, and MERGE for restricted
roles.

### `pgedge_safesession.block_ddl`

Default: `on`

Block DDL and other utility commands for restricted roles.
Uses a whitelist approach: only explicitly allowed
statements (SELECT, EXPLAIN, transaction control, SET,
SHOW, LISTEN/NOTIFY, cursors, DO blocks) can execute.

### `pgedge_safesession.block_c_functions`

Default: `on`

Block C-language function execution for restricted roles.
By default, only **volatile** C functions are blocked.
IMMUTABLE and STABLE C functions (such as PostGIS geometry
operations or pgvector distance operators) are allowed
since they promise no side effects.

### `pgedge_safesession.block_all_c_functions`

Default: `off`

When enabled, blocks **all** C-language functions
regardless of volatility. This provides stricter
protection at the cost of blocking read-only extension
functions. Only applies when `block_c_functions` is on.

### `pgedge_safesession.force_read_only`

Default: `on`

Sets `default_transaction_read_only = on` and
`XactReadOnly = true` for restricted sessions as
belt-and-suspenders protection. This ensures that even if
something bypasses the hooks, PostgreSQL's own internal
read-only checks will catch it.

## What is Blocked

For restricted sessions (with all protections enabled),
the following operations are blocked:

- **DML**: INSERT, UPDATE, DELETE, MERGE (PostgreSQL 15+)
- **DDL**: CREATE, ALTER, DROP, TRUNCATE, and all other
  schema modification commands
- **COPY FROM**: data import (COPY TO is allowed)
- **COPY TO PROGRAM**: program execution via COPY
- **CREATE TABLE AS / SELECT INTO**: table creation from
  queries
- **GRANT / REVOKE**: privilege modifications
- **VACUUM / ANALYZE**: maintenance commands
- **Volatile C-language functions**: functions implemented
  in C that are marked VOLATILE (e.g., `dblink_exec`,
  `lo_import`, `set_config`). IMMUTABLE/STABLE C functions
  are allowed by default.
- **Exclusive locks**: LOCK TABLE with modes above
  ROW SHARE
- **GUC tampering**: SET/RESET of
  `default_transaction_read_only`, SET TRANSACTION
  READ WRITE, and RESET ALL

## What is Allowed

- **SELECT**: all read queries, including those using
  WHERE clauses, aggregates, and built-in functions
- **EXPLAIN**: query plans (does not execute)
- **Transaction control**: BEGIN, COMMIT, ROLLBACK,
  SAVEPOINT
- **SET / RESET**: non-protected GUC changes
  (e.g., work_mem)
- **SET TRANSACTION ISOLATION LEVEL**: isolation level
  changes
- **SHOW**: display settings
- **LISTEN / NOTIFY**: notification channels
- **Cursors**: DECLARE, FETCH, CLOSE
- **DO blocks**: anonymous code blocks (inner writes are
  caught by the executor hook)
- **PL/pgSQL and SQL functions**: read-only functions
  execute normally; any write attempt inside a function
  is caught by the executor hook
- **IMMUTABLE/STABLE C functions**: extension functions
  that promise no side effects (e.g., PostGIS spatial
  calculations, pgvector distance operators)

## Security Model

### Session User is the Anchor

The session user identity (set at connection time) is the
primary check. Even if a restricted user executes
`SET ROLE` to assume another role, the session user remains
restricted. This prevents bypass via role switching.

### Superuser Exemption

Superusers are never restricted, even if they are members
of a restricted role. The superuser check is based on the
session user, so SECURITY DEFINER functions owned by
superusers cannot bypass restrictions when called from a
restricted session.

### SECURITY DEFINER Functions

A SECURITY DEFINER function temporarily changes the
effective user to the function owner. However, SafeSession
checks the session user, not the effective user. This
means a restricted session cannot use a SECURITY DEFINER
function owned by a privileged user to perform writes.

### Role Membership Inheritance

If role `app_reader` is listed in
`pgedge_safesession.roles`, then any role that is a member
of `app_reader` is also restricted. This uses PostgreSQL's
`is_member_of_role()` function for membership checking.

### Belt-and-Suspenders

When `force_read_only` is enabled (the default),
SafeSession sets `default_transaction_read_only = on` for
restricted sessions. This provides an additional layer of
protection: even if a C function somehow bypasses the
hooks and attempts direct heap writes, PostgreSQL's own
internal read-only checks will catch it.

## Example

```sql
-- As superuser: configure restrictions
ALTER SYSTEM SET pgedge_safesession.roles =
    'reporting_user';
SELECT pg_reload_conf();

-- Connect as reporting_user
-- Reads work normally:
SELECT * FROM sales;          -- OK
SELECT count(*) FROM sales;   -- OK
EXPLAIN SELECT * FROM sales;  -- OK
COPY sales TO '/tmp/out.csv'; -- OK

-- Writes are blocked:
INSERT INTO sales VALUES (1); -- ERROR
CREATE TABLE tmp (id int);    -- ERROR
COPY sales FROM '/tmp/in.csv'; -- ERROR
```

## Licence

See the [Licence](LICENCE.md) page for details.
