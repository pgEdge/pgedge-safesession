<div class="banner" markdown>
![pgEdge Labs](img/pgedge-labs-light.svg#only-light){ width="320" }
![pgEdge Labs](img/pgedge-labs-dark.svg#only-dark){ width="320" }
</div>

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

## What is Blocked

For restricted sessions (with all protections enabled),
the following operations are blocked:

- **DML**: INSERT, UPDATE, DELETE, MERGE (PostgreSQL 15+),
  including data-modifying CTEs
  (`WITH c AS (INSERT ... RETURNING ...) ...`)
- **DDL**: CREATE, ALTER, DROP, TRUNCATE, and all other
  schema modification commands
- **COPY FROM**: data import (COPY TO is allowed)
- **COPY TO PROGRAM**: program execution via COPY
- **CREATE TABLE AS / SELECT INTO**: table creation from
  queries, including their `EXPLAIN ANALYZE` forms
- **EXPLAIN ANALYZE of a writing statement**: it executes
  the statement, so it is treated as a write
- **GRANT / REVOKE**: privilege modifications
- **VACUUM / ANALYZE**: maintenance commands
- **CHECKPOINT**: forces heavy I/O and emits WAL
- **Two-phase commit**: PREPARE TRANSACTION, COMMIT
  PREPARED, ROLLBACK PREPARED
- **Side-effecting functions**: volatile functions in
  untrusted languages (C, internal, or an untrusted PL
  such as `plpython3u`), plus a curated set of
  side-effecting built-ins (`lo_import`, `pg_read_file`,
  `set_config`, `pg_advisory_lock`, `nextval`, and others).
  A `DO` block or `CALL` in an untrusted language is
  blocked for the same reason.
- **Exclusive locks**: LOCK TABLE with modes above
  ROW SHARE
- **GUC tampering**: any attempt to relax
  `transaction_read_only` or `default_transaction_read_only`,
  whether by setting one of them to a false value, by
  RESET or SET TO DEFAULT, or through SET TRANSACTION READ
  WRITE and SET SESSION CHARACTERISTICS AS TRANSACTION READ
  WRITE

## What is Allowed

- **SELECT**: all read queries, including those using
  WHERE clauses, aggregates, and built-in functions
- **EXPLAIN**: query plans. Plain EXPLAIN only plans and
  is always allowed; EXPLAIN ANALYZE is allowed only when
  the statement it runs does not write.
- **Transaction control**: BEGIN, COMMIT, ROLLBACK,
  SAVEPOINT
- **SET / RESET**: non-protected GUC changes
  (e.g., work_mem)
- **SET TRANSACTION**: ISOLATION LEVEL and READ ONLY
  (tightening the transaction is allowed)
- **Asserting read-only**: setting `transaction_read_only`
  or `default_transaction_read_only` to on, which asks for
  the state that is already enforced. Clients that assert
  read-only on every connection they open, such as a
  connection pool with writes disabled, therefore work
  against restricted roles.
- **SHOW**: display settings
- **LISTEN / NOTIFY**: notification channels
- **Cursors**: DECLARE, FETCH, CLOSE
- **Connection-pooler resets**: DISCARD ALL, DISCARD
  PLANS, and RESET ALL (they cannot relax the restriction,
  which is re-asserted per statement)
- **DO blocks and CALL**: in a trusted language (PL/pgSQL,
  SQL, ...); any write inside is caught by the executor
  hook
- **PL/pgSQL and SQL functions**: read-only functions
  execute normally; any write attempt inside a function
  is caught by the executor hook
- **IMMUTABLE/STABLE functions**, and harmless volatile
  built-ins such as `random()` and `clock_timestamp()`

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

For every restricted session SafeSession also forces the
current transaction read-only (`XactReadOnly`), re-asserted
on each statement. This provides an additional layer of
protection that cannot be turned off: even if something
bypasses the hooks and attempts direct heap writes,
PostgreSQL's own internal read-only checks will catch it.
The setting is applied without writing any session-level
GUC, so it leaves no state behind and does not interfere
with connection poolers.

## Known Limitations

- The list of side-effecting built-in functions is curated
  and deliberately conservative rather than exhaustive.
  Most such functions are superuser-only in any case; the
  notable exceptions, the advisory-lock and sequence
  functions, are on the list. A volatile function in a
  trusted language is allowed to run, and any write it
  performs is caught at execution instead.
- Enforcement anchors on the session user. A superuser can
  still use `SET SESSION AUTHORIZATION` to become a
  restricted role (that is how the restriction is entered);
  this is by design and is not a bypass.
- The roles list must be set from the server configuration
  (`shared_preload_libraries` is required, and the roles
  are normally set in `postgresql.conf` or with
  `ALTER SYSTEM`). Setting it only for a single session
  with `SET` would be undone by that session's `DISCARD
  ALL` or `RESET ALL`.
- SafeSession and Spock both install executor and utility
  hooks. They chain correctly, but if both are deployed the
  interaction has not been exhaustively tested.

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
