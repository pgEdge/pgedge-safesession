# pgEdge SafeSession

pgEdge SafeSession is a PostgreSQL extension that enforces
read-only sessions for specified database roles. It provides
defense-in-depth protection using executor and utility hooks
to block all write operations, DDL, and other potentially
dangerous commands.

## Features

- Block DML (INSERT, UPDATE, DELETE) for restricted roles
- Block DDL (CREATE, ALTER, DROP, TRUNCATE, etc.)
- Block COPY FROM, GRANT/REVOKE, VACUUM/ANALYZE
- Block C-language function execution (which can bypass the
  executor)
- Prevent tampering with read-only GUC settings
- Role membership inheritance: members of restricted roles
  are also restricted
- Superuser exemption: superusers are never restricted, even
  if they are members of restricted roles
- Session-user anchored: SET ROLE cannot escape restrictions

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

### GUC: `pgedge_safesession.roles`

A comma-separated list of PostgreSQL role names whose sessions
will be restricted to read-only operations. This is a SUSET
parameter, meaning only superusers can modify it.

```sql
ALTER SYSTEM SET pgedge_safesession.roles =
    'readonly_user, reporting_role';
SELECT pg_reload_conf();
```

Any session authenticated as one of these roles, or as a role
that is a member of one of these roles, will be restricted to
read-only operations.

## What is Blocked

For restricted sessions, the following operations are blocked:

- **DML**: INSERT, UPDATE, DELETE
- **DDL**: CREATE, ALTER, DROP, TRUNCATE, and all other schema
  modification commands
- **COPY FROM**: data import (COPY TO is allowed)
- **CREATE TABLE AS / SELECT INTO**: table creation from
  queries
- **GRANT / REVOKE**: privilege modifications
- **VACUUM / ANALYZE**: maintenance commands
- **C-language functions**: functions implemented in C can
  bypass the executor, so they are blocked entirely
- **Exclusive locks**: LOCK TABLE with modes above
  ROW SHARE
- **GUC tampering**: SET/RESET of
  `default_transaction_read_only`, `transaction_read_only`,
  and RESET ALL

## What is Allowed

- **SELECT**: all read queries
- **EXPLAIN**: query plans (does not execute)
- **Transaction control**: BEGIN, COMMIT, ROLLBACK, SAVEPOINT
- **SET / RESET**: non-protected GUC changes (e.g., work_mem)
- **SHOW**: display settings
- **LISTEN / NOTIFY**: notification channels
- **Cursors**: DECLARE, FETCH, CLOSE
- **DO blocks**: anonymous code blocks (inner writes are
  caught by the executor hook)
- **PL/pgSQL and SQL functions**: read-only functions execute
  normally; any write attempt inside a function is caught by
  the executor hook

## Security Model

### Session User is the Anchor

The session user identity (set at connection time) is the
primary check. Even if a restricted user executes
`SET ROLE` to assume another role, the session user remains
restricted. This prevents bypass via role switching.

### Superuser Exemption

Superusers are never restricted, even if they are members of
a restricted role. The superuser check is based on the session
user, so SECURITY DEFINER functions owned by superusers cannot
bypass restrictions when called from a restricted session.

### SECURITY DEFINER Functions

A SECURITY DEFINER function temporarily changes the effective
user to the function owner. However, SafeSession checks the
session user, not the effective user. This means a restricted
session cannot use a SECURITY DEFINER function owned by a
privileged user to perform writes.

### Role Membership Inheritance

If role `app_reader` is listed in
`pgedge_safesession.roles`, then any role that is a member of
`app_reader` is also restricted. This uses PostgreSQL's
`is_member_of_role()` function for membership checking.

### Belt-and-Suspenders

SafeSession also sets `default_transaction_read_only = on` for
restricted sessions. This provides an additional layer of
protection: even if a C function somehow bypasses the hooks
and attempts direct heap writes, PostgreSQL's own internal
read-only checks will catch it.

## Example

```sql
-- As superuser: configure restrictions
ALTER SYSTEM SET pgedge_safesession.roles =
    'reporting_user';
SELECT pg_reload_conf();

-- Connect as reporting_user
-- Reads work normally:
SELECT * FROM sales;          -- OK
EXPLAIN SELECT * FROM sales;  -- OK
COPY sales TO '/tmp/out.csv'; -- OK

-- Writes are blocked:
INSERT INTO sales VALUES (1); -- ERROR
CREATE TABLE tmp (id int);    -- ERROR
COPY sales FROM '/tmp/in.csv'; -- ERROR
```

## Licence

See the [Licence](LICENCE.md) page for details.
