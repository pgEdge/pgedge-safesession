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
  (a delegating session is judged by the role it acts as)
- Delegating sessions: a pooled login role, such as
  PostgREST's, is judged by the role each request acts as
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

Each list of roles is a comma-separated list of names.
Spaces around a name are ignored, and a name not in double
quotes is read in lower case. A role named `Mixed` must be
written `"Mixed"`; written `Mixed`, it is read as `mixed`
and protects nothing. In SQL, write the whole list as one
string in single quotes, such as
`SET pgedge_safesession.read_only_roles = '"Mixed", other'`.
Written `SET ... = "Mixed"`, the double quotes are taken by
SQL, and the name is read as `mixed`.

A list that does not parse is refused by `SET` and
`ALTER SYSTEM`. In the configuration file, it stops the
server from starting; at a reload, PostgreSQL keeps the
previous value and logs the error. A `pgedge_safesession`
setting name the extension does not know, such as a
misspelled one, also stops the server from starting, and
is refused by `SET`, `ALTER SYSTEM`, `ALTER ROLE` and
`ALTER DATABASE` on every PostgreSQL version. `RESET` and
`SET ... TO DEFAULT` still work, so a saved name can be
removed. A name added to the configuration file and
applied with a reload is not refused: the server keeps
running without it, and its next start fails. The same
check runs in single-user mode and, on PostgreSQL 15 and
later, for `postgres -C` of a computed setting.

Before upgrading from an earlier release, look for such
names; PostgreSQL 14 could save one with `ALTER SYSTEM`:

```sql
SELECT sourcefile, sourceline, name
FROM pg_file_settings
WHERE name ILIKE 'pgedge_safesession.%';
```

Before going back to an earlier release, remove the
settings it does not know. If the server does not start,
start it with `-c shared_preload_libraries=''`, remove the
setting with `ALTER SYSTEM RESET`, and start it again.

A role name that does not exist is accepted, since the
role may be created later. `SET` warns about it, and a
name from the configuration file is reported in the
server log once in each session that looks the names up,
and again after a list changes.

### `pgedge_safesession.read_only_roles`

A comma-separated list of PostgreSQL role names whose
sessions will be restricted to read-only operations.

```sql
ALTER SYSTEM SET pgedge_safesession.read_only_roles =
    'readonly_user, reporting_role';
SELECT pg_reload_conf();
```

Any session authenticated as one of these roles, or as a
role that is a member of one of these roles, will be
restricted to read-only operations. A session of
`delegating_roles` is judged by the role it acts as
instead; see [Delegating Sessions](#delegating-sessions).

### `pgedge_safesession.roles`

The old name of `read_only_roles`, which keeps working. A
role on either list is restricted.

Releases 1.0 and 1.1 know only `roles`. They ignore
`read_only_roles`, `delegating_roles` and
`acting_read_only_roles` with a warning, so after going
back to one of them, roles on `acting_read_only_roles` can
write again. Listing them on `roles` instead makes every
request through the login role fail, because those
releases judge a session by the login role's memberships.
They cannot make only API requests read-only.

### `pgedge_safesession.delegating_roles`

Default: empty

Login roles that switch into another role for each
transaction, such as PostgREST's authenticator. A session
whose login role is one of these roles itself, not a
member of one, is judged by the role it acts as, not by
the login role's own memberships. See
[Delegating Sessions](#delegating-sessions).

Name the exact login role. A member of it, or the same
role after a rename, is an ordinary session, and
`acting_read_only_roles` does not apply to it. A superuser
login role on this list is judged the same way. Do not
give the login role a role at login, such as with
`ALTER ROLE ... SET role`: its sessions then start
switched, and if that role is read-only, every request
fails.

### `pgedge_safesession.acting_read_only_roles`

Default: empty

Roles that are read-only when a delegating session acts as
them, or as a member of one. Only delegated requests are
affected: a person who logs in directly as a member of the
same role can still write. Use `read_only_roles` for a
role that must never write, however it is reached.

It has no effect unless `delegating_roles` is set; the
server log says so.

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
  such as `plpython3u`), plus any volatile built-in
  (`pg_catalog`) function that is not on a small allow-list
  of built-ins confirmed to have no observable side effect
  (`random()`, `clock_timestamp()`, and similar). A volatile
  built-in is blocked by default; only functions verified
  harmless are exempted, so a new PostgreSQL release that
  adds a side-effecting built-in is blocked automatically.
  A `DO` block or `CALL` in an untrusted language is
  blocked for the same reason. Arguments count as part of
  the statement, so a blocked function is rejected whether
  it is called directly, passed as a `CALL` argument, or
  passed as an `EXECUTE` parameter (including through
  `EXPLAIN EXECUTE` and `CREATE TABLE AS ... EXECUTE`). A
  function reached only indirectly, through a view body, a
  row-level security policy's `USING`/`WITH CHECK` qual, or
  a domain `CHECK` constraint, is rejected the same way as a
  direct call. For a domain this holds however the coercion
  that runs the constraint is reached: a cast, a prepared
  statement's declared parameter type, a parameter bound
  over the extended query protocol, a PL/pgSQL variable's
  declared type, or a function's `RETURNS` type.
- **Fast-path function calls**: the protocol behind libpq's
  `PQfn`, which the large-object client API is built on. It
  bypasses the parser and planner entirely, so the same
  function policy is applied to it directly.
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
- **SET CONSTRAINTS**: it only changes when the
  transaction's deferred checks run; PostgREST sends it to
  roll a request back
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
  is caught by the executor hook, and a blocked function
  called from a SQL function body is rejected before the
  call runs
- **IMMUTABLE/STABLE functions**, and harmless volatile
  built-ins such as `random()` and `clock_timestamp()`

## Security Model

### Session User is the Anchor

The session user identity (set at connection time) is the
primary check. Even if a restricted user executes
`SET ROLE` to assume another role, the session user remains
restricted. This prevents bypass via role switching.
A delegating session is the exception; see
[Delegating Sessions](#delegating-sessions).

### Delegating Sessions

A connection pool such as PostgREST logs in as one role
and, for each request, switches into the role the request
acts as with `SET LOCAL ROLE` or `set_config('role', ...,
true)`. The login role is a member of every role a request
can act as, so its memberships say nothing about the
request. When the login role is listed in
`delegating_roles`:

- The pool's own statements, before it switches, are not
  read-only.
- After the switch, the request is judged by the role it
  acts as. A role on `read_only_roles` or
  `acting_read_only_roles`, or a member of one, makes the
  request read-only, and so does the login role itself on
  `read_only_roles`. A request that switches into the login
  role itself is judged the same way, by that role's
  memberships too, so it is read-only if the login role is
  a member of a listed role.
- Inside a SECURITY DEFINER function the request is still
  judged by the role it switched into, so the function's
  owner cannot lift the restriction. A SECURITY DEFINER
  function owned by a role on `read_only_roles`, or a
  member of one, is read-only inside, as in any session.

A read-only delegated request may call `set_config()` on a
`response.*` setting, such as `response.status` or
`response.headers`, when the name is written in the
statement, the third argument is written as `true`, and
the statement is a simple one that reads no table: no
`UNION`, `INTERSECT` or `EXCEPT`, no function or `VALUES`
list of more than one row in `FROM`, no window function
and no `GROUPING SETS`. Examples are
`SELECT set_config(...)`, `PERFORM set_config(...)` in
PL/pgSQL, and a SQL function called the way PostgREST
calls a function. PostgREST reads these settings to set
the HTTP status and headers. To use a value read from a
table, read it into a variable first, then pass the
variable to `PERFORM set_config(...)`.

Any other `set_config()` call is still refused. That
includes one in a PL/pgSQL assignment, `RETURN` or `IF`
(such as `v := set_config(...)`), which PL/pgSQL runs
outside any statement; one in the arguments of `CALL` or
`EXECUTE`; one in a polymorphic SQL function; and one
whose name is cast to a type other than `text`. A function
that sets other settings, such as `app.*` names, with
`set_config()` fails in a read-only request; use
`SET LOCAL` instead, for example
`EXECUTE format('SET LOCAL app.x = %L', v)`.

The pool must switch role before it binds a statement of
the request or opens a cursor for it; PostgREST does. Each
switch into a read-only role discards the connection's
cached plans, so every role's prepared statements and
PL/pgSQL plans are planned again. A pool that switches
with SQL `PREPARE` and `EXECUTE` sent as a simple query
gets an error on each read-only request; switch with the
protocol's prepared statements, `SET LOCAL ROLE`, or an
unprepared `set_config()`.

This release does not stop a request from switching role a
second time in the same transaction, for example with
`SET ROLE`, `RESET ROLE` or `RESET SESSION AUTHORIZATION`.
Turn on `delegating_roles` only with a release that does.

### Superuser Exemption

Superusers are never restricted, even if they are members
of a restricted role. The superuser check is based on the
session user, so SECURITY DEFINER functions owned by
superusers cannot bypass restrictions when called from a
restricted session. A superuser login role on
`delegating_roles` is judged by the role it acts as once
it switches.

### SECURITY DEFINER Functions

A SECURITY DEFINER function temporarily changes the
effective user to the function owner. However, SafeSession
checks the session user, not the effective user. This
means a restricted session cannot use a SECURITY DEFINER
function owned by a privileged user to perform writes. A
delegating session is judged by the role it acts as, which
also stays the same inside such a function; see
[Delegating Sessions](#delegating-sessions).

### Role Membership Inheritance

If role `app_reader` is listed in
`pgedge_safesession.read_only_roles`, then any role that is a member
of `app_reader` is also restricted. Membership is tested
with PostgreSQL's `is_member_of_role_nosuper()`, so it
follows actual grants only.

The distinction matters because PostgreSQL otherwise reports
a superuser as a member of every role in the database, with
no grant behind it, which is the right answer for a
privilege test and the wrong one here. Any mechanism that
briefly makes the current user a superuser whilst the
session user is not, such as a SECURITY DEFINER function
owned by a superuser or an extension like supautils
elevating a privileged role for a single command, would
otherwise appear to be acting as a member of every
restricted role and be blocked. Enforcement still anchors on
the session user (in a delegating session, on the role it
acts as), so such elevation is not a way out of the
restriction either: a restricted session stays restricted
inside a superuser-owned SECURITY DEFINER function.

### Restriction Changes and Cached Plans

Side-effecting function calls are detected when a statement
or expression is parsed, and again when it is planned (to
catch a function reached only through a view body or an RLS
qual, which are substituted during query rewrite, after
parse analysis), rather than when it is executed, so a plan
cached before a session became restricted would otherwise be
replayed without either check running again. That matters
because a session can become restricted part-way through its
life: the roles list can be edited and the configuration
reloaded, or a role can be granted membership of a listed
role, whilst sessions are open.

Becoming restricted is therefore treated as an invalidation
event, and the session's cached plans are discarded exactly
as `DISCARD PLANS` does, so that everything is re-analysed
under the new state. This covers prepared statements and the
plans PL/pgSQL caches for its expressions alike. Plans built
whilst a session was restricted are left alone when the
restriction is lifted, since they have already been checked.
In a delegating session this happens at every request that
acts as a read-only role.

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

- The allow-list of harmless volatile built-in functions is
  deliberately conservative rather than exhaustive: a
  volatile built-in that is actually harmless but missing
  from the list is blocked anyway, which can surface as a
  restricted session being refused a read-only built-in
  call that a future release should add to the list. This
  is a usability trade-off in favour of failing closed: a
  newly added side-effecting built-in is blocked by default
  rather than silently allowed. A volatile function in a
  trusted language is allowed to run, and any write it
  performs is caught at execution instead.
- Enforcement anchors on the session user, except in a
  delegating session, which is judged by the role it acts
  as. A superuser can
  still use `SET SESSION AUTHORIZATION` to become a
  restricted role (that is how the restriction is entered);
  this is by design and is not a bypass.
- The roles list must be set from the server configuration
  (`shared_preload_libraries` is required, and the roles
  are normally set in `postgresql.conf` or with
  `ALTER SYSTEM`). Setting it only for a single session
  with `SET` would be undone by that session's `DISCARD
  ALL` or `RESET ALL`.
- SafeSession and Spock both install executor, utility, and
  planner hooks. They chain correctly, but if both are
  deployed the interaction has not been exhaustively tested.
- A blocked function is caught either when it appears in a
  statement's parse tree or when the executor compiles it as
  part of an expression. A function PostgreSQL calls directly
  through `fmgr`, without compiling an expression around it,
  is seen by neither: a type's own input and output
  functions, and an index access method's support functions,
  are the cases that arise in practice. Reaching one requires
  a type or operator class that somebody else defined, since
  a restricted role cannot create either.

## Example

```sql
-- As superuser: configure restrictions
ALTER SYSTEM SET pgedge_safesession.read_only_roles =
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
