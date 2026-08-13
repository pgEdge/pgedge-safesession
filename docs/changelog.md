# Changelog

All notable changes to the pgEdge SafeSession will be
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0-alpha2] - Unreleased

### Added

- Configurable protection layers via new SUSET GUCs:

    - `block_dml`: toggle DML blocking (default: on)
    - `block_ddl`: toggle DDL blocking (default: on)
    - `block_c_functions`: toggle C-language function
      blocking (default: on)
    - `block_all_c_functions`: block all C functions
      regardless of volatility (default: off)

- COPY TO PROGRAM blocking for restricted sessions
- SET TRANSACTION READ WRITE blocking for restricted
  sessions
- New regression tests for advanced attack vectors
  (PREPARE/EXECUTE, DO blocks, aggregates, WHERE clauses,
  SET TRANSACTION)
- New regression tests for GUC toggle behavior

### Changed

- C-language function blocking now only blocks VOLATILE
  C functions by default. IMMUTABLE and STABLE C functions
  (e.g., PostGIS geometry operations, pgvector distance
  operators) are allowed. Use `block_all_c_functions = on`
  to restore the previous behavior of blocking all
  C functions.

### Fixed

- SET TRANSACTION READ WRITE was silently accepted by
  restricted sessions (policy gap, not exploitable due to
  belt-and-suspenders protection)
- COPY TO PROGRAM was not explicitly blocked (mitigated by
  PostgreSQL privilege requirements, but added for
  defense-in-depth)
- Restricted sessions rejected SET of `transaction_read_only`
  or `default_transaction_read_only` to on, which asks for
  the state SafeSession already enforces. A client that
  asserts read-only on each connection it opens, such as a
  connection pool running with writes disabled, was locked
  out entirely. Only relaxing either setting is blocked now.
- A restricted session could run any blocked function by
  passing it as a parameter to `EXECUTE`, because the
  parameters of a prepared statement are neither part of the
  prepared query nor evaluated through the executor, so
  neither of the checks that would catch them ever saw them.
  The same evaluation happens for `EXPLAIN EXECUTE`, with or
  without `ANALYZE`, and for `CREATE TABLE AS ... EXECUTE`,
  and all three are now checked.
- Role membership was tested with `is_member_of_role()`,
  which reports a superuser as a member of every role in the
  database with no grant behind it. Any role that briefly
  acts as a superuser whilst its session user does not, such
  as one inside a SECURITY DEFINER function owned by a
  superuser or one elevated for a single command by an
  extension like supautils, was therefore treated as a
  member of every restricted role and blocked, even when it
  was listed nowhere and granted nothing. Membership now
  uses `is_member_of_role_nosuper()` and follows actual
  grants only.
- Side-effecting function calls are detected when a statement
  is parsed, so a plan cached before a session became
  restricted was replayed without the check running again. A
  session that became restricted part-way through its life,
  because the roles list was reloaded or because a role was
  granted membership of a listed role, could therefore go on
  calling blocked functions through any prepared statement or
  PL/pgSQL expression it had already executed. Becoming
  restricted now discards the session's cached plans, so they
  are re-analysed under the new state.
- PostgreSQL 19 no longer compiled, because it reaches
  `GETSTRUCT` through a different header than earlier releases
  and it made the `jstate` argument of
  `post_parse_analyze_hook_type` const. Builds on
  PostgreSQL 14 to 18 are unchanged.

## [1.0-alpha1] - Unreleased

### Added

- Initial release of pgEdge SafeSession
- GUC `pgedge_safesession.roles` (SUSET) to specify
  restricted roles
- ExecutorStart hook to block DML (INSERT, UPDATE, DELETE,
  MERGE) and C-language function execution
- ProcessUtility hook to block DDL, COPY FROM, GRANT/REVOKE,
  VACUUM/ANALYZE, exclusive locks, and GUC tampering
- Session-user anchored role checking: SET ROLE cannot escape
  restrictions
- Superuser exemption: superusers are never restricted
- Role membership inheritance via `is_member_of_role()`
- Belt-and-suspenders: automatic
  `default_transaction_read_only = on` for restricted sessions
- SECURITY DEFINER bypass prevention: session user is always
  checked regardless of effective user
- Comprehensive regression test suite covering:

    - Basic DML blocking
    - SET ROLE bypass prevention
    - PL/pgSQL and SQL function enforcement
    - DDL blocking
    - COPY FROM/TO handling
    - CREATE TABLE AS / SELECT INTO blocking
    - SECURITY DEFINER function enforcement
    - Role membership inheritance and superuser exemption
