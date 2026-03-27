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
    - `force_read_only`: toggle belt-and-suspenders
      XactReadOnly enforcement (default: off)

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
