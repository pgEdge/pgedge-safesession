# Changelog

All notable changes to the pgEdge SafeSession will be
documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0-alpha1] - Unreleased

### Added

- Initial release of pgEdge SafeSession
- GUC `pgedge_safesession.roles` (SUSET) to specify
  restricted roles
- ExecutorStart hook to block DML (INSERT, UPDATE, DELETE)
  and C-language function execution
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
