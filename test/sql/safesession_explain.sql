-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- EXPLAIN tests for pgEdge SafeSession
-- Plain EXPLAIN only plans and must be allowed, but EXPLAIN ANALYZE
-- executes the statement. Writes carried as an intoClause (CREATE TABLE
-- AS, CREATE MATERIALIZED VIEW AS, SELECT INTO) must be blocked, because
-- they never reach the DML check in the executor hook as a top-level
-- INSERT/UPDATE/DELETE.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_explain;
DROP ROLE IF EXISTS safesession_explain;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_explain LOGIN;
CREATE TABLE test_explain (id int);
INSERT INTO test_explain VALUES (1), (2);
GRANT SELECT ON test_explain TO safesession_explain;
-- Grant CREATE so the write is what fails, not a schema permission check
-- (public loses its default CREATE grant on PostgreSQL 15+).
GRANT CREATE ON SCHEMA public TO safesession_explain;

-- Configure the restricted role
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_explain';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to the restricted role (changes the session user)
SET SESSION AUTHORIZATION safesession_explain;

-- Plain EXPLAIN only plans; allowed (COSTS OFF for deterministic output)
EXPLAIN (COSTS OFF) SELECT * FROM test_explain;

-- EXPLAIN of a writing statement without ANALYZE only plans; allowed
EXPLAIN (COSTS OFF) CREATE TABLE should_not_exist AS SELECT * FROM test_explain;
EXPLAIN (ANALYZE false, COSTS OFF) SELECT * INTO should_not_exist2 FROM test_explain;

-- EXPLAIN ANALYZE of a write must be blocked, in every spelling
EXPLAIN (ANALYZE) CREATE TABLE ctas_blocked AS SELECT * FROM test_explain;
EXPLAIN ANALYZE CREATE TABLE ctas_blocked AS SELECT * FROM test_explain;
EXPLAIN (ANALYZE) SELECT * INTO into_blocked FROM test_explain;
EXPLAIN (ANALYZE) CREATE MATERIALIZED VIEW mv_blocked AS SELECT * FROM test_explain;

-- Switch back to superuser to check the outcome
RESET SESSION AUTHORIZATION;

-- None of the tables or the materialized view should have been created
SET default_transaction_read_only = off;
SELECT count(*) AS leaked_objects
    FROM pg_class
    WHERE relname IN ('ctas_blocked', 'into_blocked', 'mv_blocked',
                      'should_not_exist', 'should_not_exist2');

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
REVOKE ALL ON SCHEMA public FROM safesession_explain;
DROP TABLE test_explain;
DROP ROLE safesession_explain;
DROP EXTENSION pgedge_safesession;
