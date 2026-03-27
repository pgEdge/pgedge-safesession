-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- GUC toggle tests for pgEdge SafeSession
-- Verify each protection can be independently disabled

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_gucs;
DROP ROLE IF EXISTS safesession_guc_test;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_guc_test LOGIN;
CREATE TABLE test_gucs (id int, val text);
INSERT INTO test_gucs VALUES (1, 'hello'), (2, 'world');

GRANT SELECT, INSERT, UPDATE, DELETE ON test_gucs
    TO safesession_guc_test;
GRANT CREATE ON SCHEMA public TO safesession_guc_test;

-- Configure the restricted role
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_guc_test';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- ============================================================
-- Test 1: block_dml = off (with force_read_only = off)
-- allows DML
-- ============================================================
ALTER SYSTEM SET pgedge_safesession.block_dml = off;
ALTER SYSTEM SET pgedge_safesession.force_read_only = off;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

SET SESSION AUTHORIZATION safesession_guc_test;
INSERT INTO test_gucs VALUES (3, 'dml_allowed');
SELECT * FROM test_gucs ORDER BY id;
RESET SESSION AUTHORIZATION;

-- Re-enable and clean up
ALTER SYSTEM SET pgedge_safesession.block_dml = on;
ALTER SYSTEM SET pgedge_safesession.force_read_only = on;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);
DELETE FROM test_gucs WHERE id = 3;

-- Verify DML is blocked again
SET SESSION AUTHORIZATION safesession_guc_test;
INSERT INTO test_gucs VALUES (4, 'should_fail');
RESET SESSION AUTHORIZATION;

-- ============================================================
-- Test 2: block_ddl = off (with force_read_only = off)
-- allows DDL
-- ============================================================
ALTER SYSTEM SET pgedge_safesession.block_ddl = off;
ALTER SYSTEM SET pgedge_safesession.force_read_only = off;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

SET SESSION AUTHORIZATION safesession_guc_test;
CREATE TABLE test_gucs_temp (id int);
DROP TABLE test_gucs_temp;
RESET SESSION AUTHORIZATION;

-- Re-enable
ALTER SYSTEM SET pgedge_safesession.block_ddl = on;
ALTER SYSTEM SET pgedge_safesession.force_read_only = on;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Verify DDL is blocked again
SET SESSION AUTHORIZATION safesession_guc_test;
CREATE TABLE test_gucs_temp2 (id int);
RESET SESSION AUTHORIZATION;

-- ============================================================
-- Test 3: force_read_only = off with block_dml = on
-- DML blocked by hook, not by XactReadOnly
-- ============================================================

-- Show default state (should be on)
SHOW pgedge_safesession.force_read_only;

ALTER SYSTEM SET pgedge_safesession.force_read_only = off;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- DML should still be blocked by block_dml
SET SESSION AUTHORIZATION safesession_guc_test;
INSERT INTO test_gucs VALUES (5, 'still_blocked');
RESET SESSION AUTHORIZATION;

-- Re-enable
ALTER SYSTEM SET pgedge_safesession.force_read_only = on;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- ============================================================
-- Cleanup
-- ============================================================
RESET SESSION AUTHORIZATION;
ALTER SYSTEM RESET pgedge_safesession.roles;
ALTER SYSTEM RESET pgedge_safesession.block_dml;
ALTER SYSTEM RESET pgedge_safesession.block_ddl;
ALTER SYSTEM RESET pgedge_safesession.block_c_functions;
ALTER SYSTEM RESET pgedge_safesession.block_all_c_functions;
ALTER SYSTEM RESET pgedge_safesession.force_read_only;
SELECT pg_reload_conf();
REVOKE CREATE ON SCHEMA public FROM safesession_guc_test;
DROP TABLE test_gucs;
DROP ROLE safesession_guc_test;
DROP EXTENSION pgedge_safesession;
