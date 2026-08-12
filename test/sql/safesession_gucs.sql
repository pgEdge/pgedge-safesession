-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- GUC toggle tests for pgEdge SafeSession
--
-- A restricted transaction is now forced read-only unconditionally, so
-- disabling a block_* protection removes only SafeSession's own, more
-- specific check; ordinary writes are still rejected by PostgreSQL's own
-- read-only transaction checks. The wording of the error shows which
-- layer caught the statement: "... in a read-only session" is
-- SafeSession's own check, "... in a read-only transaction" is core's.

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
SET pgedge_safesession.roles = 'safesession_guc_test';

-- ============================================================
-- All protections on: SafeSession's own checks fire
-- ============================================================
SET SESSION AUTHORIZATION safesession_guc_test;
INSERT INTO test_gucs VALUES (3, 'blocked');
CREATE TABLE test_gucs_temp (id int);
RESET SESSION AUTHORIZATION;

-- ============================================================
-- Test 1: block_dml = off
-- SafeSession's DML check is skipped, but the write is still
-- rejected by the read-only transaction floor.
-- ============================================================
SET pgedge_safesession.block_dml = off;

SET SESSION AUTHORIZATION safesession_guc_test;
INSERT INTO test_gucs VALUES (4, 'still_blocked');
RESET SESSION AUTHORIZATION;

SET pgedge_safesession.block_dml = on;

-- ============================================================
-- Test 2: block_ddl = off
-- SafeSession's utility check is skipped, but ordinary DDL is
-- still rejected by the read-only transaction floor.
-- ============================================================
SET pgedge_safesession.block_ddl = off;

SET SESSION AUTHORIZATION safesession_guc_test;
CREATE TABLE test_gucs_temp (id int);
RESET SESSION AUTHORIZATION;

SET pgedge_safesession.block_ddl = on;

-- Nothing above should have modified the table
SET default_transaction_read_only = off;
SELECT * FROM test_gucs ORDER BY id;

-- ============================================================
-- Cleanup
-- ============================================================
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.roles;
RESET pgedge_safesession.block_dml;
RESET pgedge_safesession.block_ddl;
RESET pgedge_safesession.block_c_functions;
RESET pgedge_safesession.block_all_c_functions;
REVOKE CREATE ON SCHEMA public FROM safesession_guc_test;
DROP TABLE test_gucs;
DROP ROLE safesession_guc_test;
DROP EXTENSION pgedge_safesession;
