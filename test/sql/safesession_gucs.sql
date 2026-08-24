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
--
-- Every other file that touches a block_* setting turns it off as
-- scaffolding, to isolate some other subject from it. This is the file
-- where the settings themselves are the subject, so each one is toggled
-- here on its own, and then all of them at once, which is the only
-- configuration that isolates the read-only floor.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_gucs;
DROP ROLE IF EXISTS safesession_guc_test;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

-- The settings the extension owns, and their defaults. Asserted before
-- anything is configured, so this is also what documents the default
-- posture: everything blocked except the C-language escalation. A
-- renamed or removed setting, or a changed default, shows up here as one
-- clear failure rather than as puzzling behaviour in another file.
SELECT name, setting FROM pg_settings
    WHERE name LIKE 'pgedge_safesession.%' ORDER BY name;

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
--
-- All four write commands go through the same commandType switch, and a
-- data-modifying CTE through the hasModifyingCTE check beside it, so the
-- floor has to catch each of them and not only the INSERT.
-- ============================================================
SET pgedge_safesession.block_dml = off;

SET SESSION AUTHORIZATION safesession_guc_test;
INSERT INTO test_gucs VALUES (4, 'still_blocked');
UPDATE test_gucs SET val = 'still_blocked' WHERE id = 1;
DELETE FROM test_gucs WHERE id = 1;
WITH c AS (INSERT INTO test_gucs VALUES (4, 'via_cte') RETURNING id)
    SELECT id FROM c;
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

-- ============================================================
-- Test 3: block_c_functions = off
--
-- This is the toggle with the widest reach: it gates the walker, the SQL
-- function body check, the domain constraint check, the EXECUTE
-- parameter check and the object access hook. set_config() is the probe
-- because it is the one blocked thing the read-only floor does not also
-- stop -- it changes a setting rather than writing data -- so turning
-- the check off is directly observable rather than merely untested.
-- ============================================================
SET SESSION AUTHORIZATION safesession_guc_test;
SET work_mem = '4MB';
SELECT set_config('work_mem', '71MB', false);
SHOW work_mem;
RESET SESSION AUTHORIZATION;

SET pgedge_safesession.block_c_functions = off;

SET SESSION AUTHORIZATION safesession_guc_test;
SET work_mem = '4MB';
SELECT set_config('work_mem', '72MB', false) AS took_effect;
SHOW work_mem;
RESET SESSION AUTHORIZATION;

SET pgedge_safesession.block_c_functions = on;

-- ============================================================
-- Test 4: every SafeSession check off at once
--
-- block_all_c_functions is already off by default, so disabling the
-- other three leaves nothing of SafeSession's own checks running. What
-- still fails here is failing because the transaction is read-only and
-- for no other reason, which is the claim the whole design rests on.
--
-- It also shows what that floor does not cover, and therefore why
-- block_c_functions exists as a separate layer rather than as a
-- refinement of the floor: a GUC change is not a write, so nothing
-- stops it once SafeSession stands aside.
-- ============================================================
SET pgedge_safesession.block_dml = off;
SET pgedge_safesession.block_ddl = off;
SET pgedge_safesession.block_c_functions = off;

SET SESSION AUTHORIZATION safesession_guc_test;
SET work_mem = '4MB';

-- Still restricted: the toggles change what is checked, not who is
-- subject to it
SELECT pgedge_safesession_is_restricted() AS still_restricted;

INSERT INTO test_gucs VALUES (5, 'floor');
UPDATE test_gucs SET val = 'floor' WHERE id = 1;
DELETE FROM test_gucs WHERE id = 1;
CREATE TABLE test_gucs_temp (id int);

-- ... but a setting change is not a write, so the floor lets it past
SELECT set_config('work_mem', '73MB', false) AS not_a_write;
SHOW work_mem;

RESET SESSION AUTHORIZATION;

SET pgedge_safesession.block_dml = on;
SET pgedge_safesession.block_ddl = on;
SET pgedge_safesession.block_c_functions = on;

-- ============================================================
-- Test 5: an empty roles list restricts nobody
--
-- With nothing configured the check returns before it looks at the
-- session user or at the cached list of role OIDs, so the role that was
-- restricted throughout everything above is released entirely. This is
-- a different path from a role being dropped out of a list that still
-- has other names in it, which safesession_rolecache covers.
-- ============================================================
SET pgedge_safesession.roles = '';

SET SESSION AUTHORIZATION safesession_guc_test;
SELECT pgedge_safesession_is_restricted() AS restricted_with_empty_list;
INSERT INTO test_gucs VALUES (6, 'unrestricted');
RESET SESSION AUTHORIZATION;

SET pgedge_safesession.roles = 'safesession_guc_test';

-- The only write that got through is the one made while nothing was
-- configured; everything attempted under a restriction was rejected
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
RESET work_mem;
REVOKE CREATE ON SCHEMA public FROM safesession_guc_test;
DROP TABLE test_gucs;
DROP ROLE safesession_guc_test;
DROP EXTENSION pgedge_safesession;
