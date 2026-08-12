-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Function-detection tests for pgEdge SafeSession
-- Blocked functions must be detected wherever they appear in a
-- statement, not just in the top-level target list or WHERE clause. A
-- denylisted built-in (nextval) is placed in a range of plan positions;
-- each must be rejected. Harmless functions, and volatile functions in
-- trusted languages, must still be allowed.
--
-- Function detection runs in the post_parse_analyze hook, before the
-- statement executes, so the error comes from SafeSession's own check
-- ("... in a read-only session") rather than from core's execution-time
-- read-only transaction check.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_walk, test_walk2;
DROP SEQUENCE IF EXISTS walk_seq;
DROP FUNCTION IF EXISTS walk_vol(int);
DROP FUNCTION IF EXISTS walk_imm(int);
DROP ROLE IF EXISTS safesession_walk;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_walk LOGIN;
CREATE TABLE test_walk (id int);
INSERT INTO test_walk VALUES (1), (2), (3);
CREATE TABLE test_walk2 (id int);
INSERT INTO test_walk2 VALUES (1), (2);
CREATE SEQUENCE walk_seq;

-- A VOLATILE function in a trusted language (SQL): allowed, because any
-- write it performs is caught downstream by the executor hook.
CREATE FUNCTION walk_vol(int) RETURNS int LANGUAGE sql VOLATILE
    AS 'SELECT $1';
-- An IMMUTABLE function: allowed.
CREATE FUNCTION walk_imm(int) RETURNS int LANGUAGE sql IMMUTABLE
    AS 'SELECT $1';

GRANT SELECT ON test_walk, test_walk2 TO safesession_walk;
GRANT USAGE ON SEQUENCE walk_seq TO safesession_walk;
GRANT EXECUTE ON FUNCTION walk_vol(int), walk_imm(int) TO safesession_walk;

SET pgedge_safesession.roles = 'safesession_walk';

-- Switch to the restricted role (changes the session user)
SET SESSION AUTHORIZATION safesession_walk;

-- A denylisted built-in must be blocked wherever it appears:

-- target list
SELECT nextval('walk_seq');
-- WHERE qual
SELECT id FROM test_walk WHERE id = nextval('walk_seq')::int;
-- ORDER BY
SELECT id FROM test_walk ORDER BY nextval('walk_seq');
-- HAVING
SELECT count(*) FROM test_walk HAVING count(*) > nextval('walk_seq');
-- ScalarArrayOpExpr (= ANY)
SELECT id FROM test_walk WHERE id = ANY (ARRAY[nextval('walk_seq')::int]);
-- join qualification
SELECT a.id FROM test_walk a JOIN test_walk2 b
    ON a.id = b.id + nextval('walk_seq')::int;
-- correlated sub-select
SELECT (SELECT nextval('walk_seq')) FROM test_walk;
-- common table expression
WITH c AS (SELECT nextval('walk_seq') AS n) SELECT n FROM c;

-- Other denylisted built-ins
SELECT pg_advisory_lock(42);
SELECT set_config('work_mem', '5MB', false);

-- These must all be allowed:
SELECT walk_vol(1);                 -- volatile, trusted language
SELECT walk_imm(1);                 -- immutable
SELECT random() < 2 AS ok;          -- volatile built-in, not denylisted
SELECT count(*) FROM test_walk;     -- built-in aggregate
SELECT id FROM test_walk WHERE id = 2 ORDER BY id;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- The blocked statements must not have advanced the sequence
SET default_transaction_read_only = off;
SELECT last_value, is_called FROM walk_seq;

-- Cleanup
RESET pgedge_safesession.roles;
DROP FUNCTION walk_vol(int);
DROP FUNCTION walk_imm(int);
DROP SEQUENCE walk_seq;
DROP TABLE test_walk;
DROP TABLE test_walk2;
DROP ROLE safesession_walk;
DROP EXTENSION pgedge_safesession;
