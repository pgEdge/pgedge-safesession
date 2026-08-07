-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Data-modifying CTE tests for pgEdge SafeSession
-- WITH ... (INSERT|UPDATE|DELETE) ... RETURNING writes even though the
-- top-level command is a SELECT, so the ModifyTable node is buried in the
-- plan tree. block_dml must catch it on its own; its check runs in
-- ExecutorStart ahead of core's read-only transaction check, so the error
-- comes from SafeSession ("... in a read-only session").

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_cte;
DROP ROLE IF EXISTS safesession_cte;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_cte LOGIN;
CREATE TABLE test_cte (id int, val text);
INSERT INTO test_cte VALUES (1, 'seed');
GRANT SELECT, INSERT, UPDATE, DELETE ON test_cte TO safesession_cte;

-- Restrict the role (block_dml is on by default).
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_cte';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to the restricted role (changes the session user)
SET SESSION AUTHORIZATION safesession_cte;

-- A read-only WITH is allowed
WITH c AS (SELECT * FROM test_cte) SELECT count(*) FROM c;

-- Data-modifying CTEs must all be blocked
WITH c AS (INSERT INTO test_cte VALUES (2, 'cte') RETURNING *)
    SELECT * FROM c;
WITH c AS (UPDATE test_cte SET val = 'changed' RETURNING *)
    SELECT count(*) FROM c;
WITH c AS (DELETE FROM test_cte RETURNING *)
    SELECT count(*) FROM c;

-- EXPLAIN ANALYZE of a data-modifying CTE executes it too, so it is blocked
EXPLAIN (ANALYZE) WITH c AS (INSERT INTO test_cte VALUES (3, 'ea') RETURNING *)
    SELECT * FROM c;

-- Switch back to superuser to check the outcome
RESET SESSION AUTHORIZATION;

-- Nothing should have changed: still just the seed row
SET default_transaction_read_only = off;
SELECT * FROM test_cte ORDER BY id;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP TABLE test_cte;
DROP ROLE safesession_cte;
DROP EXTENSION pgedge_safesession;
