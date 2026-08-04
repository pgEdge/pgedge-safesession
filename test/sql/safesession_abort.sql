-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Abort-path tests for pgEdge SafeSession
-- A restricted role must be able to ROLLBACK or COMMIT after an error
-- inside an explicit transaction. The utility hook runs for those
-- commands when the transaction has already aborted and no valid
-- transaction state remains; it must not read the catalog there, or it
-- crashes the backend.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_abort;
DROP ROLE IF EXISTS safesession_abort;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_abort LOGIN;
CREATE TABLE test_abort (id int);
INSERT INTO test_abort VALUES (1);
GRANT SELECT, INSERT ON test_abort TO safesession_abort;

-- Configure the restricted role
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_abort';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to the restricted role (changes the session user)
SET SESSION AUTHORIZATION safesession_abort;

-- Enforcement is active for this role
INSERT INTO test_abort VALUES (2);

-- ROLLBACK after an error must succeed without crashing the backend
BEGIN;
SELECT 1/0;
ROLLBACK;

-- COMMIT after an error must also succeed (it rolls back)
BEGIN;
SELECT 1/0;
COMMIT;

-- The session survives, remains usable, and is still restricted
SELECT count(*) FROM test_abort;
INSERT INTO test_abort VALUES (3);

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP TABLE test_abort;
DROP ROLE safesession_abort;
DROP EXTENSION pgedge_safesession;
