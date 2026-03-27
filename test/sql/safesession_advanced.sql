-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Advanced tests for pgEdge SafeSession
-- Tests additional attack vectors and edge cases

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_advanced;
DROP ROLE IF EXISTS safesession_adv;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_adv LOGIN;
CREATE TABLE test_advanced (id int, val text);
INSERT INTO test_advanced VALUES (1, 'hello'), (2, 'world');

-- Grant access
GRANT SELECT, INSERT, UPDATE, DELETE ON test_advanced
    TO safesession_adv;

-- Configure the restricted role
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_adv';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to restricted role
SET SESSION AUTHORIZATION safesession_adv;

-- SELECT with WHERE clause should work
SELECT * FROM test_advanced WHERE id = 1;

-- SELECT with multiple WHERE conditions should work
SELECT * FROM test_advanced WHERE id > 0 AND val = 'hello';

-- Aggregate functions should work
SELECT count(*) FROM test_advanced;
SELECT sum(id) FROM test_advanced;
SELECT max(id), min(id) FROM test_advanced;

-- PREPARE a write statement (allowed)
PREPARE write_plan AS INSERT INTO test_advanced VALUES (3, 'blocked');

-- EXECUTE it (should be blocked at executor level)
EXECUTE write_plan;

-- Cleanup the prepared statement
DEALLOCATE write_plan;

-- DO block with inner write should be blocked
DO $$ BEGIN INSERT INTO test_advanced VALUES (3, 'blocked'); END; $$;

-- SET TRANSACTION READ WRITE should be blocked
SET TRANSACTION READ WRITE;

-- SET TRANSACTION ISOLATION LEVEL should be allowed
BEGIN;
SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;
SELECT * FROM test_advanced WHERE id = 1;
COMMIT;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP TABLE test_advanced;
DROP ROLE safesession_adv;
DROP EXTENSION pgedge_safesession;
