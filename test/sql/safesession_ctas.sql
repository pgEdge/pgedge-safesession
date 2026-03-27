-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- CTAS tests for pgEdge SafeSession
-- CREATE TABLE AS and SELECT INTO should be blocked

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_ctas_src;
DROP TABLE IF EXISTS test_ctas_dest;
DROP TABLE IF EXISTS test_ctas_dest2;
DROP ROLE IF EXISTS safesession_readonly;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_readonly LOGIN;
CREATE TABLE test_ctas_src (id int, val text);
INSERT INTO test_ctas_src VALUES (1, 'hello');
GRANT SELECT ON test_ctas_src TO safesession_readonly;
GRANT CREATE ON SCHEMA public TO safesession_readonly;

-- Configure restriction
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_readonly';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to restricted role
SET SESSION AUTHORIZATION safesession_readonly;

-- CREATE TABLE AS should be blocked
CREATE TABLE test_ctas_dest AS SELECT * FROM test_ctas_src;

-- SELECT INTO should be blocked
SELECT * INTO test_ctas_dest2 FROM test_ctas_src;

-- Regular SELECT should work
SELECT * FROM test_ctas_src ORDER BY id;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
REVOKE CREATE ON SCHEMA public FROM safesession_readonly;
DROP TABLE test_ctas_src;
DROP ROLE safesession_readonly;
DROP EXTENSION pgedge_safesession;
