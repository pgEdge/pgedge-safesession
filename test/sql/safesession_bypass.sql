-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Bypass tests for pgEdge SafeSession
-- Verify SET ROLE cannot escape restrictions

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_bypass;
DROP ROLE IF EXISTS safesession_unrestricted;
DROP ROLE IF EXISTS safesession_readonly;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_readonly LOGIN;
CREATE ROLE safesession_unrestricted LOGIN;
CREATE TABLE test_bypass (id int, val text);
INSERT INTO test_bypass VALUES (1, 'original');

GRANT ALL ON test_bypass TO safesession_readonly;
GRANT ALL ON test_bypass TO safesession_unrestricted;

-- Allow restricted role to SET ROLE to unrestricted
GRANT safesession_unrestricted TO safesession_readonly;

-- Configure restriction
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_readonly';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Connect as restricted role
SET SESSION AUTHORIZATION safesession_readonly;

-- SELECT should work
SELECT * FROM test_bypass ORDER BY id;

-- INSERT should be blocked
INSERT INTO test_bypass VALUES (2, 'blocked');

-- Try SET ROLE to unrestricted role (should still be blocked
-- because session user is restricted)
SET ROLE safesession_unrestricted;
INSERT INTO test_bypass VALUES (2, 'still_blocked');

-- Reset role back
RESET ROLE;

-- INSERT still blocked
INSERT INTO test_bypass VALUES (2, 'still_blocked');

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP TABLE test_bypass;
REVOKE safesession_unrestricted FROM safesession_readonly;
DROP ROLE safesession_unrestricted;
DROP ROLE safesession_readonly;
DROP EXTENSION pgedge_safesession;
