-- COPY tests for pgEdge SafeSession
-- COPY FROM blocked, COPY TO allowed

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_copy;
DROP ROLE IF EXISTS safesession_readonly;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_readonly LOGIN;
CREATE TABLE test_copy (id int, val text);
INSERT INTO test_copy VALUES (1, 'hello'), (2, 'world');
GRANT ALL ON test_copy TO safesession_readonly;

-- Configure restriction
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_readonly';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to restricted role
SET SESSION AUTHORIZATION safesession_readonly;

-- COPY TO (stdout) should be allowed
COPY test_copy TO STDOUT;

-- COPY FROM should be blocked
COPY test_copy FROM STDIN;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP TABLE test_copy;
DROP ROLE safesession_readonly;
DROP EXTENSION pgedge_safesession;
