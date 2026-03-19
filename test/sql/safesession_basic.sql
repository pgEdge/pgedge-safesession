-- Basic tests for pgEdge SafeSession
-- Test that SELECT is allowed and DML is blocked for restricted roles

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_basic;
DROP ROLE IF EXISTS safesession_readonly;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_readonly LOGIN;
CREATE TABLE test_basic (id int, val text);
INSERT INTO test_basic VALUES (1, 'hello'), (2, 'world');

-- Grant access
GRANT SELECT, INSERT, UPDATE, DELETE ON test_basic
    TO safesession_readonly;

-- Configure the restricted role
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_readonly';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to restricted role (changes session user)
SET SESSION AUTHORIZATION safesession_readonly;

-- SELECT should work
SELECT * FROM test_basic ORDER BY id;

-- INSERT should be blocked
INSERT INTO test_basic VALUES (3, 'blocked');

-- UPDATE should be blocked
UPDATE test_basic SET val = 'blocked' WHERE id = 1;

-- DELETE should be blocked
DELETE FROM test_basic WHERE id = 1;

-- SHOW should work
SHOW pgedge_safesession.roles;

-- EXPLAIN should work (does not execute)
EXPLAIN SELECT * FROM test_basic;

-- Transaction control should work
BEGIN;
SELECT * FROM test_basic ORDER BY id;
COMMIT;

-- SET (non-protected) should work
SET work_mem = '64MB';
SHOW work_mem;
RESET work_mem;

-- Protected GUC SET should be blocked
SET default_transaction_read_only = off;

-- RESET ALL should be blocked
RESET ALL;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP TABLE test_basic;
DROP ROLE safesession_readonly;
DROP EXTENSION pgedge_safesession;
