-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Membership tests for pgEdge SafeSession
-- Role membership inheritance and superuser exemption

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_membership;
DROP ROLE IF EXISTS safesession_member;
DROP ROLE IF EXISTS safesession_supertest;
DROP ROLE IF EXISTS safesession_readonly;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_readonly;
CREATE ROLE safesession_member LOGIN;
CREATE ROLE safesession_supertest SUPERUSER LOGIN;

-- Make safesession_member a member of safesession_readonly
GRANT safesession_readonly TO safesession_member;

-- Also make superuser a member for testing exemption
GRANT safesession_readonly TO safesession_supertest;

CREATE TABLE test_membership (id int, val text);
INSERT INTO test_membership VALUES (1, 'original');
GRANT ALL ON test_membership TO safesession_member;
GRANT ALL ON test_membership TO safesession_supertest;

-- Configure restriction on the parent role
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_readonly';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Test: member role should be restricted
SET SESSION AUTHORIZATION safesession_member;

-- SELECT should work
SELECT * FROM test_membership ORDER BY id;

-- INSERT should be blocked (member of restricted role)
INSERT INTO test_membership VALUES (2, 'blocked');

-- Switch back
RESET SESSION AUTHORIZATION;

-- Test: superuser member should NOT be restricted
SET SESSION AUTHORIZATION safesession_supertest;

-- INSERT should work (superuser exemption)
INSERT INTO test_membership VALUES (2, 'superuser_allowed');
SELECT * FROM test_membership ORDER BY id;

-- Switch back
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP TABLE test_membership;
REVOKE safesession_readonly FROM safesession_member;
REVOKE safesession_readonly FROM safesession_supertest;
DROP ROLE safesession_member;
DROP ROLE safesession_supertest;
DROP ROLE safesession_readonly;
DROP EXTENSION pgedge_safesession;
