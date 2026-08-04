-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Additional coverage for pgEdge SafeSession
-- Exercises cases not covered by the other test files: nested and
-- NOINHERIT role membership, the LOCK TABLE mode boundary, connection
-- pooler resets, NOTIFY, and temporary-table creation.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_cov;
DROP ROLE IF EXISTS safesession_grp;
DROP ROLE IF EXISTS safesession_mid;
DROP ROLE IF EXISTS safesession_leaf;
DROP ROLE IF EXISTS safesession_noinherit;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE TABLE test_cov (id int);
INSERT INTO test_cov VALUES (1);

-- Membership two levels deep: leaf -> mid -> grp
CREATE ROLE safesession_grp;
CREATE ROLE safesession_mid IN ROLE safesession_grp;
CREATE ROLE safesession_leaf LOGIN IN ROLE safesession_mid;
-- A member that does not inherit privileges is still a member. Using the
-- NOINHERIT role attribute (rather than the per-membership WITH INHERIT
-- option, which only exists on PostgreSQL 16+) keeps this portable.
CREATE ROLE safesession_noinherit LOGIN NOINHERIT;
GRANT safesession_grp TO safesession_noinherit;

-- Grant enough that the permitted LOCK modes below succeed on every
-- supported version. Before PostgreSQL 16, LOCK ... IN ROW SHARE MODE
-- required UPDATE/DELETE/TRUNCATE rather than just SELECT; the stronger
-- modes are rejected by SafeSession ahead of the privilege check either
-- way, and any actual write is still blocked.
GRANT SELECT, INSERT, UPDATE, DELETE ON test_cov TO safesession_grp;
GRANT INSERT ON test_cov TO safesession_noinherit;

-- Only the group role is listed
SET pgedge_safesession.roles = 'safesession_grp';

-- A role two levels below the listed group is restricted
SET SESSION AUTHORIZATION safesession_leaf;
INSERT INTO test_cov VALUES (2);
RESET SESSION AUTHORIZATION;

-- A NOINHERIT member is still restricted (membership, not inheritance)
SET SESSION AUTHORIZATION safesession_noinherit;
INSERT INTO test_cov VALUES (3);
RESET SESSION AUTHORIZATION;

-- The rest of the checks run as the nested leaf role
SET SESSION AUTHORIZATION safesession_leaf;

-- LOCK TABLE: modes up to ROW SHARE are permitted, stronger modes are not
BEGIN;
LOCK test_cov IN ACCESS SHARE MODE;
LOCK test_cov IN ROW SHARE MODE;
ROLLBACK;
BEGIN;
LOCK test_cov IN ROW EXCLUSIVE MODE;
ROLLBACK;
BEGIN;
LOCK test_cov IN ACCESS EXCLUSIVE MODE;
ROLLBACK;

-- NOTIFY is allowed; a temporary table is still DDL and is blocked
NOTIFY safesession_channel;
CREATE TEMP TABLE test_cov_tmp (id int);

-- Connection-pooler resets are allowed. These run last because DISCARD
-- ALL / RESET ALL reset session GUCs, which here (where the roles list
-- was set with a session SET) also clears the restriction; in a real
-- deployment the list comes from the configuration file, so a reset
-- restores it rather than clearing it.
DISCARD ALL;
DISCARD PLANS;

-- Switch back to superuser to confirm nothing was written
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
SELECT id FROM test_cov ORDER BY id;

-- Cleanup
RESET pgedge_safesession.roles;
DROP TABLE test_cov;
DROP ROLE safesession_leaf;
DROP ROLE safesession_mid;
DROP ROLE safesession_noinherit;
DROP ROLE safesession_grp;
DROP EXTENSION pgedge_safesession;
