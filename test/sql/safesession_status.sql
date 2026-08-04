-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Introspection tests for pgEdge SafeSession
-- pgedge_safesession_is_restricted() reports whether the current session
-- is restricted to read-only access.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP ROLE IF EXISTS safesession_status;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_status LOGIN;

ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_status';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- A superuser session is never restricted
SELECT pgedge_safesession_is_restricted();

-- The restricted role reports as restricted
SET SESSION AUTHORIZATION safesession_status;
SELECT pgedge_safesession_is_restricted();
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP ROLE safesession_status;
DROP EXTENSION pgedge_safesession;
