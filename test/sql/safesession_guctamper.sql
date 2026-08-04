-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- GUC-tampering tests for pgEdge SafeSession
-- A restricted role must not be able to relax the read-only settings,
-- whether through the transaction-scoped transaction_read_only, the
-- session default default_transaction_read_only, SET TRANSACTION READ
-- WRITE or SET SESSION CHARACTERISTICS. Unrelated GUCs, and making the
-- transaction *more* restrictive, must still be allowed.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP ROLE IF EXISTS safesession_guctamper;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_guctamper LOGIN;

ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_guctamper';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

SET SESSION AUTHORIZATION safesession_guctamper;

-- Attempts to relax read-only must all be blocked
SET transaction_read_only = off;
SET default_transaction_read_only = off;
RESET transaction_read_only;
SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE;
BEGIN;
SET TRANSACTION READ WRITE;
ROLLBACK;

-- Setting transaction_read_only = on is also treated as protected, for
-- consistency: the value is not honoured by SafeSession's own enforcement
SET transaction_read_only = on;

-- Unrelated GUCs and more-restrictive settings are allowed
SET work_mem = '4MB';
RESET work_mem;
BEGIN;
SET TRANSACTION READ ONLY;
COMMIT;
SHOW transaction_read_only;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP ROLE safesession_guctamper;
DROP EXTENSION pgedge_safesession;
