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
-- session or transaction *more* restrictive, must still be allowed,
-- through the plain GUCs as well as through SET TRANSACTION.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP ROLE IF EXISTS safesession_guctamper;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_guctamper LOGIN;

SET pgedge_safesession.roles = 'safesession_guctamper';

SET SESSION AUTHORIZATION safesession_guctamper;

-- Attempts to relax read-only must all be blocked
SET transaction_read_only = off;
SET default_transaction_read_only = off;
RESET transaction_read_only;
RESET default_transaction_read_only;
SET default_transaction_read_only TO DEFAULT;
SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE;
BEGIN;
SET TRANSACTION READ WRITE;
ROLLBACK;

-- Anything that does not resolve to a plain "true" is treated as an
-- attempt to relax the setting
SET default_transaction_read_only = 'not a boolean';

-- Asking for the read-only state we already enforce is allowed: it agrees
-- with the restriction, and clients that assert read-only on every
-- connection they open must not be locked out
SET default_transaction_read_only = on;
SET default_transaction_read_only = 'on';
SET default_transaction_read_only TO true;
SET default_transaction_read_only = 1;
SET transaction_read_only = on;
SHOW default_transaction_read_only;

-- FROM CURRENT resolves to the live value, so it is a no-op and allowed
-- while the setting is on
SET default_transaction_read_only FROM CURRENT;

-- Unrelated GUCs and more-restrictive settings are allowed
SET work_mem = '4MB';
RESET work_mem;
BEGIN;
SET TRANSACTION READ ONLY;
COMMIT;
SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;
SHOW transaction_read_only;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;

-- Cleanup
RESET pgedge_safesession.roles;
DROP ROLE safesession_guctamper;
DROP EXTENSION pgedge_safesession;
