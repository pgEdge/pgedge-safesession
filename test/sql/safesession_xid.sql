-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Transaction ID assignment tests for pgEdge SafeSession
--
-- pg_current_xact_id() and its older spelling txid_current() force the
-- current transaction to take a real transaction ID. A read-only
-- transaction does not forbid that, so nothing else stops it, and a
-- restricted session looping over it consumes transaction IDs and adds
-- wraparound pressure. The _if_assigned() variants only report an ID that
-- has already been handed out, so they stay allowed.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP ROLE IF EXISTS safesession_xid;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_xid LOGIN;

SET pgedge_safesession.roles = 'safesession_xid';

SET SESSION AUTHORIZATION safesession_xid;

-- Both spellings must be rejected
SELECT pg_current_xact_id();
SELECT txid_current();

-- Reporting an ID that was already assigned is harmless, so it is allowed
-- and returns NULL, no transaction ID having been assigned here
SELECT pg_current_xact_id_if_assigned() IS NULL AS no_xid_assigned;
SELECT txid_current_if_assigned() IS NULL AS no_xid_assigned;

RESET SESSION AUTHORIZATION;

-- Cleanup
SET default_transaction_read_only = off;
RESET pgedge_safesession.roles;
DROP ROLE safesession_xid;
DROP EXTENSION pgedge_safesession;
