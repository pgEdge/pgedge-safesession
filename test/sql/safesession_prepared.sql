-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Two-phase commit tests for pgEdge SafeSession
-- The T_TransactionStmt tag covers ordinary transaction control as well
-- as PREPARE TRANSACTION / COMMIT PREPARED / ROLLBACK PREPARED. COMMIT
-- PREPARED commits whatever the prepared transaction wrote, so a
-- restricted session must not be able to drive two-phase commit, while
-- ordinary BEGIN/COMMIT/ROLLBACK/SAVEPOINT and prepared statements
-- (PREPARE ... AS) must still work.
--
-- The block is applied in the utility hook, ahead of core's own checks,
-- so these cases are exercised without needing max_prepared_transactions
-- raised above 0.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP ROLE IF EXISTS safesession_2pc;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_2pc LOGIN;

SET pgedge_safesession.roles = 'safesession_2pc';

SET SESSION AUTHORIZATION safesession_2pc;

-- Two-phase commit statements must all be blocked
COMMIT PREPARED 'nosuch';
ROLLBACK PREPARED 'nosuch';
BEGIN;
PREPARE TRANSACTION 'nosuch';
ROLLBACK;

-- Ordinary transaction control must still work
BEGIN;
SAVEPOINT sp;
RELEASE SAVEPOINT sp;
COMMIT;
BEGIN;
ROLLBACK;

-- Prepared statements (not two-phase commit) must still work
PREPARE myplan AS SELECT 1;
EXECUTE myplan;
DEALLOCATE myplan;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
RESET pgedge_safesession.roles;
DROP ROLE safesession_2pc;
DROP EXTENSION pgedge_safesession;
