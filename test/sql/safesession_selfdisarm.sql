-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Self-disarm tests for pgEdge SafeSession
--
-- The whole mechanism rests on a restricted role being unable to turn it
-- off, so that has to be asserted rather than assumed. Every setting the
-- extension owns is PGC_SUSET, which is what stops a plain SET; the
-- statements that would write one into the configuration persistently
-- (ALTER SYSTEM, ALTER ROLE ... SET) are utility statements and fall to
-- the default deny in the utility hook; and set_config() reaches the same
-- GUC machinery from inside a query, where no utility hook runs, so it is
-- stopped as a blocked built-in instead. All three routes are covered
-- here, because each is refused by a different layer and a change to any
-- one of them would leave the other two looking healthy.
--
-- That difference shows in the output below: "permission denied to set
-- parameter" is core's GUC machinery refusing the SET, whereas "... in a
-- read-only session" is SafeSession's own check.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_disarm;
DROP ROLE IF EXISTS safesession_disarm;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_disarm LOGIN;
CREATE TABLE test_disarm (id int);
INSERT INTO test_disarm VALUES (1);
GRANT SELECT, INSERT ON test_disarm TO safesession_disarm;

SET pgedge_safesession.roles = 'safesession_disarm';

SET SESSION AUTHORIZATION safesession_disarm;

-- Clearing the roles list, or sending it back to its default, must be
-- refused in every spelling
SET pgedge_safesession.roles = '';
SET pgedge_safesession.roles TO DEFAULT;
RESET pgedge_safesession.roles;

-- ... as must replacing it with a list this session is not named in
SET pgedge_safesession.roles = 'nosuchrole';

-- Turning an individual protection off must be refused
SET pgedge_safesession.block_dml = off;
SET pgedge_safesession.block_ddl = off;
SET pgedge_safesession.block_c_functions = off;

-- Even asking for more restriction is refused: the setting is not the
-- restricted role's to choose in either direction
SET pgedge_safesession.block_all_c_functions = on;

-- set_config() is the same assignment from inside a query, where the
-- utility hook never runs, so the function check is what stops it
SELECT set_config('pgedge_safesession.block_dml', 'off', false);

-- Writing the setting into the configuration persistently is a utility
-- statement, and falls to the default deny
ALTER SYSTEM SET pgedge_safesession.roles = '';
ALTER SYSTEM RESET pgedge_safesession.roles;
ALTER ROLE safesession_disarm SET pgedge_safesession.block_dml = off;

-- The read-only floor that safesession_guctamper protects for the
-- session must also be out of reach persistently
ALTER ROLE safesession_disarm SET default_transaction_read_only = off;

-- Nothing above took effect: the settings still read as configured
SHOW pgedge_safesession.roles;
SHOW pgedge_safesession.block_dml;
SHOW pgedge_safesession.block_all_c_functions;

-- ... and the session is still restricted
SELECT pgedge_safesession_is_restricted() AS still_restricted;
INSERT INTO test_disarm VALUES (2);

RESET SESSION AUTHORIZATION;

-- Confirm the blocked INSERT did not add a row
SET default_transaction_read_only = off;
SELECT count(*) AS test_disarm_rows FROM test_disarm;

-- Cleanup
RESET pgedge_safesession.roles;
DROP TABLE test_disarm;
DROP ROLE safesession_disarm;
DROP EXTENSION pgedge_safesession;
