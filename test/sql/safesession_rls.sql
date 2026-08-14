-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Row-level security tests for pgEdge SafeSession
--
-- An RLS policy's USING/WITH CHECK qual is attached to the relevant
-- range-table entry's securityQuals during QueryRewrite(), the same
-- rewrite stage that substitutes a view body, so a policy calling a
-- blocked function is invisible to the post_parse_analyze walker for
-- the same reason a view is. The planner_hook check catches this.
--
-- set_config() is used throughout because it escapes the read-only
-- floor (it changes a GUC rather than writing data), so it would
-- otherwise take effect; SHOW work_mem shows whether it did.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_rls;
DROP ROLE IF EXISTS safesession_rls;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_rls LOGIN;
CREATE TABLE test_rls (id int, val text);
INSERT INTO test_rls VALUES (1, 'a'), (2, 'b');
GRANT SELECT ON test_rls TO safesession_rls;

ALTER TABLE test_rls ENABLE ROW LEVEL SECURITY;

-- A USING qual that calls a blocked function
CREATE POLICY p_using ON test_rls
    USING (set_config('work_mem', '62MB', false) IS NOT NULL);

SET pgedge_safesession.roles = 'safesession_rls';

SET SESSION AUTHORIZATION safesession_rls;

SET work_mem = '4MB';

-- A blocked function reached only through an RLS USING qual must be
-- rejected
SHOW work_mem;
SELECT * FROM test_rls;
SHOW work_mem;

RESET SESSION AUTHORIZATION;
DROP POLICY p_using ON test_rls;

-- Ordinary RLS filtering (no blocked function) must still work
CREATE POLICY p_plain ON test_rls USING (id = 1);
SET SESSION AUTHORIZATION safesession_rls;
SELECT * FROM test_rls ORDER BY id;
RESET SESSION AUTHORIZATION;
DROP POLICY p_plain ON test_rls;

-- With block_c_functions off, the check is skipped as it is
-- everywhere else, and the policy's function takes effect
CREATE POLICY p_using ON test_rls
    USING (set_config('work_mem', '63MB', false) IS NOT NULL);
SET pgedge_safesession.block_c_functions = off;
SET SESSION AUTHORIZATION safesession_rls;
SELECT * FROM test_rls;
SHOW work_mem;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_c_functions = on;

-- Cleanup
RESET pgedge_safesession.roles;
DROP TABLE test_rls;
DROP ROLE safesession_rls;
DROP EXTENSION pgedge_safesession;
