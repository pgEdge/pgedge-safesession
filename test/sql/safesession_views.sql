-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- View-body tests for pgEdge SafeSession
--
-- A view's body is substituted into the range table during
-- QueryRewrite(), which runs after post_parse_analyze, so a blocked
-- function reached only through a view is invisible to the
-- post_parse_analyze walker even though it actually executes. The
-- planner_hook check, which runs on the Query after rewrite, is what
-- catches this.
--
-- set_config() is used throughout because it escapes the read-only
-- floor (it changes a GUC rather than writing data), so it would
-- otherwise take effect; SHOW work_mem shows whether it did.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP VIEW IF EXISTS v_setcfg, v_setcfg_wrap;
DROP ROLE IF EXISTS safesession_views;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_views LOGIN;

-- As the DBA: create a view wrapping a blocked function, and a view
-- of that view (nested substitution)
CREATE VIEW v_setcfg AS SELECT set_config('work_mem', '61MB', false);
CREATE VIEW v_setcfg_wrap AS SELECT * FROM v_setcfg;
GRANT SELECT ON v_setcfg, v_setcfg_wrap TO safesession_views;

SET pgedge_safesession.roles = 'safesession_views';

SET SESSION AUTHORIZATION safesession_views;

SET work_mem = '4MB';

-- A blocked function reached only through a view must be rejected
SHOW work_mem;
SELECT * FROM v_setcfg;
SHOW work_mem;

-- ... and through a view of a view
SELECT * FROM v_setcfg_wrap;
SHOW work_mem;

RESET SESSION AUTHORIZATION;

-- An ordinary view (no blocked function) must still work normally
DROP VIEW IF EXISTS v_plain;
CREATE VIEW v_plain AS SELECT 1 AS n;
GRANT SELECT ON v_plain TO safesession_views;

SET SESSION AUTHORIZATION safesession_views;
SELECT * FROM v_plain;
RESET SESSION AUTHORIZATION;

-- With block_c_functions off, the check is skipped as it is
-- everywhere else, and the view's function takes effect
SET pgedge_safesession.block_c_functions = off;
SET SESSION AUTHORIZATION safesession_views;
SELECT * FROM v_setcfg;
SHOW work_mem;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_c_functions = on;

-- Cleanup
RESET pgedge_safesession.roles;
DROP VIEW v_setcfg_wrap, v_setcfg, v_plain;
DROP ROLE safesession_views;
DROP EXTENSION pgedge_safesession;
