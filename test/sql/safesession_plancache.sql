-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Plan-cache invalidation tests for pgEdge SafeSession
--
-- The blocked-function check runs in the post_parse_analyze hook, so it
-- runs when a statement or expression is parsed rather than when it is
-- executed, and a plan built whilst the session was unrestricted would
-- otherwise be replayed without the check running again. PL/pgSQL caches
-- the plans for its expressions, and a prepared statement caches its plan
-- by definition, so both are exercised here.
--
-- Becoming restricted is therefore treated as an invalidation event: the
-- cached plans are discarded, exactly as DISCARD PLANS does, and
-- everything is re-analysed under the new state. Each case below runs the
-- call once whilst it is legitimately allowed, so that a plan really is
-- cached, and then again once the session has become restricted.

-- Some rejections below happen inside a PL/pgSQL function, and the
-- wording of the CONTEXT line for that differs between major versions, so
-- context is suppressed; the error and its hint are what matter.
\set SHOW_CONTEXT never

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP ROLE IF EXISTS safesession_pc_other;
DROP ROLE IF EXISTS safesession_pc_admin;
DROP ROLE IF EXISTS safesession_pc_group;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_pc_group;
CREATE ROLE safesession_pc_admin LOGIN;
CREATE ROLE safesession_pc_other LOGIN;

CREATE FUNCTION pc_setcfg(t text) RETURNS text LANGUAGE plpgsql
    SECURITY DEFINER AS $$
BEGIN
    RETURN set_config('work_mem', t, false);
END $$;
GRANT EXECUTE ON FUNCTION pc_setcfg(text)
    TO safesession_pc_admin, safesession_pc_other;

SET pgedge_safesession.roles = 'safesession_pc_group';

-- ============================================================
-- A prepared statement planned whilst unrestricted
-- ============================================================
SET SESSION AUTHORIZATION safesession_pc_admin;
SET work_mem = '4MB';
PREPARE pc_plan AS SELECT set_config('work_mem', '44MB', false);

-- Allowed here, and the plan is now cached
EXECUTE pc_plan;
SHOW work_mem;
RESET SESSION AUTHORIZATION;

-- Adding the role to the configuration makes the session restricted, so
-- the cached plan must not be reused as it stands
SET pgedge_safesession.roles =
    'safesession_pc_group, safesession_pc_admin';

SET SESSION AUTHORIZATION safesession_pc_admin;
SET work_mem = '4MB';
EXECUTE pc_plan;
SHOW work_mem;
RESET SESSION AUTHORIZATION;

DEALLOCATE pc_plan;
SET pgedge_safesession.roles = 'safesession_pc_group';

-- ============================================================
-- A PL/pgSQL expression plan, then a grant of membership
-- ============================================================
SET SESSION AUTHORIZATION safesession_pc_other;
SET work_mem = '4MB';

-- Allowed here, and PL/pgSQL now has a plan for the expression
SELECT pc_setcfg('55MB');
SHOW work_mem;
RESET SESSION AUTHORIZATION;

-- Granting the restricted role mid-session must not leave that plan
-- usable
GRANT safesession_pc_group TO safesession_pc_other;

SET SESSION AUTHORIZATION safesession_pc_other;
SET work_mem = '4MB';
SELECT pc_setcfg('66MB');
SHOW work_mem;
RESET SESSION AUTHORIZATION;

-- ============================================================
-- Revoking it again releases the session, and repeated calls
-- through the now-cached plan must keep working
-- ============================================================
REVOKE safesession_pc_group FROM safesession_pc_other;

SET SESSION AUTHORIZATION safesession_pc_other;
SET work_mem = '4MB';
SELECT pc_setcfg('7MB');
SELECT pc_setcfg('8MB');
SHOW work_mem;
RESET SESSION AUTHORIZATION;

-- Cleanup
SET default_transaction_read_only = off;
RESET pgedge_safesession.roles;
RESET work_mem;
DROP FUNCTION pc_setcfg(text);
DROP ROLE safesession_pc_other;
DROP ROLE safesession_pc_admin;
DROP ROLE safesession_pc_group;
DROP EXTENSION pgedge_safesession;
