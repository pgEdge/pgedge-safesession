-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Brief-elevation tests for pgEdge SafeSession
--
-- PostgreSQL reports a superuser as a member of every role in the
-- database, with no grant behind it, so a membership test that does not
-- ignore superuserness answers "yes" for every configured role. That
-- matters whenever the current user is a superuser whilst the session user
-- is not: a SECURITY DEFINER function owned by a superuser does exactly
-- that, and so does an extension such as supautils when it briefly
-- elevates a privileged-but-not-superuser role for a single command.
--
-- Two things must hold at once. A role that is neither listed nor a member
-- of a listed role must stay unrestricted throughout such a window, and a
-- role that genuinely is a member must stay restricted throughout it,
-- because the session user is the anchor and elevation must not become an
-- escape hatch. The SECURITY DEFINER functions below stand in for the
-- elevation, since they change the current user the same way.

-- One rejection below happens inside a PL/pgSQL function, and the wording
-- of the CONTEXT line for that differs between major versions ("SQL
-- expression" on PostgreSQL 14 to 17, "PL/pgSQL expression" on 18), so
-- context is suppressed; the error and its hint are what matter here.
\set SHOW_CONTEXT never

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP ROLE IF EXISTS safesession_elev_member;
DROP ROLE IF EXISTS safesession_elev_admin;
DROP ROLE IF EXISTS safesession_elev_group;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

-- safesession_elev_group is the restricted role, elev_member is genuinely
-- granted it, and elev_admin has nothing to do with it
CREATE ROLE safesession_elev_group;
CREATE ROLE safesession_elev_member LOGIN;
CREATE ROLE safesession_elev_admin LOGIN;
GRANT safesession_elev_group TO safesession_elev_member;

CREATE FUNCTION elev_is_restricted() RETURNS bool
    LANGUAGE sql SECURITY DEFINER
    AS $$ SELECT pgedge_safesession_is_restricted() $$;
CREATE FUNCTION elev_set_config() RETURNS text
    LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    RETURN set_config('work_mem', '33MB', false);
END $$;
GRANT EXECUTE ON FUNCTION elev_is_restricted(), elev_set_config()
    TO safesession_elev_member, safesession_elev_admin;

SET pgedge_safesession.roles = 'safesession_elev_group';

-- Core's own view: the superuser running this test is reported as a member
-- of the restricted role purely by being a superuser, whilst elev_admin,
-- which has no grant either, is correctly reported as not a member
SELECT pg_has_role(current_user, 'safesession_elev_group', 'member')
           AS superuser_is_member,
       pg_has_role('safesession_elev_admin', 'safesession_elev_group',
                   'member') AS admin_is_member;

-- ============================================================
-- An unrelated role must not be caught by the elevation
-- ============================================================
SET SESSION AUTHORIZATION safesession_elev_admin;
SET work_mem = '4MB';

SELECT pgedge_safesession_is_restricted() AS restricted;
SELECT elev_is_restricted() AS restricted_while_elevated;

-- ... and a privileged operation in that window must go through
SELECT elev_set_config();
SHOW work_mem;

RESET SESSION AUTHORIZATION;

-- ============================================================
-- A genuine member must stay restricted through the elevation
-- ============================================================
-- The plans PL/pgSQL cached for its expressions during the block above
-- were built whilst this session was unrestricted, and the function check
-- runs in post_parse_analyze, i.e. only when an expression is parsed.
-- Discard them, so that what follows measures the restriction rather than
-- the contents of the plan cache.
DISCARD PLANS;

SET SESSION AUTHORIZATION safesession_elev_member;
SET work_mem = '4MB';

SELECT pgedge_safesession_is_restricted() AS restricted;
SELECT elev_is_restricted() AS restricted_while_elevated;

-- A SECURITY DEFINER function owned by a superuser is not an escape
-- hatch: the blocked function inside it is still rejected, and work_mem
-- is left where it was
SELECT elev_set_config();
SHOW work_mem;

RESET SESSION AUTHORIZATION;

-- Cleanup
SET default_transaction_read_only = off;
RESET pgedge_safesession.roles;
RESET work_mem;
DROP FUNCTION elev_is_restricted();
DROP FUNCTION elev_set_config();
REVOKE safesession_elev_group FROM safesession_elev_member;
DROP ROLE safesession_elev_member;
DROP ROLE safesession_elev_admin;
DROP ROLE safesession_elev_group;
DROP EXTENSION pgedge_safesession;
