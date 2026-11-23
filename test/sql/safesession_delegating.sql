-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Delegating sessions: a login role (here safesession_authenticator,
-- standing in for PostgREST's authenticator) that switches into another
-- role for each transaction is judged by the role it acts as, not by its
-- own memberships. Each request below is written the way PostgREST sends
-- it: a transaction whose first statement switches role with
-- set_config(..., true) and sets the request's claims.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS ss_notes;
DROP FUNCTION IF EXISTS ss_set_status();
DROP FUNCTION IF EXISTS ss_set_headers();
DROP FUNCTION IF EXISTS ss_pre_request();
DROP FUNCTION IF EXISTS ss_set_any(text);
DROP FUNCTION IF EXISTS ss_definer_write();
DROP FUNCTION IF EXISTS ss_uses_var();
DROP FUNCTION IF EXISTS ss_assign_status();
DROP FUNCTION IF EXISTS ss_ro_definer();
DROP FUNCTION IF EXISTS ss_takes_xid();
DROP FUNCTION IF EXISTS ss_with_default(text);
DROP FUNCTION IF EXISTS ss_ret_dom();
DROP FUNCTION IF EXISTS ss_poly(anyelement);
DROP TABLE IF EXISTS ss_parted;
DROP FUNCTION IF EXISTS ss_pick(int);
DROP AGGREGATE IF EXISTS ss_d_agg(text);
DROP FUNCTION IF EXISTS ss_d_sfunc(ss_d, text);
DROP DOMAIN IF EXISTS ss_d;
DROP FUNCTION IF EXISTS ss_ro_status();
DROP FUNCTION IF EXISTS ss_set_lang();
DROP ROLE IF EXISTS safesession_person;
DROP ROLE IF EXISTS safesession_api_super;
DROP ROLE IF EXISTS safesession_api_member;
DROP ROLE IF EXISTS safesession_pool_member;
DROP ROLE IF EXISTS safesession_authenticator;
DROP ROLE IF EXISTS safesession_anon;
DROP ROLE IF EXISTS safesession_authenticated;
DROP ROLE IF EXISTS safesession_writer;
DROP ROLE IF EXISTS safesession_ro;
DROP ROLE IF EXISTS "safesession_Mixed";

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_anon NOLOGIN;
CREATE ROLE safesession_authenticated NOLOGIN;
CREATE ROLE safesession_writer NOLOGIN;
CREATE ROLE safesession_ro NOLOGIN;
CREATE ROLE safesession_authenticator LOGIN NOINHERIT;
GRANT safesession_anon, safesession_authenticated, safesession_writer
    TO safesession_authenticator;
-- A role that is a member of the API roles, which requests can act as
CREATE ROLE safesession_api_member NOLOGIN
    IN ROLE safesession_anon, safesession_authenticated;
GRANT safesession_api_member TO safesession_authenticator;
-- A superuser login role, for a pool that logs in as one
CREATE ROLE safesession_api_super SUPERUSER LOGIN;
-- A person who logs in directly as a member of an API role
CREATE ROLE safesession_person LOGIN;
GRANT safesession_authenticated TO safesession_person;
-- A person granted the delegating role is not a delegating session
CREATE ROLE safesession_pool_member LOGIN;
GRANT safesession_authenticator TO safesession_pool_member;

CREATE TABLE ss_notes (id int, val text);
GRANT SELECT, INSERT ON ss_notes
    TO safesession_anon, safesession_authenticated, safesession_writer,
       safesession_person, safesession_pool_member;

-- Functions an app would expose: set the response with set_config()
CREATE FUNCTION ss_set_status() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('response.status', '201', true);
END $$;
CREATE FUNCTION ss_set_headers() RETURNS text LANGUAGE sql AS $$
    SELECT set_config('response.headers', '[{"X-Test": "1"}]', true)
$$;
-- A db-pre-request function, which PostgREST runs after the switch
CREATE FUNCTION ss_pre_request() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('response.headers', '[{"X-Pre": "1"}]', true);
END $$;
-- A name passed in could name any setting
CREATE FUNCTION ss_set_any(name text) RETURNS text LANGUAGE sql AS $$
    SELECT set_config(name, '1', true)
$$;
-- A SECURITY DEFINER function owned by a role that may write
GRANT INSERT ON ss_notes TO safesession_writer;
CREATE FUNCTION ss_definer_write() RETURNS void LANGUAGE plpgsql
    SECURITY DEFINER AS $$
BEGIN
    INSERT INTO ss_notes VALUES (99, 'definer');
END $$;
ALTER FUNCTION ss_definer_write() OWNER TO safesession_writer;
GRANT EXECUTE ON FUNCTION ss_definer_write() TO safesession_anon;

-------------------------------------------------------------------------
-- Test 1: without delegating_roles (as in release 1.0), a login role that
-- is a member of a read-only role makes every request fail, even its role
-- switch.
-------------------------------------------------------------------------
GRANT safesession_ro TO safesession_authenticator;
SET pgedge_safesession.read_only_roles = 'safesession_ro';
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_writer', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
ROLLBACK;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 2: with delegating_roles, the login role's memberships are
-- ignored, so the same requests work.
-------------------------------------------------------------------------
SET pgedge_safesession.delegating_roles = 'safesession_authenticator';
SET SESSION AUTHORIZATION safesession_authenticator;
-- The pool's own statements are never read-only
SELECT pgedge_safesession_is_restricted();
BEGIN;
SELECT set_config('role', 'safesession_writer', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT pgedge_safesession_is_restricted();
INSERT INTO ss_notes VALUES (1, 'writer');
COMMIT;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.read_only_roles;
REVOKE safesession_ro FROM safesession_authenticator;

-------------------------------------------------------------------------
-- Test 3: acting_read_only_roles makes requests acting as safesession_anon
-- read-only. They can read; their writes are refused.
-------------------------------------------------------------------------
SET pgedge_safesession.acting_read_only_roles = 'safesession_anon';
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_anon', true),
       set_config('request.jwt.claims', '{}', true);
SELECT pgedge_safesession_is_restricted();
SELECT * FROM ss_notes ORDER BY id;
INSERT INTO ss_notes VALUES (2, 'anon');
ROLLBACK;
-- A write through a SECURITY DEFINER function is refused too
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_definer_write();
ROLLBACK;
-- So are requests acting as a member of a listed role
BEGIN;
SELECT set_config('role', 'safesession_api_member', true);
SELECT pgedge_safesession_is_restricted();
INSERT INTO ss_notes VALUES (2, 'member');
ROLLBACK;
-- Requests acting as other roles can write
BEGIN;
SELECT set_config('role', 'safesession_authenticated', true);
SELECT pgedge_safesession_is_restricted();
INSERT INTO ss_notes VALUES (3, 'authenticated');
COMMIT;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 4: acting_read_only_roles affects delegated requests only. A
-- person who logs in directly as a member of the same role can write.
-------------------------------------------------------------------------
SET pgedge_safesession.acting_read_only_roles = 'safesession_authenticated';
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_authenticated', true);
INSERT INTO ss_notes VALUES (4, 'api');
ROLLBACK;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION safesession_person;
SELECT pgedge_safesession_is_restricted();
INSERT INTO ss_notes VALUES (4, 'person');
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.acting_read_only_roles;

-------------------------------------------------------------------------
-- Test 5: read_only_roles (and its old name, roles) still restricts every
-- session of a listed role, delegated requests included.
-------------------------------------------------------------------------
SET pgedge_safesession.read_only_roles = 'safesession_authenticated';
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_authenticated', true);
INSERT INTO ss_notes VALUES (5, 'api');
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_api_member', true);
INSERT INTO ss_notes VALUES (5, 'member');
ROLLBACK;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION safesession_person;
INSERT INTO ss_notes VALUES (5, 'person');
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.read_only_roles;
SET pgedge_safesession.roles = 'safesession_anon';
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
INSERT INTO ss_notes VALUES (5, 'anon');
ROLLBACK;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.roles;

-------------------------------------------------------------------------
-- Test 6: the delegating role named on read_only_roles makes every
-- request read-only once it has switched; the pool's own statements, and
-- a person who is only a member of it, are judged as before.
-------------------------------------------------------------------------
SET pgedge_safesession.read_only_roles = 'safesession_authenticator';
SET SESSION AUTHORIZATION safesession_authenticator;
SELECT pgedge_safesession_is_restricted();
BEGIN;
SELECT set_config('role', 'safesession_writer', true);
SELECT pgedge_safesession_is_restricted();
INSERT INTO ss_notes VALUES (6, 'writer');
ROLLBACK;
-- So does a request that switches into the login role itself
BEGIN;
SELECT set_config('role', 'safesession_authenticator', true);
SELECT pgedge_safesession_is_restricted();
INSERT INTO ss_notes VALUES (6, 'self');
ROLLBACK;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION safesession_pool_member;
SELECT pgedge_safesession_is_restricted();
INSERT INTO ss_notes VALUES (6, 'member');
-- Not a delegating session, so no response.* set_config() either
SELECT set_config('response.status', '201', true);
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.read_only_roles;

-------------------------------------------------------------------------
-- Test 7: a read-only request can set the response status and headers
-- with set_config(..., true), from a statement, a PL/pgSQL or SQL
-- function, and a db-pre-request function.
-------------------------------------------------------------------------
SET pgedge_safesession.acting_read_only_roles = 'safesession_anon';
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_pre_request();
SELECT set_config('response.status', '200', true);
SELECT ss_set_status();
SELECT ss_set_headers();
SELECT current_setting('response.status'),
       current_setting('response.headers');
COMMIT;

-------------------------------------------------------------------------
-- Test 8: any other set_config() in a read-only request is still refused:
-- for the whole session, another setting, a name passed in, or a value
-- that calls a blocked function.
-------------------------------------------------------------------------
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('response.status', '201', false);
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('request.jwt.claims', '{"sub": "2"}', true);
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('role', 'safesession_writer', true);
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_set_any('response.status');
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('response.status', txid_current()::text, true);
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('response.status', set_config('app.nested', 'x', false),
                  true);
COMMIT;
RESET SESSION AUTHORIZATION;
SELECT current_setting('app.nested', true) IS NULL AS not_set;

-- A read-only session that is not delegating is unchanged: no set_config()
SET pgedge_safesession.read_only_roles = 'safesession_authenticated';
SET SESSION AUTHORIZATION safesession_person;
SELECT set_config('response.status', '201', true);
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.read_only_roles;
RESET pgedge_safesession.acting_read_only_roles;

-------------------------------------------------------------------------
-- Test 9: each list is a comma-separated list of names. One that does
-- not parse is refused, and a role that does not exist is warned about
-- when set and logged when the names are looked up. An unquoted name with
-- capitals is read in lower case, so it does not match the role
-- "safesession_Mixed".
-------------------------------------------------------------------------
SET pgedge_safesession.delegating_roles =
    'safesession_authenticator,,safesession_anon';
SET pgedge_safesession.acting_read_only_roles = '"safesession_anon';
SET pgedge_safesession.read_only_roles = 'a b';
SHOW pgedge_safesession.delegating_roles;
CREATE ROLE "safesession_Mixed" NOLOGIN;
GRANT "safesession_Mixed" TO safesession_authenticator;
SET pgedge_safesession.acting_read_only_roles = 'safesession_Mixed';
-- One query, so a server that logs statements adds no lines of its own
SET client_min_messages = log\; SET SESSION AUTHORIZATION safesession_authenticator\; SET client_min_messages = notice;
BEGIN;
SELECT set_config('role', 'safesession_Mixed', true);
SELECT pgedge_safesession_is_restricted();
ROLLBACK;
RESET SESSION AUTHORIZATION;
-- Set again to the same value: not logged a second time
SET pgedge_safesession.acting_read_only_roles = 'safesession_Mixed';
SET client_min_messages = log\; SET SESSION AUTHORIZATION safesession_authenticator\; SET client_min_messages = notice;
RESET SESSION AUTHORIZATION;
-- Quoted, the name matches
SET pgedge_safesession.acting_read_only_roles = '"safesession_Mixed"';
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_Mixed', true);
SELECT pgedge_safesession_is_restricted();
ROLLBACK;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.acting_read_only_roles;

-------------------------------------------------------------------------
-- Test 10: only a superuser can change the new settings
-------------------------------------------------------------------------
SET SESSION AUTHORIZATION safesession_authenticator;
SET pgedge_safesession.delegating_roles = '';
SET pgedge_safesession.acting_read_only_roles = '';
SET pgedge_safesession.read_only_roles = '';
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 11: set_config() that no statement shows, such as one in a
-- domain's CHECK run for a PL/pgSQL variable, is still refused in a
-- read-only request, so it cannot set a value for the whole session. So
-- is a set_config() PL/pgSQL evaluates as a simple expression; PERFORM
-- (Test 7) is the form to use.
-------------------------------------------------------------------------
CREATE DOMAIN ss_d AS text
    CHECK (set_config('app.leak', VALUE, false) IS NOT NULL);
CREATE FUNCTION ss_uses_var() RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v ss_d := 'from-variable';
BEGIN
    RETURN v;
END $$;
CREATE FUNCTION ss_assign_status() RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    v text;
BEGIN
    v := set_config('response.status', '201', true);
    RETURN v;
END $$;
SET pgedge_safesession.acting_read_only_roles = 'safesession_anon';
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
-- The line in the error context differs between versions
\set SHOW_CONTEXT never
SELECT ss_uses_var();
\set SHOW_CONTEXT errors
ROLLBACK;
SELECT current_setting('app.leak', true) IS NULL AS not_set;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_assign_status();
ROLLBACK;
-- A request that can write is refused too, by the role lock: the value
-- would still be there for the next request
BEGIN;
SELECT set_config('role', 'safesession_writer', true);
SELECT ss_uses_var();
ROLLBACK;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.acting_read_only_roles;

-------------------------------------------------------------------------
-- Test 12: a pgedge_safesession setting this release does not know, such
-- as a misspelled one, is refused when it is typed, so it can never be
-- saved and then stop the server at its next start.
-------------------------------------------------------------------------
SET pgedge_safesession.delegating_role = 'safesession_authenticator';
ALTER SYSTEM SET pgedge_safesession.delegating_role =
    'safesession_authenticator';
ALTER ROLE safesession_person
    SET pgedge_safesession.acting_read_only_role = 'x';
ALTER DATABASE contrib_regression
    SET pgedge_safesession.read_only_role = 'x';
-- SET ... TO DEFAULT removes a saved setting, as RESET does
ALTER ROLE safesession_person
    SET pgedge_safesession.acting_read_only_role TO DEFAULT;
-- Known names are not affected
ALTER ROLE safesession_person
    SET pgedge_safesession.acting_read_only_roles = '';
ALTER ROLE safesession_person
    RESET pgedge_safesession.acting_read_only_roles;

-------------------------------------------------------------------------
-- Test 13: how a delegated request is judged, in the corners.
-------------------------------------------------------------------------
-- A SECURITY DEFINER function owned by a role on read_only_roles is
-- read-only inside, as in any session, even for a request that can write
CREATE FUNCTION ss_ro_definer() RETURNS boolean LANGUAGE sql
    SECURITY DEFINER AS $$ SELECT pgedge_safesession_is_restricted() $$;
ALTER FUNCTION ss_ro_definer() OWNER TO safesession_ro;
GRANT EXECUTE ON FUNCTION ss_ro_definer()
    TO safesession_writer, safesession_authenticator;
-- A function a writer runs first, so its plan is cached in the session
CREATE FUNCTION ss_takes_xid() RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN
    PERFORM txid_current();
    RETURN true;
END $$;
GRANT EXECUTE ON FUNCTION ss_takes_xid()
    TO safesession_writer, safesession_anon;
-- Sets the response status inside a definer owned by a read-only role
CREATE FUNCTION ss_ro_status() RETURNS text LANGUAGE plpgsql
    SECURITY DEFINER AS $$
BEGIN
    PERFORM set_config('response.status', '201', true);
    RETURN current_setting('response.status');
END $$;
ALTER FUNCTION ss_ro_status() OWNER TO safesession_ro;
GRANT EXECUTE ON FUNCTION ss_ro_status() TO safesession_writer;
-- Sets a value for the whole session: fine for a writer, not when read-only
CREATE FUNCTION ss_set_lang() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('app.lang', 'x', false);
END $$;
GRANT EXECUTE ON FUNCTION ss_set_lang()
    TO safesession_writer, safesession_anon;
-- Switches role and then casts through a volatile input function. The cast
-- runs no function-execute check, so only the plan check stops it, and the
-- second statement's plan is fetched before it starts: the restriction must
-- be noticed when the switch statement ends.
-- (quiet: the shell-type notices differ between versions)
SET client_min_messages = error;
CREATE TYPE ss_t;
CREATE FUNCTION ss_t_in(cstring) RETURNS ss_t LANGUAGE internal VOLATILE
    STRICT AS 'textin';
CREATE FUNCTION ss_t_out(ss_t) RETURNS cstring LANGUAGE internal IMMUTABLE
    STRICT AS 'textout';
CREATE TYPE ss_t (INPUT = ss_t_in, OUTPUT = ss_t_out,
                  INTERNALLENGTH = VARIABLE);
RESET client_min_messages;
CREATE FUNCTION ss_switch_then_cast(r text) RETURNS boolean
    LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('role', r, true);
    PERFORM ('x'::text)::ss_t;
    RETURN true;
END $$;
GRANT EXECUTE ON FUNCTION ss_switch_then_cast(text)
    TO safesession_authenticator;
SET pgedge_safesession.read_only_roles = 'safesession_ro';
SET pgedge_safesession.acting_read_only_roles = 'safesession_anon';
SET SESSION AUTHORIZATION safesession_authenticator;
-- Also in the pool's own statements, before any switch
SELECT pgedge_safesession_is_restricted() AS outside,
       ss_ro_definer() AS inside;
BEGIN;
SELECT set_config('role', 'safesession_writer', true);
SELECT pgedge_safesession_is_restricted() AS outside,
       ss_ro_definer() AS inside;
ROLLBACK;
-- ... and can still set a response.* setting there
BEGIN;
SELECT set_config('role', 'safesession_writer', true);
SELECT ss_ro_status();
ROLLBACK;
-- A request acting as the login role itself is judged by its memberships
-- too: it is a member of safesession_anon, so it is read-only
BEGIN;
SELECT set_config('role', 'safesession_authenticator', true);
SELECT pgedge_safesession_is_restricted();
ROLLBACK;
-- A response.* setting set by the first statement after the switch
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_set_headers();
ROLLBACK;
-- A plan cached while writing is checked again once read-only
BEGIN;
SELECT set_config('role', 'safesession_writer', true);
SELECT ss_takes_xid();
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_takes_xid();
ROLLBACK;
-- The same for a plan that sets a value for the whole session, cached by
-- a PL/pgSQL function or prepared by a writer. A request cannot set a
-- value for the whole session, or PREPARE, after the switch, so the pool's
-- own switch statement prepares, after it switches.
\set SHOW_CONTEXT never
BEGIN;
SELECT set_config('role', 'safesession_writer', true);
SELECT ss_set_lang();
ROLLBACK;
BEGIN;
DO $$ BEGIN
    PERFORM set_config('role', 'safesession_writer', true);
    EXECUTE 'PREPARE ss_lang AS SELECT set_config(''app.lang'', ''y'','
        ' false)';
END $$;
ROLLBACK;
\set SHOW_CONTEXT errors
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_set_lang();
ROLLBACK;
-- A read-only request keeps the read-only error for SET too
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SET default_transaction_read_only = off;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
EXECUTE ss_lang;
ROLLBACK;
DEALLOCATE ss_lang;
-- A plan cached while writing, fetched right after a switch in the same
-- statement, is checked again once read-only
BEGIN;
SELECT ss_switch_then_cast('safesession_writer');
ROLLBACK;
BEGIN;
SELECT ss_switch_then_cast('safesession_anon');
ROLLBACK;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.read_only_roles;
RESET pgedge_safesession.acting_read_only_roles;

-------------------------------------------------------------------------
-- Test 14: a set_config() no statement shows is refused even while a
-- statement starts: a parameter default, which the planner adds; the
-- domain coercion the planner adds when it inlines a SQL function; and a
-- function initial partition pruning runs. A response.* setting can be
-- set from a statement that reads no table, such as PostgREST's call of a
-- function, and not from one that reads a table.
-------------------------------------------------------------------------
CREATE FUNCTION ss_with_default(
    x text DEFAULT set_config('app.leak', 'default', false))
    RETURNS text LANGUAGE plpgsql AS $$ BEGIN RETURN x; END $$;
CREATE FUNCTION ss_ret_dom() RETURNS ss_d LANGUAGE sql
    AS $$ SELECT 'from-result'::text $$;
CREATE TABLE ss_parted (k int) PARTITION BY LIST (k);
CREATE TABLE ss_parted_1 PARTITION OF ss_parted FOR VALUES IN (1);
CREATE TABLE ss_parted_2 PARTITION OF ss_parted FOR VALUES IN (2);
CREATE FUNCTION ss_pick(i int) RETURNS int LANGUAGE plpgsql STABLE AS $$
DECLARE
    v ss_d := 'from-pruning';
BEGIN
    RETURN i;
END $$;
GRANT SELECT ON ss_parted TO safesession_anon;
CREATE FUNCTION ss_poly(v anyelement) RETURNS text LANGUAGE sql
    AS $$ SELECT set_config('response.status', v::text, true) $$;
-- A window aggregate converts its initial value while the statement starts
CREATE FUNCTION ss_d_sfunc(ss_d, text) RETURNS ss_d LANGUAGE sql IMMUTABLE
    AS $$ SELECT $1 $$;
CREATE AGGREGATE ss_d_agg(text) (SFUNC = ss_d_sfunc, STYPE = ss_d,
    INITCOND = 'from-initcond');
-- CREATE AGGREGATE checked the initial value, which ran the CHECK here
RESET app.leak;
SET pgedge_safesession.acting_read_only_roles = 'safesession_anon';
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_with_default();
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_ret_dom();
COMMIT;
\set SHOW_CONTEXT never
BEGIN;
SET LOCAL plan_cache_mode = force_generic_plan;
DO $$ BEGIN
    PERFORM set_config('role', 'safesession_anon', true);
    EXECUTE 'PREPARE ss_q(int) AS'
        ' SELECT * FROM ss_parted WHERE k = ss_pick($1)';
END $$;
EXECUTE ss_q(1);
\set SHOW_CONTEXT errors
COMMIT;
DEALLOCATE ss_q;
-- Each was refused before it ran, so nothing was committed
SELECT coalesce(current_setting('app.leak', true), '') = '' AS not_set;
-- Also when the same statement sets a response.* setting: the check reads
-- every call in the plan, and refuses a plan that can run other code while
-- it starts
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('response.status', '201', true), ss_with_default();
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('response.status', '201', true), ss_ret_dom();
COMMIT;
\set SHOW_CONTEXT never
BEGIN;
SET LOCAL plan_cache_mode = force_generic_plan;
DO $$ BEGIN
    PERFORM set_config('role', 'safesession_anon', true);
    EXECUTE 'PREPARE ss_q2(int) AS'
        ' SELECT set_config(''response.status'', ''201'', true), k'
        ' FROM ss_parted WHERE k = ss_pick($1)';
END $$;
EXECUTE ss_q2(1);
\set SHOW_CONTEXT errors
COMMIT;
DEALLOCATE ss_q2;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('response.status', '201', true), ss_d_agg(v) OVER ()
FROM (VALUES ('a')) t(v);
COMMIT;
SELECT coalesce(current_setting('app.leak', true), '') = '' AS not_set;
-- The value of an allowed call is read too
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('response.status', ss_with_default(), true);
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT set_config('response.status', ss_ret_dom()::text, true);
COMMIT;
-- A polymorphic SQL function's body cannot be read before it runs
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT ss_poly(201);
ROLLBACK;
SELECT coalesce(current_setting('app.leak', true), '') = '' AS not_set;
-- A value read from a table is set from a variable, not a subquery
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
\set SHOW_CONTEXT never
DO $$ BEGIN
    PERFORM set_config('response.status',
                       (SELECT count(*) FROM ss_notes)::text, true);
END $$;
\set SHOW_CONTEXT errors
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
DO $$
DECLARE
    n bigint := (SELECT count(*) FROM ss_notes);
BEGIN
    PERFORM set_config('response.status', n::text, true);
END $$;
SELECT current_setting('response.status') IS NOT NULL AS status_set;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
WITH pgrst_source AS (
    SELECT pgrst_call.pgrst_scalar
    FROM (SELECT ss_set_headers() pgrst_scalar) pgrst_call)
SELECT coalesce(json_agg(t.pgrst_scalar) -> 0, 'null') AS body
FROM (SELECT * FROM pgrst_source) t;
SELECT set_config('response.status', '404', true) FROM ss_notes LIMIT 1;
ROLLBACK;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.acting_read_only_roles;

-------------------------------------------------------------------------
-- Test 15: a superuser login role on delegating_roles is judged by the
-- role it acts as, like any other; its own statements are not read-only.
-------------------------------------------------------------------------
SET pgedge_safesession.delegating_roles =
    'safesession_authenticator, safesession_api_super';
SET pgedge_safesession.acting_read_only_roles = 'safesession_anon';
SET SESSION AUTHORIZATION safesession_api_super;
SELECT pgedge_safesession_is_restricted();
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SELECT pgedge_safesession_is_restricted();
INSERT INTO ss_notes VALUES (15, 'anon');
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_writer', true);
INSERT INTO ss_notes VALUES (15, 'writer');
ROLLBACK;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.delegating_roles = 'safesession_authenticator';

-------------------------------------------------------------------------
-- Test 16: SET CONSTRAINTS, which PostgREST sends to roll a request back,
-- works in a read-only request.
-------------------------------------------------------------------------
SET SESSION AUTHORIZATION safesession_authenticator;
BEGIN;
SELECT set_config('role', 'safesession_anon', true);
SET CONSTRAINTS ALL IMMEDIATE;
ROLLBACK;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.acting_read_only_roles;

-------------------------------------------------------------------------
-- Test 17: acting_read_only_roles has no effect without delegating_roles,
-- and the server log says so.
-------------------------------------------------------------------------
RESET pgedge_safesession.delegating_roles;
SET pgedge_safesession.acting_read_only_roles = 'safesession_anon';
-- One query, so a server that logs statements adds no lines of its own
SET client_min_messages = log\; SET SESSION AUTHORIZATION safesession_person\; SET client_min_messages = notice;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.acting_read_only_roles;

-- Cleanup
RESET client_min_messages;
RESET pgedge_safesession.delegating_roles;
SELECT * FROM ss_notes ORDER BY id;
DROP TABLE ss_notes;
DROP FUNCTION ss_set_status();
DROP FUNCTION ss_set_headers();
DROP FUNCTION ss_pre_request();
DROP FUNCTION ss_set_any(text);
DROP FUNCTION ss_definer_write();
DROP FUNCTION ss_uses_var();
DROP FUNCTION ss_assign_status();
DROP FUNCTION ss_ro_definer();
DROP FUNCTION ss_takes_xid();
DROP FUNCTION ss_ro_status();
DROP FUNCTION ss_set_lang();
DROP FUNCTION ss_switch_then_cast(text);
DROP FUNCTION ss_t_in(cstring) CASCADE;
DROP FUNCTION ss_with_default(text);
DROP FUNCTION ss_ret_dom();
DROP FUNCTION ss_poly(anyelement);
DROP TABLE ss_parted;
DROP FUNCTION ss_pick(int);
DROP AGGREGATE ss_d_agg(text);
DROP FUNCTION ss_d_sfunc(ss_d, text);
DROP DOMAIN ss_d;
DROP ROLE safesession_person;
DROP ROLE safesession_api_super;
DROP ROLE safesession_api_member;
DROP ROLE safesession_pool_member;
DROP ROLE safesession_authenticator;
DROP ROLE safesession_anon;
DROP ROLE safesession_authenticated;
DROP ROLE safesession_writer;
DROP ROLE safesession_ro;
DROP ROLE "safesession_Mixed";
DROP EXTENSION pgedge_safesession;
