-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- require_where_roles: a session logged in as one of these roles, or a
-- member of one, has an UPDATE or DELETE with no WHERE clause refused, as
-- pg-safeupdate does, with the same SQLSTATE (21000) and messages.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP FUNCTION IF EXISTS rw_sql_delete();
DROP FUNCTION IF EXISTS rw_plpgsql_delete();
DROP FUNCTION IF EXISTS rw_definer_delete();
DROP FUNCTION IF EXISTS rw_atomic_delete();
DROP FUNCTION IF EXISTS rw_del_all();
DROP FUNCTION IF EXISTS rw_guard() CASCADE;
DROP FUNCTION IF EXISTS rw_set_owner(text);
DROP VIEW IF EXISTS rw_view;
DROP TABLE IF EXISTS rw_items;
DROP ROLE IF EXISTS safesession_rw_login;
DROP ROLE IF EXISTS safesession_rw_member;
DROP ROLE IF EXISTS safesession_rw_group;
DROP ROLE IF EXISTS safesession_rw_other;
DROP ROLE IF EXISTS safesession_rw_owner;
DROP ROLE IF EXISTS safesession_rw_made;
DROP ROLE IF EXISTS safesession_rw_admin;
DROP ROLE IF EXISTS safesession_rw_pool;
DROP ROLE IF EXISTS safesession_rw_ro;
DROP ROLE IF EXISTS safesession_rw_wr;
DROP ROLE IF EXISTS safesession_rw_guard;
DROP ROLE IF EXISTS safesession_rw_caller;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_rw_login LOGIN;
CREATE ROLE safesession_rw_group NOLOGIN;
CREATE ROLE safesession_rw_member LOGIN IN ROLE safesession_rw_group;
CREATE ROLE safesession_rw_other LOGIN;
CREATE ROLE safesession_rw_owner NOLOGIN;
GRANT safesession_rw_other TO safesession_rw_login;

CREATE TABLE rw_items (id int, val text);
INSERT INTO rw_items VALUES (1, 'a'), (2, 'b');
CREATE VIEW rw_view AS SELECT * FROM rw_items WHERE id > 0;
GRANT ALL ON rw_items, rw_view
    TO safesession_rw_login, safesession_rw_member, safesession_rw_other,
       safesession_rw_owner;

CREATE FUNCTION rw_sql_delete() RETURNS void LANGUAGE sql
    AS $$ DELETE FROM rw_items $$;
CREATE FUNCTION rw_plpgsql_delete() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM rw_items;
END $$;
CREATE FUNCTION rw_definer_delete() RETURNS void LANGUAGE plpgsql
    SECURITY DEFINER AS $$
BEGIN
    DELETE FROM rw_items;
END $$;
ALTER FUNCTION rw_definer_delete() OWNER TO safesession_rw_owner;
CREATE FUNCTION rw_atomic_delete() RETURNS void LANGUAGE sql
BEGIN ATOMIC
    DELETE FROM rw_items;
END;

SET pgedge_safesession.require_where_roles =
    'safesession_rw_login, safesession_rw_group';

-------------------------------------------------------------------------
-- Test 1: an UPDATE or DELETE with no WHERE is refused, with safeupdate's
-- SQLSTATE and messages; one with a WHERE works, even WHERE true.
-------------------------------------------------------------------------
SET SESSION AUTHORIZATION safesession_rw_login;
UPDATE rw_items SET val = 'x';
DELETE FROM rw_items;
DO $$
BEGIN
    DELETE FROM rw_items;
EXCEPTION WHEN cardinality_violation THEN
    RAISE NOTICE 'refused with SQLSTATE %: %', SQLSTATE, SQLERRM;
END $$;
BEGIN;
UPDATE rw_items SET val = 'x' WHERE true;
DELETE FROM rw_items WHERE id = 1;
SELECT * FROM rw_items ORDER BY id;
ROLLBACK;
-- A join without WHERE is refused too
UPDATE rw_items SET val = 'x' FROM rw_items i2;
DELETE FROM rw_items USING rw_items i2;
-- WHERE CURRENT OF counts as a WHERE
BEGIN;
DECLARE c CURSOR FOR SELECT * FROM rw_items ORDER BY id FOR UPDATE;
FETCH c;
UPDATE rw_items SET val = 'cursor' WHERE CURRENT OF c;
ROLLBACK;

-------------------------------------------------------------------------
-- Test 2: also inside WITH queries, functions, SECURITY DEFINER functions
-- and BEGIN ATOMIC bodies, and after SET ROLE.
-------------------------------------------------------------------------
WITH d AS (DELETE FROM rw_items RETURNING *) SELECT count(*) FROM d;
WITH u AS (UPDATE rw_items SET val = 'x' RETURNING *)
SELECT count(*) FROM u;
\set SHOW_CONTEXT never
SELECT rw_sql_delete();
SELECT rw_plpgsql_delete();
SELECT rw_definer_delete();
SELECT rw_atomic_delete();
\set SHOW_CONTEXT errors
SET ROLE safesession_rw_other;
DELETE FROM rw_items;
RESET ROLE;
-- Prepared, then executed
PREPARE rw_del AS DELETE FROM rw_items;
DEALLOCATE ALL;
EXPLAIN (COSTS OFF) DELETE FROM rw_items;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 3: a member of a listed role is covered; other logins, and a
-- superuser who is not listed, are not.
-------------------------------------------------------------------------
SET SESSION AUTHORIZATION safesession_rw_member;
DELETE FROM rw_items;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION safesession_rw_other;
BEGIN;
DELETE FROM rw_items;
ROLLBACK;
RESET SESSION AUTHORIZATION;
BEGIN;
DELETE FROM rw_items;
ROLLBACK;

-------------------------------------------------------------------------
-- Test 4: not covered, as in safeupdate: TRUNCATE, and MERGE (not run
-- here: PostgreSQL 14 has no MERGE). A DELETE on a view with its own
-- WHERE is refused: the view's WHERE is not the statement's.
-------------------------------------------------------------------------
SET SESSION AUTHORIZATION safesession_rw_login;
DELETE FROM rw_view;
BEGIN;
TRUNCATE rw_items;
ROLLBACK;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 5: a plan cached before the rule applied is checked again: when
-- the list changes, and when the session user changes.
-------------------------------------------------------------------------
RESET pgedge_safesession.require_where_roles;
SET SESSION AUTHORIZATION safesession_rw_login;
CREATE FUNCTION pg_temp.rw_cached() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM rw_items;
END $$;
BEGIN;
SELECT pg_temp.rw_cached();
ROLLBACK;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.require_where_roles = 'safesession_rw_login';
SET SESSION AUTHORIZATION safesession_rw_login;
\set SHOW_CONTEXT never
SELECT pg_temp.rw_cached();
\set SHOW_CONTEXT errors
RESET SESSION AUTHORIZATION;
-- Cached by an unlisted login in this session, then run as a listed one
SET SESSION AUTHORIZATION safesession_rw_other;
PREPARE rw_del2 AS DELETE FROM rw_items;
BEGIN;
EXECUTE rw_del2;
ROLLBACK;
RESET SESSION AUTHORIZATION;
SET SESSION AUTHORIZATION safesession_rw_login;
EXECUTE rw_del2;
DEALLOCATE rw_del2;
RESET SESSION AUTHORIZATION;
DROP FUNCTION pg_temp.rw_cached();

-------------------------------------------------------------------------
-- Test 6: only a superuser can change the setting, and a list that does
-- not parse is refused.
-------------------------------------------------------------------------
SET pgedge_safesession.require_where_roles = 'a,,b';
SET SESSION AUTHORIZATION safesession_rw_login;
SET pgedge_safesession.require_where_roles = '';
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 7: on PostgreSQL 16 and later, a CREATEROLE role is given an
-- ADMIN-only membership in each role it creates. It cannot act as that
-- role, so it is not covered when that role is listed.
-------------------------------------------------------------------------
CREATE ROLE safesession_rw_admin LOGIN CREATEROLE;
GRANT ALL ON rw_items TO safesession_rw_admin;
SET SESSION AUTHORIZATION safesession_rw_admin;
CREATE ROLE safesession_rw_made LOGIN;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.require_where_roles = 'safesession_rw_made';
SET SESSION AUTHORIZATION safesession_rw_admin;
BEGIN;
DELETE FROM rw_items;
ROLLBACK;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 8: a read-only session gets the read-only error, which PostgREST
-- answers with 405, not the WHERE one.
-------------------------------------------------------------------------
SET pgedge_safesession.require_where_roles = 'safesession_rw_login';
SET pgedge_safesession.read_only_roles = 'safesession_rw_login';
SET SESSION AUTHORIZATION safesession_rw_login;
DELETE FROM rw_items;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.read_only_roles;

-------------------------------------------------------------------------
-- Test 9: a plan made under a session user that is not covered is not
-- reused under one that is, even after a switch that was rolled back and
-- a statement that failed.
-------------------------------------------------------------------------
CREATE FUNCTION rw_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('is_superuser') = 'on' THEN
        RAISE EXCEPTION 'failed while running';
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER rw_guard BEFORE DELETE ON rw_items
    FOR EACH STATEMENT EXECUTE FUNCTION rw_guard();
CREATE FUNCTION rw_del_all() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM rw_items;
END $$;
SET plan_cache_mode = force_generic_plan;
BEGIN;
SET SESSION AUTHORIZATION safesession_rw_login;
ROLLBACK;
\set SHOW_CONTEXT never
SELECT rw_del_all();
SET SESSION AUTHORIZATION safesession_rw_login;
SELECT rw_del_all();
RESET SESSION AUTHORIZATION;
\set SHOW_CONTEXT errors
RESET plan_cache_mode;
DROP TRIGGER rw_guard ON rw_items;
DROP FUNCTION rw_guard();
SELECT count(*) AS rows_left FROM rw_items;

-------------------------------------------------------------------------
-- Test 10: a change of the database's owner is noticed, with
-- pg_database_owner listed: a plan cached while the login did not own
-- the database is checked again once it does.
-------------------------------------------------------------------------
CREATE FUNCTION rw_set_owner(r text) RETURNS void LANGUAGE plpgsql
    SECURITY DEFINER AS $$
BEGIN
    EXECUTE format('ALTER DATABASE %I OWNER TO %I', current_database(), r);
END $$;
GRANT EXECUTE ON FUNCTION rw_set_owner(text) TO safesession_rw_login;
SELECT d.datdba::regrole::text AS old_owner FROM pg_database d
    WHERE d.datname = current_database() \gset
SET pgedge_safesession.require_where_roles = 'pg_database_owner';
SET SESSION AUTHORIZATION safesession_rw_login;
SET plan_cache_mode = force_generic_plan;
PREPARE rw_owner_del AS DELETE FROM rw_items;
BEGIN;
EXECUTE rw_owner_del;
ROLLBACK;
SELECT rw_set_owner('safesession_rw_login');
EXECUTE rw_owner_del;
SELECT rw_set_owner(:'old_owner');
DEALLOCATE rw_owner_del;
RESET plan_cache_mode;
RESET SESSION AUTHORIZATION;
DROP FUNCTION rw_set_owner(text);

-------------------------------------------------------------------------
-- Test 11: in a delegating session, an unfiltered UPDATE or DELETE made
-- while the acting role is read-only is refused at once, with the
-- read-only error, so no unchecked plan is left to run after a switch to
-- a role that can write. A filtered one still works there.
-------------------------------------------------------------------------
CREATE ROLE safesession_rw_pool LOGIN NOINHERIT;
CREATE ROLE safesession_rw_ro NOLOGIN;
CREATE ROLE safesession_rw_wr NOLOGIN;
GRANT safesession_rw_ro, safesession_rw_wr TO safesession_rw_pool;
GRANT ALL ON rw_items TO safesession_rw_ro, safesession_rw_wr;
SET pgedge_safesession.require_where_roles = 'safesession_rw_pool';
SET pgedge_safesession.delegating_roles = 'safesession_rw_pool';
SET pgedge_safesession.acting_read_only_roles = 'safesession_rw_ro';
SET plan_cache_mode = force_generic_plan;
SET SESSION AUTHORIZATION safesession_rw_pool;
BEGIN;
SELECT set_config('role', 'safesession_rw_ro', true);
PREPARE rw_ro_all AS DELETE FROM rw_items;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_rw_ro', true);
PREPARE rw_ro_one AS DELETE FROM rw_items WHERE id = 1;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_rw_wr', true);
EXECUTE rw_ro_all;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_rw_wr', true);
EXECUTE rw_ro_one;
ROLLBACK;
DEALLOCATE rw_ro_one;
RESET SESSION AUTHORIZATION;
RESET plan_cache_mode;
RESET pgedge_safesession.acting_read_only_roles;
RESET pgedge_safesession.delegating_roles;

-------------------------------------------------------------------------
-- Test 12: a change of session user in the middle of a statement, from
-- set_config(), discards cached plans before anything else runs, so a
-- plan cached under a session user that is not covered is checked again.
-------------------------------------------------------------------------
CREATE FUNCTION rw_del_arg(x text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM rw_items;
    RETURN 'deleted';
END $$;
SET pgedge_safesession.require_where_roles = 'safesession_rw_login';
SET plan_cache_mode = force_generic_plan;
BEGIN;
SELECT rw_del_arg('as a superuser');
ROLLBACK;
\set SHOW_CONTEXT never
BEGIN;
SELECT rw_del_arg(set_config('session_authorization',
                             'safesession_rw_login', true));
ROLLBACK;
\set SHOW_CONTEXT errors
RESET plan_cache_mode;
DROP FUNCTION rw_del_arg(text);

-------------------------------------------------------------------------
-- Test 13: a plan made before the rule applied is refused when it runs
-- after the rule starts to apply in the same transaction. On PostgreSQL
-- 14 to 17 a SQL function plans all its statements when it starts, so here
-- the DELETE is planned before the GRANT that makes the caller covered.
-- WHERE true still counts as a WHERE clause.
-------------------------------------------------------------------------
CREATE ROLE safesession_rw_guard NOLOGIN;
CREATE ROLE safesession_rw_caller LOGIN;
GRANT ALL ON rw_items TO safesession_rw_caller;
CREATE FUNCTION rw_grant_delete() RETURNS void LANGUAGE sql
    SECURITY DEFINER AS $$
    GRANT safesession_rw_guard TO safesession_rw_caller;
    DELETE FROM rw_items;
$$;
CREATE FUNCTION rw_grant_delete_true() RETURNS void LANGUAGE sql
    SECURITY DEFINER AS $$
    GRANT safesession_rw_guard TO safesession_rw_caller;
    DELETE FROM rw_items WHERE true;
$$;
GRANT EXECUTE ON FUNCTION rw_grant_delete(), rw_grant_delete_true()
    TO safesession_rw_caller;
SET pgedge_safesession.require_where_roles = 'safesession_rw_guard';
SET SESSION AUTHORIZATION safesession_rw_caller;
\set SHOW_CONTEXT never
BEGIN;
SELECT rw_grant_delete();
ROLLBACK;
\set SHOW_CONTEXT errors
BEGIN;
SELECT rw_grant_delete_true();
SELECT count(*) AS rows_left_where_true FROM rw_items;
ROLLBACK;
RESET SESSION AUTHORIZATION;
SELECT count(*) AS rows_left FROM rw_items;
DROP FUNCTION rw_grant_delete();
DROP FUNCTION rw_grant_delete_true();

-- Cleanup
RESET pgedge_safesession.require_where_roles;
SELECT * FROM rw_items ORDER BY id;
DROP FUNCTION rw_sql_delete();
DROP FUNCTION rw_plpgsql_delete();
DROP FUNCTION rw_definer_delete();
DROP FUNCTION rw_atomic_delete();
DROP FUNCTION rw_del_all();
DROP VIEW rw_view;
DROP TABLE rw_items;
DROP ROLE safesession_rw_login;
DROP ROLE safesession_rw_member;
DROP ROLE safesession_rw_group;
DROP ROLE safesession_rw_other;
DROP ROLE safesession_rw_owner;
DROP ROLE safesession_rw_made;
DROP ROLE safesession_rw_admin;
DROP ROLE safesession_rw_pool;
DROP ROLE safesession_rw_ro;
DROP ROLE safesession_rw_wr;
DROP ROLE safesession_rw_guard;
DROP ROLE safesession_rw_caller;
DROP EXTENSION pgedge_safesession;
