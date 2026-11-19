-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- The role lock: a delegating login (safesession_lk_auth, standing in for
-- PostgREST's authenticator) may switch role once per transaction. After
-- that, the role and the request settings it already has cannot change.
-- Each request below is written the way PostgREST sends it: a
-- transaction whose first statement switches role with
-- set_config(..., true) and sets the request's settings.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP FUNCTION IF EXISTS ss_lk_try(text);
DROP FUNCTION IF EXISTS ss_lk_set_role();
DROP FUNCTION IF EXISTS ss_lk_definer();
DROP FUNCTION IF EXISTS ss_lk_claims();
DROP TABLE IF EXISTS ss_lk_notes;
DROP ROLE IF EXISTS safesession_lk_person;
DROP ROLE IF EXISTS safesession_lk_super;
DROP ROLE IF EXISTS safesession_lk_auth;
DROP ROLE IF EXISTS safesession_lk_anon;
DROP ROLE IF EXISTS safesession_lk_user;
DROP ROLE IF EXISTS safesession_lk_admin;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_lk_anon NOLOGIN;
CREATE ROLE safesession_lk_user NOLOGIN;
CREATE ROLE safesession_lk_admin NOLOGIN;
CREATE ROLE safesession_lk_auth LOGIN NOINHERIT;
GRANT safesession_lk_anon, safesession_lk_user, safesession_lk_admin
    TO safesession_lk_auth;
-- A superuser login, for a pool that switches with SESSION AUTHORIZATION
CREATE ROLE safesession_lk_super SUPERUSER LOGIN;
-- A person who logs in directly: not a delegating session
CREATE ROLE safesession_lk_person LOGIN;
GRANT safesession_lk_user, safesession_lk_admin TO safesession_lk_person;

-- Rows each user may read, chosen by the request's claims
CREATE TABLE ss_lk_notes (owner text, val text);
INSERT INTO ss_lk_notes VALUES ('1', 'one'), ('2', 'two');
ALTER TABLE ss_lk_notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY ss_lk_own ON ss_lk_notes FOR SELECT USING
    (owner = current_setting('request.jwt.claims', true)::json->>'sub');
GRANT SELECT ON ss_lk_notes TO safesession_lk_user;

-- Run a statement and give the SQLSTATE it fails with, or ok
CREATE FUNCTION ss_lk_try(stmt text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE stmt;
    RETURN 'ok';
EXCEPTION WHEN OTHERS THEN
    RETURN SQLSTATE || ': ' || SQLERRM;
END $$;
GRANT EXECUTE ON FUNCTION ss_lk_try(text) TO PUBLIC;

-- A function that switches role with a SET clause
CREATE FUNCTION ss_lk_set_role() RETURNS text LANGUAGE sql
    SET role = 'safesession_lk_admin'
    AS $$ SELECT current_user::text $$;
GRANT EXECUTE ON FUNCTION ss_lk_set_role() TO PUBLIC;

-- A SECURITY DEFINER function changes the user without the role setting
CREATE FUNCTION ss_lk_definer() RETURNS text LANGUAGE sql SECURITY DEFINER
    AS $$ SELECT current_user::text $$;
GRANT EXECUTE ON FUNCTION ss_lk_definer() TO PUBLIC;
-- A fixed owner, so the output does not depend on who runs the tests
ALTER FUNCTION ss_lk_definer() OWNER TO safesession_lk_admin;

-- A function that rewrites the claims
CREATE FUNCTION ss_lk_claims() RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    PERFORM set_config('request.jwt.claims', '{"sub": "2"}', true);
    RETURN current_setting('request.jwt.claims');
END $$;
GRANT EXECUTE ON FUNCTION ss_lk_claims() TO PUBLIC;

SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SHOW pgedge_safesession.locked_setting_prefixes;

-------------------------------------------------------------------------
-- Test 1: the first role switch in a transaction is allowed; any later
-- one is refused, however it is made, with SQLSTATE 42501 (PostgREST
-- answers 403, or 401 with no token).
-------------------------------------------------------------------------
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT current_user;
SELECT set_config('role', 'safesession_lk_admin', true);
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SET ROLE safesession_lk_admin');
SELECT ss_lk_try('SET LOCAL ROLE safesession_lk_admin');
-- Setting the same role again is a second change too
SELECT ss_lk_try('SET LOCAL ROLE safesession_lk_user');
SELECT ss_lk_try('RESET ROLE');
SELECT ss_lk_try('SET ROLE NONE');
SELECT ss_lk_try('SELECT set_config(''role'', ''none'', true)');
SELECT ss_lk_try('SELECT set_config(''role'', ''safesession_lk_admin'','
                 || ' false)');
SELECT ss_lk_try('SELECT ss_lk_set_role()');
SELECT ss_lk_try('RESET SESSION AUTHORIZATION');
SELECT ss_lk_try('SET SESSION AUTHORIZATION DEFAULT');
-- Still the role it switched to, and a later statement still works
SELECT current_user;
SELECT ss_lk_try('SELECT 1');
COMMIT;

-------------------------------------------------------------------------
-- Test 2: after a refused request, the next request on the same
-- connection works and may switch to another role.
-------------------------------------------------------------------------
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SET ROLE safesession_lk_admin;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_admin', true);
SELECT current_user;
COMMIT;
SELECT current_user;

-------------------------------------------------------------------------
-- Test 3: the request's settings are held after the switch statement.
-- Changing, resetting or setting them for the session is refused; they
-- keep their values, and row-level security reads them as before. Other
-- settings, such as the response's, still change.
-------------------------------------------------------------------------
BEGIN;
SELECT set_config('search_path', 'public', true),
       set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true),
       set_config('request.method', 'GET', true);
SELECT * FROM ss_lk_notes;
SELECT ss_lk_try('SELECT set_config(''request.jwt.claims'','
                 || ' ''{"sub": "2"}'', true)');
SELECT ss_lk_try('SELECT set_config(''request.jwt.claims'','
                 || ' ''{"sub": "2"}'', false)');
SELECT ss_lk_try('SET LOCAL request.jwt.claims = ''{"sub": "2"}''');
SELECT ss_lk_try('RESET request.jwt.claims');
SELECT ss_lk_try('SELECT set_config(''request.method'', NULL, true)');
SELECT ss_lk_try('SELECT ss_lk_claims()');
SELECT current_setting('request.jwt.claims'),
       current_setting('request.method');
SELECT * FROM ss_lk_notes;
SELECT set_config('response.status', '201', true),
       set_config('response.headers', '[{"X-A": "b"}]', true);
COMMIT;

-- The next request sets its own claims
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "2"}', true);
SELECT * FROM ss_lk_notes;
COMMIT;
-- Outside a request the settings read as before: empty
SELECT current_setting('request.jwt.claims', true) AS claims;

-- A refused change inside the request's own exception block keeps the
-- value, and a direct one aborts the request
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT ss_lk_try('SELECT ss_lk_claims()');
SELECT current_setting('request.jwt.claims');
SELECT ss_lk_claims();
ROLLBACK;

-------------------------------------------------------------------------
-- Test 4: a pool that sets the role in one statement and the settings in
-- the next is refused once the settings are held: set them in the same
-- statement as the role, or before it.
-------------------------------------------------------------------------
BEGIN;
SET LOCAL ROLE safesession_lk_user;
SET LOCAL request.jwt.claims = '{"sub": "1"}';
ROLLBACK;
BEGIN;
SET LOCAL request.jwt.claims = '{"sub": "1"}';
SET LOCAL ROLE safesession_lk_user;
SELECT * FROM ss_lk_notes;
COMMIT;

-------------------------------------------------------------------------
-- Test 5: savepoints. A switch inside a savepoint that rolls back never
-- happened, so the next one is allowed. A request's own savepoint cannot
-- undo the lock.
-------------------------------------------------------------------------
BEGIN;
SAVEPOINT a;
SELECT set_config('role', 'safesession_lk_admin', true);
ROLLBACK TO a;
SELECT current_user;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT current_user;
SAVEPOINT b;
SELECT ss_lk_try('SET LOCAL ROLE safesession_lk_admin');
ROLLBACK TO b;
SELECT ss_lk_try('SET LOCAL ROLE safesession_lk_admin');
RELEASE b;
SELECT current_user;
COMMIT;

-- A switch in a savepoint that is released belongs to the transaction
BEGIN;
SAVEPOINT a;
SELECT set_config('role', 'safesession_lk_user', true);
RELEASE a;
SELECT ss_lk_try('SET LOCAL ROLE safesession_lk_admin');
COMMIT;

-------------------------------------------------------------------------
-- Test 6: SECURITY DEFINER functions work as before after the switch.
-------------------------------------------------------------------------
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_definer(), current_user;
COMMIT;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 7: locked_setting_prefixes chooses what is held. An empty list
-- holds nothing; a prefix holds the names under it, not names that only
-- start with the same letters.
-------------------------------------------------------------------------
SET pgedge_safesession.locked_setting_prefixes = 'app.user';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('app.user.id', '1', true),
       set_config('app.username', 'a', true),
       set_config('app.other', 'x', true);
SELECT ss_lk_try('SELECT set_config(''app.user.id'', ''2'', true)');
SELECT ss_lk_try('SELECT set_config(''app.username'', ''b'', true)');
SELECT ss_lk_try('SELECT set_config(''app.other'', ''y'', true)');
COMMIT;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.locked_setting_prefixes = '';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('app.free.id', '1', true);
SELECT ss_lk_try('SELECT set_config(''app.free.id'', ''2'', true)');
-- The role is still locked
SELECT ss_lk_try('SET LOCAL ROLE safesession_lk_admin');
COMMIT;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.locked_setting_prefixes;

-- Each entry must be a prefix; only a superuser can change the list
SET pgedge_safesession.locked_setting_prefixes = 'request.';
SET pgedge_safesession.locked_setting_prefixes = '1abc';
SET pgedge_safesession.locked_setting_prefixes = 'request, "jwt.claims"';
SHOW pgedge_safesession.locked_setting_prefixes;
RESET pgedge_safesession.locked_setting_prefixes;
SET SESSION AUTHORIZATION safesession_lk_auth;
SET pgedge_safesession.locked_setting_prefixes = '';
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 8: a superuser login on delegating_roles that switches with SET
-- SESSION AUTHORIZATION is locked the same way.
-------------------------------------------------------------------------
SET pgedge_safesession.delegating_roles =
    'safesession_lk_auth, safesession_lk_super';
SET SESSION AUTHORIZATION safesession_lk_super;
BEGIN;
SET LOCAL SESSION AUTHORIZATION safesession_lk_auth;
SELECT session_user, current_user;
SELECT ss_lk_try('SET LOCAL ROLE safesession_lk_user');
SELECT ss_lk_try('SET LOCAL SESSION AUTHORIZATION safesession_lk_super');
-- The same role again, for the whole session, is refused too
SELECT ss_lk_try('SET SESSION AUTHORIZATION safesession_lk_auth');
SELECT ss_lk_try('SET ROLE NONE');
COMMIT;
SELECT session_user, current_user;
-- A pool whose session has a role set can still switch
SET ROLE safesession_lk_admin;
BEGIN;
SET LOCAL SESSION AUTHORIZATION safesession_lk_auth;
SELECT session_user, current_user;
COMMIT;
SELECT session_user, current_user;
RESET ROLE;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 9: only delegating sessions are locked. A person who logs in
-- directly, and every login while delegating_roles is empty, may switch
-- as often as before.
-------------------------------------------------------------------------
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_person;
BEGIN;
SET LOCAL ROLE safesession_lk_user;
SET LOCAL ROLE safesession_lk_admin;
RESET ROLE;
SELECT current_user;
COMMIT;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.delegating_roles;
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT set_config('role', 'safesession_lk_admin', true);
SELECT set_config('request.jwt.claims', '{"sub": "2"}', true);
COMMIT;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 10: a request setting the pool starts to set later in the session
-- is held too, and so is one whose name the pool passes as a parameter.
-------------------------------------------------------------------------
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.cookies', 'a=1', true);
SELECT ss_lk_try('SELECT set_config(''request.cookies'', ''a=2'', true)');
COMMIT;
PREPARE ss_lk_switch(text) AS
    SELECT set_config('role', 'safesession_lk_user', true),
           set_config($1, 'x', true);
BEGIN;
EXECUTE ss_lk_switch('request.header.x_a');
SELECT ss_lk_try('SELECT set_config(''request.header.x_a'', ''y'', true)');
COMMIT;
DEALLOCATE ss_lk_switch;

-- A request setting a request creates itself is held from the next
-- request on the connection, like any other the session has
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SELECT set_config(''request.own'', ''1'', true)');
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SELECT set_config(''request.own'', ''2'', true)');
COMMIT;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 11: a parallel worker has no lock of its own, so there a function
-- whose SET clause sets the role or a held setting is refused. Other SET
-- clauses still work.
-------------------------------------------------------------------------
CREATE FUNCTION ss_lk_par_role() RETURNS text LANGUAGE sql PARALLEL SAFE
    SET role = 'safesession_lk_admin' AS $$ SELECT current_user::text $$;
CREATE FUNCTION ss_lk_par_claims() RETURNS text LANGUAGE sql PARALLEL SAFE
    SET request.jwt.claims = '{"sub": "2"}'
    AS $$ SELECT current_setting('request.jwt.claims') $$;
CREATE FUNCTION ss_lk_par_ok() RETURNS text LANGUAGE sql PARALLEL SAFE
    SET search_path = public AS $$ SELECT current_user::text $$;
GRANT EXECUTE ON FUNCTION ss_lk_par_role(), ss_lk_par_claims(),
    ss_lk_par_ok() TO PUBLIC;
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT set_config(CASE WHEN current_setting('server_version_num')::int
                            >= 160000
                       THEN 'debug_parallel_query'
                       ELSE 'force_parallel_mode' END, 'on', true)
    IS NOT NULL AS parallel;
SELECT ss_lk_try('SELECT ss_lk_par_role()');
SELECT ss_lk_try('SELECT ss_lk_par_claims()');
SELECT ss_lk_par_ok();
SELECT current_user, current_setting('request.jwt.claims');
COMMIT;
RESET SESSION AUTHORIZATION;
DROP FUNCTION ss_lk_par_role();
DROP FUNCTION ss_lk_par_claims();
DROP FUNCTION ss_lk_par_ok();

-------------------------------------------------------------------------
-- Test 12: however a request creates a request setting, it is held from
-- the next request on: through a view, a SQL-standard function body, a
-- name built at run time, a function's SET clause and SET LOCAL. A new
-- connection starts without the settings these functions name.
-------------------------------------------------------------------------
CREATE VIEW ss_lk_view AS SELECT set_config('request.via_view', '1', true);
CREATE FUNCTION ss_lk_body() RETURNS text LANGUAGE sql
    RETURN set_config('request.via_body', '1', true);
CREATE FUNCTION ss_lk_clause() RETURNS text LANGUAGE sql
    SET request.via_clause = '1' AS $$ SELECT 'x' $$;
CREATE FUNCTION ss_lk_dyn(n text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    RETURN set_config('request.' || n, '1', true);
END $$;
GRANT SELECT ON ss_lk_view TO PUBLIC;
GRANT EXECUTE ON FUNCTION ss_lk_body(), ss_lk_clause(), ss_lk_dyn(text)
    TO PUBLIC;
\c
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
-- Each request creates one setting; the next request may not change it
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT * FROM ss_lk_view;
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SELECT set_config(''request.via_view'', ''2'', true)');
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_body();
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SELECT set_config(''request.via_body'', ''2'', true)');
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_dyn('via_dyn');
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SELECT set_config(''request.via_dyn'', ''2'', true)');
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_clause();
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SELECT set_config(''request.via_clause'', ''2'', true)');
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SET LOCAL request.via_set = '1';
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SELECT set_config(''request.via_set'', ''2'', true)');
COMMIT;
RESET SESSION AUTHORIZATION;
DROP VIEW ss_lk_view;
DROP FUNCTION ss_lk_body();
DROP FUNCTION ss_lk_clause();
DROP FUNCTION ss_lk_dyn(text);
RESET pgedge_safesession.delegating_roles;

-------------------------------------------------------------------------
-- Test 13: a setting the pool creates in its switch statement is held
-- however the statement sets it: through a view, or with a name passed as
-- a parameter inside a WITH query. Each starts on a new connection.
-------------------------------------------------------------------------
CREATE VIEW ss_lk_pool_view AS
    SELECT set_config('request.pool_view', '1', true) AS v;
GRANT SELECT ON ss_lk_pool_view TO safesession_lk_auth;
\c
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true), v
    FROM ss_lk_pool_view;
SELECT ss_lk_try('SELECT set_config(''request.pool_view'', ''2'', true)');
COMMIT;
RESET SESSION AUTHORIZATION;
\c
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
PREPARE ss_lk_cte(text) AS
    WITH c AS MATERIALIZED (SELECT set_config($1, 'v', true) AS x)
    SELECT set_config('role', 'safesession_lk_user', true), x FROM c;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
COMMIT;
BEGIN;
EXECUTE ss_lk_cte('request.pool_cte');
SELECT ss_lk_try('SELECT set_config(''request.pool_cte'', ''2'', true)');
COMMIT;
DEALLOCATE ss_lk_cte;
RESET SESSION AUTHORIZATION;
DROP VIEW ss_lk_pool_view;
RESET pgedge_safesession.delegating_roles;

-- Cleanup
DROP FUNCTION ss_lk_try(text);
DROP FUNCTION ss_lk_set_role();
DROP FUNCTION ss_lk_definer();
DROP FUNCTION ss_lk_claims();
DROP TABLE ss_lk_notes;
DROP ROLE safesession_lk_person;
DROP ROLE safesession_lk_super;
DROP ROLE safesession_lk_auth;
DROP ROLE safesession_lk_anon;
DROP ROLE safesession_lk_user;
DROP ROLE safesession_lk_admin;
