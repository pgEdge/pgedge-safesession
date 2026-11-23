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

-- A request cannot create a request setting of its own after the switch,
-- in this request or a later one
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
-- Test 12: after the switch, a request cannot create a setting under a
-- locked prefix that the pool did not set, however it tries, so a policy
-- that reads such a name, such as an older PostgREST claim, cannot be
-- fooled. A name built at run time is caught when the statement ends, also
-- when a savepoint that rolled back made it.
-------------------------------------------------------------------------
CREATE TABLE ss_lk_orgs (org text);
INSERT INTO ss_lk_orgs VALUES ('a'), ('b');
ALTER TABLE ss_lk_orgs ENABLE ROW LEVEL SECURITY;
CREATE POLICY ss_lk_org ON ss_lk_orgs FOR SELECT
    USING (org = current_setting('request.jwt.claim.org', true));
GRANT SELECT ON ss_lk_orgs TO safesession_lk_user;
CREATE VIEW ss_lk_view AS
    SELECT set_config('request.jwt.claim.org', 'b', true);
CREATE FUNCTION ss_lk_body() RETURNS text LANGUAGE sql
    RETURN set_config('request.jwt.claim.org', 'b', true);
CREATE FUNCTION ss_lk_clause() RETURNS text LANGUAGE sql
    SET request.jwt.claim.org = 'b' AS $$ SELECT 'x' $$;
CREATE FUNCTION ss_lk_dyn(n text) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    RETURN set_config('request.' || n, 'b', true);
END $$;
GRANT SELECT ON ss_lk_view TO PUBLIC;
GRANT EXECUTE ON FUNCTION ss_lk_body(), ss_lk_clause(), ss_lk_dyn(text)
    TO PUBLIC;
-- A new connection, without the setting creating ss_lk_clause made
\c
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT x AS how, ss_lk_try(x) AS result FROM unnest(ARRAY[
    'SELECT set_config(''request.jwt.claim.org'', ''b'', true)',
    'SET LOCAL request.jwt.claim.org = ''b''',
    'SET request.jwt.claim.org = ''b''',
    'RESET request.jwt.claim.org',
    'SELECT * FROM ss_lk_view',
    'SELECT ss_lk_body()',
    'SELECT ss_lk_clause()',
    'CREATE FUNCTION ss_lk_made() RETURNS int LANGUAGE sql'
        || ' SET request.jwt.claim.org = ''b'' AS $f$ SELECT 1 $f$',
    'ALTER ROLE safesession_lk_user SET request.jwt.claim.org = ''b''',
    'RESET ALL']) AS x;
SELECT count(*) AS orgs_seen FROM ss_lk_orgs;
COMMIT;
\set SHOW_CONTEXT never
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_dyn('jwt.claim.dept');
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SELECT ss_lk_dyn(''jwt.claim.team''),'
                 || ' 1 / (random() * 0)::int');
ROLLBACK;
\set SHOW_CONTEXT errors
-- The next request works
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT count(*) AS orgs_seen FROM ss_lk_orgs;
COMMIT;
RESET SESSION AUTHORIZATION;
DROP VIEW ss_lk_view;
DROP FUNCTION ss_lk_body();
DROP FUNCTION ss_lk_clause();
DROP FUNCTION ss_lk_dyn(text);
DROP TABLE ss_lk_orgs;
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

-------------------------------------------------------------------------
-- Test 14: a switch into the login role itself leaves that role set
-- explicitly, and the lock keeps it so: going back to no role would make
-- the request look like the pool's own statement, which is not read-only.
-------------------------------------------------------------------------
CREATE ROLE safesession_lk_ro NOLOGIN;
GRANT safesession_lk_ro TO safesession_lk_auth;
SET pgedge_safesession.read_only_roles = 'safesession_lk_ro';
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_auth', true);
SELECT ss_lk_try('RESET ROLE');
SELECT pgedge_safesession_is_restricted() AS read_only;
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_auth', true),
       set_config('role', NULL, true);
ROLLBACK;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.read_only_roles;
RESET pgedge_safesession.delegating_roles;
DROP ROLE safesession_lk_ro;

-------------------------------------------------------------------------
-- Test 15: a superuser pool whose login sets a role, here with a
-- connection option, can switch with RESET SESSION AUTHORIZATION: Postgres
-- then sets the login's role again, as part of the same switch.
-------------------------------------------------------------------------
SELECT format('-c role=safesession_lk_user'
              ' -c pgedge_safesession.delegating_roles=%s',
              quote_ident(current_user)) AS ss_lk_options,
       format('dbname=%s', current_database()) AS ss_lk_db \gset
\setenv PGOPTIONS :ss_lk_options
\c -reuse-previous=off :ss_lk_db
SELECT current_user;
BEGIN;
RESET SESSION AUTHORIZATION;
SELECT current_user;
SELECT ss_lk_try('SET ROLE NONE');
COMMIT;
\setenv PGOPTIONS
\c -reuse-previous=off :ss_lk_db

-------------------------------------------------------------------------
-- Test 16: the prefix list decides what is held on a connection that is
-- reused after it changes, and a long prefix is kept whole.
-------------------------------------------------------------------------
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT ss_lk_try('SELECT set_config(''request.jwt.claims'', ''x'', true)');
COMMIT;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.locked_setting_prefixes = 'jwt';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT ss_lk_try('SELECT set_config(''request.jwt.claims'', ''x'', true)');
COMMIT;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.locked_setting_prefixes;
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT ss_lk_try('SELECT set_config(''request.jwt.claims'', ''x'', true)');
COMMIT;
RESET SESSION AUTHORIZATION;
SELECT 'ss' || repeat('x', 68) AS ss_lk_long \gset
SELECT 'request, ' || :'ss_lk_long' AS ss_lk_prefixes,
       :'ss_lk_long' || '.claims' AS ss_lk_long_name \gset
SET pgedge_safesession.locked_setting_prefixes = :'ss_lk_prefixes';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config(:'ss_lk_long_name', 'a', true) IS NOT NULL AS long_set;
SELECT ss_lk_try(format('SELECT set_config(%L, %L, true)',
                        :'ss_lk_long_name', 'b'));
COMMIT;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.locked_setting_prefixes;

-------------------------------------------------------------------------
-- Test 17: a request setting the pool sets with its name as a parameter
-- that only a LIMIT uses, or in an argument of EXECUTE, is held too.
-------------------------------------------------------------------------
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
PREPARE ss_lk_lim(text, text) AS
    SELECT set_config('role', 'safesession_lk_user', true)
    LIMIT (SELECT 1 WHERE set_config($1, $2, true) IS NOT NULL);
BEGIN;
EXECUTE ss_lk_lim('request.lim', 'v');
SELECT ss_lk_try('SELECT set_config(''request.lim'', ''x'', true)');
COMMIT;
PREPARE ss_lk_arg(text) AS
    SELECT set_config('role', 'safesession_lk_user', true), $1 AS arg;
BEGIN;
EXECUTE ss_lk_arg(set_config('request.arg', 'v', true));
SELECT ss_lk_try('SELECT set_config(''request.arg'', ''x'', true)');
COMMIT;
DEALLOCATE ss_lk_lim;
DEALLOCATE ss_lk_arg;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 18: a setting another extension defines under a locked prefix
-- cannot be changed after the switch either.
-------------------------------------------------------------------------
-- PL/pgSQL, loaded by the functions above, defines plpgsql.* settings
SET pgedge_safesession.locked_setting_prefixes = 'request, plpgsql';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SET LOCAL plpgsql.extra_warnings = ''all''');
SELECT ss_lk_try('SELECT set_config(''plpgsql.extra_warnings'','
                 || ' ''all'', true)');
SELECT current_setting('plpgsql.extra_warnings') AS extra_warnings;
COMMIT;
RESET SESSION AUTHORIZATION;
RESET pgedge_safesession.locked_setting_prefixes;
RESET pgedge_safesession.delegating_roles;

-------------------------------------------------------------------------
-- Test 19: a request setting made with a name built at run time where
-- PostgreSQL undoes it before the end of the statement, inside CREATE
-- INDEX, is still found when the statement ends, also when the function
-- already ran in the request; so is one an AFTER trigger makes. A
-- function with a SET clause can still set response.status that way. A
-- superuser not on delegating_roles that becomes the pool's login with
-- SET SESSION AUTHORIZATION is not locked.
-------------------------------------------------------------------------
CREATE FUNCTION ss_lk_forge(name text, n int) RETURNS int
    LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE v text;
BEGIN
    v := set_config(name, 'x', true);
    RETURN n;
END $$;
CREATE FUNCTION ss_lk_status() RETURNS text LANGUAGE plpgsql
    SECURITY DEFINER SET search_path = public AS $$
DECLARE v text;
BEGIN
    v := set_config('response.' || 'status', '201', true);
    RETURN v;
END $$;
CREATE SCHEMA ss_lk_s AUTHORIZATION safesession_lk_user;
CREATE TABLE ss_lk_s.ss_lk_own (id int);
INSERT INTO ss_lk_s.ss_lk_own VALUES (1);
ALTER TABLE ss_lk_s.ss_lk_own OWNER TO safesession_lk_user;
CREATE FUNCTION ss_lk_after() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v text;
BEGIN
    v := set_config('request.' || 'after', 'x', true);
    RETURN NULL;
END $$;
CREATE TRIGGER ss_lk_after AFTER INSERT ON ss_lk_s.ss_lk_own
    FOR EACH ROW EXECUTE FUNCTION ss_lk_after();
GRANT EXECUTE ON FUNCTION ss_lk_forge(text, int), ss_lk_after(),
    ss_lk_status() TO PUBLIC;
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
\set SHOW_CONTEXT never
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
CREATE INDEX ON ss_lk_s.ss_lk_own
    ((public.ss_lk_forge('request.' || 'forged', id)));
ROLLBACK;
-- The function runs first with a harmless name, so PL/pgSQL keeps its
-- set_config() expression for the index build
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SET LOCAL search_path = pg_catalog, pg_temp;
SELECT public.ss_lk_forge('response.' || 'status', 0) AS primed;
CREATE INDEX ON ss_lk_s.ss_lk_own
    ((public.ss_lk_forge('request.' || 'primed', id)));
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_status() AS status;
COMMIT;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
INSERT INTO ss_lk_s.ss_lk_own VALUES (2);
ROLLBACK;
\set SHOW_CONTEXT errors
RESET SESSION AUTHORIZATION;
SELECT count(*) AS own_rows FROM ss_lk_s.ss_lk_own;
BEGIN;
SET LOCAL SESSION AUTHORIZATION safesession_lk_auth;
RESET SESSION AUTHORIZATION;
SET LOCAL SESSION AUTHORIZATION safesession_lk_auth;
SELECT current_user;
COMMIT;
DROP SCHEMA ss_lk_s CASCADE;
DROP FUNCTION ss_lk_forge(text, int);
DROP FUNCTION ss_lk_after();
DROP FUNCTION ss_lk_status();
RESET pgedge_safesession.delegating_roles;

-------------------------------------------------------------------------
-- Test 20: after the switch, a request cannot change a setting for the
-- whole session, with SET, RESET or set_config(..., false or null), also
-- with a name built at run time or one that starts with transaction_
-- (only SET TRANSACTION's own settings are let through), so nothing is
-- left for the next request on the connection. SET LOCAL,
-- set_config(..., true) and SET TRANSACTION still work, and after each
-- refusal the next request works.
-------------------------------------------------------------------------
CREATE FUNCTION ss_lk_session_set(name text) RETURNS text
    LANGUAGE plpgsql AS $$
DECLARE v text;
BEGIN
    v := set_config(name, 'leaked', false);
    RETURN v;
END $$;
GRANT EXECUTE ON FUNCTION ss_lk_session_set(text) TO PUBLIC;
CREATE FUNCTION ss_lk_set_any(name text, value text, local bool)
    RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    RETURN set_config(name, value, local);
END $$;
GRANT EXECUTE ON FUNCTION ss_lk_set_any(text, text, bool) TO PUBLIC;
CREATE FUNCTION ss_lk_pick(name text, value text, local bool)
    RETURNS int LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN length(set_config(name, value, local));
END $$;
GRANT EXECUTE ON FUNCTION ss_lk_pick(text, text, bool) TO PUBLIC;
CREATE TABLE ss_lk_part (k int) PARTITION BY LIST (k);
CREATE TABLE ss_lk_part1 PARTITION OF ss_lk_part FOR VALUES IN (1);
CREATE TABLE ss_lk_part4 PARTITION OF ss_lk_part FOR VALUES IN (4);
GRANT SELECT ON ss_lk_part TO PUBLIC;
SET pgedge_safesession.delegating_roles = 'safesession_lk_auth';
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SET app.leak = 'leaked';
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT set_config('app.leak', 'leaked', false);
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT set_config('app.leak', 'leaked', NULL);
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SET transaction_app.leak = 'leaked';
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_session_set('app.' || 'leak');
ROLLBACK;
-- PL/pgSQL keeps the helper's set_config() from the pool's call before the
-- switch; the request's call after it is still checked
BEGIN;
SELECT ss_lk_set_any('app.pool', 'pool', true);
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_set_any('app.leak', 'leaked', false);
ROLLBACK;
-- the same, when the helper first runs as the pool's statement starts, to
-- prune a partitioned table
PREPARE ss_lk_pool(text) AS
    SELECT count(*) FROM ss_lk_part WHERE k = ss_lk_pick($1, 'pool', true);
BEGIN;
SET LOCAL plan_cache_mode = force_generic_plan;
EXECUTE ss_lk_pool('app.pool');
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_pick('app.leak', 'leaked', false);
ROLLBACK;
DEALLOCATE ss_lk_pool;
-- the same, when the helper first runs after a switch that a savepoint
-- then rolls back, and the pool switches again
BEGIN;
SAVEPOINT retry;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_set_any('app.pool', 'pool', true);
ROLLBACK TO retry;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_set_any('app.leak', 'leaked', false);
ROLLBACK;
-- the pool's own change before a switch statement that calls set_config()
-- under UNION ALL still works
BEGIN;
SET statement_timeout = '5s';
SELECT set_config('role', 'safesession_lk_user', true) UNION ALL SELECT 'x';
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
RESET search_path;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('SET app.leak = ''leaked''');
SET TRANSACTION READ ONLY;
SET LOCAL app.leak = 'local';
SELECT set_config('app.other', 'local', true) AS local_set;
COMMIT;
RESET SESSION AUTHORIZATION;
SELECT coalesce(current_setting('app.leak', true), '') AS app_leak,
       coalesce(current_setting('app.other', true), '') AS app_other,
       coalesce(current_setting('transaction_app.leak', true), '')
           AS transaction_app_leak;

-------------------------------------------------------------------------
-- Test 21: after the switch, a request cannot PREPARE, which would leave
-- a prepared statement for the next request, or DEALLOCATE, which would
-- remove one the pool uses. The pool's own statement still runs.
-------------------------------------------------------------------------
SET SESSION AUTHORIZATION safesession_lk_auth;
PREPARE ss_lk_pool AS SELECT current_user::text AS who;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
PREPARE ss_lk_mine AS SELECT 1;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
DEALLOCATE ss_lk_pool;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
DEALLOCATE ALL;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('PREPARE ss_lk_mine AS SELECT 1');
EXECUTE ss_lk_pool;
COMMIT;
SELECT name FROM pg_prepared_statements ORDER BY name;
DEALLOCATE ss_lk_pool;
RESET SESSION AUTHORIZATION;

-------------------------------------------------------------------------
-- Test 22: after the switch, a request cannot save settings for later
-- sessions with ALTER ROLE or ALTER DATABASE ... SET or RESET, even for
-- its own role or a database it owns.
-------------------------------------------------------------------------
SELECT current_database() AS ss_lk_dbname,
       datdba::regrole::text AS ss_lk_dbowner
    FROM pg_database WHERE datname = current_database() \gset
ALTER DATABASE :"ss_lk_dbname" OWNER TO safesession_lk_user;
SET SESSION AUTHORIZATION safesession_lk_auth;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
ALTER ROLE CURRENT_USER SET work_mem = '7777kB';
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
ALTER ROLE CURRENT_USER RESET ALL;
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
ALTER DATABASE :"ss_lk_dbname" SET work_mem = '7777kB';
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true);
SELECT ss_lk_try('ALTER ROLE CURRENT_USER SET work_mem = ''7777kB''');
COMMIT;
RESET SESSION AUTHORIZATION;
ALTER DATABASE :"ss_lk_dbname" OWNER TO :"ss_lk_dbowner";
SELECT count(*) AS saved_settings FROM pg_db_role_setting
    WHERE array_to_string(setconfig, ',') LIKE '%7777kB%';

-------------------------------------------------------------------------
-- Test 23: a set_config() call SafeSession cannot read before it runs,
-- here a PL/pgSQL assignment with a name passed in, is refused with its
-- own message: for a held setting at once, and for a new one when the
-- statement ends. A call the plan shows keeps the usual message.
-------------------------------------------------------------------------
CREATE FUNCTION ss_lk_set_named(name text) RETURNS text
    LANGUAGE plpgsql AS $$
DECLARE v text;
BEGIN
    v := set_config(name, 'forged', true);
    RETURN v;
END $$;
GRANT EXECUTE ON FUNCTION ss_lk_set_named(text) TO PUBLIC;
CREATE DOMAIN ss_lk_posint AS int CHECK (VALUE > 0);
SET SESSION AUTHORIZATION safesession_lk_auth;
\set SHOW_CONTEXT never
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT set_config('request.jwt.claims', '{"sub": "2"}', true);
ROLLBACK;
-- The written call keeps the usual message after one it cannot read
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT set_config(coalesce(current_setting('app.n', true), '') ||
                  'response.status', '201', true),
       set_config('request.jwt.claims', '{"sub": "2"}', true);
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT 1::ss_lk_posint,
       set_config('request.jwt.claims', '{"sub": "2"}', true);
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT ss_lk_set_named('request.jwt.claims');
ROLLBACK;
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT ss_lk_set_named('request.' || 'runtime');
ROLLBACK;
\set SHOW_CONTEXT errors
BEGIN;
SELECT set_config('role', 'safesession_lk_user', true),
       set_config('request.jwt.claims', '{"sub": "1"}', true);
SELECT count(*) AS notes_seen FROM ss_lk_notes;
COMMIT;
RESET SESSION AUTHORIZATION;
DROP FUNCTION ss_lk_session_set(text);
DROP FUNCTION ss_lk_set_any(text, text, bool);
DROP FUNCTION ss_lk_pick(text, text, bool);
DROP TABLE ss_lk_part;
DROP FUNCTION ss_lk_set_named(text);
DROP DOMAIN ss_lk_posint;
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
