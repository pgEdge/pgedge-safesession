-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- DDL tests for pgEdge SafeSession
-- All DDL operations should be blocked for restricted roles
--
-- The utility hook is fail-closed: an explicit set of known-safe
-- statements is allowed and everything else is refused by the default
-- branch, which names the command in the error. Enumerating every DDL
-- statement PostgreSQL has would therefore exercise one code path many
-- times over, so what follows is chosen rather than exhaustive:
--
-- - a representative CREATE/ALTER/DROP of the common object types, as a
--   smoke test of that default branch and of the command naming
-- - each of the four statement types that share the privilege-change
--   branch, since three of them are reached by nothing else
-- - the statements a restricted role has the privileges to run for
--   itself, where SafeSession is the only thing standing in the way
-- - the writes that are not DML and not obviously DDL either, which is
--   where a reader-shaped role does the most damage
-- - the two ways to leave code behind that runs later on someone else's
--   statement

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP MATERIALIZED VIEW IF EXISTS test_ddl_mv;
DROP TABLE IF EXISTS test_ddl;
DROP SEQUENCE IF EXISTS test_ddl_ownseq;
DROP TYPE IF EXISTS test_ddl_owntype;
DROP FUNCTION IF EXISTS test_ddl_trigfn();
DROP ROLE IF EXISTS safesession_readonly;
DROP ROLE IF EXISTS safesession_ddl_other;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_readonly LOGIN;
CREATE ROLE safesession_ddl_other;
CREATE TABLE test_ddl (id int, val text);
GRANT ALL ON test_ddl TO safesession_readonly;
GRANT CREATE ON SCHEMA public TO safesession_readonly;

-- Existing objects for the statements below that need one to act on
CREATE MATERIALIZED VIEW test_ddl_mv AS SELECT * FROM test_ddl;
CREATE SEQUENCE test_ddl_ownseq;
CREATE TYPE test_ddl_owntype AS (a int);
CREATE FUNCTION test_ddl_trigfn() RETURNS trigger LANGUAGE plpgsql
    AS $$ BEGIN RETURN NEW; END $$;

-- Configure restriction
SET pgedge_safesession.roles = 'safesession_readonly';

-- Switch to restricted role
SET SESSION AUTHORIZATION safesession_readonly;

-- ============================================================
-- The common object types, via the default deny
-- ============================================================

-- CREATE TABLE should be blocked
CREATE TABLE test_ddl_new (id int);

-- ALTER TABLE should be blocked
ALTER TABLE test_ddl ADD COLUMN extra text;

-- DROP TABLE should be blocked
DROP TABLE test_ddl;

-- TRUNCATE should be blocked
TRUNCATE test_ddl;

-- CREATE INDEX should be blocked
CREATE INDEX test_ddl_idx ON test_ddl (id);

-- CREATE FUNCTION should be blocked
CREATE FUNCTION test_ddl_func() RETURNS void
    LANGUAGE sql AS $$ SELECT 1; $$;

-- CREATE VIEW should be blocked
CREATE VIEW test_ddl_view AS SELECT * FROM test_ddl;

-- CREATE SEQUENCE should be blocked
CREATE SEQUENCE test_ddl_seq;

-- CREATE TYPE should be blocked
CREATE TYPE test_ddl_type AS (x int, y int);

-- COMMENT should be blocked
COMMENT ON TABLE test_ddl IS 'test comment';

-- VACUUM should be blocked
VACUUM test_ddl;

-- ANALYZE should be blocked
ANALYZE test_ddl;

-- Dropping the extension is DDL like any other, and is refused like any
-- other. It would not lift the restriction even if it succeeded, because
-- the hooks come from shared_preload_libraries rather than from the
-- pg_extension entry, but a restricted role has no business trying.
DROP EXTENSION pgedge_safesession;

-- ============================================================
-- Privilege changes
--
-- All four statement types below share one branch, and only GRANT was
-- reached by any test. Granting a role to another role is the escalation
-- that matters most of the four: it is how a restricted session would
-- try to acquire an unrestricted role's privileges.
-- ============================================================

-- GRANT should be blocked
GRANT SELECT ON test_ddl TO safesession_readonly;

-- ... and so should REVOKE, which is the destructive direction
REVOKE SELECT ON test_ddl FROM safesession_readonly;

-- Role membership, i.e. GrantRoleStmt rather than GrantStmt
GRANT safesession_readonly TO safesession_ddl_other;

-- Default privileges, which apply to objects that do not exist yet
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO safesession_ddl_other;

-- Handing an object to another role
ALTER TYPE test_ddl_owntype OWNER TO safesession_ddl_other;

-- ============================================================
-- What the role may do to itself
--
-- Everything above is also refused by PostgreSQL's own privilege checks
-- once SafeSession is out of the way, because the role owns none of it.
-- These two are different: a role may always change its own password,
-- and may always drop what it owns, so SafeSession is the only thing
-- standing in the way.
-- ============================================================
ALTER ROLE safesession_readonly PASSWORD 'unchanged';
DROP OWNED BY safesession_readonly;

-- ============================================================
-- Writes that are neither DML nor obviously DDL
--
-- Each of these rewrites storage or advances a counter, and the table or
-- sequence owner may run it. None of them is an INSERT/UPDATE/DELETE, so
-- the DML check in the executor hook never sees them.
-- ============================================================
REINDEX TABLE test_ddl;
CLUSTER test_ddl;
REFRESH MATERIALIZED VIEW test_ddl_mv;
ALTER SEQUENCE test_ddl_ownseq RESTART WITH 100;

-- ============================================================
-- Leaving code behind to run later
--
-- A trigger or a rule runs on someone else's statement, after the
-- session that installed it has gone, so it escapes every check that
-- looks at the statement in front of it.
-- ============================================================
CREATE TRIGGER test_ddl_trg AFTER INSERT ON test_ddl
    FOR EACH ROW EXECUTE FUNCTION test_ddl_trigfn();
CREATE RULE test_ddl_rule AS ON INSERT TO test_ddl DO INSTEAD NOTHING;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Nothing above created, altered or dropped anything
SET default_transaction_read_only = off;
SELECT count(*) AS leaked_relations FROM pg_class
    WHERE relname IN ('test_ddl_new', 'test_ddl_idx', 'test_ddl_view',
                      'test_ddl_seq');
SELECT (SELECT count(*) FROM pg_type WHERE typname = 'test_ddl_type')
     + (SELECT count(*) FROM pg_proc WHERE proname = 'test_ddl_func')
     + (SELECT count(*) FROM pg_trigger WHERE tgname = 'test_ddl_trg')
     + (SELECT count(*) FROM pg_rewrite
            WHERE rulename = 'test_ddl_rule')
     + (SELECT count(*) FROM pg_attribute
            WHERE attrelid = 'test_ddl'::regclass AND attname = 'extra')
       AS leaked_other_objects;

-- The type is still owned by the role that created it, and the sequence
-- was not restarted
SELECT pg_get_userbyid(typowner) = current_user AS owner_unchanged
    FROM pg_type WHERE typname = 'test_ddl_owntype';
SELECT last_value AS sequence_unchanged FROM test_ddl_ownseq;

-- Cleanup
RESET pgedge_safesession.roles;
REVOKE CREATE ON SCHEMA public FROM safesession_readonly;
DROP MATERIALIZED VIEW test_ddl_mv;
DROP TABLE test_ddl;
DROP SEQUENCE test_ddl_ownseq;
DROP TYPE test_ddl_owntype;
DROP FUNCTION test_ddl_trigfn();
DROP ROLE safesession_readonly;
DROP ROLE safesession_ddl_other;
DROP EXTENSION pgedge_safesession;
