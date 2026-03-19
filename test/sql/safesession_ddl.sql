-- DDL tests for pgEdge SafeSession
-- All DDL operations should be blocked for restricted roles

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_ddl;
DROP ROLE IF EXISTS safesession_readonly;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_readonly LOGIN;
CREATE TABLE test_ddl (id int, val text);
GRANT ALL ON test_ddl TO safesession_readonly;
GRANT CREATE ON SCHEMA public TO safesession_readonly;

-- Configure restriction
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_readonly';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to restricted role
SET SESSION AUTHORIZATION safesession_readonly;

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

-- GRANT should be blocked
GRANT SELECT ON test_ddl TO safesession_readonly;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
REVOKE CREATE ON SCHEMA public FROM safesession_readonly;
DROP TABLE test_ddl;
DROP ROLE safesession_readonly;
DROP EXTENSION pgedge_safesession;
