-- Function tests for pgEdge SafeSession
-- PL/pgSQL write attempts are blocked; read-only functions allowed

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP FUNCTION IF EXISTS func_write();
DROP FUNCTION IF EXISTS func_read();
DROP FUNCTION IF EXISTS func_sql_write();
DROP FUNCTION IF EXISTS func_sql_read();
DROP TABLE IF EXISTS test_func;
DROP ROLE IF EXISTS safesession_readonly;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_readonly LOGIN;
CREATE TABLE test_func (id int, val text);
INSERT INTO test_func VALUES (1, 'original');
GRANT ALL ON test_func TO safesession_readonly;

-- Create a PL/pgSQL function that attempts an INSERT
CREATE OR REPLACE FUNCTION func_write()
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO test_func VALUES (99, 'from_function');
END;
$$;
GRANT EXECUTE ON FUNCTION func_write() TO safesession_readonly;

-- Create a read-only PL/pgSQL function
CREATE OR REPLACE FUNCTION func_read()
RETURNS int LANGUAGE plpgsql AS $$
DECLARE
    cnt int;
BEGIN
    SELECT count(*) INTO cnt FROM test_func;
    RETURN cnt;
END;
$$;
GRANT EXECUTE ON FUNCTION func_read() TO safesession_readonly;

-- Create a SQL function that attempts a write
CREATE OR REPLACE FUNCTION func_sql_write()
RETURNS void LANGUAGE sql AS $$
    INSERT INTO test_func VALUES (98, 'from_sql_func');
$$;
GRANT EXECUTE ON FUNCTION func_sql_write()
    TO safesession_readonly;

-- Create a read-only SQL function
CREATE OR REPLACE FUNCTION func_sql_read()
RETURNS bigint LANGUAGE sql AS $$
    SELECT count(*) FROM test_func;
$$;
GRANT EXECUTE ON FUNCTION func_sql_read()
    TO safesession_readonly;

-- Configure restriction
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_readonly';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to restricted role
SET SESSION AUTHORIZATION safesession_readonly;

-- Read-only PL/pgSQL function should work
SELECT func_read();

-- Write PL/pgSQL function should be blocked
SELECT func_write();

-- Read-only SQL function should work
SELECT func_sql_read();

-- Write SQL function should be blocked
SELECT func_sql_write();

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP FUNCTION func_write();
DROP FUNCTION func_read();
DROP FUNCTION func_sql_write();
DROP FUNCTION func_sql_read();
DROP TABLE test_func;
DROP ROLE safesession_readonly;
DROP EXTENSION pgedge_safesession;
