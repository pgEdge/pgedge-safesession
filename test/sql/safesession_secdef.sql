-- SECURITY DEFINER tests for pgEdge SafeSession
-- Writes blocked even via SECURITY DEFINER functions
-- owned by unrestricted roles (including superuser)

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP FUNCTION IF EXISTS secdef_write();
DROP FUNCTION IF EXISTS secdef_read();
DROP TABLE IF EXISTS test_secdef;
DROP ROLE IF EXISTS safesession_readonly;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_readonly LOGIN;
CREATE TABLE test_secdef (id int, val text);
INSERT INTO test_secdef VALUES (1, 'original');
GRANT SELECT ON test_secdef TO safesession_readonly;

-- Create a SECURITY DEFINER function owned by superuser
-- that attempts a write
CREATE OR REPLACE FUNCTION secdef_write()
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    INSERT INTO test_secdef VALUES (99, 'from_secdef');
END;
$$;
GRANT EXECUTE ON FUNCTION secdef_write()
    TO safesession_readonly;

-- Create a SECURITY DEFINER read-only function
CREATE OR REPLACE FUNCTION secdef_read()
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    cnt bigint;
BEGIN
    SELECT count(*) INTO cnt FROM test_secdef;
    RETURN cnt;
END;
$$;
GRANT EXECUTE ON FUNCTION secdef_read()
    TO safesession_readonly;

-- Configure restriction
ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_readonly';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

-- Switch to restricted role
SET SESSION AUTHORIZATION safesession_readonly;

-- SECURITY DEFINER write function should be blocked
-- (session user is still restricted)
SELECT secdef_write();

-- SECURITY DEFINER read function should work
SELECT secdef_read();

-- Verify no data was written
SELECT * FROM test_secdef ORDER BY id;

-- Switch back to superuser for cleanup
RESET SESSION AUTHORIZATION;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP FUNCTION secdef_write();
DROP FUNCTION secdef_read();
DROP TABLE test_secdef;
DROP ROLE safesession_readonly;
DROP EXTENSION pgedge_safesession;
