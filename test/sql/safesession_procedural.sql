-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- CHECKPOINT and procedural-code tests for pgEdge SafeSession
-- CHECKPOINT is not a read-only operation and must be blocked. DO blocks
-- and CALL are treated alike: a trusted language (PL/pgSQL) is allowed,
-- because any write is still caught by the read-only floor; an untrusted
-- language would be rejected (not exercised here, as no untrusted PL is
-- installed).

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_proc;
DROP ROLE IF EXISTS safesession_proc;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_proc LOGIN;
CREATE TABLE test_proc (id int);
INSERT INTO test_proc VALUES (1);
GRANT SELECT, INSERT ON test_proc TO safesession_proc;

CREATE PROCEDURE proc_read() LANGUAGE plpgsql AS $$
DECLARE n int;
BEGIN
    SELECT count(*) INTO n FROM test_proc;
END $$;
CREATE PROCEDURE proc_write() LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO test_proc VALUES (2);
END $$;
CREATE PROCEDURE proc_arg(t text) LANGUAGE plpgsql AS $$
BEGIN
END $$;
GRANT EXECUTE ON PROCEDURE proc_read(), proc_write(), proc_arg(text)
    TO safesession_proc;

ALTER SYSTEM SET pgedge_safesession.roles = 'safesession_proc';
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);

SET SESSION AUTHORIZATION safesession_proc;

-- CHECKPOINT is not read-only and must be blocked
CHECKPOINT;

-- A DO block in a trusted language is allowed
DO $$ BEGIN PERFORM 1; END $$;

-- CALL of a read-only trusted procedure is allowed
CALL proc_read();

-- CALL of a writing procedure is allowed to start, but the write inside
-- it is caught by the read-only floor
CALL proc_write();

-- The arguments of a CALL are evaluated before the procedure body runs,
-- so a blocked function passed as one must be rejected, exactly as it is
-- when called directly. set_config() escapes the read-only floor (it
-- changes a GUC rather than writing data), so it would otherwise take
-- effect.
SHOW work_mem;
CALL proc_arg(set_config('work_mem', '55MB', false));
SHOW work_mem;

-- An ordinary argument is still fine
CALL proc_arg('plain text');

-- Switch back to superuser to confirm nothing was written
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
SELECT count(*) AS rows FROM test_proc;

-- Cleanup
ALTER SYSTEM RESET pgedge_safesession.roles;
SELECT pg_reload_conf();
DROP PROCEDURE proc_read();
DROP PROCEDURE proc_write();
DROP PROCEDURE proc_arg(text);
DROP TABLE test_proc;
DROP ROLE safesession_proc;
DROP EXTENSION pgedge_safesession;
