-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- EXECUTE parameter tests for pgEdge SafeSession
--
-- The parameters of a prepared statement are not part of the prepared
-- query, so the post_parse_analyze walker never sees them, and they are
-- evaluated in the utility layer rather than through the executor, so the
-- ExecutorStart hook never sees them either. A blocked function passed as
-- a parameter must therefore be rejected by the utility hook. The same
-- evaluation happens for EXPLAIN EXECUTE, with or without ANALYZE, and
-- for CREATE TABLE AS ... EXECUTE.
--
-- set_config() is used throughout because it escapes the read-only floor
-- (it changes a GUC rather than writing data), so it would otherwise take
-- effect; SHOW work_mem shows whether it did.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_execparams;
DROP ROLE IF EXISTS safesession_exec;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_exec LOGIN;
GRANT CREATE ON SCHEMA public TO safesession_exec;

SET pgedge_safesession.roles = 'safesession_exec';

SET SESSION AUTHORIZATION safesession_exec;

SET work_mem = '4MB';
PREPARE ps (text) AS SELECT $1;
PREPARE ps_const (text) AS SELECT 'ok'::text;
PREPARE ps_noargs AS SELECT 1;

-- A blocked function passed as a parameter must be rejected
SHOW work_mem;
EXECUTE ps (set_config('work_mem', '11MB', false));
SHOW work_mem;

-- It must also be caught when buried in a larger expression
EXECUTE ps ('x' || set_config('work_mem', '12MB', false));
SHOW work_mem;

-- EXPLAIN evaluates the parameters even without ANALYZE
EXPLAIN (COSTS OFF) EXECUTE ps (set_config('work_mem', '13MB', false));
SHOW work_mem;

-- ... and with it
EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF)
    EXECUTE ps (set_config('work_mem', '14MB', false));
SHOW work_mem;

-- Ordinary parameters must still work
EXECUTE ps ('plain text');

-- As must a prepared statement with no parameters at all
EXECUTE ps_noargs;

-- A harmless volatile built-in is allowed, exactly as it is elsewhere
EXECUTE ps_const (random()::text);

-- A subquery is not a legal EXECUTE parameter; core rejects it during
-- parse analysis, which is the same transformation this check performs
EXECUTE ps ((SELECT set_config('work_mem', '15MB', false)));
SHOW work_mem;

-- The check is governed by block_c_functions, not block_ddl, so turning
-- DDL blocking off must not open the CREATE TABLE AS ... EXECUTE route
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_ddl = off;
SET SESSION AUTHORIZATION safesession_exec;

CREATE TABLE test_execparams AS
    EXECUTE ps (set_config('work_mem', '16MB', false));
SHOW work_mem;

RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_ddl = on;

-- EXPLAIN and CREATE TABLE AS can be combined, which nests two wrappers
-- around the EXECUTE rather than one. Without ANALYZE nothing is written,
-- so no other check applies and this is reachable at the default settings;
-- with ANALYZE the write is refused first, by the analyze-of-a-write check.
SET SESSION AUTHORIZATION safesession_exec;

EXPLAIN (COSTS OFF) CREATE TABLE test_execparams AS
    EXECUTE ps (set_config('work_mem', '18MB', false));
SHOW work_mem;

EXPLAIN (ANALYZE, COSTS OFF, TIMING OFF, SUMMARY OFF)
    CREATE TABLE test_execparams AS
    EXECUTE ps (set_config('work_mem', '19MB', false));
SHOW work_mem;

RESET SESSION AUTHORIZATION;

-- With block_c_functions off, SafeSession's own function check is skipped
-- here as it is everywhere else, and the parameter takes effect
SET pgedge_safesession.block_c_functions = off;
SET SESSION AUTHORIZATION safesession_exec;

EXECUTE ps (set_config('work_mem', '17MB', false));
SHOW work_mem;

RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_c_functions = on;

-- Confirm no table was created by any of the above
SET default_transaction_read_only = off;
SELECT count(*) AS leaked_tables FROM pg_class
    WHERE relname = 'test_execparams';

-- Cleanup
RESET pgedge_safesession.roles;
RESET pgedge_safesession.block_ddl;
RESET pgedge_safesession.block_c_functions;
REVOKE CREATE ON SCHEMA public FROM safesession_exec;
DROP ROLE safesession_exec;
DROP EXTENSION pgedge_safesession;
