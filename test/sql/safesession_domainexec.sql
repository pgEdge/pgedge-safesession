-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Domain CHECK constraints reached from outside the query tree.
--
-- safesession_domains covers the coercions the walker can see, which
-- reach the constraint through a CoerceToDomain node in some statement:
-- a cast written in a query, and a value passed for a function
-- parameter of the domain type, which the caller coerces.
--
-- The three shapes below produce no such node in any statement, and the
-- constraint runs anyway. A PL/pgSQL variable is coerced to its declared
-- type when the block initialises it, before anything is assigned, and a
-- function's result is coerced to its RETURNS type after the body has
-- produced it. Both are caught at expression compile time instead, by
-- the object access hook, which sees each function as the constraint
-- expression is compiled and before it is evaluated.
--
-- set_config() is used throughout because it escapes the read-only
-- floor (it changes a GUC rather than writing data), so it would
-- otherwise take effect; SHOW work_mem shows whether it did.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP FUNCTION IF EXISTS de_declare(), de_plpgsql_returns(),
                        de_sql_returns(), de_declare_plain(),
                        de_plpgsql_returns_plain(int),
                        de_sql_returns_plain(int);
DROP DOMAIN IF EXISTS d_exec, d_exec_plain;
DROP ROLE IF EXISTS safesession_domainexec;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_domainexec LOGIN;

-- As the DBA: a domain whose CHECK calls a blocked function. Unlike the
-- one in safesession_domains it accepts NULL, so that a PL/pgSQL
-- variable of this type can be declared without the constraint
-- rejecting the NULL it starts out as.
CREATE DOMAIN d_exec AS text
    CHECK (set_config('work_mem', '64MB', false) IS NOT NULL);

-- A PL/pgSQL variable declared as the domain and never assigned: the
-- constraint runs when the block initialises it to NULL.
CREATE FUNCTION de_declare() RETURNS int AS $$
DECLARE
    v d_exec;
BEGIN
    RETURN 1;
END
$$ LANGUAGE plpgsql;

-- A PL/pgSQL function returning the domain: the coercion is applied to
-- the result, not written in the body.
CREATE FUNCTION de_plpgsql_returns() RETURNS d_exec AS $$
BEGIN
    RETURN 'x';
END
$$ LANGUAGE plpgsql;

-- The same for a SQL function.
CREATE FUNCTION de_sql_returns() RETURNS d_exec AS $$
    SELECT 'x'::text
$$ LANGUAGE sql;

SET pgedge_safesession.roles = 'safesession_domainexec';

SET SESSION AUTHORIZATION safesession_domainexec;

-- A PL/pgSQL variable of the domain type must be rejected when the
-- block initialises it, with nothing ever assigned to it
SET work_mem = '4MB';
SELECT de_declare();
SHOW work_mem;

-- ... and so must a PL/pgSQL function returning the domain
SET work_mem = '4MB';
SELECT de_plpgsql_returns();
SHOW work_mem;

-- ... and a SQL function returning it
SET work_mem = '4MB';
SELECT de_sql_returns();
SHOW work_mem;

RESET SESSION AUTHORIZATION;

-- An ordinary domain (no blocked function) must still validate normally
-- in all three shapes: a value that fails the constraint is still
-- rejected by core, and one that passes is still accepted
CREATE DOMAIN d_exec_plain AS int CHECK (VALUE IS NULL OR VALUE > 0);

CREATE FUNCTION de_declare_plain() RETURNS int AS $$
DECLARE
    v d_exec_plain;
BEGIN
    RETURN 1;
END
$$ LANGUAGE plpgsql;

CREATE FUNCTION de_plpgsql_returns_plain(n int) RETURNS d_exec_plain AS $$
BEGIN
    RETURN n;
END
$$ LANGUAGE plpgsql;

CREATE FUNCTION de_sql_returns_plain(n int) RETURNS d_exec_plain AS $$
    SELECT n
$$ LANGUAGE sql;

SET SESSION AUTHORIZATION safesession_domainexec;
SELECT de_declare_plain();
SELECT de_plpgsql_returns_plain(5);
SELECT de_plpgsql_returns_plain(-5);
SELECT de_sql_returns_plain(5);
SELECT de_sql_returns_plain(-5);
RESET SESSION AUTHORIZATION;

-- With block_c_functions off, the check is skipped as it is everywhere
-- else, and the constraint's function takes effect
SET pgedge_safesession.block_c_functions = off;
SET SESSION AUTHORIZATION safesession_domainexec;
SET work_mem = '4MB';
SELECT de_sql_returns();
SHOW work_mem;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_c_functions = on;

-- Cleanup
RESET pgedge_safesession.roles;
DROP FUNCTION de_declare(), de_plpgsql_returns(), de_sql_returns(),
              de_declare_plain(), de_plpgsql_returns_plain(int),
              de_sql_returns_plain(int);
DROP DOMAIN d_exec, d_exec_plain;
DROP ROLE safesession_domainexec;
DROP EXTENSION pgedge_safesession;
