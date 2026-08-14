-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Domain CHECK constraints reached by coercing a bound parameter, over
-- the extended query protocol.
--
-- exec_bind_message() coerces each parameter to its declared type
-- before it fetches the plan, and for a domain that coercion runs the
-- CHECK constraint. Everything that walks a Query therefore runs too
-- late to stop it: parse analysis happens at Parse, when no value is
-- bound yet, and the planner is not reached until after the coercion.
-- The constraint is caught at expression compile time instead, by the
-- object access hook.
--
-- This is the path JDBC, psycopg, node-postgres and npgsql take for an
-- ordinary parameterised query, so it is not an exotic one.
--
-- set_config() is used throughout because it escapes the read-only
-- floor (it changes a GUC rather than writing data), so it would
-- otherwise take effect; SHOW work_mem shows whether it did.

-- Parse/Bind/Execute is driven from psql's \bind, which arrived in
-- PostgreSQL 16, and nothing else in psql can express a Bind. Stop the
-- file here on an older psql: reading on would report every \bind as an
-- unknown backslash command, which \if cannot prevent, since psql
-- recognises a command before it decides whether the branch is live.
-- VERSION_NUM is psql's own version rather than the server's, which is
-- what matters for a client-side feature. What this leaves is matched
-- by safesession_xproto_1.out. safesession_domainexec covers the same
-- hook through coercions needing no protocol support, on every version.
SELECT :VERSION_NUM < 160000 AS psql_lacks_bind \gset
\if :psql_lacks_bind
    \q
\endif

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP DOMAIN IF EXISTS d_xproto, d_xproto_plain;
DROP ROLE IF EXISTS safesession_xproto;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_xproto LOGIN;

CREATE DOMAIN d_xproto AS text
    CHECK (VALUE IS NOT NULL
           AND set_config('work_mem', '64MB', false) IS NOT NULL);

CREATE DOMAIN d_xproto_plain AS int CHECK (VALUE > 0);

SET pgedge_safesession.roles = 'safesession_xproto';

SET SESSION AUTHORIZATION safesession_xproto;

-- Binding a value to a parameter of the domain type must be rejected,
-- at Bind, before the statement runs
SET work_mem = '4MB';
SELECT $1::d_xproto IS NOT NULL AS bound \bind 'x'
\g
SHOW work_mem;

-- The same when the bound value is never used for anything: the
-- constraint runs because the parameter is coerced, not because the
-- query does something with it
SET work_mem = '4MB';
SELECT 1 AS ignores_the_parameter FROM (SELECT $1::d_xproto) s \bind 'x'
\g
SHOW work_mem;

-- An ordinary domain bound the same way must still validate normally
SELECT $1::d_xproto_plain AS accepted \bind 5
\g
SELECT $1::d_xproto_plain AS rejected \bind -5
\g

-- A parameter of an ordinary type is unaffected
SELECT $1::text || '!' AS plain \bind 'x'
\g

RESET SESSION AUTHORIZATION;

-- With block_c_functions off, the check is skipped as it is everywhere
-- else, and the constraint's function takes effect
SET pgedge_safesession.block_c_functions = off;
SET SESSION AUTHORIZATION safesession_xproto;
SET work_mem = '4MB';
SELECT $1::d_xproto IS NOT NULL AS bound \bind 'x'
\g
SHOW work_mem;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_c_functions = on;

-- Cleanup
RESET pgedge_safesession.roles;
DROP DOMAIN d_xproto, d_xproto_plain;
DROP ROLE safesession_xproto;
DROP EXTENSION pgedge_safesession;
