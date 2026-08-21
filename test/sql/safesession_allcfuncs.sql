-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- block_all_c_functions tests for pgEdge SafeSession
--
-- block_c_functions rejects a C-language function only when it is
-- VOLATILE. block_all_c_functions escalates that to every function whose
-- language is C, whatever its volatility; it is the one setting the
-- documentation warns can break read-only extension functions, and
-- nothing else in the suite exercises it.
--
-- The subject is a second declaration of the extension's own
-- is_restricted symbol, marked IMMUTABLE. Declared that way it is
-- allowed at the default settings, so the only thing that can reject it
-- is the language rule this file is about, and it needs no build step
-- beyond the extension itself.
--
-- Most built-ins are LANGUAGE internal rather than LANGUAGE c, so
-- ordinary queries are unaffected by the escalation. What it reaches is
-- extension functions -- including this extension's own, which is the
-- documented cost of turning it on.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP ROLE IF EXISTS safesession_allc;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_allc LOGIN;

-- LANGUAGE c, but IMMUTABLE, so volatility alone never rejects it
CREATE FUNCTION acf_immutable_c() RETURNS boolean
    AS '$libdir/pgedge_safesession', 'pgedge_safesession_is_restricted'
    LANGUAGE c IMMUTABLE;

-- A function in another language, to show the escalation is about the
-- language and not about anything else
CREATE FUNCTION acf_sql() RETURNS int LANGUAGE sql VOLATILE
    AS $$ SELECT 1 $$;

GRANT EXECUTE ON FUNCTION acf_immutable_c(), acf_sql()
    TO safesession_allc;

SET pgedge_safesession.roles = 'safesession_allc';

-- ============================================================
-- Default settings: volatility decides, so both are allowed
-- ============================================================
SET SESSION AUTHORIZATION safesession_allc;
SELECT acf_immutable_c() AS immutable_c_allowed;
SELECT pgedge_safesession_is_restricted() AS is_restricted_allowed;
RESET SESSION AUTHORIZATION;

-- ============================================================
-- block_all_c_functions = on: the language alone decides
-- ============================================================
SET pgedge_safesession.block_all_c_functions = on;
SET SESSION AUTHORIZATION safesession_allc;

SELECT acf_immutable_c();

-- The extension's own introspection function is LANGUAGE c too, so it
-- goes with them. This is the documented cost of the setting, recorded
-- here so that changing it is a deliberate decision.
SELECT pgedge_safesession_is_restricted();

-- A function in another language is unaffected, even a VOLATILE one
SELECT acf_sql() AS sql_function_unaffected;

-- ... and so are the built-ins, which are LANGUAGE internal
SELECT random() < 2 AS builtin_unaffected;
SELECT count(*) > 0 AS catalog_still_readable FROM pg_class;

RESET SESSION AUTHORIZATION;

-- ============================================================
-- The escalation only applies while block_c_functions is on
-- ============================================================
SET pgedge_safesession.block_c_functions = off;
SET SESSION AUTHORIZATION safesession_allc;
SELECT acf_immutable_c() AS allowed_with_block_c_functions_off;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_c_functions = on;

-- ... and turning it back off restores the default behaviour
SET pgedge_safesession.block_all_c_functions = off;
SET SESSION AUTHORIZATION safesession_allc;
SELECT acf_immutable_c() AS allowed_again;
RESET SESSION AUTHORIZATION;

-- Cleanup
SET default_transaction_read_only = off;
RESET pgedge_safesession.roles;
RESET pgedge_safesession.block_c_functions;
RESET pgedge_safesession.block_all_c_functions;
DROP FUNCTION acf_immutable_c();
DROP FUNCTION acf_sql();
DROP ROLE safesession_allc;
DROP EXTENSION pgedge_safesession;
