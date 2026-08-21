-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgedge_safesession" to load this extension. \quit

-- Report whether the current session is restricted to read-only access.
CREATE FUNCTION pgedge_safesession_is_restricted()
RETURNS boolean
AS 'MODULE_PATHNAME', 'pgedge_safesession_is_restricted'
LANGUAGE C STABLE;

COMMENT ON FUNCTION pgedge_safesession_is_restricted() IS
    'true if the current session is restricted to read-only access by '
    'pgedge_safesession';
