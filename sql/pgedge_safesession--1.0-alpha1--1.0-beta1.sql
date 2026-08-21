-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "ALTER EXTENSION pgedge_safesession UPDATE" to load this extension. \quit

-- No SQL-visible schema changes between 1.0-alpha1 and 1.0-beta1; every
-- change in this release is in the extension's C-language hooks and GUCs.
