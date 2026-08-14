-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Domain CHECK constraint tests for pgEdge SafeSession
--
-- A domain's CHECK constraint expression is not part of the Query or
-- Plan tree at all: it is fetched from pg_constraint and evaluated by
-- the executor through the domain constraint cache. A restricted role
-- needs no privilege beyond USAGE on the domain (granted to PUBLIC by
-- default) to trigger it, e.g. by casting a literal.
--
-- set_config() is used throughout because it escapes the read-only
-- floor (it changes a GUC rather than writing data), so it would
-- otherwise take effect; SHOW work_mem shows whether it did.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP DOMAIN IF EXISTS d_setcfg, d_setcfg_stacked;
DROP ROLE IF EXISTS safesession_domains;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_domains LOGIN;

-- As the DBA: create a domain whose CHECK constraint calls a blocked
-- function, and a domain stacked over it (the constraint stays on the
-- outer domain only)
CREATE DOMAIN d_setcfg AS text
    CHECK (VALUE IS NOT NULL
           AND set_config('work_mem', '64MB', false) IS NOT NULL);
CREATE DOMAIN d_setcfg_stacked AS d_setcfg;

SET pgedge_safesession.roles = 'safesession_domains';

SET SESSION AUTHORIZATION safesession_domains;

SET work_mem = '4MB';

-- Coercing a value to the domain must be rejected
SHOW work_mem;
SELECT 'x'::d_setcfg;
SHOW work_mem;

-- ... and through a domain stacked over it
SELECT 'x'::d_setcfg_stacked;
SHOW work_mem;

RESET SESSION AUTHORIZATION;

-- An ordinary domain (no blocked function) must still validate
-- normally: a value that fails the constraint is still rejected by
-- core, and one that passes is still accepted
DROP DOMAIN IF EXISTS d_plain;
CREATE DOMAIN d_plain AS int CHECK (VALUE > 0);

SET SESSION AUTHORIZATION safesession_domains;
SELECT 5::d_plain;
SELECT (-5)::d_plain;
RESET SESSION AUTHORIZATION;

-- With block_c_functions off, the check is skipped as it is
-- everywhere else, and the constraint's function takes effect
SET pgedge_safesession.block_c_functions = off;
SET SESSION AUTHORIZATION safesession_domains;
SELECT 'x'::d_setcfg;
SHOW work_mem;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_c_functions = on;

-- Cleanup
RESET pgedge_safesession.roles;
DROP DOMAIN d_setcfg_stacked, d_setcfg, d_plain;
DROP ROLE safesession_domains;
DROP EXTENSION pgedge_safesession;
