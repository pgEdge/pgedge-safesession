-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Index maintenance tests for pgEdge SafeSession
--
-- brin_summarize_new_values(), brin_summarize_range(),
-- brin_desummarize_range() and gin_clean_pending_list() modify index
-- pages and emit WAL, but they do so without going through the executor
-- and without calling PreventCommandIfReadOnly(), so neither the DML
-- check nor the read-only floor sees them. The table owner may call them,
-- and a restricted role often owns its own tables, so they have to be
-- rejected by name.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP TABLE IF EXISTS test_brin;
DROP TABLE IF EXISTS test_gin;
DROP ROLE IF EXISTS safesession_idx;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_idx LOGIN;

CREATE TABLE test_brin (id int);
INSERT INTO test_brin SELECT g FROM generate_series(1, 500) g;
-- One page per range, so rows added later leave ranges unsummarized
CREATE INDEX test_brin_idx ON test_brin USING brin (id)
    WITH (pages_per_range = 1);
INSERT INTO test_brin SELECT g FROM generate_series(501, 5000) g;

CREATE TABLE test_gin (a int[]);
INSERT INTO test_gin SELECT ARRAY[g] FROM generate_series(1, 200) g;
CREATE INDEX test_gin_idx ON test_gin USING gin (a) WITH (fastupdate = on);

-- The restricted role owns both tables, so privileges are not what stops
-- it here
ALTER TABLE test_brin OWNER TO safesession_idx;
ALTER TABLE test_gin OWNER TO safesession_idx;

SET pgedge_safesession.roles = 'safesession_idx';

SET SESSION AUTHORIZATION safesession_idx;

-- All four must be rejected
SELECT brin_summarize_new_values('test_brin_idx'::regclass);
SELECT brin_summarize_range('test_brin_idx'::regclass, 0);
SELECT brin_desummarize_range('test_brin_idx'::regclass, 0);
SELECT gin_clean_pending_list('test_gin_idx'::regclass);

-- Reading the tables is still fine
SELECT count(*) FROM test_brin;
SELECT count(*) FROM test_gin;

RESET SESSION AUTHORIZATION;

-- With block_c_functions off they are allowed again, as with every other
-- entry on the list
SET pgedge_safesession.block_c_functions = off;
SET SESSION AUTHORIZATION safesession_idx;
SELECT brin_summarize_new_values('test_brin_idx'::regclass) > 0
           AS summarized_something;
RESET SESSION AUTHORIZATION;
SET pgedge_safesession.block_c_functions = on;

-- Cleanup
SET default_transaction_read_only = off;
RESET pgedge_safesession.roles;
RESET pgedge_safesession.block_c_functions;
DROP TABLE test_brin;
DROP TABLE test_gin;
DROP ROLE safesession_idx;
DROP EXTENSION pgedge_safesession;
