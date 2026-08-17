-------------------------------------------------------------------------
--
-- pgEdge SafeSession
--
-- Copyright (c) 2025 - 2026, pgEdge, Inc.
-- This software is released under The PostgreSQL License
--
-------------------------------------------------------------------------

-- Sequence introspection tests for pgEdge SafeSession
--
-- pg_sequences is built on pg_sequence_last_value(), which is VOLATILE,
-- so leaving that name off the built-in allow-list takes the view away
-- from a restricted session -- blocked-function checks follow view
-- rewrite, so the view goes wherever its body goes. Reading a sequence
-- is not advancing one, and schema introspection should not need write
-- access, so the reader is allowed while nextval() and setval() are not.

-- Setup: clean any stale state
RESET SESSION AUTHORIZATION;
SET default_transaction_read_only = off;
DROP SEQUENCE IF EXISTS test_seq;
DROP SEQUENCE IF EXISTS other_seq;
DROP ROLE IF EXISTS safesession_seq;

CREATE EXTENSION IF NOT EXISTS pgedge_safesession;

CREATE ROLE safesession_seq LOGIN;

CREATE SEQUENCE test_seq;
SELECT nextval('test_seq');
GRANT SELECT ON SEQUENCE test_seq TO safesession_seq;

-- A sequence the restricted role has no privilege on, to confirm the
-- view still filters by privilege rather than showing everything.
-- Advanced first: last_value reads NULL on a never-called sequence, so
-- an unadvanced one would read as withheld whatever the privileges are.
CREATE SEQUENCE other_seq;
SELECT nextval('other_seq');

SET pgedge_safesession.roles = 'safesession_seq';

SET SESSION AUTHORIZATION safesession_seq;

-- The view reads, and reports the value the sequence is actually on
SELECT sequencename, last_value FROM pg_sequences
    WHERE sequencename = 'test_seq';

-- The function behind it reads directly too
SELECT pg_sequence_last_value('test_seq'::regclass) AS last_value;

-- Reading is not advancing: the value is unchanged by the reads above
SELECT pg_sequence_last_value('test_seq'::regclass) AS still_the_same;

-- Allowing the reader discloses no value the role could not already
-- read. pg_sequences lists every sequence -- it always has -- but
-- last_value is privilege-checked, so an unprivileged one reads NULL.
SELECT sequencename, last_value IS NULL AS last_value_withheld
    FROM pg_sequences WHERE sequencename = 'other_seq';

-- And the function guards itself, so calling it directly does not get
-- round the view's check. Through PG 17 that raises permission denied;
-- PG 18 moved the check inside the function, which returns NULL. Assert
-- the withholding, not which guard fired.
DO $$
DECLARE
    withheld boolean;
BEGIN
    BEGIN
        withheld := pg_sequence_last_value('other_seq'::regclass) IS NULL;
    EXCEPTION WHEN insufficient_privilege THEN
        withheld := true;
    END;
    RAISE NOTICE 'direct call withheld last_value: %', withheld;
END $$;

-- Advancing a sequence is still blocked, by either route
SELECT nextval('test_seq');
SELECT setval('test_seq', 100);

RESET SESSION AUTHORIZATION;

-- The sequence was not advanced by anything above
SELECT last_value FROM test_seq;

-- Cleanup
SET default_transaction_read_only = off;
RESET pgedge_safesession.roles;
DROP SEQUENCE test_seq;
DROP SEQUENCE other_seq;
DROP ROLE safesession_seq;
DROP EXTENSION pgedge_safesession;
