# Project Design Notes

## Overview

pgEdge SafeSession is a PostgreSQL extension that enforces read-only sessions
to the database server for specified PostgreSQL roles.

## Architecture

An SUSET GUC is used to define the PostgreSQL roles to which read-only 
enforcement is applied. Any session for a role that is, or has membership of,
a role specified in a comma delimited list in the GUC 
(pgedge_safesession_roles) will have read-only operation enforced. This will
be achived through the use of planner/executor hooks which will force the
transaction into READ ONLY mode.

## Guardrails

This is a security/safety mechanism, so we need to ensure that there is no
way for a session to break out of the read-only restrictions, e.g. through
means such as:

* SET ROLE
* Stored procedures
* Functions that may call SPI_exec or similar

If a session is running as a role or member of a role that is listed in the
pgedge_safesession_roles GUC, it MUST NOT be able to break through those 
protections and execute any query that may modify data or schema, or call any
function, stored procedure, COPY TO, or similar in any way that might cause 
any writes.

## PostgreSQL Support

The extension must support PostgreSQL 14 and later.

## Tests

Comprehensive tests must be included to verify all protections and potential
attack vectors.
