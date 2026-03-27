# pgEdge SafeSession

[![CI](https://github.com/pgEdge/pgedge-safesession/actions/workflows/ci.yml/badge.svg)](https://github.com/pgEdge/pgedge-safesession/actions/workflows/ci.yml)

A PostgreSQL extension that enforces read-only sessions for
specified database roles. SafeSession uses executor and utility
hooks to provide defense-in-depth protection, blocking all
write operations, DDL, and other potentially dangerous commands
for restricted roles.

## Key Features

- Blocks DML (including MERGE on PG 15+), DDL, COPY FROM,
  GRANT/REVOKE, VACUUM/ANALYZE, and C-language function
  execution
- Session-user anchored: SET ROLE and SECURITY DEFINER
  functions cannot escape restrictions
- Role membership inheritance: members of restricted roles
  are also restricted
- Superuser exemption: superusers are never blocked
- Supports PostgreSQL 14+

## Quick Start

Build and install:

```bash
make
sudo make install
```

Add to `postgresql.conf` and restart PostgreSQL:

```
shared_preload_libraries = 'pgedge_safesession'
```

Configure restricted roles:

```sql
-- Optional: register in pg_extension catalog
CREATE EXTENSION pgedge_safesession;

ALTER SYSTEM SET pgedge_safesession.roles =
    'readonly_user, reporting_role';
SELECT pg_reload_conf();
```

Any session authenticated as a listed role (or a member of
one) will be restricted to read-only operations:

```sql
-- As readonly_user:
SELECT * FROM orders;             -- OK
INSERT INTO orders VALUES (1);    -- ERROR
CREATE TABLE tmp (id int);        -- ERROR
```

## Documentation

Full documentation is available in the
[docs](docs/index.md) directory.

## Running Tests

With the extension installed and loaded via
`shared_preload_libraries`:

```bash
make installcheck
```

## Licence

See [LICENCE.md](LICENCE.md).
