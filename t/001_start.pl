#########################################################################
#
# pgEdge SafeSession
#
# Copyright (c) 2025 - 2026, pgEdge, Inc.
# This software is released under The PostgreSQL License
#
#########################################################################

# Start, reload and server-log checks that pg_regress cannot make: what
# the extension writes to the server log, and what it does with the
# settings it is given at start and at a reload.

use strict;
use warnings;
use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;
use Test::More;

my $node = PostgreSQL::Test::Cluster->new('safesession');
$node->init;
$node->append_conf('postgresql.conf', qq{
log_statement = none
shared_preload_libraries = 'pgedge_safesession'
pgedge_safesession.read_only_roles = 'safesession_ro, safesession_missing'
});
$node->start;
$node->safe_psql('postgres', q{
CREATE EXTENSION pgedge_safesession;
CREATE ROLE safesession_admin LOGIN CREATEROLE;
CREATE ROLE safesession_user LOGIN;
GRANT EXECUTE ON FUNCTION pg_reload_conf() TO safesession_user;
CREATE ROLE safesession_pool SUPERUSER LOGIN;
CREATE ROLE safesession_anon;
CREATE TABLE notes (id int);
GRANT ALL ON notes TO safesession_anon;
});

# Number of matches of a pattern in the server log so far
sub count_log
{
    my ($re) = @_;
    my @m = (slurp_file($node->logfile) =~ /$re/g);
    return scalar @m;
}

# The missing-role LOG can run inside any statement, such as one that sets
# a password: the statement and its context must not be logged with it
$node->safe_psql('postgres',
    q{CREATE ROLE safesession_app LOGIN PASSWORD 'Cleartext-One'},
    extra_params => [ '-U', 'safesession_admin' ]);
$node->safe_psql('postgres',
    q{DO $$BEGIN EXECUTE
      'ALTER ROLE safesession_admin PASSWORD ''Cleartext-Two'''; END$$},
    extra_params => [ '-U', 'safesession_admin' ]);
is(count_log(qr/Cleartext/), 0, 'no password in the server log');
ok(count_log(qr/role "safesession_missing" does not exist/),
    'missing role logged');

# Logged once per session, not again after a reload that changes nothing
my $before = count_log(qr/role "safesession_missing" does not exist/);
$node->safe_psql('postgres', q{
SELECT 1;
SELECT pg_reload_conf();
SELECT pg_sleep(0.5);
SELECT 2;
}, extra_params => [ '-U', 'safesession_user' ]);
is(count_log(qr/role "safesession_missing" does not exist/) - $before,
    1, 'missing role logged once per session');

# A superuser login on delegating_roles that switches with SET SESSION
# AUTHORIZATION is judged by the role it switched into, and logs a missing
# role like any delegating session
$node->append_conf('postgresql.conf',
    "pgedge_safesession.delegating_roles = 'safesession_pool'\n"
    . "pgedge_safesession.acting_read_only_roles = "
    . "'safesession_anon, safesession_ghost'\n");
$node->reload;
my ($ret, $out, $err) = $node->psql('postgres', q{
BEGIN;
SET LOCAL SESSION AUTHORIZATION safesession_anon;
INSERT INTO notes VALUES (1);
ROLLBACK;
}, extra_params => [ '-U', 'safesession_pool' ]);
like($err, qr/cannot execute INSERT in a read-only session/,
    'superuser pool switched with SET SESSION AUTHORIZATION is read-only');
ok(count_log(qr/role "safesession_ghost" does not exist/),
    'superuser pool logs a missing role');

# A reload with a bad list keeps the previous value
$node->append_conf('postgresql.conf',
    qq{pgedge_safesession.read_only_roles = '"bad'\n});
$node->reload;
$node->wait_for_log(
    qr/contains errors; (?:unaffected changes were|no changes were) applied/);
is($node->safe_psql('postgres', 'SHOW pgedge_safesession.read_only_roles'),
    'safesession_ro, safesession_missing',
    'bad list at reload keeps the old value');

# A bad list at start stops the server
$node->stop;
ok(!$node->start(fail_ok => 1), 'bad list at start refused');
ok(count_log(qr/FATAL:\ \ invalid\ value\ for\ parameter
                  \ "pgedge_safesession\.read_only_roles"/x),
    'bad list FATAL logged');

# An unknown name at start stops the server and names the file and line,
# once
$node->append_conf('postgresql.conf', qq{
pgedge_safesession.read_only_roles = 'safesession_ro'
pgedge_safesession.read_only_rolez = 'safesession_ro'
});
ok(!$node->start(fail_ok => 1), 'unknown name at start refused');
ok(count_log(qr/unrecognized\ configuration\ parameter
                  \ "pgedge_safesession\.read_only_rolez"\n
                  (?:.*\n)??.*CONTEXT:\ \ line\ \d+\ of\ configuration
                  \ file\ "[^"]*postgresql\.conf"/x),
    'unknown name FATAL names its file and line');
is(count_log(qr/given on the configuration file/), 0,
    'unknown name FATAL has one CONTEXT line');

done_testing();
