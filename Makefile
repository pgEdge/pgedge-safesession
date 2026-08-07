EXTENSION = pgedge_safesession
MODULE_big = pgedge_safesession
OBJS = src/pgedge_safesession.o

DATA = sql/pgedge_safesession--1.0-alpha1.sql

REGRESS = safesession_basic safesession_bypass safesession_functions \
          safesession_ddl safesession_copy safesession_ctas \
          safesession_secdef safesession_membership \
          safesession_advanced safesession_gucs safesession_abort \
          safesession_explain safesession_cte safesession_walker \
          safesession_prepared safesession_guctamper \
          safesession_rolescheck safesession_procedural \
          safesession_rolecache safesession_status \
          safesession_coverage
REGRESS_OPTS = --inputdir=test

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
