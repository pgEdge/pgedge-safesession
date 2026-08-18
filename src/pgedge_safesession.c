/*-------------------------------------------------------------------------
 *
 * pgEdge SafeSession
 *
 * Copyright (c) 2025 - 2026, pgEdge, Inc.
 * This software is released under The PostgreSQL License
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

/*
 * GETSTRUCT lives in access/htup_details.h, which this file used to reach
 * transitively through the other PostgreSQL headers below. PostgreSQL 19
 * dropped it from that include chain, so include it explicitly; on
 * PostgreSQL 14-18 the header is already in the chain and this is a no-op.
 */
#include "access/genam.h"
#include "access/htup_details.h"
#include "access/table.h"
#include "access/transam.h"
#include "access/xact.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_language.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_proc.h"
#include "catalog/pg_type.h"
#include "commands/defrem.h"
/* ExplainState, referenced only by the PostgreSQL 19 planner_hook below. */
#if PG_VERSION_NUM >= 190000
#include "commands/explain_state.h"
#endif
#include "commands/prepare.h"
#include "executor/executor.h"
#include "executor/functions.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/nodes.h"
#include "nodes/parsenodes.h"
#include "nodes/plannodes.h"
#include "optimizer/planner.h"
#include "parser/analyze.h"
#include "parser/parse_expr.h"
#include "parser/parse_node.h"
#include "tcop/cmdtag.h"
#include "tcop/tcopprot.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/catcache.h"
#include "utils/fmgroids.h"
#include "utils/guc.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/plancache.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/varlena.h"

PG_MODULE_MAGIC;

/* GUC variables */
static char *safesession_roles = NULL;
static bool safesession_block_dml = true;
static bool safesession_block_ddl = true;
static bool safesession_block_c_functions = true;
static bool safesession_block_all_c_functions = false;

/* Saved hook values */
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static post_parse_analyze_hook_type prev_post_parse_analyze = NULL;
static planner_hook_type prev_planner_hook = NULL;
static object_access_hook_type prev_object_access_hook = NULL;

/* Function declarations */
void _PG_init(void);

/*
 * Built-in (pg_catalog) VOLATILE functions confirmed to have no
 * observable side effect: no write (sequences, large objects), no
 * filesystem access, no configuration change, no signalling another
 * backend, no replication action, no cross-session lock.
 *
 * The sequence rule is about advancing one, not about reading one.
 * nextval() and setval() move a sequence and stay blocked;
 * pg_sequence_last_value() only reads the current page and is listed,
 * because pg_sequences is built on it and schema introspection should
 * not need write access to work.
 *
 * Built-ins are checked in their own branch in function_is_blocked(),
 * before the non-builtin branch that gates on language trust, so a
 * built-in never reaches that rule regardless of its own language. A
 * VOLATILE built-in is blocked unless its name is on this list, even
 * one written in a trusted language: pg_relation_size(), for example,
 * is LANGUAGE sql internally, but still needs an entry here. The list
 * is therefore an allow-list, not a denylist: it only needs to name
 * the built-ins verified safe, not every dangerous one, so a new
 * PostgreSQL release that adds a VOLATILE built-in is blocked by
 * default rather than silently let through.
 */
static const char *const safe_volatile_builtins[] = {
    "array_sample",
    "array_shuffle",
    "clock_timestamp",
    "current_query",
    "currval",
    "cursor_to_xml",
    "cursor_to_xmlschema",
    "gen_random_uuid",
    "lastval",
    "pg_collation_actual_version",
    "pg_current_wal_flush_lsn",
    "pg_current_wal_insert_lsn",
    "pg_current_wal_lsn",
    "pg_database_collation_actual_version",
    "pg_database_size",
    "pg_get_loaded_modules",
    "pg_get_wait_events",
    "pg_get_wal_replay_pause_state",
    "pg_get_wal_resource_managers",
    "pg_indexes_size",
    "pg_is_in_recovery",
    "pg_is_wal_replay_paused",
    "pg_jit_available",
    "pg_last_committed_xact",
    "pg_last_wal_receive_lsn",
    "pg_last_wal_replay_lsn",
    "pg_last_xact_replay_timestamp",
    "pg_notification_queue_usage",
    "pg_notify",
    "pg_partition_ancestors",
    "pg_partition_tree",
    "pg_relation_size",
    "pg_sequence_last_value",
    "pg_stat_get_io",
    "pg_stat_get_recovery_prefetch",
    "pg_stat_get_xact_blocks_fetched",
    "pg_stat_get_xact_blocks_hit",
    "pg_stat_get_xact_function_calls",
    "pg_stat_get_xact_function_self_time",
    "pg_stat_get_xact_function_total_time",
    "pg_stat_get_xact_numscans",
    "pg_stat_get_xact_tuples_deleted",
    "pg_stat_get_xact_tuples_fetched",
    "pg_stat_get_xact_tuples_hot_updated",
    "pg_stat_get_xact_tuples_inserted",
    "pg_stat_get_xact_tuples_newpage_updated",
    "pg_stat_get_xact_tuples_returned",
    "pg_stat_get_xact_tuples_updated",
    "pg_table_size",
    "pg_tablespace_size",
    "pg_total_relation_size",
    "pg_xact_commit_timestamp",
    "pg_xact_commit_timestamp_origin",
    "pg_xact_status",
    "random",
    "random_normal",
    "setseed",
    "timeofday",
    "txid_status",
    "uuidv4",
    "uuidv7",
};

static bool
name_is_safe_volatile_builtin(const char *proname)
{
    int i;

    for (i = 0; i < lengthof(safe_volatile_builtins); i++)
    {
        if (strcmp(proname, safe_volatile_builtins[i]) == 0)
            return true;
    }
    return false;
}

static bool function_is_blocked(Oid funcid, void *context);
static bool query_has_blocked_function_walker(Node *node, void *context);

/*
 * Is this function's language "trusted", i.e. does its body run its work
 * as SQL through the executor?
 *
 * SQL and the trusted procedural languages (PL/pgSQL, trusted PL/Perl,
 * ...) all have lanpltrusted set. A PL body goes through SPI, so its
 * writes and dangerous calls are re-analysed and caught there. A SQL body
 * is not always, because the planner may inline it, so
 * function_is_blocked() checks it up front; see
 * sql_function_body_is_blocked(). C, internal and untrusted PLs
 * (plpython3u, plperlu, ...) can act natively, outside anything we can
 * observe, and are treated as potentially side-effecting.
 */
static bool
language_is_trusted(Oid prolang)
{
    HeapTuple        langtup;
    Form_pg_language lang;
    bool             trusted;

    langtup = SearchSysCache1(LANGOID, ObjectIdGetDatum(prolang));
    if (!HeapTupleIsValid(langtup))
        return false;   /* unknown language: treat as untrusted */

    lang = (Form_pg_language) GETSTRUCT(langtup);
    trusted = lang->lanpltrusted;
    ReleaseSysCache(langtup);
    return trusted;
}

/*
 * Is the procedural language of a DO block trusted? A DO block in a
 * trusted language (PL/pgSQL by default) runs its work as SQL through the
 * executor, so its writes and any dangerous calls are caught downstream;
 * one in an untrusted language (plpython3u, plperlu, ...) can act
 * natively and must be rejected.
 */
static bool
do_block_is_trusted(DoStmt *stmt)
{
    ListCell   *lc;
    const char *langname = "plpgsql";   /* the default DO language */
    HeapTuple   langtup;
    bool        trusted;

    foreach(lc, stmt->args)
    {
        DefElem *de = (DefElem *) lfirst(lc);

        if (strcmp(de->defname, "language") == 0)
            langname = strVal(de->arg);
    }

    langtup = SearchSysCache1(LANGNAME, CStringGetDatum(langname));
    if (!HeapTupleIsValid(langtup))
        return false;   /* unknown language: treat as untrusted */

    trusted = ((Form_pg_language) GETSTRUCT(langtup))->lanpltrusted;
    ReleaseSysCache(langtup);
    return trusted;
}

/*
 * Is the language of the procedure invoked by a CALL trusted? Same
 * reasoning as do_block_is_trusted().
 */
static bool
call_target_is_trusted(CallStmt *stmt)
{
    HeapTuple    proctup;
    Oid          prolang;

    if (stmt->funcexpr == NULL)
        return false;

    proctup = SearchSysCache1(PROCOID,
                              ObjectIdGetDatum(stmt->funcexpr->funcid));
    if (!HeapTupleIsValid(proctup))
        return false;

    prolang = ((Form_pg_proc) GETSTRUCT(proctup))->prolang;
    ReleaseSysCache(proctup);
    return language_is_trusted(prolang);
}

/*
 * An aggregate carries its own volatility in pg_proc, which need not match
 * that of its underlying support functions: CREATE AGGREGATE happily
 * leaves an aggregate marked IMMUTABLE even when its transition function
 * is VOLATILE. A query references only the aggregate, so checking the
 * aggregate's OID alone would let a volatile transition (or final, etc.)
 * function run unnoticed. Expand the aggregate to its support functions
 * and check each of them.
 */
static bool
aggregate_support_is_blocked(Oid aggfnoid)
{
    HeapTuple          aggtup;
    Form_pg_aggregate  agg;
    bool               result = false;

    aggtup = SearchSysCache1(AGGFNOID, ObjectIdGetDatum(aggfnoid));
    if (!HeapTupleIsValid(aggtup))
        return false;

    agg = (Form_pg_aggregate) GETSTRUCT(aggtup);

    if ((OidIsValid(agg->aggtransfn) &&
         function_is_blocked(agg->aggtransfn, NULL)) ||
        (OidIsValid(agg->aggfinalfn) &&
         function_is_blocked(agg->aggfinalfn, NULL)) ||
        (OidIsValid(agg->aggcombinefn) &&
         function_is_blocked(agg->aggcombinefn, NULL)) ||
        (OidIsValid(agg->aggserialfn) &&
         function_is_blocked(agg->aggserialfn, NULL)) ||
        (OidIsValid(agg->aggdeserialfn) &&
         function_is_blocked(agg->aggdeserialfn, NULL)) ||
        (OidIsValid(agg->aggmtransfn) &&
         function_is_blocked(agg->aggmtransfn, NULL)) ||
        (OidIsValid(agg->aggminvtransfn) &&
         function_is_blocked(agg->aggminvtransfn, NULL)) ||
        (OidIsValid(agg->aggmfinalfn) &&
         function_is_blocked(agg->aggmfinalfn, NULL)))
        result = true;

    ReleaseSysCache(aggtup);
    return result;
}

/*
 * Policy: does this function OID refer to a function that a restricted
 * session must not be allowed to execute?
 *
 * A function is blocked when it is either:
 *   - a user or extension function (OID >= FirstNormalObjectId) that is
 *     marked VOLATILE and written in an untrusted language (C, internal
 *     or an untrusted PL), i.e. one that may have side effects we cannot
 *     otherwise observe. STABLE and IMMUTABLE functions, and functions in
 *     trusted languages (SQL, PL/pgSQL, ...) whose writes are caught
 *     downstream, are allowed; or
 *   - a built-in (OID < FirstNormalObjectId) that is marked VOLATILE and
 *     is not on the safe_volatile_builtins allow-list. This branch runs
 *     before the language-trust rule above, so a built-in is gated here
 *     regardless of its own language — including a trusted-language one
 *     such as pg_relation_size() (LANGUAGE sql). Unlike user functions,
 *     an unrecognised VOLATILE built-in is blocked by default rather
 *     than allowed by default, because the set of built-ins is
 *     version-dependent and grows with every PostgreSQL release.
 *
 * Harmless volatile built-ins such as random() and clock_timestamp() are
 * deliberately allow-listed. Separately, when block_all_c_functions is
 * set, every C-language function is blocked regardless of volatility.
 *
 * The signature matches check_function_callback so this can be handed to
 * check_functions_in_node().
 */
/*
 * The functions whose bodies are being walked on the current path.
 *
 * We record the path rather than counting depth. Re-entering a function
 * that is already on it adds nothing, since the frame above is already
 * walking that body, and stopping there ends a recursive or mutually
 * recursive walk without giving up on a chain that is merely long. The
 * fixed bound is a backstop against a path longer than any real one; it
 * raises an error rather than reporting "not blocked", so nesting can
 * never be used to slip a call past the check.
 */
#define SQL_BODY_MAX_DEPTH 64
static Oid sql_body_path[SQL_BODY_MAX_DEPTH];
static int sql_body_depth = 0;

static bool
funcid_on_current_path(Oid funcid)
{
    int i;

    for (i = 0; i < sql_body_depth; i++)
    {
        if (sql_body_path[i] == funcid)
            return true;
    }
    return false;
}

/*
 * Does this function have a polymorphic argument or return type, i.e. one
 * that is resolved from the call site rather than from the catalog?
 */
static bool
function_is_polymorphic(HeapTuple proctup)
{
    Form_pg_proc procform = (Form_pg_proc) GETSTRUCT(proctup);
    int          i;

    if (IsPolymorphicType(procform->prorettype))
        return true;

    for (i = 0; i < procform->pronargs; i++)
    {
        if (IsPolymorphicType(procform->proargtypes.values[i]))
            return true;
    }

    return false;
}

/*
 * Would any built-in of this name be blocked?
 *
 * A raw parse tree names the function it calls but carries no OID, so the
 * volatility and language that decide the question have to come from the
 * catalog. Look the name up among the built-ins and ask the same
 * function_is_blocked() every other path asks, so one built-in rule
 * governs both, rather than a second copy of it here that a change to the
 * allow-list would leave behind.
 *
 * The lookup is by bare name in pg_catalog, ignoring any schema
 * qualification and every overload's argument types: a raw tree cannot be
 * resolved to one overload without the types this path does not have.
 * That errs towards blocking, which is the safe direction, and it only
 * bites where a name that a built-in also carries is spelled in a body
 * whose types cannot be resolved.
 */
static bool
builtin_name_is_blocked(const char *proname)
{
    CatCList *catlist;
    int       i;
    bool      result = false;

    catlist = SearchSysCacheList1(PROCNAMEARGSNSP, CStringGetDatum(proname));

    for (i = 0; i < catlist->n_members; i++)
    {
        HeapTuple    proctup = &catlist->members[i]->tuple;
        Form_pg_proc procform = (Form_pg_proc) GETSTRUCT(proctup);

        if (procform->pronamespace != PG_CATALOG_NAMESPACE)
            continue;

        if (function_is_blocked(procform->oid, NULL))
        {
            result = true;
            break;
        }
    }

    ReleaseSysCacheList(catlist);

    return result;
}

/*
 * Scan a raw parse tree for a call to a blocked built-in, by name.
 *
 * Used for a body we cannot analyse. A polymorphic argument type is only
 * resolved from the call site, and this check has a function OID rather
 * than a call expression to resolve it from, so parse analysis of such a
 * body fails outright. Letting that error escape would make every
 * polymorphic SQL function uncallable by a restricted role, so match on
 * the names a raw tree does carry instead. That covers the built-ins,
 * which are the calls the body check exists to catch, but not a volatile
 * function in an untrusted language reached from such a body, which needs
 * types to identify.
 */
static bool
raw_body_calls_blocked_builtin(Node *node, void *context)
{
    if (node == NULL)
        return false;

    check_stack_depth();

    if (IsA(node, FuncCall))
    {
        FuncCall *fc = (FuncCall *) node;

        if (fc->funcname != NIL &&
            builtin_name_is_blocked(strVal(llast(fc->funcname))))
            return true;
    }

    return raw_expression_tree_walker(node, raw_body_calls_blocked_builtin,
                                      context);
}

/*
 * Does the body of a SQL-language function call something a restricted
 * session must not run?
 *
 * A SQL function passes the language test below, on the grounds that its
 * body is caught downstream. That holds for writes, which reach the
 * executor, but not for a built-in off the safe-VOLATILE allow-list, which
 * is blocked precisely because it escapes the executor. Nor is the body
 * always re-analysed on the way through: the planner inlines a simple SQL
 * function instead of running it through functions.c, and inlining happens
 * after this check. So look inside.
 */
static bool
sql_function_body_is_blocked(Oid funcid)
{
    HeapTuple  proctup;
    Datum      tmp;
    bool       isnull;
    bool       result = false;

    /* Already being walked further up, so its body is covered there */
    if (funcid_on_current_path(funcid))
        return false;

    if (sql_body_depth >= SQL_BODY_MAX_DEPTH)
    {
        char *funcname = get_func_name(funcid);

        ereport(ERROR,
                (errcode(ERRCODE_STATEMENT_TOO_COMPLEX),
                 errmsg("cannot verify the body of SQL function \"%s\" in"
                        " a read-only session: nesting is too deep",
                        funcname ? funcname : "?"),
                 errhint("This session is restricted to read-only access"
                         " by the pgedge_safesession extension.")));
    }

    proctup = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcid));
    if (!HeapTupleIsValid(proctup))
        return false;

    sql_body_path[sql_body_depth++] = funcid;
    PG_TRY();
    {
        tmp = SysCacheGetAttr(PROCOID, proctup, Anum_pg_proc_prosqlbody,
                              &isnull);
        if (!isnull)
        {
            /* A standard-body (BEGIN ATOMIC) function is stored analysed */
            Node *body = (Node *) stringToNode(TextDatumGetCString(tmp));

            result = query_has_blocked_function_walker(body, NULL);
        }
        else
        {
            /* An old-style body is plain text, so parse it first */
            SQLFunctionParseInfoPtr pinfo;
            char       *prosrc;
            ListCell   *lc;
            bool        polymorphic = function_is_polymorphic(proctup);

            tmp = SysCacheGetAttr(PROCOID, proctup, Anum_pg_proc_prosrc,
                                  &isnull);
            if (isnull)
                elog(ERROR, "null prosrc for function %u", funcid);
            prosrc = TextDatumGetCString(tmp);

            /*
             * Parameters of a polymorphic function cannot be typed without
             * the call site, so such a body is scanned by name rather than
             * analysed (see raw_body_calls_blocked_builtin).
             */
            pinfo = polymorphic ? NULL
                : prepare_sql_fn_parse_info(proctup, NULL, InvalidOid);

            foreach(lc, pg_parse_query(prosrc))
            {
                RawStmt  *raw = lfirst_node(RawStmt, lc);
                List     *querytrees;
                ListCell *lc2;

                if (polymorphic)
                {
                    result = raw_body_calls_blocked_builtin(raw->stmt,
                                                            NULL);
                    if (result)
                        break;
                    continue;
                }

                /*
                 * Analyse the statement the way functions.c would, which
                 * also runs this hook again on each inner statement.
                 */
#if PG_VERSION_NUM >= 150000
                querytrees = pg_analyze_and_rewrite_withcb(
                    raw, prosrc,
                    (ParserSetupHook) sql_fn_parser_setup, pinfo, NULL);
#else
                querytrees = pg_analyze_and_rewrite_params(
                    raw, prosrc,
                    (ParserSetupHook) sql_fn_parser_setup, pinfo, NULL);
#endif
                foreach(lc2, querytrees)
                {
                    if (query_has_blocked_function_walker(
                            (Node *) lfirst(lc2), NULL))
                    {
                        result = true;
                        break;
                    }
                }
                if (result)
                    break;
            }
        }
    }
    PG_FINALLY();
    {
        sql_body_depth--;
        ReleaseSysCache(proctup);
    }
    PG_END_TRY();

    return result;
}

static bool
function_is_blocked(Oid funcid, void *context)
{
    HeapTuple    proctup;
    Form_pg_proc procform;
    bool         result;
    char         prokind;
    char         provolatile;
    Oid          prolang;
    bool         is_builtin;
    NameData     proname;

    proctup = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcid));
    if (!HeapTupleIsValid(proctup))
        return false;

    procform = (Form_pg_proc) GETSTRUCT(proctup);
    prokind = procform->prokind;
    provolatile = procform->provolatile;
    prolang = procform->prolang;
    proname = procform->proname;
    is_builtin = (funcid < FirstNormalObjectId);
    ReleaseSysCache(proctup);

    if (safesession_block_all_c_functions && prolang == ClanguageId)
        result = true;
    else if (is_builtin)
        result = (provolatile == PROVOLATILE_VOLATILE) &&
                 !name_is_safe_volatile_builtin(NameStr(proname));
    else
        result = (provolatile == PROVOLATILE_VOLATILE) &&
                 !language_is_trusted(prolang);

    /*
     * An aggregate's declared volatility need not reflect its support
     * functions, so also check those (see aggregate_support_is_blocked).
     */
    if (!result && prokind == PROKIND_AGGREGATE)
        result = aggregate_support_is_blocked(funcid);

    /* A SQL function is judged by its body as well as by its language */
    if (!result && !is_builtin && prolang == SQLlanguageId &&
        prokind == PROKIND_FUNCTION)
        result = sql_function_body_is_blocked(funcid);

    return result;
}

/*
 * Does any CHECK constraint on this domain, or on any domain it is
 * stacked over, call a function a restricted session must not run?
 *
 * A domain's constraint expressions are not part of the Query or
 * Plan tree the walker otherwise sees: they are fetched from
 * pg_constraint and evaluated by the executor at runtime through the
 * domain constraint cache in typcache.c. This mirrors that lookup
 * (same catalog, same index, same contype filter) but walks the raw
 * expression with the existing function-blocked walker instead of
 * building an executable DomainConstraintState.
 *
 * A domain may be declared over another domain, and each level can
 * carry its own constraints, so this walks up through typbasetype
 * until a non-domain base type is reached.
 */
static bool
domain_constraint_is_blocked(Oid typeOid)
{
    for (;;)
    {
        HeapTuple    typtup;
        Form_pg_type typform;
        Oid          basetypid;
        Relation     conrel;
        SysScanDesc  scan;
        ScanKeyData  skey;
        HeapTuple    contup;
        bool         found = false;

        typtup = SearchSysCache1(TYPEOID, ObjectIdGetDatum(typeOid));
        if (!HeapTupleIsValid(typtup))
            return false;

        typform = (Form_pg_type) GETSTRUCT(typtup);
        if (typform->typtype != TYPTYPE_DOMAIN)
        {
            ReleaseSysCache(typtup);
            return false;
        }

        basetypid = typform->typbasetype;
        ReleaseSysCache(typtup);

        ScanKeyInit(&skey,
                    Anum_pg_constraint_contypid,
                    BTEqualStrategyNumber, F_OIDEQ,
                    ObjectIdGetDatum(typeOid));

        conrel = table_open(ConstraintRelationId, AccessShareLock);
        scan = systable_beginscan(conrel, ConstraintTypidIndexId,
                                  true, NULL, 1, &skey);

        while ((contup = systable_getnext(scan)) != NULL)
        {
            Form_pg_constraint conform =
                (Form_pg_constraint) GETSTRUCT(contup);
            Datum  conbindatum;
            bool   isnull;
            Node  *check_expr;

            if (conform->contype != CONSTRAINT_CHECK)
                continue;

            conbindatum = heap_getattr(contup,
                                       Anum_pg_constraint_conbin,
                                       RelationGetDescr(conrel),
                                       &isnull);
            if (isnull)
                continue;

            check_expr = stringToNode(
                TextDatumGetCString(conbindatum));

            if (query_has_blocked_function_walker(check_expr, NULL))
            {
                found = true;
                break;
            }
        }

        systable_endscan(scan);
        table_close(conrel, AccessShareLock);

        if (found)
            return true;

        typeOid = basetypid;
    }
}

/*
 * Walk a parse-analysed Query, and everything reachable from it
 * (subqueries, CTEs, set operations, join and index quals, aggregates,
 * window functions, ScalarArrayOpExpr, and so on), looking for a
 * function that function_is_blocked() rejects.
 *
 * check_functions_in_node() enumerates every function-bearing node type,
 * so this covers the whole statement rather than a hand-picked set of
 * plan fields, and does not need revisiting when a new node type or plan
 * shape is added.
 */
static bool
query_has_blocked_function_walker(Node *node, void *context)
{
    if (node == NULL)
        return false;

    /* This walker recurses into itself; bound it like core's walkers. */
    check_stack_depth();

    if (check_functions_in_node(node, function_is_blocked, context))
        return true;

    if (IsA(node, Query))
    {
        Query *query = (Query *) node;

        /*
         * query_tree_walker() does not descend into a utility statement,
         * but CALL evaluates its arguments before the procedure body
         * runs, and those arguments are ordinary expressions that may
         * call anything. Since the procedure itself is allowed whenever
         * its language is trusted, a blocked function passed as an
         * argument would otherwise execute unexamined.
         */
        if (query->commandType == CMD_UTILITY &&
            query->utilityStmt != NULL &&
            IsA(query->utilityStmt, CallStmt) &&
            query_has_blocked_function_walker(
                (Node *) ((CallStmt *) query->utilityStmt)->funcexpr,
                context))
            return true;

        return query_tree_walker(query,
                                 query_has_blocked_function_walker,
                                 context, 0);
    }

    /*
     * A value being coerced to a domain type will run that domain's
     * CHECK constraints, which live in pg_constraint rather than in
     * this expression tree, so they need a separate lookup; see
     * domain_constraint_is_blocked(). Unlike the Query case above,
     * this does not return on its own: the node's own arg (the value
     * being coerced) still needs to be walked below, exactly as it
     * would be if this case were not here at all.
     */
    if (IsA(node, CoerceToDomain) &&
        domain_constraint_is_blocked(
            ((CoerceToDomain *) node)->resulttype))
        return true;

    return expression_tree_walker(node,
                                  query_has_blocked_function_walker,
                                  context);
}

static bool
query_has_blocked_function(Query *query)
{
    return query_has_blocked_function_walker((Node *) query, NULL);
}

/*
 * Cache of the configured roles resolved to OIDs.
 *
 * current_role_is_restricted() runs on every statement, and re-parsing
 * the GUC string and resolving each name to an OID each time is the bulk
 * of the cost. The resolved OID list changes only when the GUC changes or
 * when pg_authid changes (a role created, dropped or renamed), so cache
 * it and rebuild lazily after either of those. Membership is not cached
 * here: is_member_of_role_nosuper() is checked per call against the live
 * session/current user and is itself cached and invalidated by core.
 *
 * The list lives in CacheMemoryContext so it survives across statements.
 */
static List *cached_role_oids = NIL;
static bool  role_cache_valid = false;

/*
 * Whether this session was restricted the last time we looked, as a
 * tri-state: -1 until the first observation, then 0 or 1.
 *
 * The blocked-function check runs in the post_parse_analyze and planner
 * hooks, so it runs when a statement or expression is parsed and planned,
 * not when it is executed. A plan built whilst the session was
 * unrestricted is therefore reused without either check running again,
 * and PL/pgSQL caches the plans for its expressions aggressively, so a
 * session that becomes restricted part-way through its life could go on
 * calling blocked functions through anything it had already executed.
 * Nor can the check simply be moved to execution time: PL/pgSQL
 * evaluates a simple expression through ExecEvalExprSwitchContext()
 * without ever starting the executor, so the ExecutorStart hook does not
 * see it.
 *
 * What makes the cached plan wrong is the change of state, so treat that
 * change as an invalidation event and discard the cached plans, exactly as
 * DISCARD PLANS does. Everything is then re-analysed under the new state.
 *
 * Only a transition into the restricted state needs this. A plan built
 * whilst restricted has already passed the check, so it stays safe if the
 * restriction is later lifted; the first observation in a session is
 * treated as a transition so that a session which starts out restricted is
 * not trusting anything cached before we first looked.
 */
static int last_restricted_state = -1;

static void
note_restriction_state(bool restricted)
{
    int state = restricted ? 1 : 0;

    if (state == last_restricted_state)
        return;

    if (restricted)
        ResetPlanCache();

    last_restricted_state = state;
}

/*
 * The restriction also changes when the configured roles change, or when a
 * role is created, dropped, renamed or granted to another, and those can
 * happen between two executions of an already-cached plan without this
 * session running a statement in between. Discard cached plans there too,
 * rather than waiting for the next statement to notice. Registering the
 * plan-cache reset from a syscache callback is what core's own plancache
 * does (see PlanCacheSysCallback).
 */
static void
invalidate_role_cache(Datum arg, int cacheid, uint32 hashvalue)
{
    role_cache_valid = false;
    ResetPlanCache();
}

static void
assign_safesession_roles(const char *newval, void *extra)
{
    role_cache_valid = false;
    ResetPlanCache();
}

/*
 * Rebuild cached_role_oids from the current GUC value. Must be called
 * with a valid transaction in progress (it reads the catalog).
 */
static void
rebuild_role_cache(void)
{
    char     *rawstring;
    List     *rolelist;
    ListCell *lc;
    List     *newoids = NIL;

    /* We are about to read the catalog; a transaction must be active. */
    Assert(IsTransactionState());

    /*
     * Mark the cache valid before resolving anything, so that an
     * invalidation arriving while we work is not lost. The list is built to
     * one side and installed only once it is complete, so an error part of
     * the way through leaves the previous list in place rather than a
     * half-built one that would silently under-restrict.
     */
    role_cache_valid = true;

    if (safesession_roles != NULL && safesession_roles[0] != '\0')
    {
        rawstring = pstrdup(safesession_roles);

        /* Malformed; the check hook rejects this, so treat as empty. */
        if (SplitIdentifierString(rawstring, ',', &rolelist))
        {
            foreach(lc, rolelist)
            {
                char *rolename = (char *) lfirst(lc);
                Oid   roleid = get_role_oid(rolename, true);

                if (OidIsValid(roleid))
                {
                    MemoryContext old;

                    old = MemoryContextSwitchTo(CacheMemoryContext);
                    newoids = lappend_oid(newoids, roleid);
                    MemoryContextSwitchTo(old);
                }
            }
        }

        pfree(rawstring);
        list_free(rolelist);
    }

    list_free(cached_role_oids);
    cached_role_oids = newoids;
}

/*
 * Check whether the current session role is restricted.
 *
 * Returns true if the session user or current user is listed in
 * pgedge_safesession.roles, or is a member of a listed role.
 *
 * Superuser exemption: if the SESSION user is a superuser, the
 * session is never restricted. We deliberately check the session
 * user (not the current user) so that SECURITY DEFINER functions
 * owned by superusers cannot bypass the restriction.
 *
 * Membership is tested with is_member_of_role_nosuper() rather than
 * is_member_of_role(), because the latter reports that a superuser is a
 * member of every role in the database, having no grant behind it at all.
 * That is the right answer for a privilege test and the wrong one here:
 * we are asking whether the acting role was actually placed in a
 * restricted group, not whether it happens to hold that group's
 * privileges by other means.
 */
static bool
current_role_is_restricted(void)
{
    ListCell   *lc;
    Oid         session_userid;
    Oid         current_userid;

    /* No roles configured means no restrictions */
    if (safesession_roles == NULL ||
        safesession_roles[0] == '\0')
        return false;

    /*
     * Superuser exemption: only check the session user.
     * This ensures that SECURITY DEFINER functions owned by
     * superusers cannot bypass the restriction when called
     * from a restricted session.
     */
    session_userid = GetSessionUserId();
    if (superuser_arg(session_userid))
        return false;

    if (!role_cache_valid)
        rebuild_role_cache();

    current_userid = GetUserId();

    foreach(lc, cached_role_oids)
    {
        Oid roleid = lfirst_oid(lc);

        /* Check session user */
        if (session_userid == roleid ||
            is_member_of_role_nosuper(session_userid, roleid))
            return true;

        /*
         * Check current user (in case SET ROLE was used).
         *
         * The current user can be a superuser whilst the session user is
         * not, which is what a SECURITY DEFINER function owned by a
         * superuser does, and what an extension such as supautils does
         * when it briefly elevates a privileged-but-not-superuser role for
         * a single command. Asking is_member_of_role() there would answer
         * "yes" for every configured role and restrict a session that has
         * nothing to do with any of them, so the membership test must
         * ignore superuserness (see the comment above this function).
         */
        if (current_userid != session_userid &&
            (current_userid == roleid ||
             is_member_of_role_nosuper(current_userid, roleid)))
            return true;
    }

    return false;
}

/*
 * SQL-visible introspection: is the current session restricted by
 * SafeSession? Lets operators and the regression tests ask directly
 * rather than inferring it from whether a write is rejected.
 */
PG_FUNCTION_INFO_V1(pgedge_safesession_is_restricted);

Datum
pgedge_safesession_is_restricted(PG_FUNCTION_ARGS)
{
    PG_RETURN_BOOL(current_role_is_restricted());
}

/*
 * Belt-and-suspenders: force the current transaction read-only for a
 * restricted session, so PostgreSQL's own internal checks reject any
 * write that slips past our hooks.
 *
 * We set XactReadOnly directly, per statement, and never touch the
 * default_transaction_read_only GUC. XactReadOnly is transaction-scoped
 * and reset from the GUC at the start of each transaction, so setting it
 * on every executed statement and utility command keeps the current
 * transaction read-only without leaving any session-level state behind.
 *
 * We deliberately never clear it: a session that is not restricted is
 * left alone, so a user's own BEGIN READ ONLY / SET TRANSACTION READ ONLY
 * is not overridden.
 */
static void
enforce_read_only(void)
{
    XactReadOnly = true;
}

/*
 * Reject the current statement with a consistent error: the given SQLSTATE
 * and message, plus a hint identifying SafeSession as the reason, so a
 * user can tell that an extension (not core PostgreSQL) rejected the
 * statement and which setting governs it. Used by both hooks.
 */
static void
safesession_reject(int sqlerrcode, const char *msg)
{
    ereport(ERROR,
            (errcode(sqlerrcode),
             errmsg("%s", msg),
             errhint("This session is restricted to read-only access"
                     " by the pgedge_safesession extension.")));
}

/*
 * ExecutorStart hook: block DML (including data-modifying CTEs) for
 * restricted roles. Blocked function calls are handled earlier, in the
 * post_parse_analyze and planner hooks.
 */
static void
safesession_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
    bool restricted = false;

    /*
     * Only consult the catalog (the role lookups in
     * current_role_is_restricted()) or touch the read-only GUC
     * machinery while a valid transaction is in progress. See the
     * matching guard and fuller rationale in
     * safesession_ProcessUtility().
     */
    if (IsTransactionState())
    {
        restricted = current_role_is_restricted();

        /*
         * Discard cached plans if this is the moment the session became
         * restricted; see note_restriction_state(). Doing it here, before
         * the statement runs, means anything it goes on to call, such as
         * the body of a PL/pgSQL function, is re-analysed under the new
         * state rather than replayed from a plan built under the old one.
         */
        note_restriction_state(restricted);

        /* Belt-and-suspenders: force the transaction read-only */
        if (restricted)
            enforce_read_only();
    }

    if (restricted)
    {
        PlannedStmt *pstmt = queryDesc->plannedstmt;

        /* Block INSERT, UPDATE, DELETE, MERGE */
        if (safesession_block_dml)
        {
            const char *cmd = NULL;

            switch (pstmt->commandType)
            {
                case CMD_INSERT:
                    cmd = "INSERT";
                    break;
                case CMD_UPDATE:
                    cmd = "UPDATE";
                    break;
                case CMD_DELETE:
                    cmd = "DELETE";
                    break;
#if PG_VERSION_NUM >= 150000
                case CMD_MERGE:
                    cmd = "MERGE";
                    break;
#endif
                default:
                    break;
            }

            if (cmd != NULL)
                safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                                   psprintf("cannot execute %s in a"
                                            " read-only session", cmd));

            /*
             * A data-modifying CTE, e.g.
             * WITH c AS (INSERT ... RETURNING ...) SELECT * FROM c,
             * writes even though the top-level command is a SELECT, so
             * the switch above does not catch it: the ModifyTable node
             * is buried in the plan tree. PlannedStmt.hasModifyingCTE
             * flags this directly.
             */
            if (pstmt->hasModifyingCTE)
                safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                                   "cannot execute a data-modifying"
                                   " WITH clause in a read-only"
                                   " session");
        }
    }

    /* Chain to previous hook or standard function */
    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

/*
 * post_parse_analyze hook: block statements that call a function a
 * restricted session must not run. Working from the analysed Query
 * rather than the plan lets us examine every function the statement
 * references, wherever it ends up in the plan tree.
 *
 * The jstate parameter arrived in PostgreSQL 14, and PostgreSQL 19 made it
 * const in post_parse_analyze_hook_type, so each of the three signatures has
 * to be spelled out here: keeping the older one would make the assignment to
 * the hook an incompatible function pointer assignment.
 */
static void
safesession_post_parse_analyze(ParseState *pstate, Query *query
#if PG_VERSION_NUM >= 190000
                               , const JumbleState *jstate
#elif PG_VERSION_NUM >= 140000
                               , JumbleState *jstate
#endif
                               )
{
    if (prev_post_parse_analyze)
        prev_post_parse_analyze(pstate, query
#if PG_VERSION_NUM >= 140000
                                , jstate
#endif
                                );

    if (safesession_block_c_functions &&
        IsTransactionState() &&
        current_role_is_restricted() &&
        query_has_blocked_function(query))
        safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                           "cannot execute functions that may have"
                           " side effects in a read-only session");
}

/*
 * planner_hook: catch a blocked function reachable only through
 * something QueryRewrite() introduces after post_parse_analyze
 * already ran, such as a view body spliced into the range table or
 * an RLS policy's USING/WITH CHECK qual attached to an RTE's
 * securityQuals. planner_hook receives the Query after rewrite, for
 * every statement that reaches the planner (simple query protocol,
 * extended/prepared protocol -- planning happens at Bind, not Parse
 * -- and SPI queries issued from PL/pgSQL), so it is the first point
 * at which those substitutions are visible.
 *
 * A CMD_UTILITY Query (CALL, EXECUTE, ...) never reaches the
 * planner, so this does not replace the post_parse_analyze check:
 * the two cover different statement shapes, with some harmless
 * overlap for a plain top-level SELECT that calls a blocked function
 * directly.
 *
 * The check runs before chaining to the previous hook or
 * standard_planner(), both to fail fast and because standard_planner()
 * may mutate parse in place (e.g. subquery pullup); checking first
 * means the tree walked is exactly the post-rewrite Query, before any
 * planner-internal transformation.
 *
 * PostgreSQL 19 added a 5th parameter, an ExplainState *es, to both
 * planner_hook_type and standard_planner(); this function's own logic
 * never touches it, so it is only accepted and forwarded unchanged on
 * PG19+, following the same version-branching approach used for the
 * jstate parameter in safesession_post_parse_analyze() above.
 */
static PlannedStmt *
safesession_planner(Query *parse, const char *query_string,
                    int cursorOptions, ParamListInfo boundParams
#if PG_VERSION_NUM >= 190000
                    , ExplainState *es
#endif
                    )
{
    if (safesession_block_c_functions &&
        IsTransactionState() &&
        current_role_is_restricted() &&
        query_has_blocked_function(parse))
        safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                           "cannot execute functions that may have"
                           " side effects in a read-only session");

    if (prev_planner_hook)
        return prev_planner_hook(parse, query_string, cursorOptions,
                                 boundParams
#if PG_VERSION_NUM >= 190000
                                 , es
#endif
                                 );
    else
        return standard_planner(parse, query_string, cursorOptions,
                                boundParams
#if PG_VERSION_NUM >= 190000
                                , es
#endif
                                );
}

/*
 * object_access_hook: catch a blocked function that no query tree
 * mentions.
 *
 * A domain's CHECK constraint runs during coercion, not during planning
 * or execution of the statement that triggers it. For a parameter bound
 * over the extended query protocol that coercion is in
 * exec_bind_message(), which runs before the plan is fetched; for a
 * PL/pgSQL variable's declared type or a function's RETURNS type there
 * is no CoerceToDomain node in any statement to find. The Query-walking
 * hooks see neither, and by the time either of them could run, the
 * constraint has already fired.
 *
 * PostgreSQL compiles a constraint expression before evaluating it
 * (domain_check_input -> prep_domain_constraints -> ExecInitExpr), and
 * ExecInitFunc() invokes this hook for every function it compiles, so
 * rejecting here still prevents the call rather than reporting it
 * afterwards. It also covers the fast-path function protocol (PQfn),
 * which reaches none of the other hooks.
 *
 * Chained first, so a co-installed extension still sees the access even
 * when we go on to reject it.
 */
static void
safesession_object_access(ObjectAccessType access, Oid classId,
                          Oid objectId, int subId, void *arg)
{
    if (prev_object_access_hook)
        prev_object_access_hook(access, classId, objectId, subId, arg);

    if (access == OAT_FUNCTION_EXECUTE &&
        safesession_block_c_functions &&
        IsTransactionState() &&
        current_role_is_restricted() &&
        function_is_blocked(objectId, NULL))
        safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                           "cannot execute functions that may have"
                           " side effects in a read-only session");
}

/*
 * Does this SET ask for read-only to be turned on?
 *
 * A statement that asks for the state we already enforce agrees with the
 * restriction rather than working around it, so there is nothing to
 * protect against, and rejecting it would lock out any client that
 * defensively asserts read-only on the sessions it opens (a connection
 * pool that runs SET default_transaction_read_only = on for every new
 * connection would never obtain a usable one).
 *
 * ExtractSetVariableArgs() gives us the requested value for
 * SET ... = value, and the live value for SET ... FROM CURRENT, which is
 * therefore a no-op and judged on what the setting already is. It returns
 * NULL for RESET and SET ... TO DEFAULT, both of which head back towards
 * read-write and so remain protected, as does anything that does not
 * parse as a true boolean.
 */
static bool
guc_set_requests_read_only(VariableSetStmt *stmt)
{
    char *value = ExtractSetVariableArgs(stmt);
    bool  requested;

    if (value == NULL || !parse_bool(value, &requested))
        return false;

    return requested;
}

/*
 * Check if a VariableSetStmt targets a read-only GUC we protect.
 */
static bool
is_protected_guc_set(VariableSetStmt *stmt)
{
    if (stmt->kind == VAR_SET_VALUE ||
        stmt->kind == VAR_SET_DEFAULT ||
        stmt->kind == VAR_SET_CURRENT ||
        stmt->kind == VAR_RESET)
    {
        /*
         * Both the transaction-scoped transaction_read_only and the
         * session default default_transaction_read_only are protected,
         * but only against being relaxed. transaction_read_only is a
         * plain PGC_USERSET GUC any user may set, so without this a
         * restricted role's SET would report success even though
         * enforcement re-asserts read-only on the next statement.
         * Setting either of them to on cannot mislead anyone that way,
         * so it is allowed, exactly as SET TRANSACTION READ ONLY is
         * below.
         */
        if (stmt->name != NULL &&
            (pg_strcasecmp(stmt->name,
                           "default_transaction_read_only") == 0 ||
             pg_strcasecmp(stmt->name,
                           "transaction_read_only") == 0))
            return !guc_set_requests_read_only(stmt);
    }

    /*
     * SET TRANSACTION ... uses VAR_SET_MULTI with
     * name = "TRANSACTION" and a DefElem args list.
     * Check if any DefElem targets transaction_read_only
     * with a false value (i.e., READ WRITE).
     */
    if (stmt->kind == VAR_SET_MULTI)
    {
        ListCell *lc;

        foreach(lc, stmt->args)
        {
            DefElem *opt = (DefElem *) lfirst(lc);

            /*
             * Plain strcmp is correct here: defname arrives already
             * lower-cased from the grammar, unlike stmt->name above
             * (a user-supplied GUC name), which is matched with
             * pg_strcasecmp.
             */
            if (strcmp(opt->defname,
                       "transaction_read_only") == 0)
            {
                /*
                 * Block READ WRITE (value 0). Allow
                 * READ ONLY (value 1) since it is
                 * redundant with our enforcement.
                 *
                 * The argument is an A_Const wrapping an
                 * integer. We must read the value through
                 * the embedded node: applying intVal()
                 * directly to the A_Const reads the wrong
                 * field on PostgreSQL 14 (where A_Const
                 * embeds a legacy Value node) and would
                 * trip an assertion on assert-enabled
                 * builds of PostgreSQL 15+.
                 */
                if (opt->arg != NULL &&
                    IsA(opt->arg, A_Const) &&
                    intVal(&((A_Const *) opt->arg)->val) == 0)
                    return true;
            }
        }
    }

    /*
     * RESET ALL is intentionally not treated as protected. Enforcement no
     * longer relies on any session-level GUC we could set (XactReadOnly is
     * re-asserted per statement), and our own GUCs are PGC_SUSET, so a
     * restricted role's RESET ALL cannot relax the restriction. Allowing it
     * keeps connection poolers, which issue RESET ALL on connection reset,
     * working.
     */

    return false;
}

/*
 * Does this EXPLAIN request ANALYZE (which actually executes the
 * statement, rather than only planning it)?
 *
 * The whole option list is walked and the last analyze wins, because
 * that is what ExplainQuery() does when it parses the same list. Taking
 * the first would read EXPLAIN (ANALYZE off, ANALYZE on) as a plan-only
 * request whilst core went on to execute it.
 */
static bool
explain_is_analyze(ExplainStmt *stmt)
{
    ListCell *lc;
    bool      analyze = false;

    foreach(lc, stmt->options)
    {
        DefElem *opt = (DefElem *) lfirst(lc);

        if (strcmp(opt->defname, "analyze") == 0)
            analyze = defGetBoolean(opt);
    }
    return analyze;
}

/*
 * Would the statement wrapped by EXPLAIN write data if executed?
 *
 * By the time the utility hook runs, parse analysis has already replaced
 * ExplainStmt->query with an analyzed Query. We only need the write cases
 * that escape the DML check in ExecutorStart: CREATE TABLE AS, CREATE
 * MATERIALIZED VIEW AS and SELECT ... INTO. All three become a utility
 * Query whose utilityStmt is a CreateTableAsStmt, carrying the write in
 * an intoClause rather than as a top-level INSERT/UPDATE/DELETE.
 *
 * A top-level INSERT/UPDATE/DELETE/MERGE wrapped in EXPLAIN ANALYZE is
 * already blocked by ExecutorStart, so it is not handled here.
 */
static bool
explained_stmt_writes(Node *query)
{
    Query *q;

    if (query == NULL || !IsA(query, Query))
        return false;

    q = (Query *) query;

    return (q->commandType == CMD_UTILITY &&
            q->utilityStmt != NULL &&
            IsA(q->utilityStmt, CreateTableAsStmt));
}

/*
 * If this statement is an EXECUTE, or carries one, return that ExecuteStmt;
 * otherwise return NULL.
 *
 * EXPLAIN and CREATE TABLE AS each hold the statement they wrap in a field
 * that parse analysis has replaced with a utility Query, and the two can be
 * combined, so EXPLAIN CREATE TABLE AS EXECUTE nests two of them:
 *
 *     ExplainStmt->query -> Query->utilityStmt -> CreateTableAsStmt->query
 *         -> Query->utilityStmt -> ExecuteStmt
 *
 * Descend through as many of those layers as are present rather than a
 * fixed number of them. Every branch below moves strictly inwards through a
 * finite parse tree, so this terminates; in practice the grammar allows at
 * most the three levels shown above.
 */
static ExecuteStmt *
extract_execute_stmt(Node *node)
{
    for (;;)
    {
        if (node == NULL)
            return NULL;

        if (IsA(node, ExecuteStmt))
            return (ExecuteStmt *) node;

        if (IsA(node, Query))
        {
            Query *q = (Query *) node;

            if (q->commandType != CMD_UTILITY)
                return NULL;
            node = q->utilityStmt;
        }
        else if (IsA(node, ExplainStmt))
            node = ((ExplainStmt *) node)->query;
        else if (IsA(node, CreateTableAsStmt))
            node = ((CreateTableAsStmt *) node)->query;
        else
            return NULL;
    }
}

/*
 * Does the parameter list of an EXECUTE call a function a restricted
 * session must not run?
 *
 * The parameters of a prepared statement are not part of the prepared
 * Query, so the post_parse_analyze walker never sees them, and they are
 * not evaluated through the executor either: EvaluateParams() transforms
 * them at execution time and evaluates them with ExecPrepareExprList() and
 * ExecEvalExprSwitchContext(), neither of which reaches ExecutorStart().
 * Without this check a restricted role could run any blocked function
 * simply by passing it as a parameter, and would not even need a grant to
 * do so, since it can prepare the statement itself.
 *
 * At this point the parameters are still raw parse nodes (the walker dies
 * on a T_FuncCall), so each one is transformed the way EvaluateParams()
 * does, with the same ParseState setup and expression kind core uses, and
 * the transformed expression is then handed to the ordinary walker. The
 * parse tree is copied first, both because the parser scribbles on its
 * input and because core transforms the same list again afterwards.
 *
 * Unlike core we do not coerce the parameter expression itself to the
 * prepared statement's declared parameter types: coercion only adds cast
 * expressions, and its purpose here would be type checking, which core
 * still does when it evaluates the parameters for real. We do, however,
 * separately check the declared parameter types themselves for a blocked
 * domain constraint, below, since a value is coerced to its declared
 * type when it is bound regardless of what expression was passed for it,
 * and a domain's CHECK constraint is a security-relevant side effect,
 * not mere type-checking, so it must be caught even when the parameter
 * expression that will be coerced into it has nothing to do with the
 * blocked function itself (e.g. "PREPARE q(d) AS SELECT 1; EXECUTE
 * q('x')" for a domain d with a blocked-function CHECK). This means we
 * do look the prepared statement up now.
 */
static bool
execute_params_have_blocked_function(ExecuteStmt *stmt,
                                     const char *queryString)
{
    ParseState        *pstate;
    ListCell          *lc;
    PreparedStatement *pstmt_lookup;
    bool               found = false;

    pstmt_lookup = FetchPreparedStatement(stmt->name, false);
    if (pstmt_lookup != NULL)
    {
        int i;

        for (i = 0; i < pstmt_lookup->plansource->num_params; i++)
        {
            if (domain_constraint_is_blocked(
                    pstmt_lookup->plansource->param_types[i]))
                return true;
        }
    }

    if (stmt->params == NIL)
        return false;

    pstate = make_parsestate(NULL);
    pstate->p_sourcetext = queryString;

    foreach(lc, stmt->params)
    {
        Node *expr = (Node *) copyObject((Node *) lfirst(lc));

        expr = transformExpr(pstate, expr, EXPR_KIND_EXECUTE_PARAMETER);

        if (query_has_blocked_function_walker(expr, NULL))
        {
            found = true;
            break;
        }
    }

    free_parsestate(pstate);
    return found;
}

/*
 * ProcessUtility hook: block DDL and other write operations.
 *
 * This hook is fail-closed: the switch below allows an explicit set of
 * known-safe utility statements and rejects everything else in its
 * default branch. A utility statement (in particular a DDL command) that
 * nobody has considered is therefore denied rather than let through, and
 * a new statement type added by a future PostgreSQL release is denied
 * until it is deliberately allowed. Function-call detection, by contrast,
 * lives in the post_parse_analyze and planner hooks and walks the whole
 * query with check_functions_in_node(), so it does not depend on
 * enumerating plan shapes and does not have a fail-open default.
 */
static void
safesession_ProcessUtility(PlannedStmt *pstmt,
                           const char *queryString,
                           bool readOnlyTree,
                           ProcessUtilityContext context,
                           ParamListInfo params,
                           QueryEnvironment *queryEnv,
                           DestReceiver *dest,
                           QueryCompletion *qc)
{
    Node *parsetree = pstmt->utilityStmt;
    bool  restricted = false;

    /*
     * This hook runs for every utility statement, including COMMIT
     * and ROLLBACK issued after an error. At that point the
     * transaction has already been cleaned up: IsTransactionState()
     * is false, and the role lookups in current_role_is_restricted()
     * would read the catalog with no active transaction. On an
     * assert-enabled build that trips an assertion and crashes the
     * backend (restarting the whole cluster); otherwise it builds a
     * relcache entry with no snapshot and the behaviour is undefined.
     * Such statements cannot write, so when there is no valid
     * transaction we skip enforcement entirely and chain straight
     * through to standard processing below.
     */
    if (IsTransactionState())
    {
        restricted = current_role_is_restricted();

        /* See the matching call in safesession_ExecutorStart(). */
        note_restriction_state(restricted);

        /* Belt-and-suspenders: force the transaction read-only */
        if (restricted)
            enforce_read_only();
    }

    /*
     * Checks that apply to a restricted session whatever the block_*
     * toggles say, because the statement writes and nothing else stops
     * it.
     *
     * EXPLAIN ANALYZE of a write carried in an intoClause (CREATE TABLE
     * AS, CREATE MATERIALIZED VIEW AS, SELECT ... INTO) is the one case
     * that needs this. PostgreSQL treats EXPLAIN as strictly read-only
     * for the purposes of its own check, so the write executes even with
     * XactReadOnly set, and it never reaches the ExecutorStart DML check
     * as a top-level INSERT/UPDATE/DELETE either. Gating it on block_ddl
     * would leave the EXPLAIN path weaker than the plain statement,
     * which PostgreSQL does refuse.
     */
    if (restricted && parsetree != NULL &&
        IsA(parsetree, ExplainStmt) &&
        explain_is_analyze((ExplainStmt *) parsetree) &&
        explained_stmt_writes(((ExplainStmt *) parsetree)->query))
        safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                           "cannot execute EXPLAIN ANALYZE of a writing"
                           " statement in a read-only session");

    /*
     * The parameters of an EXECUTE are evaluated here in the utility
     * layer, so a blocked function passed as one escapes both of the
     * checks that would otherwise catch it; see
     * execute_params_have_blocked_function() for the detail. This is
     * governed by block_c_functions rather than block_ddl, because what is
     * at stake is the function-blocking policy and not the statement
     * itself: EXECUTE stays allowed either way.
     *
     * EXPLAIN EXECUTE evaluates the parameters too, with or without
     * ANALYZE, and so do CREATE TABLE AS ... EXECUTE and the two combined,
     * so extract_execute_stmt() looks through those wrappers as well as
     * recognising a bare EXECUTE.
     */
    if (restricted && safesession_block_c_functions && parsetree != NULL)
    {
        ExecuteStmt *estmt = extract_execute_stmt(parsetree);

        if (estmt != NULL &&
            execute_params_have_blocked_function(estmt, queryString))
            safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                               "cannot execute functions that may have"
                               " side effects in a read-only session");
    }

    if (restricted && parsetree != NULL && safesession_block_ddl)
    {
        NodeTag tag = nodeTag(parsetree);

        switch (tag)
        {
            /*
             * Allow these utility commands for restricted
             * roles:
             *
             * - Transaction control
             * - PREPARE/EXECUTE/DEALLOCATE
             * - SET/RESET (except protected GUCs and
             *   SET TRANSACTION READ WRITE)
             * - SHOW
             * - LISTEN/NOTIFY/UNLISTEN
             * - DECLARE/FETCH/CLOSE cursor
             * - COPY TO (read-only, not PROGRAM)
             * - DISCARD (session-state reset; enforcement is
             *   re-asserted per statement, so it is harmless and
             *   is needed by connection poolers)
             *
             * CHECKPOINT is deliberately not here: it is not a
             * read-only operation (heavy I/O, emits WAL) and is a
             * denial-of-service lever for a role holding
             * pg_checkpoint, so it falls through to the default deny.
             */
            case T_PrepareStmt:
            case T_ExecuteStmt:
            case T_DeallocateStmt:
            case T_DeclareCursorStmt:
            case T_FetchStmt:
            case T_ClosePortalStmt:
            case T_ListenStmt:
            case T_NotifyStmt:
            case T_UnlistenStmt:
            case T_DiscardStmt:
                /* These are allowed */
                break;

            case T_DoStmt:
                /*
                 * A DO block in a trusted language is allowed (its
                 * writes and dangerous calls are caught downstream);
                 * one in an untrusted language can act natively and
                 * is rejected.
                 */
                if (!do_block_is_trusted((DoStmt *) parsetree))
                    safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                                       "cannot execute a DO block in an"
                                       " untrusted language in a"
                                       " read-only session");
                break;

            case T_CallStmt:
                /*
                 * CALL is treated the same way as a DO block: a
                 * procedure in a trusted language is allowed, one in
                 * an untrusted language is rejected.
                 */
                if (!call_target_is_trusted((CallStmt *) parsetree))
                    safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                                       "cannot CALL a procedure in an"
                                       " untrusted language in a"
                                       " read-only session");
                break;

            case T_TransactionStmt:
                /*
                 * Ordinary transaction control (BEGIN, COMMIT,
                 * ROLLBACK, SAVEPOINT, ...) is fine, but the
                 * two-phase-commit forms are not. COMMIT PREPARED
                 * commits whatever the prepared transaction wrote,
                 * and a read-only session has no business driving
                 * two-phase commit at all, so PREPARE TRANSACTION
                 * and ROLLBACK PREPARED are rejected as well.
                 */
                switch (((TransactionStmt *) parsetree)->kind)
                {
                    case TRANS_STMT_PREPARE:
                    case TRANS_STMT_COMMIT_PREPARED:
                    case TRANS_STMT_ROLLBACK_PREPARED:
                        safesession_reject(
                            ERRCODE_READ_ONLY_SQL_TRANSACTION,
                            "cannot execute two-phase commit"
                            " statements in a read-only session");
                        break;
                    default:
                        break;
                }
                break;

            case T_ExplainStmt:
                /*
                 * Plain EXPLAIN only plans the statement and is safe.
                 * EXPLAIN ANALYZE executes it, but the write cases were
                 * rejected above, before this switch, so that they are
                 * caught whatever block_ddl is set to.
                 */
                break;

            case T_VariableSetStmt:
                if (is_protected_guc_set(
                        (VariableSetStmt *) parsetree))
                    safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                                       "cannot modify read-only"
                                       " transaction settings in a"
                                       " read-only session");
                /* Other SET/RESET allowed */
                break;

            case T_VariableShowStmt:
                /* SHOW is always allowed */
                break;

            case T_CopyStmt:
            {
                CopyStmt *cstmt =
                    (CopyStmt *) parsetree;

                /* Block COPY FROM */
                if (cstmt->is_from)
                    safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                                       "cannot execute COPY FROM in a"
                                       " read-only session");

                /* Block COPY TO PROGRAM */
                if (cstmt->is_program)
                    safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                                       "cannot execute COPY TO PROGRAM"
                                       " in a read-only session");
                break;
            }

            case T_LockStmt:
                /*
                 * Block lock modes stronger than ROW SHARE. This relies
                 * on the ordinal ordering of the lock modes: everything
                 * above RowShareLock (ROW EXCLUSIVE and up) can conflict
                 * with writers and is rejected; ACCESS SHARE and ROW
                 * SHARE, which ordinary reads take, remain permitted.
                 */
                if (((LockStmt *) parsetree)->mode >
                    RowShareLock)
                    safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                                       "cannot acquire exclusive locks"
                                       " in a read-only session");
                break;

            /*
             * Block GRANT/REVOKE and privilege changes
             */
            case T_GrantStmt:
            case T_GrantRoleStmt:
            case T_AlterDefaultPrivilegesStmt:
            case T_AlterOwnerStmt:
                safesession_reject(ERRCODE_INSUFFICIENT_PRIVILEGE,
                                   "cannot execute privilege changes"
                                   " in a read-only session");
                break;

            /*
             * Block VACUUM and ANALYZE
             */
            case T_VacuumStmt:
                safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                                   "cannot execute VACUUM/ANALYZE in a"
                                   " read-only session");
                break;

            /*
             * Block all other utility statements (DDL, etc.).
             * This is a whitelist approach: anything not explicitly
             * allowed above is blocked. Name the command so the error
             * is actionable.
             */
            default:
                safesession_reject(
                    ERRCODE_INSUFFICIENT_PRIVILEGE,
                    psprintf("cannot execute %s in a read-only session",
                             GetCommandTagName(
                                 CreateCommandTag(parsetree))));
                break;
        }
    }

    /* Chain to previous hook or standard function */
    if (prev_ProcessUtility)
        prev_ProcessUtility(pstmt, queryString, readOnlyTree,
                            context, params, queryEnv,
                            dest, qc);
    else
        standard_ProcessUtility(pstmt, queryString, readOnlyTree,
                                context, params, queryEnv,
                                dest, qc);

    /*
     * Some utility statements change who we are acting as, and therefore
     * whether we are restricted, as their whole purpose: SET ROLE, SET
     * SESSION AUTHORIZATION, and the RESET ALL and DISCARD ALL that undo
     * them. The check at the top of this function ran before any of that
     * took effect, so look again now that it has, rather than leaving the
     * change to be noticed by whatever statement happens to come next.
     */
    if (IsTransactionState())
        note_restriction_state(current_role_is_restricted());
}

/*
 * GUC check hook for pgedge_safesession.roles.
 *
 * Validates the list at assignment time so that a misconfiguration is
 * surfaced then, rather than silently disabling all protection. A list
 * that does not parse is rejected outright. Names that do not resolve to
 * a role draw a WARNING, but only when we can safely read the catalog:
 * at postmaster start and during a SIGHUP reload there is no transaction,
 * so name resolution is skipped there (the syntax check still runs).
 */
static bool
check_safesession_roles(char **newval, void **extra, GucSource source)
{
    char     *rawstring;
    List     *rolelist;
    ListCell *lc;

    if (*newval == NULL || (*newval)[0] == '\0')
        return true;

    rawstring = pstrdup(*newval);

    if (!SplitIdentifierString(rawstring, ',', &rolelist))
    {
        GUC_check_errdetail("List syntax is invalid.");
        pfree(rawstring);
        list_free(rolelist);
        return false;
    }

    if (IsTransactionState())
    {
        foreach(lc, rolelist)
        {
            char *rolename = (char *) lfirst(lc);

            if (!OidIsValid(get_role_oid(rolename, true)))
                ereport(WARNING,
                        (errmsg("pgedge_safesession.roles: role"
                                " \"%s\" does not exist", rolename)));
        }
    }

    pfree(rawstring);
    list_free(rolelist);
    return true;
}

/*
 * Module initialization
 */
void
_PG_init(void)
{
    /*
     * The hooks installed below only take effect for the backend that
     * loads this library, so it must be loaded via
     * shared_preload_libraries to protect every session. Loading it into
     * a single session (LOAD, or an implicit load from calling one of its
     * functions) would silently leave other sessions unprotected, so
     * refuse that.
     */
    if (!process_shared_preload_libraries_in_progress)
        ereport(ERROR,
                (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                 errmsg("pgedge_safesession must be loaded via "
                        "shared_preload_libraries"),
                 errdetail("Add \"pgedge_safesession\" to "
                           "shared_preload_libraries and restart the "
                           "server.")));

    /* Define GUCs */
    DefineCustomStringVariable(
        "pgedge_safesession.roles",
        "Roles that are restricted to read-only sessions.",
        "A comma-separated list of role names. A session whose "
        "session or current user is one of these roles, or is a "
        "member of one, is restricted to read-only access.",
        &safesession_roles,
        "",
        PGC_SUSET,
        GUC_LIST_INPUT,
        check_safesession_roles,
        assign_safesession_roles,
        NULL);

    DefineCustomBoolVariable(
        "pgedge_safesession.block_dml",
        "Block INSERT, UPDATE, DELETE, and MERGE for "
        "restricted roles.",
        "This includes data-modifying CTEs (WITH ... INSERT/"
        "UPDATE/DELETE ... RETURNING). When off, such writes are "
        "still rejected by the read-only transaction the "
        "extension enforces.",
        &safesession_block_dml,
        true,
        PGC_SUSET,
        0,
        NULL,
        NULL,
        NULL);

    DefineCustomBoolVariable(
        "pgedge_safesession.block_ddl",
        "Block DDL and other utility commands for "
        "restricted roles.",
        "Covers the utility statements the read-only transaction "
        "does not catch on its own, such as COPY TO PROGRAM, "
        "exclusive LOCK, VACUUM/ANALYZE and CHECKPOINT. When off, "
        "ordinary DDL is still rejected by the read-only "
        "transaction.",
        &safesession_block_ddl,
        true,
        PGC_SUSET,
        0,
        NULL,
        NULL,
        NULL);

    DefineCustomBoolVariable(
        "pgedge_safesession.block_c_functions",
        "Block execution of functions that may have side "
        "effects for restricted roles.",
        "Blocks volatile functions in untrusted languages (C, "
        "internal or an untrusted PL) and a curated list of "
        "side-effecting built-ins. Harmless volatile built-ins "
        "such as random() remain allowed.",
        &safesession_block_c_functions,
        true,
        PGC_SUSET,
        0,
        NULL,
        NULL,
        NULL);

    DefineCustomBoolVariable(
        "pgedge_safesession.block_all_c_functions",
        "Additionally block every C-language function "
        "regardless of volatility.",
        "Escalates block_c_functions to reject all C-language "
        "functions, not only volatile ones. This can break "
        "read-only extension functions (e.g. PostGIS or pgvector "
        "operators), so leave it off unless you specifically need "
        "it. Only applies when block_c_functions is on.",
        &safesession_block_all_c_functions,
        false,
        PGC_SUSET,
        0,
        NULL,
        NULL,
        NULL);

    /* Install ExecutorStart hook */
    prev_ExecutorStart = ExecutorStart_hook;
    ExecutorStart_hook = safesession_ExecutorStart;

    /* Install ProcessUtility hook */
    prev_ProcessUtility = ProcessUtility_hook;
    ProcessUtility_hook = safesession_ProcessUtility;

    /* Install post_parse_analyze hook (blocked function detection) */
    prev_post_parse_analyze = post_parse_analyze_hook;
    post_parse_analyze_hook = safesession_post_parse_analyze;

    /*
     * Install planner hook (blocked function detection for anything
     * QueryRewrite() introduces after post_parse_analyze already ran,
     * such as a view body or an RLS policy qual)
     */
    prev_planner_hook = planner_hook;
    planner_hook = safesession_planner;

    /*
     * Install object access hook (blocked function detection for a
     * function no query tree mentions, such as one called from a domain
     * CHECK constraint reached by a coercion rather than by a cast)
     */
    prev_object_access_hook = object_access_hook;
    object_access_hook = safesession_object_access;

    /*
     * Invalidate the cached role-OID list when pg_authid changes (a role
     * created, dropped or renamed). GUC changes are handled by the assign
     * hook.
     *
     * A membership grant writes pg_auth_members rather than pg_authid, so
     * AUTHMEMROLEMEM is registered too. Either of the two pg_auth_members
     * caches will do, as both are invalidated by the same tuple change.
     */
    CacheRegisterSyscacheCallback(AUTHOID, invalidate_role_cache,
                                  (Datum) 0);
    CacheRegisterSyscacheCallback(AUTHMEMROLEMEM, invalidate_role_cache,
                                  (Datum) 0);

#if PG_VERSION_NUM >= 150000
    MarkGUCPrefixReserved("pgedge_safesession");
#else
    EmitWarningsOnPlaceholders("pgedge_safesession");
#endif
}
