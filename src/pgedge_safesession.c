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

#include <ctype.h>

/*
 * GETSTRUCT lives in access/htup_details.h, which this file used to reach
 * transitively through the other PostgreSQL headers below. PostgreSQL 19
 * dropped it from that include chain, so include it explicitly; on
 * PostgreSQL 14-18 the header is already in the chain and this is a no-op.
 */
#include "access/genam.h"
#include "access/htup_details.h"
#include "access/parallel.h"
#include "access/table.h"
#include "access/transam.h"
#include "access/xact.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_authid.h"
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
#include "storage/proc.h"
#include "tcop/cmdtag.h"
#include "tcop/tcopprot.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/catcache.h"
#include "utils/fmgroids.h"
#include "utils/guc.h"
#include "utils/guc_tables.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/plancache.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/varlena.h"

PG_MODULE_MAGIC;

/* GUC variables */
static char *safesession_roles = NULL;
static char *safesession_read_only_roles = NULL;
static char *safesession_delegating_roles = NULL;
static char *safesession_acting_read_only_roles = NULL;
static char *safesession_require_where_roles = NULL;
static char *safesession_locked_setting_prefixes = NULL;
static bool safesession_block_dml = true;
static bool safesession_block_ddl = true;
static bool safesession_block_c_functions = true;
static bool safesession_block_all_c_functions = false;

/* Saved hook values */
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;
static ExecutorFinish_hook_type prev_ExecutorFinish = NULL;
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
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

/*
 * Built-in functions whose declared volatility understates what they do.
 *
 * PostgreSQL declares both of these STABLE, so the volatility rule in
 * function_is_blocked() never reaches them, but calling either one forces
 * the transaction to take a real transaction ID. A read-only transaction
 * permits that, so a restricted session could consume transaction IDs and
 * add wraparound pressure.
 *
 * The pg_current_xact_id_if_assigned() and txid_current_if_assigned()
 * forms only report an ID already handed out, assign nothing, and are
 * deliberately absent from this list.
 *
 * This is not a return to blocking built-ins by name: volatility still
 * decides every other built-in. It is the same kind of exception as
 * aggregate_support_is_blocked() below, for a side effect the catalog's
 * own labelling does not describe.
 */
static const char *const unsafe_nonvolatile_builtins[] = {
    "pg_current_xact_id",
    "txid_current",
};

static bool
name_is_unsafe_nonvolatile_builtin(const char *proname)
{
    int i;

    for (i = 0; i < lengthof(unsafe_nonvolatile_builtins); i++)
    {
        if (strcmp(proname, unsafe_nonvolatile_builtins[i]) == 0)
            return true;
    }
    return false;
}

static bool function_is_blocked(Oid funcid, void *context);
static bool query_has_blocked_function_walker(Node *node, void *context);
static bool session_is_delegating(void);

/*
 * The statement the executor is starting right now, if any. A statement's
 * function calls are set up while it starts; see
 * safesession_object_access().
 */
static QueryDesc *starting_query = NULL;

/* plan_allows_set_config() of starting_query: -1 not yet read */
static int starting_verdict = -1;

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
        result = name_is_unsafe_nonvolatile_builtin(NameStr(proname)) ||
                 ((provolatile == PROVOLATILE_VOLATILE) &&
                  !name_is_safe_volatile_builtin(NameStr(proname)));
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
 * Is this call set_config() on a response.* setting, with the name written
 * in the statement and the third argument written as true?
 *
 * PostgREST reads response.status and response.headers after a request to
 * set the HTTP status and headers, and app functions, including a
 * db-pre-request function, set them with set_config(..., true). A setting
 * changed for the transaction only, and under a prefix PostgREST only
 * reads, changes no data and outlives nothing, so a read-only API request
 * may make this call. A name or flag that is not a constant, such as one
 * built at run time or passed in, could name any setting and is not
 * allowed.
 */
static bool
is_response_set_config(FuncExpr *fexpr)
{
    Const *name;
    Const *is_local;
    char  *setting;

    if (fexpr->funcid != F_SET_CONFIG || list_length(fexpr->args) != 3)
        return false;

    name = (Const *) linitial(fexpr->args);
    is_local = (Const *) lthird(fexpr->args);

    if (!IsA(name, Const) || name->constisnull ||
        name->consttype != TEXTOID ||
        !IsA(is_local, Const) || is_local->constisnull ||
        is_local->consttype != BOOLOID ||
        !DatumGetBool(is_local->constvalue))
        return false;

    setting = TextDatumGetCString(name->constvalue);

    return pg_strncasecmp(setting, "response.", 9) == 0 &&
        setting[9] != '\0';
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

    /*
     * In a delegating session, set_config() on a response.* setting is
     * allowed (see is_response_set_config). Only the call itself is: its
     * arguments are still walked, since the value may call anything.
     */
    if (IsA(node, FuncExpr) &&
        is_response_set_config((FuncExpr *) node) &&
        session_is_delegating())
        return expression_tree_walker(node,
                                      query_has_blocked_function_walker,
                                      context);

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
 * What the role lock reads from a plan being started; see
 * set_config_keeps_lock(). name is set to a setting the plan would set
 * that the lock forbids.
 */
typedef struct LockPlanRead
{
    const char *name;
} LockPlanRead;

static bool set_config_keeps_lock(FuncExpr *fexpr, LockPlanRead *read);

/*
 * Would this expression stop set_config() being set up for its plan? Yes
 * for a set_config() call that is not the response.* form, and for what
 * runs other code as the plan starts: a domain coercion sets up the
 * domain's CHECK, and a user-defined aggregate reads its initial value
 * through its state type's input function. (The planner already converts
 * a plain aggregate's initial value, so the aggregate rule is defence in
 * depth.)
 *
 * With the locked prefixes as context, the question is the role lock's
 * instead: may a set_config() call create a setting under a locked prefix?
 * See set_config_keeps_lock().
 */
static bool
expr_bars_set_config(Node *node, void *context)
{
    if (node == NULL)
        return false;

    if (IsA(node, FuncExpr) &&
        ((FuncExpr *) node)->funcid == F_SET_CONFIG &&
        !(context == NULL ?
          is_response_set_config((FuncExpr *) node) :
          set_config_keeps_lock((FuncExpr *) node, (LockPlanRead *) context)))
        return true;

    if (IsA(node, CoerceToDomain) ||
        (IsA(node, Aggref) &&
         ((Aggref *) node)->aggfnoid >= FirstNormalObjectId))
        return true;

    return expression_tree_walker(node, expr_bars_set_config, context);
}

/*
 * Is this plan made only of nodes plan_allows_set_config() reads whole,
 * with nothing in them that bars set_config()?
 */
static bool
plan_node_allows_set_config(Plan *plan, void *context)
{
    if (plan == NULL)
        return true;

    switch (nodeTag(plan))
    {
        case T_Result:
            if (expr_bars_set_config(((Result *) plan)->resconstantqual,
                                     context))
                return false;
            break;
        case T_Limit:
            if (expr_bars_set_config(((Limit *) plan)->limitOffset,
                                     context) ||
                expr_bars_set_config(((Limit *) plan)->limitCount, context))
                return false;
            break;
        case T_SubqueryScan:
            if (!plan_node_allows_set_config(((SubqueryScan *) plan)->subplan,
                                             context))
                return false;
            break;
        case T_Agg:
            /* Grouping sets chain further Agg nodes; not read here */
            if (((Agg *) plan)->chain != NIL)
                return false;
            break;
        case T_ProjectSet:
        case T_CteScan:
        case T_Sort:
        case T_Material:
        case T_Unique:
            break;
        default:
            return false;
    }

    return !expr_bars_set_config((Node *) plan->targetlist, context) &&
        !expr_bars_set_config((Node *) plan->qual, context) &&
        !expr_bars_set_config((Node *) plan->initPlan, context) &&
        plan_node_allows_set_config(plan->lefttree, context) &&
        plan_node_allows_set_config(plan->righttree, context);
}

/*
 * May set_config() be set up for this plan, in a read-only API request?
 *
 * The object access hook sees a function but not its arguments, and the
 * plan being started is the one place that shows both, so it is read here
 * rather than trusted: what the Query-walking hooks checked is not all of
 * it, since the planner adds parameter defaults and the coercions of an
 * inlined SQL function's result. Only a plan made of the nodes a
 * statement that reads no table is made of qualifies (SELECT
 * set_config(...), PERFORM set_config(...) in PL/pgSQL, a SQL function
 * called that way or as PostgREST calls a function), and only when every
 * set_config() call in it is the response.* form. None of those nodes runs
 * other code while the plan starts; a table scan, or the initial pruning
 * of a partitioned table, can. Anything else is refused, as in 1.0.
 */
static bool
plan_allows_set_config(PlannedStmt *pstmt, void *context)
{
    ListCell *lc;

    if (!plan_node_allows_set_config(pstmt->planTree, context))
        return false;

    foreach(lc, pstmt->subplans)
    {
        if (!plan_node_allows_set_config((Plan *) lfirst(lc), context))
            return false;
    }
    return true;
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
 * The lists live in CacheMemoryContext so they survive across statements.
 * cached_role_oids holds both names of the read-only list, roles and
 * read_only_roles.
 */
static List *cached_role_oids = NIL;
static List *delegating_role_oids = NIL;
static List *acting_read_only_oids = NIL;
static List *require_where_oids = NIL;
static bool  role_cache_valid = false;

/*
 * What is wrong with the lists is logged once per session, and again after
 * a list changes; not after every catalog change or reload, which every
 * session sees. lists_changed is set by the assign hook, which also runs at
 * a reload that changes nothing, so the values last reported are kept to
 * tell.
 */
static bool  lists_changed = true;
static char *reported_lists = NULL;

static inline bool
list_is_set(const char *list)
{
    return list != NULL && list[0] != '\0';
}

/* Is any delegating role configured? Most servers have none. */
static inline bool
delegating_configured(void)
{
    return list_is_set(safesession_delegating_roles);
}

/* Is roleid in this list of role OIDs, or a member of a role in it? */
static bool
role_in_list(List *oids, Oid roleid)
{
    ListCell *lc;

    foreach(lc, oids)
    {
        Oid listed = lfirst_oid(lc);

        if (roleid == listed || is_member_of_role_nosuper(roleid, listed))
            return true;
    }
    return false;
}

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

/*
 * The syscache hash of this database's pg_database row, worked out in
 * session_requires_where(): it can need the catalog, which a cache callback
 * may not read. 0 until then.
 */
static uint32 my_database_hash = 0;
static bool  where_owner_matters = true;

/*
 * A change of this database's owner changes who is a member of
 * pg_database_owner, and so who must qualify its UPDATEs and DELETEs:
 * discard the cached plans, which were checked for the old answer. A
 * change to another database's row is ignored once this one's hash is
 * known.
 */
static void
invalidate_database_owner(Datum arg, int cacheid, uint32 hashvalue)
{
    if (!list_is_set(safesession_require_where_roles))
        return;

    if (role_cache_valid && !where_owner_matters)
        return;

    if (hashvalue == 0 || my_database_hash == 0 ||
        hashvalue == my_database_hash)
        ResetPlanCache();
}

/* The assign hook for every list of roles. */
static void
assign_safesession_roles(const char *newval, void *extra)
{
    role_cache_valid = false;
    lists_changed = true;
    ResetPlanCache();
}

/*
 * Append the OIDs of the roles named in a list to *oids, in
 * CacheMemoryContext.
 *
 * A name that matches no role protects nothing. A list given in the
 * configuration file is read with no transaction, so its names cannot be
 * looked up then; say so in the server log here instead, when the
 * caller asks. LOG rather than WARNING, so the client of every new
 * session is not sent it; a SET of the list warns the client itself.
 */
static void
resolve_role_list(const char *setting, const char *list, List **oids,
                  bool log_missing)
{
    char     *rawstring;
    List     *rolelist;
    ListCell *lc;

    if (!list_is_set(list))
        return;

    rawstring = pstrdup(list);

    /* Malformed; the check hook rejects this, so treat as empty. */
    if (SplitIdentifierString(rawstring, ',', &rolelist))
    {
        foreach(lc, rolelist)
        {
            char *rolename = (char *) lfirst(lc);
            Oid   roleid = get_role_oid(rolename, true);

            if (OidIsValid(roleid))
            {
                MemoryContext old = MemoryContextSwitchTo(CacheMemoryContext);

                *oids = lappend_oid(*oids, roleid);
                MemoryContextSwitchTo(old);
            }
            /*
             * The statement and context are left out: this can run inside
             * any statement, such as one that sets a password.
             */
            else if (log_missing)
                ereport(LOG,
                        (errmsg("%s: role \"%s\" does not exist",
                                setting, rolename),
                         errhidestmt(true),
                         errhidecontext(true),
                         /* The name was written with capitals, unquoted */
                         strstr(list, rolename) == NULL ?
                         errhint("A name not in double quotes is read in"
                                 " lower case.") : 0));
        }
    }

    pfree(rawstring);
    list_free(rolelist);
}

/*
 * Rebuild the cached lists of role OIDs from the GUC values. Must be
 * called with a valid transaction in progress (it reads the catalog).
 */
static void
rebuild_role_cache(void)
{
    List *read_only = NIL;
    List *delegating = NIL;
    List *acting = NIL;
    List *require_where = NIL;

    /* We are about to read the catalog; a transaction must be active. */
    Assert(IsTransactionState());

    /*
     * Mark the cache valid before resolving anything, so that an
     * invalidation arriving while we work is not lost. The lists are built
     * to one side and installed only once they are complete, so an error
     * part of the way through leaves the previous lists in place rather
     * than half-built ones that would silently under-restrict.
     */
    role_cache_valid = true;

    /* read_only_roles is the new name for roles; a role on either counts. */
    resolve_role_list("pgedge_safesession.roles", safesession_roles,
                      &read_only, false);
    resolve_role_list("pgedge_safesession.read_only_roles",
                      safesession_read_only_roles, &read_only, false);
    resolve_role_list("pgedge_safesession.delegating_roles",
                      safesession_delegating_roles, &delegating, false);
    resolve_role_list("pgedge_safesession.acting_read_only_roles",
                      safesession_acting_read_only_roles, &acting, false);
    resolve_role_list("pgedge_safesession.require_where_roles",
                      safesession_require_where_roles, &require_where,
                      false);

    list_free(cached_role_oids);
    list_free(delegating_role_oids);
    list_free(acting_read_only_oids);
    list_free(require_where_oids);
    cached_role_oids = read_only;
    delegating_role_oids = delegating;
    acting_read_only_oids = acting;
    require_where_oids = require_where;
    where_owner_matters = role_in_list(require_where_oids,
                                       ROLE_PG_DATABASE_OWNER);
}

/*
 * Log what is wrong with the lists: each name that matches no role, and
 * acting_read_only_roles set while delegating_roles is empty. Called in a
 * session the lists apply to, once the lists may have changed; see
 * lists_changed. Needs a transaction: it reads the catalog.
 */
static void
report_role_lists(void)
{
    char *lists;
    List *unused = NIL;

    lists_changed = false;
    lists = psprintf("%s\n%s\n%s\n%s\n%s",
                     safesession_roles ? safesession_roles : "",
                     safesession_read_only_roles ?
                     safesession_read_only_roles : "",
                     safesession_delegating_roles ?
                     safesession_delegating_roles : "",
                     safesession_acting_read_only_roles ?
                     safesession_acting_read_only_roles : "",
                     safesession_require_where_roles ?
                     safesession_require_where_roles : "");
    if (reported_lists != NULL && strcmp(lists, reported_lists) == 0)
    {
        pfree(lists);
        return;
    }

    resolve_role_list("pgedge_safesession.roles", safesession_roles,
                      &unused, true);
    resolve_role_list("pgedge_safesession.read_only_roles",
                      safesession_read_only_roles, &unused, true);
    resolve_role_list("pgedge_safesession.delegating_roles",
                      safesession_delegating_roles, &unused, true);
    resolve_role_list("pgedge_safesession.acting_read_only_roles",
                      safesession_acting_read_only_roles, &unused, true);
    resolve_role_list("pgedge_safesession.require_where_roles",
                      safesession_require_where_roles, &unused, true);
    list_free(unused);

    /* The acting list only applies to delegating sessions */
    if (list_is_set(safesession_acting_read_only_roles) &&
        !delegating_configured())
        ereport(LOG,
                (errmsg("pgedge_safesession.acting_read_only_roles has no"
                        " effect while pgedge_safesession.delegating_roles"
                        " is empty"),
                 errhidestmt(true),
                 errhidecontext(true)));

    if (reported_lists != NULL)
        pfree(reported_lists);
    reported_lists = MemoryContextStrdup(TopMemoryContext, lists);
    pfree(lists);
}

/*
 * Is this session logged in as a role named in delegating_roles?
 *
 * A delegating role, such as PostgREST's authenticator, logs in once and
 * switches into another role for each transaction. Only the role itself
 * counts, not a member of it: a person granted the delegating role is not
 * a pool, and judging their session by the role it switches into would
 * lift the read-only lists from it until it switched. Needs a
 * transaction; every caller is past current_role_is_restricted().
 */
static Oid
delegating_login(void)
{
    Oid login = GetSessionUserId();

    if (!delegating_configured())
        return InvalidOid;

    if (!role_cache_valid)
        rebuild_role_cache();

    if (list_member_oid(delegating_role_oids, login))
        return login;

    /*
     * A superuser login can switch with SET SESSION AUTHORIZATION instead,
     * which changes the session user; the role it logged in as still
     * counts.
     */
    login = GetAuthenticatedUserId();
    return list_member_oid(delegating_role_oids, login) ? login : InvalidOid;
}

static bool
session_is_delegating(void)
{
    return OidIsValid(delegating_login());
}

/*
 * Is roleid on require_where_roles, or a member that can act as a role on
 * it? On PostgreSQL 16 and later that means one that can SET ROLE to it:
 * an ADMIN-only grant, such as the one a CREATEROLE role is given over
 * each role it creates, does not count. A superuser counts only when it is
 * listed itself: PostgreSQL makes it able to act as every role, which says
 * nothing about which logins the list means.
 */
static bool
role_requires_where(Oid roleid)
{
    ListCell *lc;
    bool      superuser = superuser_arg(roleid);

    foreach(lc, require_where_oids)
    {
        Oid listed = lfirst_oid(lc);

        if (roleid == listed)
            return true;
        if (superuser)
            continue;
#if PG_VERSION_NUM >= 160000
        if (member_can_set_role(roleid, listed))
            return true;
#else
        if (is_member_of_role_nosuper(roleid, listed))
            return true;
#endif
    }
    return false;
}

/*
 * Must this session give every UPDATE and DELETE a WHERE clause? True when
 * the role it logged in as is, or is a member of, a role in
 * require_where_roles. The session user counts, and so does the role the
 * connection authenticated as, so a superuser pool that switches with SET
 * SESSION AUTHORIZATION stays covered; SET ROLE and SECURITY DEFINER
 * functions change neither. Needs a transaction: it reads the catalog.
 */
static bool
session_requires_where(void)
{
    Oid session_userid;
    Oid authenticated;

    if (!list_is_set(safesession_require_where_roles))
        return false;

    session_userid = GetSessionUserId();

    /* As in current_role_is_restricted(), for a session the list fits */
    if (lists_changed && !IsParallelWorker() &&
        !superuser_arg(session_userid))
        report_role_lists();

    if (!role_cache_valid)
        rebuild_role_cache();

    if (my_database_hash == 0)
        my_database_hash =
            GetSysCacheHashValue1(DATABASEOID,
                                  ObjectIdGetDatum(MyDatabaseId));

    if (role_requires_where(session_userid))
        return true;

    authenticated = GetAuthenticatedUserId();
    return authenticated != session_userid &&
        role_requires_where(authenticated);
}

/*
 * The session user the last time note_session_user() looked.
 *
 * The WHERE check runs when a statement is parsed and planned, so a plan
 * cached while the rule did not apply would skip it. A change of the
 * setting, of a role's memberships or of the database's owner discards
 * cached plans by itself (see the assign hook and the cache callbacks).
 * What is left is a change of the session user, with SET SESSION
 * AUTHORIZATION or set_config('session_authorization', ...): when the new
 * session user must qualify its UPDATEs and DELETEs, discard the cached
 * plans, as note_restriction_state() does for read-only.
 */
static Oid where_session_user = InvalidOid;

static void
note_session_user(void)
{
    Oid user;

    if (!list_is_set(safesession_require_where_roles))
        return;

    user = GetSessionUserId();
    if (user == where_session_user)
        return;
    where_session_user = user;

    if (session_requires_where())
        ResetPlanCache();
}

/*
 * The session user changes when session_authorization is set, which can
 * happen in the middle of a statement, from set_config(). A plan cached
 * under another session user could then run next, unchecked. So the
 * wrapper around Postgres's own assign function for session_authorization
 * (safesession_assign_sessauth) discards cached plans whenever it runs
 * while require_where_roles is set: a cached UPDATE or DELETE is then
 * planned, and checked, again before it runs.
 */

/* Postgres's own string setting, to wrap its check and assign. */
static struct config_string *
core_string_setting(const char *name)
{
    struct config_generic *gen = NULL;
#if PG_VERSION_NUM >= 160000
    gen = find_option(name, false, false, ERROR);
#else
    struct config_generic **vars = get_guc_variables();
    int         i;

    for (i = 0; i < GetNumConfigOptions(); i++)
        if (strcmp(vars[i]->name, name) == 0)
            gen = vars[i];
#endif
    if (gen == NULL || gen->vartype != PGC_STRING)
        elog(ERROR, "pgedge_safesession: setting \"%s\" not found", name);
#if PG_VERSION_NUM >= 190000
    /* PostgreSQL 19 moved the type's fields into a union in config_generic. */
    return &gen->_string;
#else
    return (struct config_string *) gen;
#endif
}

/*
 * Refuse an UPDATE or DELETE with no WHERE clause, the check pg-safeupdate
 * makes, including inside data-modifying WITH queries. The SQLSTATE and
 * the messages match safeupdate's, so PostgREST and its clients see no
 * difference. Any WHERE clause counts, even WHERE true: this guards
 * against mistakes, and row-level security still decides which rows a
 * request can change.
 *
 * It runs from the post_parse_analyze hook, before rewrite, so a view's
 * own WHERE does not count, and again from the planner hook, because a
 * BEGIN ATOMIC function body is stored already analysed and is planned
 * but never parsed again. MERGE and TRUNCATE are not covered.
 *
 * In a read-only session such a statement could never run, and it is
 * refused with the read-only error instead, which PostgREST answers with
 * 405 rather than 400. It is still refused here, not left to the executor:
 * otherwise its plan could be cached unchecked and run later, once the
 * session can write.
 */
/* The first UPDATE or DELETE with no WHERE clause in the query, or NULL. */
static const char *
unfiltered_command(Query *query)
{
    ListCell *lc;

    foreach(lc, query->cteList)
    {
        CommonTableExpr *cte = (CommonTableExpr *) lfirst(lc);
        const char      *cmd;

        if (IsA(cte->ctequery, Query) &&
            (cmd = unfiltered_command((Query *) cte->ctequery)) != NULL)
            return cmd;
    }

    if ((query->commandType != CMD_UPDATE &&
         query->commandType != CMD_DELETE) ||
        query->jointree == NULL || query->jointree->quals != NULL)
        return NULL;
    return query->commandType == CMD_UPDATE ? "UPDATE" : "DELETE";
}

static void
refuse_unfiltered(const char *cmd, bool restricted)
{
    if (restricted)
        ereport(ERROR,
                (errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),
                 errmsg("cannot execute %s in a read-only session", cmd),
                 errhint("This session is restricted to read-only access"
                         " by the pgedge_safesession extension.")));
    ereport(ERROR,
            (errcode(ERRCODE_CARDINALITY_VIOLATION),
             errmsg("%s requires a WHERE clause", cmd)));
}

static void
check_where_required(Query *query, bool restricted)
{
    const char *cmd = unfiltered_command(query);

    if (cmd != NULL)
        refuse_unfiltered(cmd, restricted);
}

/*
 * A plan made while the rule did not apply to the session, for an UPDATE
 * or DELETE with no WHERE clause, is remembered until the transaction ends.
 * If the rule applies by the time the plan is run, it is refused then. A
 * plan Postgres caches for later is planned again when the rule may have
 * changed (see note_session_user() and invalidate_role_cache()), but on
 * PostgreSQL 14 to 17 a SQL function plans all its statements when it
 * starts and keeps them to itself, so a GRANT earlier in the same function
 * that makes the rule apply would otherwise let a later unfiltered DELETE
 * run. The plan is told apart by its address and two of its parts, so a
 * new plan that happens to reuse the address is not mistaken for it.
 */
typedef struct UncheckedPlan
{
    PlannedStmt *stmt;
    Plan        *tree;
    List        *rtable;
    const char  *cmd;
} UncheckedPlan;

static List *unchecked_plans = NIL;     /* in TopTransactionContext */

static bool current_role_is_restricted(void);

static void
note_unchecked_plan(PlannedStmt *stmt, const char *cmd)
{
    MemoryContext  old = MemoryContextSwitchTo(TopTransactionContext);
    UncheckedPlan *plan = palloc(sizeof(UncheckedPlan));

    plan->stmt = stmt;
    plan->tree = stmt->planTree;
    plan->rtable = stmt->rtable;
    plan->cmd = cmd;
    unchecked_plans = lappend(unchecked_plans, plan);
    MemoryContextSwitchTo(old);
}

static void
check_unchecked_plan(PlannedStmt *stmt)
{
    ListCell *lc;

    if (unchecked_plans == NIL || !IsTransactionState())
        return;
    foreach(lc, unchecked_plans)
    {
        UncheckedPlan *plan = lfirst(lc);

        if (plan->stmt == stmt && plan->tree == stmt->planTree &&
            plan->rtable == stmt->rtable &&
            session_requires_where())
            refuse_unfiltered(plan->cmd, current_role_is_restricted());
    }
}

/* The list lives in the transaction's memory; forget it when that goes. */
static void recheck_request_settings(void);

static void
safesession_xact_callback(XactEvent event, void *arg)
{
    /* The role lock's last look, after deferred triggers and cursors */
    if (event == XACT_EVENT_PRE_COMMIT || event == XACT_EVENT_PRE_PREPARE)
        recheck_request_settings();
    if (event == XACT_EVENT_COMMIT || event == XACT_EVENT_ABORT ||
        event == XACT_EVENT_PREPARE ||
        event == XACT_EVENT_PARALLEL_COMMIT ||
        event == XACT_EVENT_PARALLEL_ABORT)
        unchecked_plans = NIL;
}

/*
 * Check whether the current session role is restricted.
 *
 * Returns true if the session user or current user is listed in
 * pgedge_safesession.roles or pgedge_safesession.read_only_roles, or is a
 * member of a listed role. A delegating session is judged by the role it
 * acts as instead; see below.
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
    Oid         login;

    /* No roles configured means no restrictions */
    if (!list_is_set(safesession_roles) &&
        !list_is_set(safesession_read_only_roles) &&
        !list_is_set(safesession_acting_read_only_roles))
        return false;

    /*
     * Superuser exemption: only check the session user.
     * This ensures that SECURITY DEFINER functions owned by
     * superusers cannot bypass the restriction when called
     * from a restricted session. A superuser login on delegating_roles is
     * judged like any other delegating session, by the role it acts as;
     * otherwise listing one would silently turn the read-only lists off
     * for its requests.
     */
    session_userid = GetSessionUserId();
    if (superuser_arg(session_userid) && !session_is_delegating())
        return false;

    /*
     * Report what is wrong with the lists in a session they apply to: not
     * a parallel worker, which copies the leader's settings. A superuser's
     * session returned above, unless it is a delegating one.
     */
    if (lists_changed && !IsParallelWorker())
        report_role_lists();

    if (!role_cache_valid)
        rebuild_role_cache();

    current_userid = GetUserId();

    /*
     * A delegating role (such as PostgREST's authenticator) is a member of
     * every role it may switch into, so its memberships say nothing about
     * what a request is acting as. The acting role is what counts: the one
     * the session switched into, which stays the outer user inside a
     * SECURITY DEFINER function, so the function's owner cannot lift the
     * restriction; and, as in any session, the current user, so a function
     * owned by a restricted role is restricted.
     */
    login = delegating_login();
    if (OidIsValid(login))
    {
        Oid  acting = GetOuterUserId();
        bool switched = OidIsValid(GetCurrentRoleId()) ||
            session_userid != login;

        /*
         * Not switched: the pool's own statements, the switch among them,
         * must run; inside a SECURITY DEFINER function, its owner counts.
         */
        if (!switched)
            return current_userid != login &&
                role_in_list(cached_role_oids, current_userid);

        /*
         * acting_read_only_roles is read-only for delegated requests alone:
         * other sessions of the role, such as a person's own login, keep
         * their writes. The delegating role named on a read-only list makes
         * every request read-only once it has switched; its memberships
         * still say nothing. A request switched into the login role itself
         * is judged by that role's memberships too, which fails closed.
         */
        return role_in_list(acting_read_only_oids, acting) ||
            list_member_oid(cached_role_oids, login) ||
            role_in_list(cached_role_oids, acting) ||
            (current_userid != acting && current_userid != login &&
             role_in_list(cached_role_oids, current_userid));
    }

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
 * The WHERE check, as the parse and planner hooks run it, for a session
 * that must qualify its UPDATEs and DELETEs.
 *
 * The session user is noted first, so a plan made under one session user
 * is not reused under another without the check (see note_session_user()).
 * A read-only session gets the read-only error instead; see
 * check_where_required().
 */
static void
check_where_for_session(Query *query)
{
    if (!list_is_set(safesession_require_where_roles) ||
        !IsTransactionState())
        return;

    note_session_user();

    if (session_requires_where())
        check_where_required(query, current_role_is_restricted());
}

/*
 * The role lock. A delegating role, such as PostgREST's authenticator,
 * switches to the request's role once at the start of each transaction.
 * After that the role must not change again until the transaction ends,
 * or a function could act as another user. The first change in a
 * transaction takes the lock; any later one is refused, however it is
 * made: SET ROLE, SET SESSION AUTHORIZATION, set_config(), a function's
 * SET clause or RESET. All of these pass through Postgres's own
 * check and assign functions for role and session_authorization, which
 * _PG_init wraps.
 *
 * SECURITY DEFINER functions and maintenance commands change the user
 * without these settings, and Postgres refuses a role change inside
 * either, so they are left alone.
 *
 * The request's own settings are held too: every setting the session
 * already has under a prefix in pgedge_safesession.locked_setting_prefixes
 * (PostgREST's request.* by default). Row-level security and functions
 * such as auth.uid() trust them, so a request that rewrote them could act
 * for another user without changing role. The pool sets them in the
 * statement that switches role, so when that statement ends each such
 * setting the session has is given a check that refuses any change until
 * the transaction ends. One a request creates itself is held from the next
 * request on; see hold_locked_settings().
 */
#define ROLE_LOCK_ROLE_MSG \
    "cannot change role again after the role switch in this transaction"
#define ROLE_LOCK_SETTINGS_MSG \
    "cannot change request settings after the role switch in this transaction"
#define ROLE_LOCK_NEW_MSG \
    "cannot set a new request setting after the role switch in this" \
    " transaction"
#define ROLE_LOCK_HINT \
    "pgedge_safesession lets a delegating role" \
    " (pgedge_safesession.delegating_roles) switch role once per" \
    " transaction; after that, the role and the settings named by" \
    " pgedge_safesession.locked_setting_prefixes cannot change."

static LocalTransactionId role_lock_lxid = InvalidLocalTransactionId;
static Oid                role_lock_role = InvalidOid;
/*
 * Did the switch leave an explicit role set (SET ROLE x), not none? Postgres
 * tells the two apart even for the same user, and so does the read-only
 * rule for delegating sessions (current_role_is_restricted()), so a later
 * change between them is a change of role too.
 */
static bool               role_lock_explicit = false;
static int                role_lock_nest = 0;     /* subtransaction depth */
static LocalTransactionId settings_lock_lxid = InvalidLocalTransactionId;

/*
 * How deep the executor and utility statements are nested: 0 between
 * statements from the client, so a hook that sees 0 is at the start or end
 * of one. Counted as pg_stat_statements does.
 */
static int                exec_nesting_level = 0;

static LocalTransactionId
current_lxid(void)
{
#if PG_VERSION_NUM >= 170000
    return MyProc->vxid.lxid;
#else
    return MyProc->lxid;
#endif
}

static void
role_lock_reject(const char *msg)
{
    ereport(ERROR,
            (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
             errmsg("%s", msg),
             errhint("%s", ROLE_LOCK_HINT)));
}

/* Are the request's settings held in this transaction? */
static bool
settings_lock_held(void)
{
    return IsTransactionState() && settings_lock_lxid == current_lxid() &&
        list_is_set(safesession_locked_setting_prefixes);
}

static bool
check_request_setting(char **newval, void **extra, GucSource source)
{
    if (!settings_lock_held())
        return true;
    GUC_check_errcode(ERRCODE_INSUFFICIENT_PRIVILEGE);
    GUC_check_errmsg(ROLE_LOCK_SETTINGS_MSG);
    GUC_check_errhint(ROLE_LOCK_HINT);
    return false;
}

/*
 * A reset, such as RESET or set_config(name, NULL, ...), passes no check,
 * only the assign, so refuse it here while the settings are held, before
 * the value changes. The assign also runs when a setting is first defined,
 * and when a transaction or subtransaction ends and the earlier value comes
 * back; the settings are not held yet then, or no transaction is in
 * progress, so those go through.
 */
static void
assign_request_setting(const char *newval, void *extra)
{
    if (settings_lock_held())
        role_lock_reject(ROLE_LOCK_SETTINGS_MSG);
}

/* Is this name one of the prefixes, or under one of them? */
static bool
name_under_prefixes(const char *name, List *prefixes)
{
    ListCell *lc;

    foreach(lc, prefixes)
    {
        const char *prefix = lfirst(lc);
        size_t      len = strlen(prefix);

        if (pg_strncasecmp(name, prefix, len) == 0 &&
            (name[len] == '.' || name[len] == '\0'))
            return true;
    }
    return false;
}

/*
 * Which settings are held when the lock is taken: every setting the
 * session has under a locked prefix. Once held, a setting keeps its check
 * for the session.
 *
 * Looking over every setting the session has sorts them all on PostgreSQL
 * 16 and later, which would double the cost of a short request. So there,
 * the full look is done only when a setting may have been created since
 * the last one:
 *
 * - at the session's first lock, and after the prefix list changes;
 * - at every lock, for a pool whose statements before the switch this
 *   cannot follow (a DO, a CALL, one of its own functions, or a user's
 *   table or view);
 * - at the next lock, after a request did something that may create one
 *   (scan_next_lock; see note_request_may_create).
 *
 * Otherwise only the names the pool sets are looked at: written in a
 * statement run before the switch, noted when it is parsed
 * (note_pool_settings), or passed as a parameter of one, read when it
 * starts (note_pool_param_names). On PostgreSQL 14 and 15 the full look is
 * cheap and always done.
 */
static List *noted_setting_names = NIL;     /* in TopMemoryContext */
/* The settings SafeSession defined to hold them; in TopMemoryContext */
static List *held_setting_names = NIL;
/* The prefix list changed since the held settings' checks were set */
static bool  held_checks_stale = false;
/*
 * The look for what the plan reading cannot see (see
 * recheck_request_settings()), wanted in this transaction, and a new
 * setting a savepoint that rolled back made.
 */
static bool  settings_recheck = false;
static char  pending_new_setting[256] = "";
static bool  settings_scanned = false;
static bool  scan_every_lock = false;
static bool  scan_next_lock = false;
static bool  pool_param_names = false;

/* More names than a pool sets; past it, look at every setting instead. */
#define MAX_NOTED_SETTINGS 64

/* The prefix list, parsed when first needed after it changes. */
static List *locked_prefixes = NIL;         /* in TopMemoryContext */
static char *locked_prefixes_raw = NULL;    /* split in place */
static char *locked_prefixes_value = NULL;  /* as set, to compare */
static bool  locked_prefixes_valid = false;

static List *
get_locked_prefixes(void)
{
    MemoryContext old;

    if (locked_prefixes_valid)
        return locked_prefixes;
    list_free(locked_prefixes);
    if (locked_prefixes_raw != NULL)
        pfree(locked_prefixes_raw);
    if (locked_prefixes_value != NULL)
        pfree(locked_prefixes_value);
    old = MemoryContextSwitchTo(TopMemoryContext);
    locked_prefixes_value = pstrdup(safesession_locked_setting_prefixes);
    locked_prefixes_raw = pstrdup(safesession_locked_setting_prefixes);
    /*
     * The check hook made sure the list parses. SplitGUCList, unlike
     * SplitIdentifierString, keeps a name longer than an identifier whole, as
     * setting names are.
     */
    (void) SplitGUCList(locked_prefixes_raw, ',', &locked_prefixes);
    MemoryContextSwitchTo(old);
    locked_prefixes_valid = true;
    return locked_prefixes;
}

/* Note a name the pool sets, if it is under a locked prefix. */
static void
note_setting_name(const char *name)
{
    MemoryContext old;
    ListCell   *lc;

    if (!list_is_set(safesession_locked_setting_prefixes) ||
        !name_under_prefixes(name, get_locked_prefixes()))
        return;
    foreach(lc, noted_setting_names)
        if (pg_strcasecmp(lfirst(lc), name) == 0)
            return;
    if (list_length(noted_setting_names) >= MAX_NOTED_SETTINGS)
    {
        scan_every_lock = true;
        return;
    }
    old = MemoryContextSwitchTo(TopMemoryContext);
    noted_setting_names = lappend(noted_setting_names, pstrdup(name));
    MemoryContextSwitchTo(old);
}

static bool
is_user_function(Oid funcid, void *context)
{
    return funcid >= FirstNormalObjectId;
}

/*
 * Does an argument of EXECUTE run code, such as a function call? A plain
 * value becomes a parameter of the statement, read by
 * note_pool_param_names(); anything else is evaluated before the statement
 * starts, where no walk sees it.
 */
static bool
execute_runs_code(ExecuteStmt *stmt)
{
    ListCell   *lc;

    foreach(lc, stmt->params)
    {
        Node   *arg = lfirst(lc);

        if (IsA(arg, TypeCast))
            arg = ((TypeCast *) arg)->arg;
        if (!IsA(arg, A_Const) && !IsA(arg, ParamRef))
            return true;
    }
    return false;
}

/* Note what a statement run before the switch sets; see above. */
static bool
note_pool_settings(Node *node, void *context)
{
    if (node == NULL)
        return false;
    if (IsA(node, FuncExpr) && ((FuncExpr *) node)->funcid == F_SET_CONFIG)
    {
        Node   *name = linitial(((FuncExpr *) node)->args);

        if (IsA(name, Const) && !((Const *) name)->constisnull)
            note_setting_name(
                TextDatumGetCString(((Const *) name)->constvalue));
        else if (IsA(name, Param) &&
                 ((Param *) name)->paramkind == PARAM_EXTERN)
            pool_param_names = true;
        else
            scan_every_lock = true;
    }
    else if (check_functions_in_node(node, is_user_function, NULL))
        scan_every_lock = true;

    /*
     * A user's table or view can run code this walk does not see: a view's
     * body, a rule, a trigger or a row-level security policy.
     */
    if (IsA(node, RangeTblEntry))
    {
        RangeTblEntry *rte = (RangeTblEntry *) node;

        if (rte->rtekind == RTE_RELATION && rte->relid >= FirstNormalObjectId)
            scan_every_lock = true;
        return false;
    }
    if (IsA(node, Query))
    {
        Query *query = (Query *) node;

        if (query->commandType == CMD_UTILITY && query->utilityStmt != NULL)
        {
            Node   *stmt = query->utilityStmt;

            if (IsA(stmt, VariableSetStmt) &&
                ((VariableSetStmt *) stmt)->name != NULL)
                note_setting_name(((VariableSetStmt *) stmt)->name);
            /*
             * Code this walk cannot see into, and the arguments of EXECUTE,
             * which are evaluated before the prepared statement starts
             */
            else if (IsA(stmt, CallStmt) || IsA(stmt, DoStmt) ||
                     (IsA(stmt, ExecuteStmt) &&
                      execute_runs_code((ExecuteStmt *) stmt)))
                scan_every_lock = true;
            return false;
        }
        return query_tree_walker(query, note_pool_settings, context,
                                 QTW_EXAMINE_RTES_BEFORE);
    }
    return expression_tree_walker(node, note_pool_settings, context);
}

/*
 * A setting name passed as a parameter, as PostgREST passes the names of
 * the role's own settings. Which parameter holds a name is seen when the
 * statement is parsed, but a plan can put it in many places (a LIMIT, a
 * WHERE clause, a function in FROM), so the values of the statement's
 * parameters are read instead, each one that names a setting under a
 * locked prefix noted: that is all a name can be. A parameter fetched only
 * when needed cannot be read here, so it asks for the full look.
 */
static void
note_pool_param_names(ParamListInfo params)
{
    int     i;

    if (params == NULL)
        return;
    if (params->paramFetch != NULL)
    {
        scan_every_lock = true;
        return;
    }
    for (i = 0; i < params->numParams; i++)
    {
        ParamExternData *prm = &params->params[i];

        if (!prm->isnull && prm->ptype == TEXTOID)
            note_setting_name(TextDatumGetCString(prm->value));
    }
}

/*
 * Functions seen with no SET clause that matters here, in TopMemoryContext;
 * see safesession_fmgr_hook. Forgotten when a function or the prefix list
 * changes.
 */
static List *plain_set_clause_oids = NIL;
#define MAX_PLAIN_SET_CLAUSE_OIDS 1024

static void
invalidate_set_clauses(Datum arg, int cacheid, uint32 hashvalue)
{
    list_free(plain_set_clause_oids);
    plain_set_clause_oids = NIL;
}

/*
 * The prefix list changed: look over every setting at the next lock. A
 * reload runs this too, with the same value most of the time.
 */
static void
assign_locked_setting_prefixes(const char *newval, void *extra)
{
    if (locked_prefixes_valid && newval != NULL &&
        strcmp(newval, locked_prefixes_value) == 0)
        return;
    locked_prefixes_valid = false;
    settings_scanned = false;
    held_checks_stale = true;
    list_free(plain_set_clause_oids);
    plain_set_clause_oids = NIL;
}

/* Is this a placeholder under a locked prefix? */
static bool
unheld_locked_setting(struct config_generic *gen, List *prefixes)
{
    return gen != NULL && (gen->flags & GUC_CUSTOM_PLACEHOLDER) &&
        name_under_prefixes(gen->name, prefixes);
}

/*
 * Does SafeSession hold this setting? A held setting has SafeSession's
 * check while its name is under a locked prefix, so this costs the same
 * however many settings are held.
 */
static bool
gen_held_by_us(struct config_generic *gen)
{
    if (gen == NULL || gen->vartype != PGC_STRING)
        return false;
#if PG_VERSION_NUM >= 190000
    return gen->_string.check_hook == check_request_setting;
#else
    return ((struct config_string *) gen)->check_hook ==
        check_request_setting;
#endif
}

/* The same, by name. */
static bool
held_by_us(const char *name)
{
#if PG_VERSION_NUM >= 160000
    return gen_held_by_us(find_option(name, false, true, ERROR));
#else
    ListCell *lc;

    /* find_option() is not exported before PostgreSQL 16 */
    foreach(lc, held_setting_names)
        if (pg_strcasecmp(lfirst(lc), name) == 0)
            return true;
    return false;
#endif
}

/*
 * Is this name under a locked prefix but not held? It is either new, or a
 * setting another extension defines. After the switch neither may be set.
 */
static bool
name_unheld_locked(const char *name)
{
    return list_is_set(safesession_locked_setting_prefixes) &&
        name_under_prefixes(name, get_locked_prefixes()) &&
        !held_by_us(name);
}

/* Refuse setting such a name after the switch. */
static void
refuse_unheld_locked(const char *name)
{
    /* A setting may be defined with no flags, so ask whether it exists */
    if (GetConfigOption(name, true, false) != NULL &&
        !(GetConfigOptionFlags(name, true) & GUC_CUSTOM_PLACEHOLDER))
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg(ROLE_LOCK_SETTINGS_MSG),
                 errdetail("Setting \"%s\" is defined by another"
                           " extension.", name),
                 errhint("%s", ROLE_LOCK_HINT)));
    ereport(ERROR,
            (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
             errmsg(ROLE_LOCK_NEW_MSG),
             errdetail("Setting \"%s\" is under a locked prefix but was not"
                       " set before the switch.", name),
             errhint("%s", ROLE_LOCK_HINT)));
}

/*
 * After the hold, may this set_config() call run? Yes when its name is
 * written in it and is outside the locked prefixes, such as
 * response.status, or is held (the held setting's own check refuses the
 * change). A name under a locked prefix that is not held is put in read;
 * a name known only at run time cannot be judged here.
 */
static bool
set_config_keeps_lock(FuncExpr *fexpr, LockPlanRead *read)
{
    Node   *name = linitial(fexpr->args);
    char   *setting;

    if (!IsA(name, Const) || ((Const *) name)->constisnull ||
        ((Const *) name)->consttype != TEXTOID)
        return false;
    setting = TextDatumGetCString(((Const *) name)->constvalue);
    if (!name_unheld_locked(setting))
        return true;
    read->name = setting;
    return false;
}

/*
 * A request did something that may create a setting under a locked prefix:
 * look over every setting at the next lock, so the setting is held from
 * the next request on, like any other the session has.
 */
static void
note_request_may_create(void)
{
    scan_next_lock = true;
}

/*
 * Give each setting the session has under a locked prefix the check and
 * assign above. Only a custom setting nobody defined, a placeholder, is
 * taken; once defined it keeps the check for the rest of the session, and
 * keeps its value.
 */
static void
hold_locked_settings(void)
{
    List       *prefixes;
    List       *names = NIL;
    ListCell   *lc;

    if (!list_is_set(safesession_locked_setting_prefixes))
        return;
    prefixes = get_locked_prefixes();

#if PG_VERSION_NUM >= 160000
    if (settings_scanned && !scan_every_lock && !scan_next_lock)
    {
        foreach(lc, noted_setting_names)
        {
            struct config_generic *gen = find_option(lfirst(lc), false,
                                                     true, ERROR);

            if (unheld_locked_setting(gen, prefixes))
                names = lappend(names, pstrdup(gen->name));
        }
    }
    else
#endif
    {
        struct config_generic **vars;
        int         nvars;
        int         i;

#if PG_VERSION_NUM >= 160000
        vars = get_guc_variables(&nvars);
#else
        vars = get_guc_variables();
        nvars = GetNumConfigOptions();
#endif
        for (i = 0; i < nvars; i++)
            if (unheld_locked_setting(vars[i], prefixes))
                names = lappend(names, pstrdup(vars[i]->name));
#if PG_VERSION_NUM >= 160000
        pfree(vars);
#endif
        settings_scanned = true;
        scan_next_lock = false;
    }

    /* Defining a setting changes the list above, so do it after. */
    foreach(lc, names)
    {
        MemoryContext old;

        DefineCustomStringVariable(lfirst(lc),
                                   "A request setting held by"
                                   " pgedge_safesession.",
                                   "It cannot change after the role"
                                   " switch.",
                                   MemoryContextAllocZero(TopMemoryContext,
                                                          sizeof(char *)),
                                   NULL, PGC_USERSET,
                                   GUC_NOT_IN_SAMPLE | GUC_NO_SHOW_ALL,
                                   check_request_setting,
                                   assign_request_setting, NULL);
        old = MemoryContextSwitchTo(TopMemoryContext);
        held_setting_names = lappend(held_setting_names,
                                     pstrdup(lfirst(lc)));
        MemoryContextSwitchTo(old);
    }
    list_free_deep(names);

    /* A held name needs no look again. */
    foreach(lc, noted_setting_names)
    {
        char   *name = lfirst(lc);
        int     flags = GetConfigOptionFlags(name, true);

        if (flags != 0 && !(flags & GUC_CUSTOM_PLACEHOLDER))
        {
            noted_setting_names = foreach_delete_current(noted_setting_names,
                                                         lc);
            pfree(name);
        }
    }
}

/*
 * A setting under a locked prefix that SafeSession does not hold: a
 * placeholder, or one another extension defines that this transaction
 * changed. The hold takes every placeholder under the prefixes, so one
 * there now was made after the switch. It stays after its value is undone,
 * by a savepoint that rolled back or at the end of a command such as
 * REFRESH MATERIALIZED VIEW, CREATE INDEX or ANALYZE, so it is found by
 * being there, whatever its value.
 */
static bool
unheld_locked_setting_changed(struct config_generic *gen, List *prefixes)
{
    if (!name_under_prefixes(gen->name, prefixes) || gen_held_by_us(gen))
        return false;
    return (gen->flags & GUC_CUSTOM_PLACEHOLDER) || gen->stack != NULL;
}

/*
 * The look. The plan reading in safesession_object_access() judges every
 * set_config() call whose name is written in it, before it runs. A call it
 * cannot judge, such as one with a name built at run time or one PL/pgSQL
 * runs as an expression on its own (v := set_config(...)), asks for this
 * look instead, for the rest of the transaction: at the end of each
 * statement from the client and before COMMIT or PREPARE TRANSACTION, it
 * looks over every setting for one under a locked prefix that is not held
 * (see unheld_locked_setting_changed()), and refuses the transaction if it
 * finds one. The statement that set it can read it, but the transaction is
 * undone. Such a call costs a look over every setting each time, so a
 * request should set response.status with PERFORM set_config(...).
 */
static void
recheck_request_settings(void)
{
    struct config_generic **vars;
    int         nvars;
    int         i;
    List       *prefixes;
    char       *found = NULL;

    if (!settings_recheck || !settings_lock_held())
        return;
    prefixes = get_locked_prefixes();
#if PG_VERSION_NUM >= 160000
    vars = get_guc_variables(&nvars);
#else
    vars = get_guc_variables();
    nvars = GetNumConfigOptions();
#endif
    for (i = 0; i < nvars && found == NULL; i++)
        if (unheld_locked_setting_changed(vars[i], prefixes))
            found = pstrdup(vars[i]->name);
#if PG_VERSION_NUM >= 160000
    pfree(vars);
#endif
    if (found == NULL && pending_new_setting[0] != '\0')
        found = pstrdup(pending_new_setting);
    if (found != NULL)
        refuse_unheld_locked(found);
}

/*
 * After the prefix list changes, a held setting is held only while its name
 * is still under a locked prefix: its check is turned on or off to match.
 */
static void
sync_held_checks(void)
{
    List       *prefixes;
    ListCell   *lc;

    prefixes = list_is_set(safesession_locked_setting_prefixes) ?
        get_locked_prefixes() : NIL;
    foreach(lc, held_setting_names)
    {
        struct config_string *conf = core_string_setting(lfirst(lc));
        bool        held = name_under_prefixes(lfirst(lc), prefixes);

        conf->check_hook = held ? check_request_setting : NULL;
        conf->assign_hook = held ? assign_request_setting : NULL;
    }
    held_checks_stale = false;
}

/*
 * A switch made inside a subtransaction that rolls back never happened:
 * the role is back to what it was, so the lock must go too, or the next
 * statement would be refused. One made inside a subtransaction that is
 * released now belongs to the level above. The pool switches at the top
 * level, so a request's own subtransactions, nested deeper, release
 * nothing.
 */
static void
safesession_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
                             SubTransactionId parentSubid, void *arg)
{
    int     level;

    /*
     * A setting another extension defines, changed inside a savepoint or an
     * exception block that rolls back, is back to its old value by the time
     * the look runs, though statements inside read the new one. A new name
     * stays and is found, but this one leaves nothing behind. Postgres
     * undoes it only after this callback, so note it now for the look. The
     * subtransaction is aborting, so settings_lock_held(), which asks for a
     * transaction in progress, is not used here.
     */
    if (event == SUBXACT_EVENT_ABORT_SUB && settings_recheck &&
        pending_new_setting[0] == '\0' &&
        settings_lock_lxid == current_lxid() &&
        list_is_set(safesession_locked_setting_prefixes))
    {
        struct config_generic **vars;
        int         nvars;
        int         i;
        List       *prefixes = get_locked_prefixes();

#if PG_VERSION_NUM >= 160000
        vars = get_guc_variables(&nvars);
#else
        vars = get_guc_variables();
        nvars = GetNumConfigOptions();
#endif
        for (i = 0; i < nvars; i++)
            if (unheld_locked_setting_changed(vars[i], prefixes))
            {
                strlcpy(pending_new_setting, vars[i]->name,
                        sizeof(pending_new_setting));
                break;
            }
#if PG_VERSION_NUM >= 160000
        pfree(vars);
#endif
    }

    if (role_lock_lxid != current_lxid() || !OidIsValid(role_lock_role))
        return;
    level = GetCurrentTransactionNestLevel();
    if (event == SUBXACT_EVENT_ABORT_SUB && role_lock_nest >= level)
    {
        role_lock_role = InvalidOid;
        settings_lock_lxid = InvalidLocalTransactionId;
    }
    else if (event == SUBXACT_EVENT_COMMIT_SUB && role_lock_nest >= level)
        role_lock_nest = level - 1;
}

/*
 * Postgres follows each change of session_authorization with a forced
 * change of role: to none after SET SESSION AUTHORIZATION, and to the
 * role's default (ALTER ROLE ... SET role, or none) after RESET. Set by the
 * session_authorization assign, and used up by the next role check or
 * assign: FORCED_ROLE_SAME when the lock was already taken, so the forced
 * role may only be none for the same user; FORCED_ROLE_MOVE when this
 * session_authorization change took the lock, so the forced role is part of
 * the same first switch and the lock moves to it.
 */
#define FORCED_ROLE_NONE 0
#define FORCED_ROLE_SAME 1
#define FORCED_ROLE_MOVE 2
static int  sessauth_just_assigned = FORCED_ROLE_NONE;
/*
 * Is this transaction a delegating session's? Judged once, before its first
 * change of role, from the session as it was then: a superuser not on
 * delegating_roles that becomes a login that is, with SET SESSION
 * AUTHORIZATION, stays unlocked for the transaction, so that changes back,
 * and the ones Postgres makes when a function's SET clause ends, go through.
 */
static LocalTransactionId xact_judged_lxid = InvalidLocalTransactionId;
static bool xact_delegating = false;
/* A session_authorization change took the lock in this statement */
static bool sessauth_took_lock = false;

/*
 * May the acting role become the one named? name is a value of role or
 * session_authorization, where "none" means the login role. Takes the lock
 * at the first change in a transaction.
 *
 * is_set is true for a new value, from SET, set_config() or a function's
 * SET clause, which passes the check. After the lock, a new value is
 * refused even when it names the locked role: one set for the whole
 * session would outlive the transaction. The exception is the change of
 * role Postgres makes itself after session_authorization (forced; see
 * sessauth_just_assigned). Only the assign sees a value coming back, such
 * as at the end of a function with a SET clause, and a reset; those may
 * only bring back the locked role, and its state: a role set explicitly
 * (role_guc and a name other than none) or none, which Postgres tells
 * apart even for the same user.
 */
static bool
role_change_allowed(const char *name, bool is_set, bool role_guc,
                    int forced)
{
    Oid     userid;
    int     secctx;
    Oid     target;
    bool    locked;
    bool    explicit_role;

    if (!delegating_configured())
        return true;

    /*
     * A role chosen for the login, by ALTER ROLE or ALTER DATABASE ... SET
     * role or a connection option, is applied while the session logs in;
     * that is not a change by a request. A parallel worker is given the
     * leader's role; see safesession_fmgr_hook for what may change it there.
     */
    if (!IsTransactionState() || !IsNormalProcessingMode() ||
        InitializingParallelWorker || IsParallelWorker())
        return true;

    /*
     * Once locked, the transaction stays locked: a switch with SET SESSION
     * AUTHORIZATION changes the session user, which may make the session
     * look like it is not delegating any more. Before that, the transaction
     * is judged once (see xact_delegating), from the session as it was at
     * its first change of role.
     */
    locked = role_lock_lxid == current_lxid() && OidIsValid(role_lock_role);
    if (!locked)
    {
        if (xact_judged_lxid != current_lxid())
        {
            xact_judged_lxid = current_lxid();
            xact_delegating = session_is_delegating();
        }
        if (!xact_delegating)
            return true;
    }
    GetUserIdAndSecContext(&userid, &secctx);
    if (secctx & (SECURITY_LOCAL_USERID_CHANGE |
                  SECURITY_RESTRICTED_OPERATION))
        return true;
    /* Postgres's own check_role compares "none" case-sensitively. */
    target = (name == NULL || strcmp(name, "none") == 0) ?
        GetSessionUserId() : get_role_oid(name, true);
    if (!OidIsValid(target))
        return true;            /* Postgres refuses an unknown role itself */
    /* session_authorization leaves no role set; role none neither */
    explicit_role = role_guc && name != NULL && strcmp(name, "none") != 0;
    if (!locked || forced == FORCED_ROLE_MOVE)
    {
        role_lock_lxid = current_lxid();
        role_lock_role = target;
        role_lock_explicit = explicit_role;
        if (!locked)
        {
            role_lock_nest = GetCurrentTransactionNestLevel();
            if (!role_guc)
                sessauth_took_lock = true;
        }
        return true;
    }
    if (target != role_lock_role || explicit_role != role_lock_explicit)
        return false;
    return !is_set ||
        (forced == FORCED_ROLE_SAME && strcmp(name, "none") == 0);
}

/*
 * The wrappers around Postgres's own check and assign functions for role
 * and session_authorization. The check runs Postgres's first, so a change
 * Postgres refuses (no membership, say) never takes the lock.
 */
static GucStringCheckHook  prev_role_check = NULL;
static GucStringAssignHook prev_role_assign = NULL;
static GucStringCheckHook  prev_sessauth_check = NULL;
static GucStringAssignHook prev_sessauth_assign = NULL;

static bool
role_lock_check(GucStringCheckHook prev, char **newval, void **extra,
                GucSource source, bool role_guc, int forced)
{
    if (prev != NULL && !prev(newval, extra, source))
        return false;
    /* SET, set_config() and a function's SET clause; not login defaults. */
    if (source != PGC_S_SESSION ||
        role_change_allowed(*newval, true, role_guc, forced))
        return true;
    if (*extra != NULL)
    {
#if PG_VERSION_NUM >= 160000
        guc_free(*extra);
#else
        free(*extra);
#endif
        *extra = NULL;
    }
    GUC_check_errcode(ERRCODE_INSUFFICIENT_PRIVILEGE);
    GUC_check_errmsg(ROLE_LOCK_ROLE_MSG);
    GUC_check_errhint(ROLE_LOCK_HINT);
    return false;
}

/*
 * A reset passes no check, only the assign. It is a change of role like
 * any other: the first in a transaction takes the lock, and a later one is
 * refused before Postgres's assign runs, so the role does not change. The
 * assign also runs when a transaction, a subtransaction or a function with
 * a SET clause ends and the earlier value comes back. At the end of a
 * transaction or subtransaction no transaction is in progress, so nothing
 * is checked. A function whose SET clause made the first change of the
 * transaction is refused when it ends, since going back is a second
 * change.
 */
static void
role_lock_assign(GucStringAssignHook prev, const char *newval, void *extra,
                 bool role_guc, int forced)
{
    if (!role_change_allowed(newval, false, role_guc, forced))
        role_lock_reject(ROLE_LOCK_ROLE_MSG);
    if (prev != NULL)
        prev(newval, extra);
}

static bool
safesession_check_role(char **newval, void **extra, GucSource source)
{
    int     forced = sessauth_just_assigned;

    sessauth_just_assigned = FORCED_ROLE_NONE;
    return role_lock_check(prev_role_check, newval, extra, source, true,
                           forced);
}

static void
safesession_assign_role(const char *newval, void *extra)
{
    /* A reset of session_authorization resets role with no check. */
    int     forced = sessauth_just_assigned;

    sessauth_just_assigned = FORCED_ROLE_NONE;
    role_lock_assign(prev_role_assign, newval, extra, true, forced);
}

static bool
safesession_check_sessauth(char **newval, void **extra, GucSource source)
{
    sessauth_just_assigned = FORCED_ROLE_NONE;
    sessauth_took_lock = false;
    return role_lock_check(prev_sessauth_check, newval, extra, source,
                           false, FORCED_ROLE_NONE);
}

static void
safesession_assign_sessauth(const char *newval, void *extra)
{
    role_lock_assign(prev_sessauth_assign, newval, extra, false,
                     FORCED_ROLE_NONE);
    sessauth_just_assigned = !IsTransactionState() ? FORCED_ROLE_NONE :
        sessauth_took_lock ? FORCED_ROLE_MOVE : FORCED_ROLE_SAME;
    sessauth_took_lock = false;
    /* A change of session user; see note_session_user(). */
    if (list_is_set(safesession_require_where_roles))
        ResetPlanCache();
}

/*
 * A function's SET clause can change the role, or set a setting under a
 * locked prefix, and the fmgr hook runs after Postgres has applied the
 * clause and before the function's body runs.
 *
 * A parallel worker has neither the leader's lock nor its held settings,
 * and Postgres lets a function's SET clause run there. So in a worker of a
 * delegating session, a function whose SET clause sets the role,
 * session_authorization or a setting under a locked prefix is refused. In
 * the leader, the wrappers and the held settings judge such a clause; one
 * that may create a setting under a locked prefix after the hold is noted
 * (note_request_may_create), so the setting is held from the next request.
 */
static fmgr_hook_type prev_fmgr_hook = NULL;

/*
 * The first name in the function's SET clause that is the role or
 * session_authorization (when roles is true) or under a locked prefix
 * (only one not held yet, when unheld_only is true); NULL if none is.
 */
static char *
set_clause_name(Oid funcid, bool roles, bool unheld_only)
{
    HeapTuple   tup;
    Datum       config;
    bool        isnull;
    Datum      *items;
    int         nitems;
    int         i;
    char       *found = NULL;

    tup = SearchSysCache1(PROCOID, ObjectIdGetDatum(funcid));
    if (!HeapTupleIsValid(tup))
        return NULL;
    config = SysCacheGetAttr(PROCOID, tup, Anum_pg_proc_proconfig, &isnull);
    if (!isnull)
    {
        deconstruct_array(DatumGetArrayTypeP(config), TEXTOID, -1, false,
                          TYPALIGN_INT, &items, NULL, &nitems);
        for (i = 0; i < nitems && found == NULL; i++)
        {
            char   *name;
            char   *value;

            ParseLongOption(TextDatumGetCString(items[i]), &name, &value);
            if (name == NULL)
                continue;
            if (roles &&
                (pg_strcasecmp(name, "role") == 0 ||
                 pg_strcasecmp(name, "session_authorization") == 0))
                found = name;
            else if (unheld_only ? name_unheld_locked(name) :
                     (list_is_set(safesession_locked_setting_prefixes) &&
                      name_under_prefixes(name, get_locked_prefixes())))
                found = name;
        }
    }
    ReleaseSysCache(tup);
    return found;
}

static void
safesession_fmgr_hook(FmgrHookEventType event, FmgrInfo *flinfo, Datum *arg)
{
    if (prev_fmgr_hook)
        prev_fmgr_hook(event, flinfo, arg);
    if (event != FHET_START || !IsTransactionState())
        return;

    if (IsParallelWorker())
    {
        char   *name;

        if (delegating_configured() && session_is_delegating() &&
            (name = set_clause_name(flinfo->fn_oid, true, false)) != NULL)
            ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("cannot run a function that sets \"%s\" in a"
                            " parallel worker", name),
                     errhint("%s", ROLE_LOCK_HINT)));
    }
    else if (settings_lock_held() &&
             !list_member_oid(plain_set_clause_oids, flinfo->fn_oid))
    {
        char   *name = set_clause_name(flinfo->fn_oid, false, true);

        if (name != NULL)
        {
            /*
             * Postgres has applied the clause, so the name now exists; the
             * next lock holds it, as it would any setting the session has.
             */
            note_request_may_create();
            refuse_unheld_locked(name);
        }
        else if (list_length(plain_set_clause_oids) <
                 MAX_PLAIN_SET_CLAUSE_OIDS)
        {
            MemoryContext old = MemoryContextSwitchTo(TopMemoryContext);

            plain_set_clause_oids = lappend_oid(plain_set_clause_oids,
                                                flinfo->fn_oid);
            MemoryContextSwitchTo(old);
        }
    }
}

/*
 * Runs in the executor and utility hooks. Once this transaction has
 * switched, compares the acting role with the lock, as a second line
 * behind the wrappers, and holds the request's settings once the statement
 * that switched has ended: at the end of the outermost executor run or
 * utility statement, or else at the start of the next statement.
 */
static void
check_role_lock(void)
{
    Oid                 userid;
    int                 secctx;
    LocalTransactionId  lxid;

    sessauth_just_assigned = FORCED_ROLE_NONE;
    sessauth_took_lock = false;
    if (!IsTransactionState())
        return;
    lxid = current_lxid();
    /* Only role_change_allowed takes the lock, for delegating sessions. */
    if (role_lock_lxid != lxid || !OidIsValid(role_lock_role))
        return;

    GetUserIdAndSecContext(&userid, &secctx);
    if (!(secctx & (SECURITY_LOCAL_USERID_CHANGE |
                    SECURITY_RESTRICTED_OPERATION)) &&
        (userid != role_lock_role ||
         OidIsValid(GetCurrentRoleId()) != role_lock_explicit))
        role_lock_reject(ROLE_LOCK_ROLE_MSG);

    if (settings_lock_lxid != lxid && exec_nesting_level == 0)
    {
        if (held_checks_stale)
            sync_held_checks();
        hold_locked_settings();
        settings_lock_lxid = lxid;
        settings_recheck = false;
        pending_new_setting[0] = '\0';
    }
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

/* Chain to the previous ExecutorStart hook or the standard function. */
static void
chain_executor_start(QueryDesc *queryDesc, int eflags)
{
    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
}

/*
 * ExecutorStart hook: block DML (including data-modifying CTEs) for
 * restricted roles. Blocked function calls are handled earlier, in the
 * post_parse_analyze and planner hooks.
 */
static void
safesession_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
    bool       restricted = false;
    QueryDesc *save_starting;
    int        save_verdict;

    /* A plan made before the WHERE rule applied; see note_unchecked_plan() */
    check_unchecked_plan(queryDesc->plannedstmt);

    check_role_lock();

    /* Setting names the pool passes as parameters; see hold_locked_settings */
    if (pool_param_names && IsTransactionState() &&
        (role_lock_lxid != current_lxid() || !OidIsValid(role_lock_role)) &&
        delegating_configured() && session_is_delegating())
        note_pool_param_names(queryDesc->params);

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

    /*
     * Chain to previous hook or standard function. Where a delegating role
     * is configured, note which statement is starting, for
     * safesession_object_access(). Elsewhere nothing reads it, so the cost
     * of keeping it is not paid.
     */
    if (!delegating_configured())
    {
        chain_executor_start(queryDesc, eflags);
        return;
    }

    save_starting = starting_query;
    save_verdict = starting_verdict;
    starting_query = queryDesc;
    starting_verdict = -1;
    PG_TRY();
    {
        chain_executor_start(queryDesc, eflags);
    }
    PG_FINALLY();
    {
        starting_query = save_starting;
        starting_verdict = save_verdict;
    }
    PG_END_TRY();
}

/*
 * ExecutorRun and ExecutorFinish hooks: count how deep statements are
 * nested, and hold the request's settings once the outermost statement
 * that switched role has run; see check_role_lock().
 */
static void
safesession_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction,
                        uint64 count
#if PG_VERSION_NUM < 180000
                        , bool execute_once
#endif
                        )
{
    exec_nesting_level++;
    PG_TRY();
    {
        if (prev_ExecutorRun)
            prev_ExecutorRun(queryDesc, direction, count
#if PG_VERSION_NUM < 180000
                             , execute_once
#endif
                             );
        else
            standard_ExecutorRun(queryDesc, direction, count
#if PG_VERSION_NUM < 180000
                                 , execute_once
#endif
                                 );
    }
    PG_FINALLY();
    {
        exec_nesting_level--;
    }
    PG_END_TRY();

    if (exec_nesting_level == 0)
    {
        check_role_lock();
        recheck_request_settings();
    }
}

static void
safesession_ExecutorFinish(QueryDesc *queryDesc)
{
    exec_nesting_level++;
    PG_TRY();
    {
        if (prev_ExecutorFinish)
            prev_ExecutorFinish(queryDesc);
        else
            standard_ExecutorFinish(queryDesc);
    }
    PG_FINALLY();
    {
        exec_nesting_level--;
    }
    PG_END_TRY();

    /* AFTER triggers run here, after the outermost ExecutorRun */
    if (exec_nesting_level == 0)
    {
        check_role_lock();
        recheck_request_settings();
    }
}

/*
 * ExecutorEnd hook: on a server with a delegating role, look again at the
 * restriction once a statement ends; and, on a server with
 * require_where_roles, at whether the session user changed (see
 * note_session_user()).
 *
 * A statement can change the role the session acts as, as the switch a
 * pool runs at the start of each request does with set_config('role',
 * ...). Noticing the change here, as the utility hook does after SET ROLE,
 * discards the cached plans before the next statement fetches its plan,
 * so the Query-walking hooks check that plan under the new state rather
 * than the next statement running one a writer cached. The set_config()
 * check in safesession_object_access() reads the plan itself and does not
 * depend on this.
 */
static void
safesession_ExecutorEnd(QueryDesc *queryDesc)
{
    if (prev_ExecutorEnd)
        prev_ExecutorEnd(queryDesc);
    else
        standard_ExecutorEnd(queryDesc);

    if (delegating_configured() && IsTransactionState())
        note_restriction_state(current_role_is_restricted());

    /* set_config('session_authorization', ...) can change who must qualify */
    if (IsTransactionState())
        note_session_user();
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

    /*
     * Before rewrite, as safeupdate checks, so a view's own WHERE does not
     * count as the statement's; see check_where_required().
     */
    check_where_for_session(query);

    /* What the pool sets before it switches; see hold_locked_settings(). */
    if (delegating_configured() && IsTransactionState() &&
        (role_lock_lxid != current_lxid() || !OidIsValid(role_lock_role)) &&
        session_is_delegating())
        (void) note_pool_settings((Node *) query, NULL);

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
    PlannedStmt *result;
    const char  *unchecked = NULL;

    /* An unfiltered UPDATE or DELETE planned while the rule does not apply */
    if (list_is_set(safesession_require_where_roles) &&
        IsTransactionState() && !session_requires_where())
        unchecked = unfiltered_command(parse);

    /* For a BEGIN ATOMIC body, which is planned but never parsed again */
    check_where_for_session(parse);

    if (safesession_block_c_functions &&
        IsTransactionState() &&
        current_role_is_restricted() &&
        query_has_blocked_function(parse))
        safesession_reject(ERRCODE_READ_ONLY_SQL_TRANSACTION,
                           "cannot execute functions that may have"
                           " side effects in a read-only session");

    if (prev_planner_hook)
        result = prev_planner_hook(parse, query_string, cursorOptions,
                                   boundParams
#if PG_VERSION_NUM >= 190000
                                   , es
#endif
                                   );
    else
        result = standard_planner(parse, query_string, cursorOptions,
                                  boundParams
#if PG_VERSION_NUM >= 190000
                                  , es
#endif
                                  );

    if (unchecked != NULL)
        note_unchecked_plan(result, unchecked);
    return result;
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
 *
 * This hook sees a function but not its arguments, so it cannot tell a
 * set_config() on a response.* setting, which the Query-walking hooks
 * allow in a delegating session, from any other. So in a delegating
 * session set_config() is let through here only while a statement starts,
 * which is when its calls are set up, and only if plan_allows_set_config()
 * read that statement's plan and found nothing but the response.* form.
 * Anywhere else, such as a domain's CHECK run for a bound parameter or a
 * PL/pgSQL variable, a function run while a statement starts, or a
 * fast-path call, it is refused as before.
 *
 * That also refuses a set_config() that PL/pgSQL evaluates as an
 * expression on its own, such as v := set_config(...) or RETURN
 * set_config(...), which 1.0 refused too: this hook cannot tell it from a
 * domain's CHECK. PERFORM set_config(...) runs as a statement and is
 * allowed, so the error says to use it.
 */
static void
safesession_object_access(ObjectAccessType access, Oid classId,
                          Oid objectId, int subId, void *arg)
{
    if (prev_object_access_hook)
        prev_object_access_hook(access, classId, objectId, subId, arg);

    /*
     * Every set_config() call is set up first, which runs this hook. After
     * the hold, the plan being started is read, as above: a call that would
     * set a name under a locked prefix that is not held is refused before
     * it runs, and one whose name the plan does not show asks for the look
     * (recheck_request_settings()).
     */
    if (access == OAT_FUNCTION_EXECUTE && objectId == F_SET_CONFIG &&
        settings_lock_held())
    {
        LockPlanRead read = {NULL};

        if (starting_query == NULL ||
            !plan_allows_set_config(starting_query->plannedstmt, &read))
        {
            if (read.name != NULL)
                refuse_unheld_locked(read.name);
            settings_recheck = true;
            note_request_may_create();
        }
    }

    if (access != OAT_FUNCTION_EXECUTE ||
        !safesession_block_c_functions ||
        !IsTransactionState() ||
        !current_role_is_restricted() ||
        !function_is_blocked(objectId, NULL))
        return;

    if (objectId == F_SET_CONFIG && session_is_delegating())
    {
        if (starting_query != NULL && starting_verdict < 0)
            starting_verdict =
                plan_allows_set_config(starting_query->plannedstmt, NULL);
        if (starting_query != NULL && starting_verdict)
            return;

        ereport(ERROR,
                (errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),
                 errmsg("cannot execute functions that may have side"
                        " effects in a read-only session"),
                 errhint("This session is restricted to read-only access"
                         " by the pgedge_safesession extension. To set a"
                         " response.* setting, call set_config() in a"
                         " statement that reads no table, such as PERFORM"
                         " set_config(...) in PL/pgSQL.")));
    }

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
 * Refuse a SET, ALTER SYSTEM, ALTER ROLE ... SET or ALTER DATABASE ... SET
 * of a pgedge_safesession setting this release does not know, such as a
 * misspelled one, in any session.
 *
 * PostgreSQL 15 and later refuse such a name themselves, but PostgreSQL 14
 * accepts it with no effect. ALTER SYSTEM then saves it, and the server
 * would not start at its next restart (see refuse_unknown_settings), so a
 * typo is refused here, when it is typed. RESET and SET ... TO DEFAULT
 * are let through, so a name saved before can still be removed.
 */
static void
refuse_unknown_setting_name(VariableSetStmt *stmt)
{
    const char *name;

    if (stmt == NULL || stmt->kind == VAR_RESET ||
        stmt->kind == VAR_RESET_ALL || stmt->kind == VAR_SET_DEFAULT)
        return;

    name = stmt->name;
    if (name == NULL ||
        pg_strncasecmp(name, "pgedge_safesession.", 19) != 0)
        return;

    /* Defined by this module: known, and not a placeholder */
    if (GetConfigOption(name, true, false) != NULL &&
        (GetConfigOptionFlags(name, true) & GUC_CUSTOM_PLACEHOLDER) == 0)
        return;

    ereport(ERROR,
            (errcode(ERRCODE_UNDEFINED_OBJECT),
             errmsg("unrecognized configuration parameter \"%s\"", name),
             errhint("pgedge_safesession does not know this setting.")));
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
 * After the hold, a utility statement that would set a setting under a
 * locked prefix that is not held: SET, SET LOCAL or RESET of one, and
 * those that check a setting by setting it as a test, which creates it
 * too: a function's SET clause in CREATE or ALTER FUNCTION, and ALTER
 * ROLE, ALTER DATABASE or ALTER SYSTEM ... SET. A held setting's own check
 * refuses a change to it. RESET ALL would reset held settings, and
 * another extension's, so it is refused while settings are held.
 */
static void
refuse_unheld_set(VariableSetStmt *stmt, bool top_level)
{
    if (stmt == NULL)
        return;
    if (top_level && stmt->kind == VAR_RESET_ALL &&
        list_is_set(safesession_locked_setting_prefixes))
        ereport(ERROR,
                (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                 errmsg(ROLE_LOCK_SETTINGS_MSG),
                 errdetail("RESET ALL would reset them."),
                 errhint("%s", ROLE_LOCK_HINT)));
    if (stmt->name != NULL && name_unheld_locked(stmt->name))
        refuse_unheld_locked(stmt->name);
}

static void
refuse_unheld_in_utility(Node *parsetree)
{
    List       *options = NIL;
    ListCell   *lc;

    if (IsA(parsetree, VariableSetStmt))
        refuse_unheld_set((VariableSetStmt *) parsetree, true);
    else if (IsA(parsetree, AlterRoleSetStmt))
        refuse_unheld_set(((AlterRoleSetStmt *) parsetree)->setstmt, false);
    else if (IsA(parsetree, AlterDatabaseSetStmt))
        refuse_unheld_set(((AlterDatabaseSetStmt *) parsetree)->setstmt,
                          false);
    else if (IsA(parsetree, AlterSystemStmt))
        refuse_unheld_set(((AlterSystemStmt *) parsetree)->setstmt, false);
    else if (IsA(parsetree, CreateFunctionStmt))
        options = ((CreateFunctionStmt *) parsetree)->options;
    else if (IsA(parsetree, AlterFunctionStmt))
        options = ((AlterFunctionStmt *) parsetree)->actions;

    foreach(lc, options)
    {
        DefElem    *opt = lfirst(lc);

        if (strcmp(opt->defname, "set") == 0 && opt->arg != NULL &&
            IsA(opt->arg, VariableSetStmt))
            refuse_unheld_set((VariableSetStmt *) opt->arg, false);
    }
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
     * The role lock never refuses transaction control: refusing COMMIT
     * would leave the pool's connection in an aborted transaction.
     */
    bool  is_xact = parsetree != NULL && IsA(parsetree, TransactionStmt);

    /* A misspelled pgedge_safesession setting, in any session */
    if (parsetree != NULL)
    {
        if (IsA(parsetree, VariableSetStmt))
            refuse_unknown_setting_name((VariableSetStmt *) parsetree);
        else if (IsA(parsetree, AlterSystemStmt))
            refuse_unknown_setting_name(
                ((AlterSystemStmt *) parsetree)->setstmt);
        else if (IsA(parsetree, AlterRoleSetStmt))
            refuse_unknown_setting_name(
                ((AlterRoleSetStmt *) parsetree)->setstmt);
        else if (IsA(parsetree, AlterDatabaseSetStmt))
            refuse_unknown_setting_name(
                ((AlterDatabaseSetStmt *) parsetree)->setstmt);
    }

    if (!is_xact)
        check_role_lock();

    /* After the hold; see refuse_unheld_in_utility() */
    if (parsetree != NULL && settings_lock_held())
        refuse_unheld_in_utility(parsetree);

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
             * - SET CONSTRAINTS (only changes when this
             *   transaction's deferred checks run; a pool such as
             *   PostgREST sends it to roll a request back)
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
            case T_ConstraintsSetStmt:
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

    /* Chain to previous hook or standard function, counting the nesting */
    exec_nesting_level++;
    PG_TRY();
    {
        if (prev_ProcessUtility)
            prev_ProcessUtility(pstmt, queryString, readOnlyTree,
                                context, params, queryEnv,
                                dest, qc);
        else
            standard_ProcessUtility(pstmt, queryString, readOnlyTree,
                                    context, params, queryEnv,
                                    dest, qc);
    }
    PG_FINALLY();
    {
        exec_nesting_level--;
    }
    PG_END_TRY();

    /* SET ROLE, or a statement that switched: hold the settings now. */
    if (!is_xact)
    {
        check_role_lock();
        if (exec_nesting_level == 0)
            recheck_request_settings();
    }

    /*
     * Some utility statements change who we are acting as, and therefore
     * whether we are restricted, as their whole purpose: SET ROLE, SET
     * SESSION AUTHORIZATION, and the RESET ALL and DISCARD ALL that undo
     * them. The check at the top of this function ran before any of that
     * took effect, so look again now that it has, rather than leaving the
     * change to be noticed by whatever statement happens to come next.
     * SET SESSION AUTHORIZATION can also change who must qualify its
     * UPDATEs and DELETEs.
     */
    if (IsTransactionState())
    {
        note_restriction_state(current_role_is_restricted());
        note_session_user();
    }
}

/*
 * GUC check hook for each list of roles.
 *
 * Validates the list at assignment time so that a misconfiguration is
 * surfaced then, rather than silently disabling all protection. A list
 * that does not parse is rejected outright. Names that do not resolve to
 * a role draw a WARNING naming the setting, but only when we can safely
 * read the catalog: at postmaster start and during a SIGHUP reload there
 * is no transaction, so name resolution is skipped there (the syntax check
 * still runs, and resolve_role_list() logs the names later).
 */
static bool
check_role_list(const char *setting, char **newval)
{
    char     *rawstring;
    List     *rolelist;
    ListCell *lc;

    if (*newval == NULL || (*newval)[0] == '\0')
        return true;

    rawstring = pstrdup(*newval);

    if (!SplitIdentifierString(rawstring, ',', &rolelist))
    {
        /*
         * Postgres drops a bad value given at start with a WARNING, which
         * would leave this protection off, so refuse to start instead. At
         * a reload it keeps the previous value and logs the error.
         */
        if (process_shared_preload_libraries_in_progress)
            ereport(FATAL,
                    (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                     errmsg("invalid value for parameter \"%s\": \"%s\"",
                            setting, *newval),
                     errdetail("List syntax is invalid."),
                     errhint("pgedge_safesession does not start with a"
                             " setting it cannot read.")));
        GUC_check_errdetail("List syntax is invalid.");
        pfree(rawstring);
        list_free(rolelist);
        return false;
    }

    /* A parallel worker copies the leader's settings; the leader warned. */
    if (IsTransactionState() && !IsParallelWorker())
    {
        foreach(lc, rolelist)
        {
            char *rolename = (char *) lfirst(lc);

            if (!OidIsValid(get_role_oid(rolename, true)))
                ereport(WARNING,
                        (errmsg("%s: role \"%s\" does not exist",
                                setting, rolename),
                         /* The name was written with capitals, unquoted */
                         strstr(*newval, rolename) == NULL ?
                         errhint("A name not in double quotes is read in"
                                 " lower case.") : 0));
        }
    }

    pfree(rawstring);
    list_free(rolelist);
    return true;
}

static bool
check_safesession_roles(char **newval, void **extra, GucSource source)
{
    return check_role_list("pgedge_safesession.roles", newval);
}

static bool
check_read_only_roles(char **newval, void **extra, GucSource source)
{
    return check_role_list("pgedge_safesession.read_only_roles", newval);
}

static bool
check_delegating_roles(char **newval, void **extra, GucSource source)
{
    return check_role_list("pgedge_safesession.delegating_roles", newval);
}

static bool
check_acting_read_only_roles(char **newval, void **extra, GucSource source)
{
    return check_role_list("pgedge_safesession.acting_read_only_roles",
                           newval);
}

static bool
check_require_where_roles(char **newval, void **extra, GucSource source)
{
    return check_role_list("pgedge_safesession.require_where_roles", newval);
}

/* A prefix is one or more dot-separated names: request, or jwt.claims. */
static bool
valid_prefix(const char *p)
{
    bool    at_start = true;

    for (; *p; p++)
    {
        if (*p == '.' && !at_start)
            at_start = true;
        else if (isalpha((unsigned char) *p) || *p == '_' ||
                 (!at_start && (isdigit((unsigned char) *p) || *p == '$')))
            at_start = false;
        else
            return false;
    }
    return !at_start;
}

static bool
check_locked_setting_prefixes(char **newval, void **extra, GucSource source)
{
    char     *rawstring;
    List     *prefixes;
    ListCell *lc;
    bool      ok;

    if (*newval == NULL || (*newval)[0] == '\0')
        return true;
    rawstring = pstrdup(*newval);
    /* Not cut to an identifier's length; see get_locked_prefixes(). */
    ok = SplitGUCList(rawstring, ',', &prefixes);
    if (ok)
        foreach(lc, prefixes)
            if (!valid_prefix(lfirst(lc)))
                ok = false;
    pfree(rawstring);
    list_free(prefixes);
    if (ok)
        return true;

    /* As in check_role_list(): a bad value at start would be dropped. */
    if (process_shared_preload_libraries_in_progress)
        ereport(FATAL,
                (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                 errmsg("invalid value for parameter \"%s\": \"%s\"",
                        "pgedge_safesession.locked_setting_prefixes",
                        *newval),
                 errdetail("Each entry must be a setting prefix, such as"
                           " request or jwt.claims, with no trailing dot."),
                 errhint("pgedge_safesession does not start with a"
                         " setting it cannot read.")));
    GUC_check_errdetail("Each entry must be a setting prefix, such as"
                        " request or jwt.claims, with no trailing dot.");
    return false;
}

/*
 * Refuse to start with a pgedge_safesession setting this release does not
 * know, such as a misspelled one. Postgres would drop it with a WARNING,
 * leaving the protection it was meant to turn on off.
 */
static void
refuse_unknown_settings(void)
{
    struct config_generic **vars;
    int         nvars;
    int         i;

#if PG_VERSION_NUM >= 160000
    vars = get_guc_variables(&nvars);
#else
    vars = get_guc_variables();
    nvars = GetNumConfigOptions();
#endif
    for (i = 0; i < nvars; i++)
    {
        if ((vars[i]->flags & GUC_CUSTOM_PLACEHOLDER) &&
            pg_strncasecmp(vars[i]->name, "pgedge_safesession.", 19) == 0)
            ereport(FATAL,
                    (errcode(ERRCODE_UNDEFINED_OBJECT),
                     errmsg("unrecognized configuration parameter \"%s\"",
                            vars[i]->name),
                     errhint("pgedge_safesession does not start with a"
                             " setting it does not know."),
                     /* errcontext() is a macro: one branch each */
                     vars[i]->sourcefile ?
                     (errcontext("line %d of configuration file \"%s\"",
                                 vars[i]->sourceline,
                                 vars[i]->sourcefile)) :
                     (errcontext("given on the %s",
                                 GucSource_Names[vars[i]->source]))));
    }
#if PG_VERSION_NUM >= 160000
    pfree(vars);
#endif
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

    /* Define GUCs (a list given at start that does not parse is FATAL) */
    DefineCustomStringVariable(
        "pgedge_safesession.roles",
        "Roles that are restricted to read-only sessions.",
        "The old name of pgedge_safesession.read_only_roles, which "
        "keeps working; a role on either list is restricted.",
        &safesession_roles,
        "",
        PGC_SUSET,
        GUC_LIST_INPUT,
        check_safesession_roles,
        assign_safesession_roles,
        NULL);

    DefineCustomStringVariable(
        "pgedge_safesession.read_only_roles",
        "Roles that are restricted to read-only sessions.",
        "A comma-separated list of role names. A session whose "
        "session or current user is one of these roles, or is a "
        "member of one, is restricted to read-only access. A session "
        "of pgedge_safesession.delegating_roles is judged by the role "
        "it acts as instead.",
        &safesession_read_only_roles,
        "",
        PGC_SUSET,
        GUC_LIST_INPUT,
        check_read_only_roles,
        assign_safesession_roles,
        NULL);

    DefineCustomStringVariable(
        "pgedge_safesession.delegating_roles",
        "Login roles that switch role for each transaction.",
        "A comma-separated list of role names, such as PostgREST's "
        "authenticator. A session whose login role is one of these "
        "roles itself (not a member of one) is judged by the role "
        "it acts as, not by the login role's memberships.",
        &safesession_delegating_roles,
        "",
        PGC_SUSET,
        GUC_LIST_INPUT,
        check_delegating_roles,
        assign_safesession_roles,
        NULL);

    DefineCustomStringVariable(
        "pgedge_safesession.acting_read_only_roles",
        "Roles that are read-only when a delegating role acts as them.",
        "A comma-separated list of role names. When a session of one "
        "of pgedge_safesession.delegating_roles acts as one of these "
        "roles, or a member of one, it is restricted to read-only "
        "access. Other sessions of these roles are not affected.",
        &safesession_acting_read_only_roles,
        "",
        PGC_SUSET,
        GUC_LIST_INPUT,
        check_acting_read_only_roles,
        assign_safesession_roles,
        NULL);

    DefineCustomStringVariable(
        "pgedge_safesession.require_where_roles",
        "Login roles whose UPDATE and DELETE need a WHERE clause.",
        "A comma-separated list of role names. A session whose login "
        "role is one of these roles, or a member of one that can act "
        "as it, has an UPDATE or DELETE with no WHERE clause refused, "
        "as pg-safeupdate does, also inside WITH queries and "
        "functions.",
        &safesession_require_where_roles,
        "",
        PGC_SUSET,
        GUC_LIST_INPUT,
        check_require_where_roles,
        assign_safesession_roles,
        NULL);

    DefineCustomStringVariable(
        "pgedge_safesession.locked_setting_prefixes",
        "Setting prefixes held after a delegating role's role switch.",
        "A comma-separated list of prefixes, such as request. Once a "
        "delegating role has switched role in a transaction, the "
        "settings the session already has under these prefixes cannot "
        "change until the transaction ends.",
        &safesession_locked_setting_prefixes,
        "request",
        PGC_SUSET,
        GUC_LIST_INPUT,
        check_locked_setting_prefixes,
        assign_locked_setting_prefixes,
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

    /* Nesting, and the hold once the switch statement has run */
    prev_ExecutorRun = ExecutorRun_hook;
    ExecutorRun_hook = safesession_ExecutorRun;
    prev_ExecutorFinish = ExecutorFinish_hook;
    ExecutorFinish_hook = safesession_ExecutorFinish;

    /* Install ExecutorEnd hook (look again after a role switch) */
    prev_ExecutorEnd = ExecutorEnd_hook;
    ExecutorEnd_hook = safesession_ExecutorEnd;

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
    CacheRegisterSyscacheCallback(DATABASEOID, invalidate_database_owner,
                                  (Datum) 0);
    CacheRegisterSyscacheCallback(PROCOID, invalidate_set_clauses,
                                  (Datum) 0);

    /* The role lock; see role_change_allowed() */
    RegisterSubXactCallback(safesession_subxact_callback, NULL);
    prev_fmgr_hook = fmgr_hook;
    fmgr_hook = safesession_fmgr_hook;
    {
        struct config_string *conf = core_string_setting("role");

        prev_role_check = conf->check_hook;
        conf->check_hook = safesession_check_role;
        prev_role_assign = conf->assign_hook;
        conf->assign_hook = safesession_assign_role;
        conf = core_string_setting("session_authorization");
        prev_sessauth_check = conf->check_hook;
        conf->check_hook = safesession_check_sessauth;
        prev_sessauth_assign = conf->assign_hook;
        conf->assign_hook = safesession_assign_sessauth;
    }

    RegisterXactCallback(safesession_xact_callback, NULL);

    refuse_unknown_settings();

#if PG_VERSION_NUM >= 150000
    MarkGUCPrefixReserved("pgedge_safesession");
#else
    EmitWarningsOnPlaceholders("pgedge_safesession");
#endif
}
