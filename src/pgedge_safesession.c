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

#include "access/transam.h"
#include "access/xact.h"
#include "catalog/pg_aggregate.h"
#include "catalog/pg_language.h"
#include "catalog/pg_proc.h"
#include "commands/copy.h"
#include "commands/defrem.h"
#include "executor/executor.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/nodes.h"
#include "nodes/parsenodes.h"
#include "nodes/plannodes.h"
#include "parser/analyze.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
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

/* Function declarations */
void _PG_init(void);

/*
 * A curated list of side-effecting built-in (pg_catalog) functions.
 *
 * These are language-internal, so they are not caught by the
 * volatile-user-function rule in function_is_blocked(), but a restricted
 * session must not be able to call them: they write (sequences, large
 * objects), read from the filesystem, change configuration, signal other
 * backends, drive replication or take cross-session locks. The list is
 * matched by name against built-in functions only. It is deliberately
 * conservative rather than exhaustive; most of these are also
 * superuser-gated by default, so this is largely defence in depth (the
 * exceptions, such as the advisory-lock and sequence functions, are
 * executable by ordinary roles).
 */
static const char *const dangerous_builtins[] = {
    "lo_export",
    "lo_import",
    "nextval",
    "pg_advisory_lock",
    "pg_advisory_lock_shared",
    "pg_advisory_unlock",
    "pg_advisory_unlock_all",
    "pg_advisory_unlock_shared",
    "pg_advisory_xact_lock",
    "pg_advisory_xact_lock_shared",
    "pg_backup_start",
    "pg_backup_stop",
    "pg_cancel_backend",
    "pg_create_logical_replication_slot",
    "pg_create_physical_replication_slot",
    "pg_create_restore_point",
    "pg_drop_replication_slot",
    "pg_logical_emit_message",
    "pg_ls_dir",
    "pg_promote",
    "pg_read_binary_file",
    "pg_read_file",
    "pg_reload_conf",
    "pg_replication_origin_advance",
    "pg_replication_origin_session_setup",
    "pg_stat_file",
    "pg_stat_reset",
    "pg_stat_reset_shared",
    "pg_switch_wal",
    "pg_terminate_backend",
    "pg_try_advisory_lock",
    "pg_try_advisory_lock_shared",
    "pg_try_advisory_xact_lock",
    "pg_try_advisory_xact_lock_shared",
    "set_config",
    "setval",
};

static bool
name_is_dangerous_builtin(const char *proname)
{
    int i;

    for (i = 0; i < lengthof(dangerous_builtins); i++)
    {
        if (strcmp(proname, dangerous_builtins[i]) == 0)
            return true;
    }
    return false;
}

static bool function_is_blocked(Oid funcid, void *context);

/*
 * Is this function's language "trusted", i.e. does its body run its work
 * as SQL through the executor?
 *
 * SQL and the trusted procedural languages (PL/pgSQL, trusted PL/Perl,
 * ...) all have lanpltrusted set. Any write they perform, and any
 * dangerous function they call in turn, is caught downstream by the
 * executor hook and by this same post_parse_analyze check running again
 * on their inner statements, so their calls need not be blocked up front.
 * C, internal and untrusted PLs (plpython3u, plperlu, ...) can act
 * natively, outside anything we can observe, and are treated as
 * potentially side-effecting.
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
 *   - one of a curated set of side-effecting built-ins (see
 *     dangerous_builtins), which are language-internal and so would not
 *     be flagged by the rule above.
 *
 * Harmless volatile built-ins such as random() and clock_timestamp() are
 * deliberately allowed. Separately, when block_all_c_functions is set,
 * every C-language function is blocked regardless of volatility.
 *
 * The signature matches check_function_callback so this can be handed to
 * check_functions_in_node().
 */
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
        result = name_is_dangerous_builtin(NameStr(proname));
    else
        result = (provolatile == PROVOLATILE_VOLATILE) &&
                 !language_is_trusted(prolang);

    /*
     * An aggregate's declared volatility need not reflect its support
     * functions, so also check those (see aggregate_support_is_blocked).
     */
    if (!result && prokind == PROKIND_AGGREGATE)
        result = aggregate_support_is_blocked(funcid);

    return result;
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
 * Check whether the current session role is restricted.
 *
 * Returns true if the session user or current user is listed in
 * pgedge_safesession.roles, or is a member of a listed role.
 *
 * Superuser exemption: if the SESSION user is a superuser, the
 * session is never restricted. We deliberately check the session
 * user (not the current user) so that SECURITY DEFINER functions
 * owned by superusers cannot bypass the restriction.
 */
static bool
current_role_is_restricted(void)
{
    char       *rawstring;
    List       *rolelist;
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

    current_userid = GetUserId();

    /* Parse the comma-delimited role list */
    rawstring = pstrdup(safesession_roles);
    if (!SplitIdentifierString(rawstring, ',', &rolelist))
    {
        pfree(rawstring);
        return false;
    }

    foreach(lc, rolelist)
    {
        char   *rolename = (char *) lfirst(lc);
        Oid     roleid;

        roleid = get_role_oid(rolename, true);
        if (!OidIsValid(roleid))
            continue;

        /* Check session user */
        if (session_userid == roleid ||
            is_member_of_role(session_userid, roleid))
        {
            pfree(rawstring);
            list_free(rolelist);
            return true;
        }

        /* Check current user (in case SET ROLE was used) */
        if (current_userid != session_userid &&
            (current_userid == roleid ||
             is_member_of_role(current_userid, roleid)))
        {
            pfree(rawstring);
            list_free(rolelist);
            return true;
        }
    }

    pfree(rawstring);
    list_free(rolelist);
    return false;
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
 * ExecutorStart hook: block DML (including data-modifying CTEs) for
 * restricted roles. Blocked function calls are handled earlier, in the
 * post_parse_analyze hook.
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
            switch (pstmt->commandType)
            {
                case CMD_INSERT:
                case CMD_UPDATE:
                case CMD_DELETE:
#if PG_VERSION_NUM >= 150000
                case CMD_MERGE:
#endif
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot execute %s in a"
                                    " read-only session",
                                    pstmt->commandType ==
                                    CMD_INSERT ?
                                    "INSERT" :
                                    pstmt->commandType ==
                                    CMD_UPDATE ?
                                    "UPDATE" :
                                    pstmt->commandType ==
                                    CMD_DELETE ?
                                    "DELETE" : "MERGE")));
                    break;

                default:
                    break;
            }

            /*
             * A data-modifying CTE, e.g.
             * WITH c AS (INSERT ... RETURNING ...) SELECT * FROM c,
             * writes even though the top-level command is a SELECT, so
             * the switch above does not catch it: the ModifyTable node
             * is buried in the plan tree. PlannedStmt.hasModifyingCTE
             * flags this directly.
             */
            if (pstmt->hasModifyingCTE)
                ereport(ERROR,
                        (errcode(
                            ERRCODE_READ_ONLY_SQL_TRANSACTION),
                         errmsg("cannot execute a data-modifying"
                                " WITH clause in a read-only"
                                " session")));
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
 */
static void
safesession_post_parse_analyze(ParseState *pstate, Query *query
#if PG_VERSION_NUM >= 140000
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
        ereport(ERROR,
                (errcode(
                    ERRCODE_READ_ONLY_SQL_TRANSACTION),
                 errmsg("cannot execute functions that may have"
                        " side effects in a read-only session")));
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
         * session default default_transaction_read_only are protected.
         * transaction_read_only is a plain PGC_USERSET GUC any user may
         * set, so without this a restricted role's SET would report
         * success even though enforcement re-asserts read-only on the
         * next statement.
         */
        if (stmt->name != NULL &&
            (pg_strcasecmp(stmt->name,
                           "default_transaction_read_only") == 0 ||
             pg_strcasecmp(stmt->name,
                           "transaction_read_only") == 0))
            return true;
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
 * ProcessUtility hook: block DDL and other write operations.
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
        ereport(ERROR,
                (errcode(ERRCODE_READ_ONLY_SQL_TRANSACTION),
                 errmsg("cannot execute EXPLAIN ANALYZE of a writing"
                        " statement in a read-only session")));

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
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot execute a DO block in an"
                                    " untrusted language in a"
                                    " read-only session")));
                break;

            case T_CallStmt:
                /*
                 * CALL is treated the same way as a DO block: a
                 * procedure in a trusted language is allowed, one in
                 * an untrusted language is rejected.
                 */
                if (!call_target_is_trusted((CallStmt *) parsetree))
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot CALL a procedure in an"
                                    " untrusted language in a"
                                    " read-only session")));
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
                        ereport(ERROR,
                                (errcode(
                                    ERRCODE_READ_ONLY_SQL_TRANSACTION),
                                 errmsg("cannot execute two-phase"
                                        " commit statements in a"
                                        " read-only session")));
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
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot modify read-only"
                                    " transaction settings"
                                    " in a read-only"
                                    " session")));
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
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot execute COPY FROM"
                                    " in a read-only"
                                    " session")));

                /* Block COPY TO PROGRAM */
                if (cstmt->is_program)
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot execute"
                                    " COPY TO PROGRAM"
                                    " in a read-only"
                                    " session")));
                break;
            }

            case T_LockStmt:
                /* Block exclusive locks */
                if (((LockStmt *) parsetree)->mode >
                    RowShareLock)
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot acquire exclusive"
                                    " locks in a"
                                    " read-only session")));
                break;

            /*
             * Block GRANT/REVOKE and privilege changes
             */
            case T_GrantStmt:
            case T_GrantRoleStmt:
            case T_AlterDefaultPrivilegesStmt:
            case T_AlterOwnerStmt:
                ereport(ERROR,
                        (errcode(
                            ERRCODE_READ_ONLY_SQL_TRANSACTION),
                         errmsg("cannot execute privilege"
                                " changes in a"
                                " read-only session")));
                break;

            /*
             * Block VACUUM and ANALYZE
             */
            case T_VacuumStmt:
                ereport(ERROR,
                        (errcode(
                            ERRCODE_READ_ONLY_SQL_TRANSACTION),
                         errmsg("cannot execute VACUUM/ANALYZE"
                                " in a read-only session")));
                break;

            /*
             * Block all other utility statements (DDL, etc.)
             * This is a whitelist approach: anything not
             * explicitly allowed above is blocked.
             */
            default:
                ereport(ERROR,
                        (errcode(
                            ERRCODE_READ_ONLY_SQL_TRANSACTION),
                         errmsg("cannot execute utility"
                                " commands in a"
                                " read-only session")));
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
    /* Define GUCs */
    DefineCustomStringVariable(
        "pgedge_safesession.roles",
        "Comma-separated list of roles that are restricted "
        "to read-only sessions.",
        NULL,
        &safesession_roles,
        "",
        PGC_SUSET,
        0,
        check_safesession_roles,
        NULL,
        NULL);

    DefineCustomBoolVariable(
        "pgedge_safesession.block_dml",
        "Block INSERT, UPDATE, DELETE, and MERGE for "
        "restricted roles.",
        NULL,
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
        NULL,
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
        "effects for restricted roles: volatile user or "
        "extension functions, plus a set of side-effecting "
        "built-ins.",
        NULL,
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
        "regardless of volatility. This can break read-only "
        "extension functions (e.g. PostGIS, pgvector). Only "
        "applies when block_c_functions is on.",
        NULL,
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

#if PG_VERSION_NUM >= 150000
    MarkGUCPrefixReserved("pgedge_safesession");
#else
    EmitWarningsOnPlaceholders("pgedge_safesession");
#endif
}
