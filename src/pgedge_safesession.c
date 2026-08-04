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

#include "access/xact.h"
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
static bool safesession_force_read_only = true;

/* Track whether we've set default_transaction_read_only */
static bool read_only_guc_set = false;

/* Saved hook values */
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;
static post_parse_analyze_hook_type prev_post_parse_analyze = NULL;

/* Function declarations */
void _PG_init(void);

/*
 * Policy: does this function OID refer to a function that a restricted
 * session must not be allowed to execute?
 *
 * When block_all_c_functions is false (default), only VOLATILE C
 * functions are blocked. IMMUTABLE and STABLE C functions (e.g., PostGIS
 * geometry ops, pgvector distance ops) are allowed since they promise no
 * side effects. When block_all_c_functions is true, all C-language
 * functions are blocked regardless of volatility.
 *
 * The signature matches check_function_callback so this can be handed to
 * check_functions_in_node().
 */
static bool
function_is_blocked(Oid funcid, void *context)
{
    HeapTuple    proctup;
    Form_pg_proc procform;
    bool         result = false;

    proctup = SearchSysCache1(PROCOID,
                              ObjectIdGetDatum(funcid));
    if (!HeapTupleIsValid(proctup))
        return false;

    procform = (Form_pg_proc) GETSTRUCT(proctup);

    if (procform->prolang == ClanguageId)
    {
        if (safesession_block_all_c_functions)
            result = true;
        else
            result = (procform->provolatile ==
                      PROVOLATILE_VOLATILE);
    }

    ReleaseSysCache(proctup);
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
        return query_tree_walker((Query *) node,
                                 query_has_blocked_function_walker,
                                 context, 0);

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
 * Belt-and-suspenders: enforce read-only at the transaction level.
 *
 * Sets both XactReadOnly (current transaction) and
 * default_transaction_read_only (future transactions) when the
 * session is restricted. Clears both when the session is no
 * longer restricted (e.g., after RESET SESSION AUTHORIZATION).
 *
 * This ensures that even if something bypasses our hooks,
 * PostgreSQL's own internal read-only checks will catch it.
 */
static void
manage_read_only_state(bool is_restricted)
{
    if (is_restricted && !read_only_guc_set)
    {
        XactReadOnly = true;
        SetConfigOption("default_transaction_read_only", "on",
                        PGC_USERSET, PGC_S_SESSION);
        read_only_guc_set = true;
    }
    else if (is_restricted && read_only_guc_set)
    {
        /*
         * Already set for the session, but ensure the
         * current transaction is also read-only (each new
         * transaction resets XactReadOnly from the GUC).
         */
        XactReadOnly = true;
    }
    else if (!is_restricted && read_only_guc_set)
    {
        XactReadOnly = false;
        SetConfigOption("default_transaction_read_only", "off",
                        PGC_USERSET, PGC_S_SESSION);
        read_only_guc_set = false;
    }
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

        /* Belt-and-suspenders: manage read-only state */
        if (safesession_force_read_only)
            manage_read_only_state(restricted);
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
#if PG_VERSION_NUM >= 150000
                               , JumbleState *jstate
#endif
                               )
{
    if (prev_post_parse_analyze)
        prev_post_parse_analyze(pstate, query
#if PG_VERSION_NUM >= 150000
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
        if (stmt->name != NULL &&
            pg_strcasecmp(stmt->name,
                          "default_transaction_read_only") == 0)
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

    /* RESET ALL would reset our protected GUCs */
    if (stmt->kind == VAR_RESET_ALL)
        return true;

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

        /* Belt-and-suspenders: manage read-only state */
        if (safesession_force_read_only)
            manage_read_only_state(restricted);
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
             * - CHECKPOINT (read-only operation)
             * - COPY TO (read-only, not PROGRAM)
             * - DO blocks (inner writes caught by
             *   ExecutorStart)
             */
            case T_TransactionStmt:
            case T_PrepareStmt:
            case T_ExecuteStmt:
            case T_DeallocateStmt:
            case T_DeclareCursorStmt:
            case T_FetchStmt:
            case T_ClosePortalStmt:
            case T_ListenStmt:
            case T_NotifyStmt:
            case T_UnlistenStmt:
            case T_CheckPointStmt:
            case T_DoStmt:
                /* These are allowed */
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
        NULL,
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
        "Block C-language function execution for "
        "restricted roles. By default only volatile "
        "C functions are blocked.",
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
        "Block all C-language functions regardless of "
        "volatility. When off, only volatile C functions "
        "are blocked. Only applies when block_c_functions "
        "is on.",
        NULL,
        &safesession_block_all_c_functions,
        false,
        PGC_SUSET,
        0,
        NULL,
        NULL,
        NULL);

    DefineCustomBoolVariable(
        "pgedge_safesession.force_read_only",
        "Set default_transaction_read_only and "
        "XactReadOnly for restricted sessions as "
        "belt-and-suspenders protection.",
        NULL,
        &safesession_force_read_only,
        true,
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
