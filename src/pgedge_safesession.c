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

/* Function declarations */
void _PG_init(void);

/*
 * Check if a function OID refers to a blocked C-language
 * function.
 *
 * When block_all_c_functions is false (default), only
 * VOLATILE C functions are blocked. IMMUTABLE and STABLE
 * C functions (e.g., PostGIS geometry ops, pgvector distance
 * ops) are allowed since they promise no side effects.
 *
 * When block_all_c_functions is true, all C-language
 * functions are blocked regardless of volatility.
 */
static bool
is_c_language_function(Oid funcid)
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
 * Recursively walk an expression tree looking for C-language
 * function calls.
 */
static bool
contains_c_function_walker(Node *node, void *context)
{
    if (node == NULL)
        return false;

    if (IsA(node, FuncExpr))
    {
        FuncExpr *fexpr = (FuncExpr *) node;
        if (is_c_language_function(fexpr->funcid))
            return true;
    }
    else if (IsA(node, OpExpr))
    {
        OpExpr *opexpr = (OpExpr *) node;
        if (is_c_language_function(opexpr->opfuncid))
            return true;
    }

    return expression_tree_walker(node,
                                  contains_c_function_walker,
                                  context);
}

/*
 * Recursively walk a Plan tree checking all nodes for
 * C-language function calls. Unlike just checking the
 * top-level targetlist/qual, this visits every plan node
 * including join conditions, hash clauses, index quals,
 * sort expressions, etc.
 */
static bool
plan_walker_check_c_functions(Plan *plan)
{
    ListCell *lc;

    if (plan == NULL)
        return false;

    /* Check this node's targetlist and qual */
    if (expression_tree_walker(
            (Node *) plan->targetlist,
            contains_c_function_walker, NULL))
        return true;

    if (expression_tree_walker(
            (Node *) plan->qual,
            contains_c_function_walker, NULL))
        return true;

    /* Check initPlan expressions */
    if (expression_tree_walker(
            (Node *) plan->initPlan,
            contains_c_function_walker, NULL))
        return true;

    /* Recurse into child plan nodes */
    if (plan_walker_check_c_functions(
            innerPlan(plan)))
        return true;

    if (plan_walker_check_c_functions(
            outerPlan(plan)))
        return true;

    /* Check any additional plans in Append, MergeAppend, etc. */
    if (IsA(plan, Append))
    {
        foreach(lc, ((Append *) plan)->appendplans)
        {
            if (plan_walker_check_c_functions(
                    (Plan *) lfirst(lc)))
                return true;
        }
    }
    else if (IsA(plan, MergeAppend))
    {
        foreach(lc, ((MergeAppend *) plan)->mergeplans)
        {
            if (plan_walker_check_c_functions(
                    (Plan *) lfirst(lc)))
                return true;
        }
    }
    else if (IsA(plan, SubqueryScan))
    {
        if (plan_walker_check_c_functions(
                ((SubqueryScan *) plan)->subplan))
            return true;
    }

    return false;
}

/*
 * Check if a planned statement contains calls to C-language
 * functions anywhere in the plan tree or subplans.
 */
static bool
plan_contains_c_functions(PlannedStmt *pstmt)
{
    ListCell *lc;

    if (plan_walker_check_c_functions(pstmt->planTree))
        return true;

    /* Check all subplans (CTEs, SubLinks, etc.) */
    foreach(lc, pstmt->subplans)
    {
        if (plan_walker_check_c_functions(
                (Plan *) lfirst(lc)))
            return true;
    }

    return false;
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
 * ExecutorStart hook: block DML and C-language functions
 * for restricted roles.
 */
static void
safesession_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
    bool restricted = current_role_is_restricted();

    /* Belt-and-suspenders: manage read-only state */
    if (safesession_force_read_only)
        manage_read_only_state(restricted);

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
        }

        /* Block C-language function calls */
        if (safesession_block_c_functions &&
            plan_contains_c_functions(pstmt))
            ereport(ERROR,
                    (errcode(
                        ERRCODE_READ_ONLY_SQL_TRANSACTION),
                     errmsg("cannot execute C language"
                            " functions in a"
                            " read-only session")));
    }

    /* Chain to previous hook or standard function */
    if (prev_ExecutorStart)
        prev_ExecutorStart(queryDesc, eflags);
    else
        standard_ExecutorStart(queryDesc, eflags);
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
                 */
                if (intVal(opt->arg) == 0)
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
    bool  restricted = current_role_is_restricted();

    /* Belt-and-suspenders: manage read-only state */
    if (safesession_force_read_only)
        manage_read_only_state(restricted);

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
             * - EXPLAIN (does not execute writes)
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
            case T_ExplainStmt:
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

#if PG_VERSION_NUM >= 150000
    MarkGUCPrefixReserved("pgedge_safesession");
#else
    EmitWarningsOnPlaceholders("pgedge_safesession");
#endif
}
