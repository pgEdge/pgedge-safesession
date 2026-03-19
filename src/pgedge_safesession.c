/*-------------------------------------------------------------------------
 *
 * pgedge_safesession.c
 *      Enforce read-only sessions for specified PostgreSQL roles.
 *
 * Copyright (c) 2025, pgEdge, Inc.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

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

/* GUC variable */
static char *safesession_roles = NULL;

/* Track whether we've set default_transaction_read_only */
static bool read_only_guc_set = false;

/* Saved hook values */
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/* Function declarations */
void _PG_init(void);

/*
 * Check if a function OID refers to a C-language function.
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
    result = (procform->prolang == ClanguageId);

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
 * Check if a plan tree contains calls to C-language functions.
 */
static bool
plan_contains_c_functions(PlannedStmt *pstmt)
{
    ListCell *lc;

    if (pstmt->planTree == NULL)
        return false;

    /* Check target list */
    if (expression_tree_walker(
            (Node *) pstmt->planTree->targetlist,
            contains_c_function_walker, NULL))
        return true;

    /* Check qual */
    if (expression_tree_walker(
            (Node *) pstmt->planTree->qual,
            contains_c_function_walker, NULL))
        return true;

    /* Check all subplans */
    foreach(lc, pstmt->subplans)
    {
        Plan *subplan = (Plan *) lfirst(lc);
        if (subplan == NULL)
            continue;
        if (expression_tree_walker(
                (Node *) subplan->targetlist,
                contains_c_function_walker, NULL))
            return true;
        if (expression_tree_walker(
                (Node *) subplan->qual,
                contains_c_function_walker, NULL))
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
 * Belt-and-suspenders: manage default_transaction_read_only.
 *
 * Sets it ON when the session becomes restricted, and OFF when
 * the session is no longer restricted (e.g., after RESET SESSION
 * AUTHORIZATION). This ensures that even if something bypasses
 * our hooks, PostgreSQL's own read-only checks will catch it.
 */
static void
manage_read_only_guc(bool is_restricted)
{
    if (is_restricted && !read_only_guc_set)
    {
        SetConfigOption("default_transaction_read_only", "on",
                        PGC_USERSET, PGC_S_SESSION);
        read_only_guc_set = true;
    }
    else if (!is_restricted && read_only_guc_set)
    {
        SetConfigOption("default_transaction_read_only", "off",
                        PGC_USERSET, PGC_S_SESSION);
        read_only_guc_set = false;
    }
}

/*
 * ExecutorStart hook: block DML for restricted roles.
 */
static void
safesession_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
    bool restricted = current_role_is_restricted();

    /* Belt-and-suspenders: manage read-only GUC */
    manage_read_only_guc(restricted);

    if (restricted)
    {
        PlannedStmt *pstmt = queryDesc->plannedstmt;

        /* Block INSERT, UPDATE, DELETE */
        switch (pstmt->commandType)
        {
            case CMD_INSERT:
            case CMD_UPDATE:
            case CMD_DELETE:
                ereport(ERROR,
                        (errcode(
                            ERRCODE_READ_ONLY_SQL_TRANSACTION),
                         errmsg("cannot execute %s in a"
                                " read-only session",
                                pstmt->commandType == CMD_INSERT ?
                                "INSERT" :
                                pstmt->commandType == CMD_UPDATE ?
                                "UPDATE" : "DELETE")));
                break;

            case CMD_SELECT:
                /* Block C-language function calls */
                if (plan_contains_c_functions(pstmt))
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot execute C language"
                                    " functions in a"
                                    " read-only session")));
                break;

            default:
                /* Block C-language function calls */
                if (plan_contains_c_functions(pstmt))
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot execute C language"
                                    " functions in a"
                                    " read-only session")));
                break;
        }
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
            (pg_strcasecmp(stmt->name,
                           "default_transaction_read_only") == 0 ||
             pg_strcasecmp(stmt->name,
                           "transaction_read_only") == 0))
            return true;
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

    /* Belt-and-suspenders: manage read-only GUC */
    manage_read_only_guc(restricted);

    if (restricted && parsetree != NULL)
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
             * - SET/RESET (except protected GUCs)
             * - SHOW
             * - LISTEN/NOTIFY/UNLISTEN
             * - DECLARE/FETCH/CLOSE cursor
             * - CHECKPOINT (read-only operation)
             * - COPY TO (read-only)
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
                /* Allow COPY TO, block COPY FROM */
                if (((CopyStmt *) parsetree)->is_from)
                    ereport(ERROR,
                            (errcode(
                                ERRCODE_READ_ONLY_SQL_TRANSACTION),
                             errmsg("cannot execute COPY FROM"
                                    " in a read-only"
                                    " session")));
                break;

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
    /* Define the GUC */
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
