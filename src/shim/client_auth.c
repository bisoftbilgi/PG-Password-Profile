#include "postgres.h"
#include "libpq/auth.h"
#include "libpq/hba.h"
#include "utils/elog.h"
#include "utils/errcodes.h"
#include "miscadmin.h"
#include "catalog/pg_authid.h"
#include "utils/syscache.h"
#include "utils/builtins.h"

const char *password_profile_port_username(Port *port) {
    if (port == NULL || port->user_name == NULL) {
        return NULL;
    }
    return port->user_name;
}

/*
 * Check if the user exists in pg_authid.
 * Returns 1 if user exists, 0 if not, -1 on error.
 * 
 * This allows us to distinguish:
 * - Password wrong for existing user (track it)
 * - User does not exist (don't track it)
 */
int password_profile_user_exists(const char *username) {
    if (username == NULL || username[0] == '\0') {
        return -1;
    }
    
    /* Check in pg_authid (requires reading catalog) */
    HeapTuple roleTup;
    
    roleTup = SearchSysCache1(AUTHNAME, CStringGetDatum(username));
    if (HeapTupleIsValid(roleTup)) {
        ReleaseSysCache(roleTup);
        return 1; /* User exists */
    }
    
    return 0; /* User does not exist */
}

/*
 * Predict the SQLSTATE that auth_failed() would emit for the given
 * authentication status. This mirrors auth_failed()'s errcode logic so
 * extensions can distinguish password errors (28P01) from other failures.
 */
int password_profile_get_last_sqlstate(Port *port, int status) {
    if (port == NULL || port->hba == NULL) {
        return ERRCODE_INTERNAL_ERROR;
    }

    if (status == STATUS_OK) {
        return ERRCODE_SUCCESSFUL_COMPLETION;
    }

    if (status == STATUS_EOF) {
        return ERRCODE_CONNECTION_FAILURE;
    }

    switch (port->hba->auth_method) {
        case uaPassword:
        case uaMD5:
        case uaSCRAM:
            return ERRCODE_INVALID_PASSWORD;
        case uaCert:
        case uaReject:
        case uaImplicitReject:
        case uaTrust:
        case uaIdent:
        case uaPeer:
        case uaGSS:
        case uaSSPI:
        case uaPAM:
        case uaBSD:
        case uaLDAP:
        case uaRADIUS:
        default:
            return ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION;
    }
}

ClientAuthentication_hook_type password_profile_register_client_auth_hook(
    ClientAuthentication_hook_type hook
) {
    ClientAuthentication_hook_type previous = ClientAuthentication_hook;
    ClientAuthentication_hook = hook;
    return previous;
}

/*
 * Refuse a connection because password_profile detected structural corruption
 * in the authentication-event queue. Capacity pressure alone does not use this
 * path: an overflowed queue remains drainable and recovers when empty.
 *
 * Called from the ClientAuthentication hook only after the previous hook has
 * already run and only when PostgreSQL's own authentication SUCCEEDED: an
 * incorrect password is still rejected by PostgreSQL itself, never by this.
 *
 * FATAL terminates only this backend (PostgreSQL calls proc_exit() after
 * reporting), never the postmaster. Deliberately takes no arguments so no
 * username, cache content or internal state can leak into the message.
 */
static const char *safe_auth_username(const char *username) {
    return (username && username[0] != '\0') ? username : "unknown";
}

/*
 * Deliberately removed: password_profile_raise_unavailable_error().
 *
 * It refused an otherwise valid login whenever the extension's own journal,
 * queue or worker was unavailable, which turned an extension-internal failure
 * into a cluster-wide login outage -- including for a superuser's local
 * "trust" connection, and including the connection needed to run the
 * documented recovery function. Internal unavailability now pauses this
 * extension's enforcement instead; PostgreSQL's own authentication result is
 * never overridden by it. Only the two policy rejections below remain.
 */

/*
 * Refuse a connection because the role's password has expired and no grace
 * logins remain.
 *
 * Called from the ClientAuthentication hook only after PostgreSQL's own
 * authentication SUCCEEDED and after every LWLock has been released. FATAL
 * terminates only this backend (PostgreSQL calls proc_exit() after reporting),
 * never the postmaster. Takes no arguments so no username, expiry timestamp or
 * grace count can leak into the message.
 */
void password_profile_raise_expired_error(const char *username) {
    ereport(FATAL,
            (errcode(ERRCODE_INVALID_PASSWORD),
             errmsg("password authentication failed for user \"%s\"",
                    safe_auth_username(username)),
             errdetail_log("password_profile rejected an otherwise valid login because the password is expired and no grace logins remain")));
}

void password_profile_raise_lockout_error(const char *username, int remaining_seconds) {
    ereport(FATAL,
            (errcode(ERRCODE_INVALID_PASSWORD),
             errmsg("password authentication failed for user \"%s\"",
                    safe_auth_username(username)),
             errdetail_log("password_profile rejected an otherwise valid login because the account is locked for another %d second(s)",
                           remaining_seconds)));
}

/*
 * Password-hook audit messages must not inherit the current CREATE/ALTER ROLE
 * statement: it can contain a plaintext password.  Keep the useful username
 * and outcome, but explicitly suppress the statement for both accepted and
 * rejected validations.
 */
void password_profile_log_password_validation(const char *username,
                                                const char *reason,
                                                bool accepted) {
    const char *safe_reason = (reason && reason[0] != '\0')
        ? reason
        : "password policy validation failed";

    if (accepted) {
        ereport(LOG,
                (errmsg("[PASSWORD_PROFILE][VALIDATED][user=%s] Password meets all complexity requirements",
                        safe_auth_username(username)),
                 errhidestmt(true)));
    } else {
        ereport(WARNING,
                (errmsg("[PASSWORD_PROFILE][REJECTED][user=%s] %s",
                        safe_auth_username(username), safe_reason),
                 errhidestmt(true)));
    }
}

/*
 * Reject CREATE/ALTER ROLE password changes without letting PostgreSQL attach
 * the SQL statement to the ERROR.  The statement can contain the plaintext
 * password, so every password-hook rejection must go through this helper.
 */
void password_profile_raise_password_change_error(const char *reason) {
    const char *safe_reason = (reason && reason[0] != '\0')
        ? reason
        : "password policy validation failed";

    ereport(ERROR,
            (errcode(ERRCODE_INVALID_PASSWORD),
             errmsg("password change rejected by password_profile"),
             errdetail("%s", safe_reason),
             errhidestmt(true)));
}
