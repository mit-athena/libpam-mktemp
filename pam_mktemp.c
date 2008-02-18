/*
 * pam_mktemp.c
 * PAM session management functions for pam_mktemp.so
 *
 * Copyright © 2007 Tim Abbott <tabbott@mit.edu> and Anders Kaseorg
 * <andersk@mit.edu>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_misc.h>

#define MAXBUF 256

void mktemp_cleanup(pam_handle_t *pamh, void *data, int pam_end_status);

/* Initiate session management by creating temporary file. */
int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int i;
    int debug = 0;
    int pamret;
    int n;
    const char *user;
    struct passwd *pw;
    char mktemp_buf[MAXBUF];
    char envput[MAXBUF];
    const char *prefix = "/tmp/tempfile";
    const char *var = NULL;
    int fd;
    int dir = 0;

    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "debug") == 0)
	    debug = 1;
	else if (strncmp(argv[i], "prefix=", 7) == 0)
	    prefix = argv[i] + 7;
	else if (strncmp(argv[i], "var=", 4) == 0)
	    var = argv[i] + 4;
	else if (strcmp(argv[i], "dir") == 0)
	    dir = 1;
    }

    if (var == NULL) {
	syslog(LOG_ERR, "pam_mktemp: No variable to set");
	return PAM_SESSION_ERR;
    }
    if ((pamret = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_mktemp: pam_get_user: %s", pam_strerror(pamh, pamret));
	return PAM_SESSION_ERR;
    }
    errno = 0;
    pw = getpwnam(user);
    if (pw == NULL) {
	if (errno != 0)
	    syslog(LOG_ERR, "pam_mktemp: getpwnam: %m");
	else
	    syslog(LOG_ERR, "pam_mktemp: no such user: %s", user);
	return PAM_SESSION_ERR;
    }

    n = snprintf(mktemp_buf, MAXBUF, "%s-%d-XXXXXX", prefix, pw->pw_uid);
    if (n < 0 || n >= MAXBUF) {
	syslog(LOG_ERR, "pam_mktemp: snprintf failed");
	return PAM_SESSION_ERR;
    }
    if (dir) {
	if (mkdtemp(mktemp_buf) == NULL) {
	    syslog(LOG_ERR, "pam_mktemp: mkdtemp: %m");
	    return PAM_SESSION_ERR;
	}
    }
    else {
	fd = mkstemp(mktemp_buf);
	if (fd == -1) {
	    syslog(LOG_ERR, "pam_mktemp: mkstemp: %m");
	    return PAM_SESSION_ERR;
	}
	if (close(fd) != 0) {
	    syslog(LOG_ERR, "pam_mktemp: close: %m");
	    return PAM_SESSION_ERR;
	}
    }
    if (chown(mktemp_buf, pw->pw_uid, -1) != 0) {
	syslog(LOG_ERR, "pam_mktemp: chown: %m");
	return PAM_SESSION_ERR;
    }
    if (debug)
	syslog(LOG_DEBUG, "pam_mktemp: using temporary file %s", mktemp_buf);

    n = snprintf(envput, MAXBUF, "%s=%s", var, mktemp_buf);
    if (n < 0 || n >= MAXBUF) {
	syslog(LOG_ERR, "pam_mktemp: snprintf failed");
	return PAM_SESSION_ERR;
    }
    pamret = pam_putenv(pamh, envput);
    if (pamret != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_mktemp: pam_putenv: %s",
	       pam_strerror(pamh, pamret));
	return PAM_SESSION_ERR;
    }
    pamret = pam_set_data(pamh, var, mktemp_buf, mktemp_cleanup);
    if (pamret != PAM_SUCCESS) {
	syslog(LOG_ERR, "pam_mktemp: pam_set_data: %s",
	       pam_strerror(pamh, pamret));
	return PAM_SESSION_ERR;
    }
    return PAM_SUCCESS;
}

void
mktemp_cleanup(pam_handle_t *pamh, void *data, int pam_end_status)
{
    return;
}

/* Terminate session management by destroying old temporary file. */
int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int i;
    int debug = 0;
    const char *mktemp_buf;
    const char *var = NULL;

    for (i = 0; i < argc; i++) {
	if (strcmp(argv[i], "debug") == 0)
	    debug = 1;
	else if (strncmp(argv[i], "var=", 4) == 0)
	    var = argv[i] + 4;
    }

    if (var == NULL) {
	syslog(LOG_ERR, "pam_mktemp: Nothing to cleanup");
	return PAM_SESSION_ERR;
    }

    mktemp_buf = pam_getenv(pamh, var);
    if (mktemp_buf == NULL) {
	syslog(LOG_ERR, "pam_mktemp: cannot get %s environment variable",
	       var);
	return PAM_SESSION_ERR;
    }

    if (debug)
	syslog(LOG_DEBUG, "pam_mktemp: removing %s",
	       mktemp_buf);
    if (remove(mktemp_buf) != 0) {
	syslog(LOG_ERR, "pam_mktemp: remove(): %m");
	return PAM_SESSION_ERR;
    }

    return PAM_SUCCESS;
}

int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (flags == PAM_ESTABLISH_CRED)
	return pam_sm_open_session(pamh, flags, argc, argv);
    return PAM_SUCCESS;
}

int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

