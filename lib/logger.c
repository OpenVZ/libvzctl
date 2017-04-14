/*
 *  Copyright (c) 1999-2017, Parallels International GmbH
 *
 * This file is part of OpenVZ libraries. OpenVZ is free software; you can
 * redistribute it and/or modify it under the terms of the GNU Lesser General
 * Public License as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/> or write to Free Software Foundation,
 * 51 Franklin Street, Fifth Floor Boston, MA 02110, USA.
 *
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <stdio.h>
#include <ploop/libploop.h>

#include "logger.h"
#include "config.h"
#include "util.h"

/** Data structure for logging.
 */
struct log_param_t {
	FILE *fp;		/**< log file pointer. */
	int level;		/**< maximum logging level. */
	int enable;		/**< enable/disable logging. */
	int quiet;		/**< skip logging to stdout. */
	int verbose;		/**< Console verbosity. */
	char prog[32];		/**< program name. */
	ctid_t ctid;
};
static struct log_param_t _g_log = {
	NULL,
	-1,	/* error level */
	1,	/* disable */
	0,	/* quiet */
	-1,	/* verbose */
	"",
};

#define LOG_BUF_SIZE	8192

#ifdef __i386__
#include <pthread.h>

/* Workaround for non NPTL glibc
 * Private thread specific data */
static pthread_key_t buf_key;
static pthread_once_t buf_key_once = PTHREAD_ONCE_INIT;

static void buffer_destroy(void *buf)
{
	if (buf != NULL) free(buf);
}

static void buffer_key_alloc(void)
{
	pthread_key_create(&buf_key, buffer_destroy);
	pthread_setspecific(buf_key, calloc(1, LOG_BUF_SIZE));
}

static char *get_buffer(void)
{
	pthread_once(&buf_key_once, buffer_key_alloc);
	return pthread_getspecific(buf_key);
}
#else
/* Thread Local Storage */
static __thread char _g_log_buf[LOG_BUF_SIZE];

static char *get_buffer(void)
{
	return _g_log_buf;
}
#endif

static inline void get_date(char *buf, int len)
{
	struct tm *p_tm_time;
	time_t ptime;

	ptime = time(NULL);
	p_tm_time = localtime(&ptime);
	strftime(buf, len, "%Y-%m-%dT%T%z", p_tm_time);
}

static void logger_ap(int level, int err_no, int quiet, const char *format, va_list ap)
{
	char date[64];
	char buf[LOG_BUF_SIZE];
	char *err_buf;
	int r;
	int errno_tmp = errno;

	r = vsnprintf(buf, sizeof(buf), format, ap);
	if ((r < sizeof(buf) - 1) && err_no) {
		snprintf(buf + r, sizeof(buf) - r, ": %s",
			 strerror(err_no));
	}
	if (_g_log.enable) {
		if (!quiet && !_g_log.quiet && _g_log.verbose >= level) {
			fprintf((level < 0 ? stderr : stdout), "%s\n", buf);
			fflush(level < 0 ? stderr : stdout);
		}
		if (_g_log.fp != NULL && _g_log.level >= level) {
			get_date(date, sizeof(date));
			fprintf(_g_log.fp, "%s %s : ", date, _g_log.prog);
			if (!EMPTY_CTID(_g_log.ctid))
				fprintf(_g_log.fp, "CT %s : ", _g_log.ctid);
			fprintf(_g_log.fp, "%s\n", buf);
			fflush(_g_log.fp);
		}
	}
	if (level < 0 && (err_buf = get_buffer()) != NULL)
		strcpy(err_buf, buf); /* Preserve error */
	errno = errno_tmp;
}

void logger(int level, int err_no, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	logger_ap(level, err_no, 0, format, ap);
	va_end(ap);
}

void log_quiet(int level, int err_no, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	logger_ap(level, err_no, 1, format, ap);
	va_end(ap);
}

void vzctl2_log(int level, int err_no, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	logger_ap(level, err_no, 0, format, ap);
	va_end(ap);
}

int vzctl_err(int err, int eno, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	logger_ap(-1, eno, 0, format, ap);
	va_end(ap);

	return err;
}

const char *vzctl2_get_last_error(void)
{
	return get_buffer();
}

int vzctl2_set_log_file(const char *file)
{
	FILE *fp;

	if (_g_log.fp != NULL) {
		fclose(_g_log.fp);
		_g_log.fp = NULL;
	}
	if (file != NULL) {
		if ((fp = fopen(file, "a")) == NULL)
			return -1;
		_g_log.fp = fp;
	}

	ploop_set_log_file(file);
	return 0;
}

int vzctl2_get_log_fd(void)
{
	if (_g_log.fp == NULL)
		return -1;
	return fileno(_g_log.fp);
}

void vzctl_free_log(void)
{
	if (_g_log.fp  != NULL)
		fclose(_g_log.fp);
	memset(&_g_log, 0, sizeof(_g_log));
}

int vzctl2_set_log_level(int level)
{
	int tmp;

	tmp = _g_log.level;
	 _g_log.level = level;

	ploop_set_log_level(level);
	return tmp;
}

int vzctl2_set_log_enable(int enable)
{
	int tmp;

	tmp = _g_log.enable;
	_g_log.enable = enable;
	ploop_set_verbose_level(enable ? _g_log.level : PLOOP_LOG_NOCONSOLE);
	return tmp;
}

int vzctl2_set_log_quiet(int quiet)
{
	int tmp;

	tmp = _g_log.quiet;
	_g_log.quiet = quiet;
	ploop_set_verbose_level(PLOOP_LOG_NOCONSOLE);
	return tmp;
}

int vzctl2_get_log_quiet(void)
{
	return _g_log.quiet;
}

void vzctl2_set_ctx(const ctid_t ctid)
{
	SET_CTID(_g_log.ctid, ctid);
}

int vzctl2_set_log_verbose(int verbose)
{
	int tmp;

	tmp = _g_log.verbose;
	_g_log.verbose = (verbose < -1 ? -1 : verbose);

	ploop_set_verbose_level(verbose);

	return tmp;
}

int vzctl2_get_log_verbose(void)
{
	return _g_log.verbose;
}

int vzctl2_init_log(const char *progname)
{
	const struct vzctl_config *gconf;
	int enable = 1;
	int level = 0;
	int verbose = 0;
	const char *log_file = VZCTL_LOG_FILE;
	const char *val;

	if ((gconf = vzctl_global_conf()) != NULL) {
		if (vzctl2_conf_get_param(gconf, "LOGGING", &val) == 0 &&
		    val != NULL)
			if (!strcmp(val, "no"))
				enable = 0;
		if (vzctl2_conf_get_param(gconf, "LOGFILE", &val) == 0 &&
		    val != NULL)
			log_file = val;
		if (vzctl2_conf_get_param(gconf, "LOG_LEVEL", &val) == 0 &&
		    val != NULL)
			parse_int(val, &level);
		if (vzctl2_conf_get_param(gconf, "VERBOSE", &val) == 0 &&
		    val != NULL)
			parse_int(val, &verbose);
		else
			verbose = level;
	}
	vzctl_free_log();
	vzctl2_set_log_enable(enable);
	vzctl2_set_log_quiet(!enable);
	vzctl2_set_log_level(level);
	vzctl2_set_log_verbose(verbose);
	if (progname != NULL)
		snprintf(_g_log.prog, sizeof(_g_log.prog), progname);
	vzctl2_set_log_file(log_file);

	return 0;
}
