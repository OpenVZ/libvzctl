/*
 *  Copyright (c) 1999-2015 Parallels IP Holdings GmbH
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
 * Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/sendfile.h>
#include <sys/mount.h>
#include <dirent.h>
#include <assert.h>
#include <limits.h>
#include <ploop/libploop.h>
#include <uuid/uuid.h>

#include <math.h>

#include <iconv.h>
#include <langinfo.h>
#include <locale.h>

#include "util.h"
#include "logger.h"
#include "list.h"
#include "veth.h"
#include "vztypes.h"
#include "vzerror.h"
#include "env.h"
#include "config.h"
#include "fs.h"
#include "cleanup.h"
#include "vz.h"
#include "image.h"
#include "disk.h"
#include "vztmpl.h"
#include "exec.h"

#ifndef NR_OPEN
#define NR_OPEN 1024
#endif

static char *envp_bash[] = {"HOME=/", "TERM=linux",
	"PATH=/bin:/sbin:/usr/bin:/usr/sbin:.", NULL};

void *xmalloc(size_t size)
{
        void *p;

        if ((p = malloc(size)) == NULL)
                logger(-1, 0, "Unable to allocate %llu bytes",
				(unsigned long long) size);
        return p;
}

void xfree(void *p)
{
        if (p != NULL) free(p);
}

int xstrdup(char **dst, const char *src)
{
	char *t;

	if (src == NULL || *dst == src)
		return 0;
	if ((t = strdup(src)) == NULL)
		return vzctl_err(VZCTL_E_NOMEM, ENOMEM, "xstrdup");
	if (*dst != NULL)
		free(*dst);
	*dst = t;
	return 0;
}

int vzctl2_get_env_conf_path(const ctid_t ctid, char *buf, int len)
{
	return snprintf(buf, len, VZ_ENV_CONF_DIR "%s.conf", ctid);
}

int get_env_conf_lockfile(struct vzctl_env_handle *h, char *buf, int len)
{
	return snprintf(buf, len, VZ_ENV_CONF_LOCK_DIR "%s.conf.lck", h->ctid);
}

int vzctl2_get_global_conf_path(char *buf, int len)
{
	return snprintf(buf, len, GLOBAL_CFG);
}

int vzctl2_get_env_conf_path_orig(struct vzctl_env_handle *h, char *buf, int len)
{
	struct vzctl_fs_param *fs = h->env_param->fs;

	if (fs->layout >= VZCTL_LAYOUT_4)
		return snprintf(buf, len, "%s/" VZCTL_VE_CONF, fs->ve_private);
	else
		return snprintf(buf, len, VZ_ENV_CONF_DIR "%s.conf", h->ctid);
}

int check_name(const char *name, const char *extra, int len)
{
	const unsigned char *p;

	if (name[0] == '\0' ||
	    strlen(name) > len)
	{
		return 0;
	}
	for (p = (const unsigned char *) name; *p != 0; p++) {
		if (*p < 127 &&
		    !isdigit(*p) &&
		    !isalpha(*p) &&
		    strchr(extra, *p) == NULL)
		{
			return 0;
		}
	}
	return 1;
}

int vzctl2_is_env_name_valid(const char *name)
{
	return check_name(name, " +-_.", NAME_MAX);
}

int vzctl2_is_networkid_valid(char const *name)
{
	return check_name(name, "#() -_.", 64);
}

int is_str_valid(const char *name)
{
	return check_name(name, "-_.", NAME_MAX);
}

int vzctl_is_str_valid(const char *name)
{
	return is_str_valid(name);
}

const char *vzctl_get_str(int id, struct vzctl_idstr_pair *map)
{
	struct vzctl_idstr_pair *p;

	for (p = map; p->str != NULL; p++) {
		if (p->id == id)
			return p->str;
	}
	return NULL;
}

int vzctl_unescapestr_eq(char *src, char *dst, int size)
{
	long val;
	char *tail;
	unsigned char *s, *d, *t, *ed;
	char buf[3];
	int i, cnt;

	s = (unsigned char *) src;
	d = (unsigned char *) dst;
	cnt = 0;
	ed = (unsigned char *) dst + size;
	while (*s != '\0') {
		cnt++;
		if (*s != '=') {
			*d++ = *s++;
		} else {
			t = s++; /*  skip '=' */
			for (i = 0; i < 2 && *s != '\0'; i++, s++)
				buf[i] = *s;
			buf[i] = 0;
			val = strtol(buf, &tail, 16);
			if (*tail != 0) {
				val = *t;
				s = t;
				s++;
			}
			if (d < ed)
				*d++ = (unsigned char)val;
		}
	}
	*d = 0;
	return cnt;
}

int vzctl_escapestr_eq(const char *src, char *dst, int size)
{
	char *s, *d, *ed;
	int cnt = 0;

#define EXTRA_CHAR	"-_."
	s = (char *) src;
	d = (char *) dst;
	ed = dst + size - 1;
	while (*s != '\0') {
		if (isdigit(*s) || isalpha(*s) ||
			strchr(EXTRA_CHAR, *s) != NULL || (unsigned char)*s >= 127)
		{
			if (d < ed)
				*d++ = *s;
			cnt++;
		} else {
			if (d < ed)
				d += snprintf(d, ed - d, "=%02X", *s);
			cnt += 3;
		}
		s++;
	}
	*d = 0;
	return cnt;
}

int set_description(char **dst, const char *desc)
{
	int len;
	char *buf;

	len = strlen(desc) * 3;
	buf = malloc(len + 1);
	if (buf == NULL)
		return VZCTL_E_NOMEM;

	vzctl_escapestr_eq(desc, buf, len);

	free(*dst);
	*dst = buf;

	return 0;
}

char *get_description(char *desc)
{
	char *dst;
	int len;

	len = strlen(desc);
	dst = malloc(len + 1);
	if (dst == NULL)
		return NULL;

	vzctl_unescapestr_eq(desc, dst, len);

	return dst;
}

char *unescapestr(char *src)
{
	char *p1, *p2;
	int fl;

	if (src == NULL)
		return NULL;
	p2 = src;
	p1 = p2;
	fl = 0;
	while (*p2) {
		if (*p2 == '\\' && !fl)	{
			fl = 1;
			p2++;
		} else {
			*p1 = *p2;
	                p1++; p2++;
			fl = 0;
		}
	}
	*p1 = 0;

	return src;
}
/*
 *   man bash
 *  ...a word beginning with # causes that word and all remaining characters on that line to be
 *  ignored.
 */
char *uncommentstr(char * str)
{
        char * p1;
        int inb1 = 0, inb2 = 0, inw = 1;

        for (p1 = str; *p1; p1++) {
                if (inb1 && (*p1 != '\''))
                        continue;

                if (inb2 && (*p1 != '"'))
                        continue;

                switch(*p1) {
                case '\'':
                        inb1 ^= 1;
                        inw = 0;
                        break;
                case '"':
                        inb2 ^= 1;
                        inw = 0;
                        break;
                case '#':
                        if( !inw )
                                break;
                        *p1 = 0;
                        return str;
                default:
                        if(isspace(*p1))
                                inw = 1;
                        else
                                inw = 0;
                        break;
                }
        }

        return str;
}

void strip_end(char *str)
{
	char *ep = str + strlen(str) - 1;

	while (ep >= str && (isspace(*ep) || *ep == '\n')) *ep-- = '\0';
}

char *parse_line(char *str, char *ltoken, int lsz)
{
	char *sp = str;
	char *ep, *p;
	int len;

	unescapestr(str);
	uncommentstr(str);
	while (*sp && isspace(*sp)) sp++;
	if (!*sp || *sp == '#')
		return NULL;

	strip_end(sp);

	ep = sp + strlen(sp) - 1;
	if (*ep == '"' || *ep == '\'')
		*ep = 0;
	if (!(p = strchr(sp, '=')))
		return NULL;
	len = p - sp;
	if (len >= lsz)
		return NULL;
	strncpy(ltoken, sp, len);
	ltoken[len] = 0;
	p++;
	if (*p == '"' || *p == '\'' )
		p++;

	return p;
}

/*
	1 - exist
	0 - does't exist
	-1 - error
*/
int stat_file(const char *file)
{
	struct stat st;

	if (stat(file, &st)) {
		if (errno != ENOENT) {
			logger(-1, errno, "unable to stat %s", file);
			return -1;
		}
		return 0;
	}
	return 1;
}

int make_dir(const char *path, int full)
{
	char buf[4096];
	const char *ps, *p;
	int len;

	if (path == NULL)
		return 0;

	if (access(path, F_OK) == 0)
		return 0;

	ps = path + 1;
	while ((p = strchr(ps, '/'))) {
		len = p - path + 1;
		snprintf(buf, len, "%s", path);
		ps = p + 1;
		if (!stat_file(buf)) {
			if (mkdir(buf, 0755) && errno != EEXIST)
				return vzctl_err(VZCTL_E_CREATE_DIR, errno,
					"Can't create directory %s", buf);
		}
	}
	if (!full)
		return 0;
	if (!stat_file(path)) {
		if (mkdir(path, 0755) && errno != EEXIST)
			return vzctl_err(VZCTL_E_CREATE_DIR, errno,
				"Can't create directory %s", path);
	}
	return 0;
}

int get_mul(char c, unsigned long long *n)
{
        *n = 1;
        switch (c) {
        case 'T':
        case 't':
                *n *= 1024;
        case 'G':
        case 'g':
                *n *= 1024;
        case 'M':
        case 'm':
                *n *= 1024;
        case 'K':
        case 'k':
                *n *= 1024;
        case 'B':
        case 'b':
                break;
        default:
                return -1;
        }
        return 0;
}

/* This function parses string in form xxx[GMKPB]
*/
static const char *parse_ul_sfx(const char *str, unsigned long long *val,
		int divisor, int def_divisor)
{
	unsigned long long n = 0;
	char *tail;
	long double v = 0;

	if (!str || !val)
		return NULL;
	if (!strncmp(str, STR_UNLIMITED, 9)) {
		*val = LONG_MAX;
		return str + 9;
	}
	errno = 0;
	*val = strtoull(str, &tail, 10);
	if (errno == ERANGE)
		return NULL;
	v = *val;
	if (*tail == '.') { /* Floating point */
		errno = 0;
		v = strtold(str, &tail);
		if (errno == ERANGE)
			return NULL;
		*val = (unsigned long long) v;
	}
	if (*tail != ':' && *tail != '\0') {
		if (!divisor)
			return NULL;
			
		if (get_mul(*tail, &n))
			return NULL;
		v = v * n / divisor;
		if (v > (long double) LONG_MAX)
			*val = LONG_MAX + 1UL; /* Overflow */
		else
			*val = (unsigned long long) v;
		++tail;
	} else
		*val /= def_divisor ?: 1;

	return tail;
}

/* This function parse string in form xxx[GMKPB]:yyy[GMKPB]
 * If :yyy is omitted, it is set to xxx.
 */
int parse_twoul_sfx(const char *str, struct vzctl_2UL_res *res,
		int divisor, int def_divisor)

{
	unsigned long long tmp;
	int ret = 0;

	if (!(str = parse_ul_sfx(str, &tmp, divisor, def_divisor)))
		goto err;

	if (tmp > LONG_MAX)
		tmp = LONG_MAX;

	res->b = tmp;
	if (*str == ':') {
		str = parse_ul_sfx(++str, &tmp, divisor, def_divisor);
		if (!str || *str != '\0')
			goto err;
		if (tmp > LONG_MAX)
			tmp = LONG_MAX;
		res->l = tmp;
	} else if (*str == '\0') {
		res->l = res->b;
	} else
		goto err;

	return ret;

err:
	return vzctl_err(VZCTL_E_INVAL, 0, "An incorrect value: %s", str);;
}

int parse_int(const char *str, int *val)
{
	char *tail;
	long int n;

	if (*str == '\0')
		return 1;

	errno = 0;
	n = strtol(str, (char **)&tail, 10);
	if (*tail != '\0' || errno == ERANGE || n > INT_MAX)
		return 1;
	*val = (int)n;

	return 0;
}

int parse_ul(const char *str, unsigned long *val)
{
	char *tail;

	if (*str == '\0')
		return 1;

	errno = 0;
	*val = strtoul(str, (char **)&tail, 10);
	if (*tail != '\0' || errno == ERANGE)
		return 1;

	return 0;
}

void str_tolower(const char *from, char *to)
{
	if (from == NULL || to == NULL)
		return;
	while ((*to++ = tolower(*from++)));
}

void str_toupper(const char *from, char *to)
{
	if (from == NULL || to == NULL)
		return;
	while ((*to++ = toupper(*from++)));
}

int check_var(const void *val, const char *message)
{
	if (val != NULL)
		return 0;
	return vzctl_err(VZCTL_E_NO_PARAM, 0, "%s", message);
}

static int convert_str(const char *to, const char *from, const char *src,
	char *dst, int dst_size)
{
	iconv_t ic;
	char *inptr;
	char *wrptr;
	size_t insize, avail, nconv;
	int ret = 0;

	if (to == NULL || from == NULL)
		return 1;

	inptr = (char *)src;
	insize = strlen(src);
	avail = dst_size;
	ic = iconv_open(to, from);
	if (ic == (iconv_t) -1) {
		logger(3, errno, "Error in iconv_open()");
		return 1;
	}
	wrptr = dst;
	nconv = iconv(ic, &inptr, &insize, &wrptr, &avail);
	if (nconv == (size_t) -1) {
		logger(3, errno, "Error in iconv()");
		ret = 1;
	} else {
		iconv(ic, NULL, NULL, &wrptr, &avail);
		*wrptr = 0;
	}
	iconv_close(ic);
	return ret;
}

int vzctl2_convertstr(const char *src, char *dst, int dst_size)
{
	setlocale(LC_ALL, "");
	return convert_str(LOCALE_UTF8, nl_langinfo(CODESET), src, dst, dst_size);
}


int utf8tostr(const char *src, char *dst, int dst_size, const char *enc)
{
	char *old_locale = NULL;
	int ret;

	/* Get the name of the current locale. */
	if (enc != NULL)
		old_locale = strdup(setlocale(LC_ALL, NULL));
	else
		setlocale(LC_ALL, "");
	ret = convert_str(enc != NULL ? enc : nl_langinfo(CODESET), LOCALE_UTF8,
		src, dst, dst_size);

	/* Restore the original locale. */
	if (old_locale != NULL) {
		setlocale (LC_ALL, old_locale);
		free(old_locale);
	}
	return ret;
}

static int __cp_file(int fd_src, const char *src,
		int fd_dst, const char *dst)
{
	int ret;
	char buf[4096];

	while(1) {
		ret = read(fd_src, buf, sizeof(buf));
		if (ret == 0)
			break;
		else if (ret < 0) {
			logger(-1, errno, "Unable to read from %s", src);
			ret = -1;
			break;
		}
		if (write(fd_dst, buf, ret) < 0) {
			logger(-1, errno, "Unable to write to %s", dst);
			ret = -1;
			break;
		}
	}

	return ret;
}

int cp_file(const char *src, const char *dst)
{
	int fd_src, fd_dst, ret = 0;
	struct stat st;
	off_t off = 0;
	size_t n;

	logger(3, 0, "copy %s %s", src, dst);
	if (stat(src, &st) < 0)
		return vzctl_err(-1, errno, "Unable to find %s", src);

	if ((fd_src = open(src, O_RDONLY)) < 0)
		return vzctl_err(-1, errno, "Unable to open %s", src);

	if ((fd_dst = open(dst, O_CREAT| O_TRUNC |O_RDWR, st.st_mode)) < 0) {
		logger(-1, errno, "Unable to open %s", dst);
		close(fd_src);
		return -1;
	}
	n = sendfile(fd_dst, fd_src, &off, st.st_size);
	if (n == -1)
		ret = __cp_file(fd_src, src, fd_dst, dst);
	else if (n != st.st_size) {
		ret = vzctl_err(-1, 0, "Failed to write to %s:"
				" writen=%lu != total=%lu",
				dst, n, st.st_size);
	}
	if (ret) {
		close(fd_src);
		close(fd_dst);
		unlink(dst);
		return -1;
	}

	fsync(fd_dst);

	n = fchmod(fd_dst, st.st_mode);
	n = fchown(fd_dst, st.st_uid, st.st_gid);
	if (close(fd_dst))
		ret = vzctl_err(-1, errno, "Unable to close %s", dst);

	close(fd_src);

	return ret;
}

static char *arg2str(char *const arg[])
{
        char *const *p;
        char *str, *sp;
        int len = 0;

	if (arg == NULL)
		return NULL;
        p = arg;
        while (*p)
                len += strlen(*p++) + 1;
        if ((str = (char *)malloc(len + 1)) == NULL)
                return NULL;
        p = arg;
        sp = str;
        while (*p)
                sp += sprintf(sp, "%s ", *p++);

        return str;
}

void free_ar_str(char *ar[])
{
	char **p;

	for (p = ar; *p != NULL; p++) free(*p);
}

const char *find_ar_str(char *ar[], const char *str)
{
	for (; *ar != NULL; ar++)
		if (strcmp(*ar, str) == 0)
			return *ar;
	return NULL;
}

inline double max(double val1, double val2)
{
	return (val1 > val2) ? val1 : val2;
}

inline unsigned long max_ul(unsigned long val1, unsigned long val2)
{
	return (val1 > val2) ? val1 : val2;
}

inline unsigned long min_ul(unsigned long val1, unsigned long val2)
{
	return (val1 < val2) ? val1 : val2;
}

char *subst_VEID(const ctid_t ctid, const char *src)
{
	char *srcp;
	char str[PATH_MAX];
	char *sp, *se;
	int r, len, veidlen;

	if (src == NULL)
		return NULL;
#if 0
	/* Skip end '/' */
	se = src + strlen(src) - 1;
	while (se != str && *se == '/') {
		*se = 0;
		se--;
	}
#endif
	if ((srcp = strstr(src, "$VEID")))
		veidlen = sizeof("$VEID") - 1;
	else if ((srcp = strstr(src, "${VEID}")))
		veidlen = sizeof("${VEID}") - 1;
	else
		return strdup(src);

	sp = str;
	se = str + sizeof(str);
	len = srcp - src; /* Length of src before $VEID */
	if (len >= sizeof(str))
		return NULL;
	memcpy(str, src, len);
	sp += len;
	r = snprintf(sp, se - sp, "%s", ctid);
	sp += r;
	if ((r < 0) || (sp >= se))
		return NULL;
	if (*srcp) {
		r = snprintf(sp, se - sp, "%s", srcp + veidlen);
		sp += r;
		if ((r < 0) || (sp >= se))
			return NULL;
	}
	return strdup(str);
}

int set_not_blk(int fd)
{
	int oldfl;

	if ((oldfl = fcntl(fd, F_GETFL)) == -1)
		return -1;
	return fcntl(fd, F_SETFL, oldfl | O_NONBLOCK);
}

/*
 * Reset standart file descriptord to /dev/null in case they are closed.
 */
int reset_std(void)
{
	int ret, i, stdfd;

	stdfd = -1;
	for (i = 0; i < 3; i++) {
		ret = fcntl(i, F_GETFL);
		if (ret < 0 && errno == EBADF) {
			if (stdfd < 0) {
				if ((stdfd = open("/dev/null", O_RDWR)) < 0)
					return -1;
			}
			dup2(stdfd, i);
		}
	}
	return stdfd;
}

int yesno2id(const char *str)
{
	if (str == NULL)
		return -1;
	if (!strcmp(str, "yes"))
		return VZCTL_PARAM_ON;
	else if (!strcmp(str, "no"))
		 return VZCTL_PARAM_OFF;
	return -1;
}

const char *id2yesno(int id)
{
	switch (id) {
	case VZCTL_PARAM_ON:
		return "yes";
	case VZCTL_PARAM_OFF:
		return "no";
	}
	return NULL;
}

int onoff2id(const char *str)
{
	if (!strcmp(str, "on"))
		return VZCTL_PARAM_ON;
	else if (!strcmp(str, "off"))
		 return VZCTL_PARAM_OFF;
	return -1;
}

const char *id2onoff(int id)
{
	switch (id) {
	case VZCTL_PARAM_ON:
		return "on";
	case VZCTL_PARAM_OFF:
		return "off";
	}
	return NULL;
}

int str2env_type(const char *str)
{
	if (!strcmp(str, "regular"))
		return VZCTL_ENV_TYPE_REGULAR;
	else if (!strcmp(str, "temporary"))
		 return VZCTL_ENV_TYPE_TEMPORARY;
	else if (!strcmp(str, "template"))
		 return VZCTL_ENV_TYPE_TEMPLATE;

	return -1;
}

const char* env_type2str(int type)
{
	if (type == VZCTL_ENV_TYPE_REGULAR)
		return "regular";
	else if (type == VZCTL_ENV_TYPE_TEMPORARY)
		 return "temporary";
	else if (type == VZCTL_ENV_TYPE_TEMPLATE)
		 return "template";

	return NULL;
}

int check_ipv4(const char *ip)
{
	int cnt = 0;
	const char *p = ip;

	while (*p++ != '\0')
		if (*p == '.') cnt++;

	if (cnt != 3)
		return 0;
	return 1;
}

int make_sockaddr(int family, unsigned int *addr, struct sockaddr *sa)
{
	if (family == AF_INET) {
		struct sockaddr_in *a4 = (struct sockaddr_in *)sa;

		a4->sin_family = AF_INET;
		a4->sin_port = 0;
		a4->sin_addr.s_addr = addr[0];
	} else if (family == AF_INET6) {
		struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)sa;

		a6->sin6_family = AF_INET6;
		a6->sin6_port = 0;
		memcpy(&a6->sin6_addr, addr, 16);
	} else
		return -1;
	return 0;

}

int is_ip6(const char *ip)
{
	return (strchr(ip, ':') != NULL);
}

static int get_net_family(const char *ip)
{
	return is_ip6(ip) ? AF_INET6 : AF_INET;
}

int get_netaddr(const char *ip, unsigned int *addr)
{
	int family = get_net_family(ip);

	if (inet_pton(family, ip, addr) <= 0)
		return vzctl_err(-1, errno, "An incorrect ip address %s", ip);
	return family;
}

int parse_ip(const char *str, struct vzctl_ip_param **ip)
{
	int ret, len, family;
	char *maskstr;
	unsigned int addr[4];
	int mask = 0;
	char ipstr[128];

	*ip = NULL;

	if ((maskstr = strchr(str, '/')) != NULL) {
		maskstr++;
		len = maskstr - str;
	} else
		len = strlen(str) + 1;

	if (len > sizeof(ipstr))
		return vzctl_err(VZCTL_E_INVAL, 0 , "An incorrect ip address %s",
				str);

	snprintf(ipstr, len, "%s", str);

	family = get_netaddr(ipstr, addr);
	if (family == -1)
		return VZCTL_E_INVAL;

	/* convert to text representation */
	if (inet_ntop(family, addr, ipstr, sizeof(ipstr)-1) == NULL)
		return vzctl_err(VZCTL_E_INVAL, errno, "An incorrect ip address %s",
				str);

	if (maskstr != NULL) {
		if (check_ipv4(maskstr)) {
			if (get_netaddr(maskstr, addr) == -1)
				return VZCTL_E_INVAL;
			mask = addr[0];
		} else {
			ret = parse_int(maskstr, &mask);
			if (ret || mask > 128 || mask < 0)
				return vzctl_err(VZCTL_E_INVAL, 0,
						"An incorrect ip address mask: %s/%s",
						ipstr, maskstr);

			if (family == AF_INET)
				mask = htonl(~0 << (32 - mask));
		}
	}
	*ip = malloc(sizeof(struct vzctl_ip_param));
	if (*ip == NULL)
		return VZCTL_E_NOMEM;
	(*ip)->ip = strdup(ipstr);
	(*ip)->mask = mask;

	return 0;
}

int parse_ip_str(list_head_t *head, const char *val, int replace)
{
	int ret = 0;
	char *token;
	struct vzctl_ip_param *ip;
	char *str;
	char *savedptr;

	if (replace)
		free_str(head);

	str = strdup(val);
	if ((token = strtok_r(str, LIST_DELIMITERS, &savedptr)) != NULL) {
		do {
			if (!strcmp(token, "0.0.0.0") ||
					!strcmp(token, "::") ||
					!strcmp(token, "::0"))
			{
				continue;
			}
			if ((ret = parse_ip(token, &ip)))
				break;
			list_add_tail(&ip->list, head);
		} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)) != NULL);
	}
	free(str);
	return ret;
}

char *get_ip4_name(unsigned int ip)
{
	struct in_addr addr;

	addr.s_addr = ip;
	return inet_ntoa(addr);
}

int get_ip_name(const char *ipstr, char *buf, int size)
{
	unsigned int addr[4];
	int family;

	family = get_netaddr(ipstr, addr);
	if (family == -1)
		return -1;
	inet_ntop(family, addr, buf, size);

	return 0;
}

/* parse hwaddr in format:
00:18:51:51:EA:CF
00185151EACF
*/
int parse_hwaddr(const char *str, char *addr)
{
	int i;
	char buf[3];
	char *endptr;
	int step = 3;

	if (strlen(str) == 12)
		step = 2;

	for (i = 0; i < ETH_ALEN; i++) {
		buf[0] = str[step*i];
		buf[1] = str[step*i+1];
		buf[2] = '\0';
		addr[i] = strtol(buf, &endptr, 16);
		if (*endptr != '\0')
			return VZCTL_E_INVAL;
	}
	return 0;
}

char *hwaddr2str(char *hwaddr)
{
	char *str;
#define STR2MAC(dev)                    \
	((unsigned char *)dev)[0],      \
	((unsigned char *)dev)[1],      \
	((unsigned char *)dev)[2],      \
	((unsigned char *)dev)[3],      \
	((unsigned char *)dev)[4],      \
	((unsigned char *)dev)[5]

	str = (char *)malloc(18);
	sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
			STR2MAC(hwaddr));

	return str;
}

int set_hwaddr(const char *str, char **dst)
{
	int ret;
	char hwaddr[ETH_ALEN];

	ret = parse_hwaddr(str, hwaddr);
	if (ret)
		return ret;

	free(*dst);
	*dst = hwaddr2str(hwaddr);

	return 0;
}

#define MERGE_STR(x)                                            \
	if ((src->x) != NULL) {                                 \
		if ((dst->x) != NULL) free(dst->x);             \
		dst->x = strdup(src->x);                        \
	}

void vzctl_merge_conf_simple(struct vzctl_conf_simple *dst, struct vzctl_conf_simple *src)
{
	MERGE_STR(ve_root)
	MERGE_STR(ve_private)
	MERGE_STR(lockdir)
	MERGE_STR(dumpdir)
	MERGE_STR(name)
}

void vzctl_free_conf_simple(struct vzctl_conf_simple *conf)
{
	xfree(conf->ve_root);
	xfree(conf->ve_root_orig);
	xfree(conf->ve_private);
	xfree(conf->ve_private_orig);
	xfree(conf->lockdir);
	xfree(conf->dumpdir);
	xfree(conf->name);
	xfree(conf->veid);
}

int vzctl_parse_conf_simple(const ctid_t ctid, char *path,
	struct vzctl_conf_simple *conf)
{
	char ltoken[4096];
	char buf[4096];
	FILE *fp;
	int line = 0;
	char *rtoken;

	bzero(conf, sizeof(*conf));
	if ((fp = fopen(path, "r")) == NULL) {
		logger(-1, errno, "failed to open: %s", path);
		return -1;
	}
	while (fgets(buf, sizeof(buf), fp)) {
		line++;
		if ((rtoken = parse_line(buf, ltoken, sizeof(ltoken))) == NULL)
			continue;
		if (conf->ve_root == NULL &&
		    !strcmp("VE_ROOT", ltoken))
		{
			conf->ve_root_orig = strdup(rtoken);
			conf->ve_root = subst_VEID(ctid, rtoken);
		}
		else if (conf->ve_private == NULL &&
			!strcmp("VE_PRIVATE", ltoken))
		{
			conf->ve_private_orig = strdup(rtoken);
			conf->ve_private = subst_VEID(ctid, rtoken);
		}
		else if (conf->lockdir == NULL &&
			!strcmp("LOCKDIR", ltoken))
		{
			conf->lockdir = strdup(rtoken);
		}
		else if (conf->dumpdir == NULL &&
			!strcmp("DUMPDIR", ltoken))
		{
			conf->dumpdir = strdup(rtoken);
		}
		else if (conf->name == NULL &&
			!strcmp("NAME", ltoken))
		{
			conf->name = strdup(rtoken);
		}
		else if (conf->veid == NULL &&
			!strcmp("VEID", ltoken))
		{
			int veid;

			if (rtoken[0] == 0)
				continue;
			if (parse_int(rtoken, &veid) == 0) {
				conf->veid = malloc(sizeof(*conf->veid));
				*conf->veid = veid;
			}
		}
	}
	fclose(fp);
	return 0;
}

#if 0
/* Convert old Container to the 4.0 layout format:
 1) copy config/scripts under VE_PRIVATE
	1.a) VEID.conf -> VE_PRIVATE/ve.conf
	1.b) VEID.{mount/umount/start/stop} -> VE_PRIVATE/scripts
 2) create new root directory VE_PRIVATE/fs
 3) move VE_PRIVATE
	3.a) rename VE_PRIVATE/root -> VE_PRIVATE/fs/root
	3.b) rename VE_PRIVATE/cow -> VE_PRIVATE/fs/cow
	3.c) rename VE_PRIVATE/VERSION -> VE_PRIVATE/fs/VERSION
	3.d) rename VE_PRIVATE/templates -> VE_PRIVATE/fs/templates
 4) regiter Container
 5) upgrade VZFS version
*/
static int vzctl_env_convert_layout4(struct vzctl_env_handle *h)
{
	char buf[PATH_MAX];
	char buf2[PATH_MAX];
	char *path = h->env_param->fs->ve_private;
	int i, ret, online;
	struct stat st;
	ctid_t ctid = EID(h);
	char *dirs[] = {
		"root", "cow", "templates", ".vzpkgset", ".vzpkgver", "VERSION", NULL};
	char *action_scripts[] = {
		VZCTL_START_PREFIX, VZCTL_STOP_PREFIX,
		VZCTL_MOUNT_PREFIX, VZCTL_UMOUNT_PREFIX, NULL
	};
	struct vzctl_cpt_param cpt = {};
	struct vzctl_reg_param reg_param = {
		.veid = ctid,
	};

	if (path == NULL)
		return vzctl_err(-1, 0, "Container private area is not specified");

	if (h->conf->fname == NULL)
		return vzctl_err(-1, 0, "Container configuration file is not specified");

	if (lstat(h->conf->fname, &st) || !S_ISREG(st.st_mode))
		return vzctl_err(-1, 0, "Container configuration file %s is not a regular file",
			h->conf->fname);

	online = is_env_run(h);

	if (!online && vzctl2_env_is_mounted(h)) {
		ret = vzctl2_env_umount(h, 0);
		if (ret)
			goto err;
	}

	/* Create initial directory structure */
	if (vzctl2_create_env_private(path, VZCTL_LAYOUT_4))
		goto err;
	/* VEID.conf -> VE_PRIVATE/ve.conf */
	snprintf(buf2, sizeof(buf2), "%s/" VZCTL_VE_CONF, path);
	logger(3, 0, "Copy config: %s -> %s", h->conf->fname, buf2);
	ret = cp_file(h->conf->fname, buf2);
	if (ret) {
		logger(-1, 0, "Failed to copy: %s -> %s", h->conf->fname, buf2);
		goto err;
	}
	/* VEID.{mount/umount/start/stop} -> VE_PRIVATE/scripts */
	for (i = 0; action_scripts[i] != NULL; i++) {
		snprintf(buf, sizeof(buf), VZ_ENV_CONF_DIR "/%d.%s",
			ctid, action_scripts[i]);
		if (stat_file(buf) == 1) {
			snprintf(buf2, sizeof(buf2), "%s"VZCTL_VE_SCRIPTS_DIR"/%s",
					path, action_scripts[i]);
			logger(3, 0, "Copy action script: %s", action_scripts[i]);
			ret = cp_file(buf, buf2);
			if (ret) {
				logger(-1, 0, "Failed to copy %s", buf);
				goto err;
			}
		}
	}

	if (online) {
		ret = vzctl2_env_chkpnt(h, VZCTL_CMD_CHKPNT, &cpt, 0);
		if (ret)
			goto err;
	}

	/* /var/vzquota/quota.VEID -> VE_PRIVATE/quota.fs */
	snprintf(buf, sizeof(buf), "/var/vzquota/quota.%d", ctid);
	if (stat_file(buf) == 1) {
		snprintf(buf2, sizeof(buf2), "%s/quota.fs", path);
		logger(3, 0, "Copy quota file: %s", buf);
		ret = cp_file(buf, buf2);
		if (ret)
			logger(-1, 0, "Command failed: %s", buf);
	}

	/* VE_PRIVATE/{root,cow,VERSION} -> VE_PRIVATE/fs */
	for (i = 0; dirs[i] != NULL; i++) {
		snprintf(buf, sizeof(buf), "%s/%s", path, dirs[i]);
		snprintf(buf2, sizeof(buf), "%s" VZCTL_VE_FS_DIR "/%s",
			path, dirs[i]);
		logger(3, 0, "Moving %s -> %s", buf, buf2);
		if (rename(buf, buf2)) {
			if (errno != ENOENT)
				logger(-1, errno, "Failed to rename %s %s", buf, buf2);
			continue;
		}
		/* create compatibility link for templates */
		if (strcmp(dirs[i], "templates") == 0) {
			if (symlink("fs/templates", buf))
				logger(-1, errno, "Failed to create link %s", buf);
		}
	}

	if (vzctl2_env_register(path, &reg_param, VZ_REG_FORCE) == -1)
		return vzctl_err(-1, 0, "Container registration failed");

	h->env_param->fs->layout = VZCTL_LAYOUT_4;
	snprintf(buf, sizeof(buf), "%s", h->env_param->fs->ve_private);
	vzctl2_env_set_ve_private_path(h->env_param, buf);

	if (online) {
		cpt.cmd = VZCTL_CMD_RESTORE;
		vzctl2_env_restore(h, &cpt, 0);
	}

	/* Remove original action scripts */
	for (i = 0; action_scripts[i] != NULL; i++) {
		snprintf(buf, sizeof(buf), VZ_ENV_CONF_DIR "/%d.%s",
			ctid, action_scripts[i]);
		unlink(buf);
	}
	/* Remove quota file */
	snprintf(buf, sizeof(buf), "/var/vzquota/quota.%d", ctid);
	unlink(buf);
	logger(0, 0, "Container was successfully converted to the 4 layout");
	return 0;

err:

	snprintf(buf, sizeof(buf), "%s/" VZCTL_VE_LAYOUT, path);
	unlink(buf);
	return -1;
}
static int vzctl_env_convert_layout5(struct vzctl_env_handle *h)
{
	char *argv[10];
	int argc = 0;

	argv[argc++] = "/usr/sbin/vzmlocal";
	if (is_env_run(h))
		argv[argc++] = "--online";
	if (h->conf->fname) {
		argv[argc++] = "--config";
		argv[argc++] = h->conf->fname;
	}
	argv[argc++] = "--convert-vzfs";
	argv[argc++] = "--skiplock";

	argv[argc++] = EID(h);
	argv[argc++] = "--new-id";
	argv[argc++] = EID(h);
	argv[argc++] = NULL;


	return vzctl2_wrap_exec_script(argv, NULL, 0);
}

/* Convert CT to 5.0 layout
 * 1) mount CT
 * 2) create & mount image
 * 3) cp VE_ROOT -> image
 * 4) update ve_layout
 */
int vzctl2_env_convert_layout(struct vzctl_env_handle *h, int new_layout)
{
	int layout;
	int ret;
	struct vzctl_fs_param *fs = h->env_param->fs;

	if (new_layout < VZCTL_LAYOUT_4 || new_layout > VZCTL_LAYOUT_5)
		return vzctl_err(-1, 0, "Unable to convert to %d layout",
				new_layout);
	if (stat_file(fs->ve_private) != 1)
		return vzctl_err(-1, 0, "Container private area '%s' does not exist",
				fs->ve_private);

	layout = vzctl2_env_layout_version(fs->ve_private);
	if (layout == new_layout) {
		logger(0, 0, "Container has the %d layout already",
				new_layout);
		return 0;
	}

	if (layout < VZCTL_LAYOUT_4) {
		ret = vzctl_env_convert_layout4(h);
		if (ret)
			return ret;

		if (new_layout == VZCTL_LAYOUT_4)
			return 0;
	}

	return vzctl_env_convert_layout5(h);
}
#endif
int vzctl2_get_dump_file(struct vzctl_env_handle *h, char *buf, int size)
{
	int ret;
	const char *ve_private = h->env_param->fs->ve_private;

	if (vzctl2_env_layout_version(ve_private) < VZCTL_LAYOUT_4) {
		const struct vzctl_config *gconf;
		const char *dumpdir = NULL;

		pthread_mutex_lock(get_global_conf_mtx());
		gconf = vzctl_global_conf();
		if (!(gconf != NULL &&
		    vzctl2_conf_get_param(gconf, "DUMPDIR", &dumpdir) == 0 &&
		    dumpdir != NULL))
		{
			dumpdir = DEF_DUMPDIR;
		}
		pthread_mutex_unlock(get_global_conf_mtx());
		ret = snprintf(buf, size, "%s/" DEF_DUMPFILE, dumpdir, EID(h));
        } else {
		ret = snprintf(buf, size,
			"%s" VZCTL_VE_DUMP_DIR "/" VZCTL_VE_DUMP_FILE,
                        ve_private);
	}
	return ret;
}

int read_script(const char *fname, const char *include, char **buf)
{
	struct stat st;
	char *tmp, *p = NULL;
	int fd = -1, len = 0;
	char inc[PATH_LEN];

	if (!fname) {
		logger(-1, 0, "read_script: file name is not specified");
		return -1;
	}
	/* Read include file first */
	if (include != NULL) {
		if ((p = strrchr(fname, '/')) != NULL) {
			snprintf(inc, p - fname + 2, "%s", fname);
			strcat(inc, include);
		} else {
			snprintf(inc, sizeof(inc), "%s", include);
		}
		if (stat_file(inc))
			len = read_script(inc, NULL, buf);
		if (len < 0)
			return -1;
	}
	if (stat(fname, &st)) {
		logger(-1, 0, "file %s not found", fname);
		return -1;
	}
	if ((fd = open(fname, O_RDONLY)) < 0) {
		logger(-1, errno, "Unable to open %s", fname);
		goto err;
	}
	if (*buf != NULL) {
		tmp = realloc(*buf, st.st_size + len + 2);
		if (tmp == NULL)
			goto err;
		*buf = tmp;
		p = *buf + len;
	} else {
		*buf = malloc(st.st_size + 2);
		if (*buf == NULL)
			goto err;
		p = *buf;
	}
	if ((len = read(fd, p, st.st_size)) < 0) {
		logger(-1, errno, "Error reading %s", fname);
		goto err;
	}
	p += len;
	p[0] = '\n';
	p[1] = 0;
	close(fd);

	return len;
err:
	if (fd != -1)
		close(fd);
	if (*buf != NULL)
		free(*buf);
	return -1;
}

#define ENV_SIZE	256
int vzctl2_exec_script(char *const argv[], char *const env[], int flags)
{
	int child, fd, ret, i, j, retcode;
	char *cmd;
	char *envp[ENV_SIZE];
	struct vzctl_cleanup_hook *h;
	int out[2];

	if (strchr(argv[0], '/') && !stat_file(argv[0]))
		return vzctl_err(VZCTL_E_NOSCRIPT, 0,
			"run_script: executable %s not found", argv[0]);

	if (pipe(out))
		return vzctl_err(VZCTL_E_SYSTEM, errno, "Cannot create pipe");

	cmd = arg2str(argv);
	if (cmd != NULL) {
		logger(2, 0, "running: %s", cmd);
		free(cmd);
	}
	i = 0;
	if (env != NULL) {
		for (i = 0; i < ENV_SIZE - 1 && env[i] != NULL; i++)
			envp[i] = env[i];
	}
	for (j = 0; i < ENV_SIZE - 1 && envp_bash[j] != NULL; i++, j++)
		envp[i] = envp_bash[j];
	envp[i] = NULL;

	if ((child = fork()) == 0) {
		fd = open("/dev/null", O_WRONLY);
		dup2(fd, 0);
		if (flags & EXEC_QUIET) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
		} else {
			dup2(out[1], STDOUT_FILENO);
			dup2(out[1], STDERR_FILENO);
		}

		if (flags & EXEC_NOENV)
			execv(argv[0], argv);
		else
			execvep(argv[0], argv, envp);
		logger(-1, errno, "Error exec %s", argv[0]);
		_exit(1);
	} else if(child == -1) {
		logger(-1, errno, "Unable to fork");
		ret = VZCTL_E_FORK;
		goto err;
	}
	h = register_cleanup_hook(cleanup_kill_process, (void *) &child);
	close(out[1]);
	out[1] = -1;

	vzctl_stdredir(out[0], STDERR_FILENO, !(flags & EXEC_QUIET));

	ret = env_wait(child, 0, &retcode);
	unregister_cleanup_hook(h);
err:
	p_close(out);

	return ret ? ret : retcode;
}

void get_action_script_path(struct vzctl_env_handle *h, const char *name, char *out, int size)
{
	if (h->env_param->fs->layout >= VZCTL_LAYOUT_4 || h->env_param->fs->layout == 0)
		snprintf(out, size, "%s" VZCTL_VE_SCRIPTS_DIR "/%s",
				h->env_param->fs->ve_private, name);
	else
		snprintf(out, size, VZ_ENV_CONF_DIR"%s.%s", EID(h), name);
}

static void get_action_script(struct vzctl_env_handle *h, int action, int step,
		char *out, int size)
{
	int global = 1;
	const char *fname = NULL;

	switch(action) {
	case VZCTL_ACTION_MOUNT:
		global = step == 0 ? 1 : 0;
		fname = VZCTL_MOUNT_PREFIX;
		break;
	case VZCTL_ACTION_PRE_MOUNT:
		global = step == 0 ? 1 : 0;
		fname = VZCTL_PRE_MOUNT_PREFIX;
		break;
	case VZCTL_ACTION_UMOUNT:
		fname = VZCTL_UMOUNT_PREFIX;
		global = step == 0 ? 0 : 1;
		break;
	}

	if (global)
		snprintf(out, size, VZ_ENV_CONF_DIR"vps.%s", fname);
	else
		get_action_script_path(h, fname, out, size);
}

int run_action_scripts(struct vzctl_env_handle *h, int action)
{
	int i, ret = 0;
	char script[PATH_MAX];
	char s_id[STR_SIZE];
	char s_conf[STR_SIZE];
	char *argv[] = {script, NULL};
	char *env[] = {s_id, s_conf, NULL};

	snprintf(s_id, sizeof(s_id), "VEID=%s", EID(h));
	snprintf(s_conf, sizeof(s_conf), "VE_CONFFILE=%s%s.conf",
			VZ_ENV_CONF_DIR, EID(h));

	for (i = 0; i < 2; i++) {
		get_action_script(h, action, i, script, sizeof(script));
		if (stat_file(script) == 0)
			continue;
		ret = vzctl2_wrap_exec_script(argv, env, 0);
		if (ret && ret != VZCTL_E_SKIP_ACTION)
			return vzctl_err(VZCTL_E_ACTIONSCRIPT, 0,
				"Error on executing the mount script %s",
				script);
	}
	return ret;
}

#define MAX_WAIT_TIMEOUT	60 * 30
volatile sig_atomic_t alarm_flag;
static void alarm_handler(int sig)
{
	alarm_flag = 1;
}

int wait_on_fifo(void *data)
{
	int fd, buf, ret;
	struct sigaction act, actold;

	ret = 0;
	alarm_flag = 0;
	act.sa_flags = 0;
	act.sa_handler = alarm_handler;
	sigemptyset(&act.sa_mask);
	sigaction(SIGALRM, &act, &actold);

	alarm(MAX_WAIT_TIMEOUT);
	fd = open(VZFIFO_FILE, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Unable to open " VZFIFO_FILE " %s\n",
			strerror(errno));
		ret = VZCTL_E_WAIT;
		goto err;
	}
	if (read(fd, &buf, sizeof(buf)) == -1)
		ret = VZCTL_E_WAIT;
err:
	if (alarm_flag)
		ret = VZCTL_E_TIMEOUT;
	alarm(0);
	sigaction(SIGALRM, &actold, NULL);
	unlink(VZFIFO_FILE);

	if (fd != -1)
		close(fd);

	return ret;
}

const char *state2str(int state)
{
	switch (state) {
	case VZCTL_STATE_RUNNING:
		return "running";
	case VZCTL_STATE_STARTING:
		return "starting";
	case VZCTL_STATE_STOPPED:
		return "stopped";
	case VZCTL_STATE_STOPPING:
		return "stopping";
	case VZCTL_STATE_RESTORING:
		return "restoring";
	case VZCTL_STATE_CHECKPOINTING:
		return "checkpointing";
	}
	return NULL;
}

const char *get_state(struct vzctl_env_handle *h)
{
	return state2str(h->state);
}

int get_num_cpu(void)
{
	FILE *fd;
	char str[128];
	int ncpu = 0;

	if ((fd = fopen("/proc/cpuinfo", "r")) == NULL)	{
		logger(-1, errno, "Cannot open /proc/cpuinfo");
		return 1;
	}
	while (fgets(str, sizeof(str), fd)) {
		if (!strncmp(str, "processor", 9))
			ncpu++;
	}
	fclose(fd);
	return !ncpu ? 1 : ncpu;
}

int get_pagesize()
{
	static long pagesize;

	if (pagesize)
		return pagesize;
	if ((pagesize = sysconf(_SC_PAGESIZE)) == -1)
		return vzctl_err(-1, errno,  "Unable to get page size");
	return pagesize;
}


#if 0

int get_mem(unsigned long long *mem)
{
	long pagesize;
	if ((*mem = sysconf(_SC_PHYS_PAGES)) == -1) {
		logger(-1, errno, "Unable to get total phys pages");
		return -1;
	}
	if ((pagesize = get_pagesize()) < 0)
		return -1;
	*mem *= pagesize;
	return 0;
}

int get_thrmax(int *thrmax)
{
	FILE *fd;
	char str[128];

	if (thrmax == NULL)
		return 1;
	if ((fd = fopen(PROCTHR, "r")) == NULL) {
		logger(-1, errno, "Unable to open " PROCTHR);
		return 1;
	}
	if (fgets(str, sizeof(str), fd) == NULL) {
		fclose(fd);
		return 1;
	}
	fclose(fd);
	if (sscanf(str, "%du", thrmax) != 1)
		return 1;
	return 0;
}

int get_swap(unsigned long long *swap)
{
	FILE *fd;
	char str[128];

	if ((fd = fopen(PROCMEM, "r")) == NULL)	{
		logger(-1, errno, "Cannot open " PROCMEM);
		return -1;
	}
	while (fgets(str, sizeof(str), fd)) {
		if (sscanf(str, "SwapTotal: %llu", swap) == 1) {
			*swap *= 1024;
			fclose(fd);
			return 0;
		}
	}
	logger(-1, errno, "Swap: is not found in " PROCMEM );
	fclose(fd);

	return -1;
}

int get_lowmem(unsigned long long *mem)
{
	FILE *fd;
	char str[128];

	if ((fd = fopen(PROCMEM, "r")) == NULL)	{
		logger(-1, errno, "Cannot open " PROCMEM);
		return -1;
	}
	while (fgets(str, sizeof(str), fd)) {
		if (sscanf(str, "LowTotal: %llu", mem) == 1) {
			fclose(fd);
			*mem *= 1024;
			return 0;
		}
	}
	logger(-1, errno, "LowTotal: is not found in" PROCMEM);
	fclose(fd);
	return -1;
}

char *get_file_name(char *str)
{
	char *p;
	int len;

	len = strlen(str) - sizeof(".conf") + 1;
	if (len <= 0)
	return NULL;
	if (strcmp(str + len, ".conf"))
		return NULL;
	if ((p = malloc(len + 1)) == NULL)
		return NULL;
	strncpy(p, str, len);
	p[len] = 0;

	return p;
}



/* Renames (to "*.destroyed" if action == MOVE) or removes config,
 * (if action == DESTR)
 * Also, appropriate mount/umount scripts are linked.
 */
int move_config(const ctid_t ctid, int action)
{
	char conf[PATH_LEN];
	char newconf[PATH_LEN];

	snprintf(conf, sizeof(conf), VPS_CONF_DIR "%d.conf", ctid);
	snprintf(newconf, sizeof(newconf), "%s." DESTR_PREFIX, conf);
	action == BACKUP ? rename(conf, newconf) : unlink(newconf);

	snprintf(conf, sizeof(conf), VPS_CONF_DIR "%d." MOUNT_PREFIX, ctid);
	snprintf(newconf, sizeof(newconf), "%s." DESTR_PREFIX, conf);
	action == BACKUP ? rename(conf, newconf) : unlink(newconf);

	snprintf(conf, sizeof(conf), VPS_CONF_DIR "%d." UMOUNT_PREFIX, ctid);
	snprintf(newconf, sizeof(newconf), "%s." DESTR_PREFIX, conf);
	action == BACKUP ? rename(conf, newconf) : unlink(newconf);

	snprintf(conf, sizeof(conf), VPS_CONF_DIR "%d." START_PREFIX, ctid);
	snprintf(newconf, sizeof(newconf), "%s." DESTR_PREFIX, conf);
	action == BACKUP ? rename(conf, newconf) : unlink(newconf);

	snprintf(conf, sizeof(conf), VPS_CONF_DIR "%d." STOP_PREFIX, ctid);
	snprintf(newconf, sizeof(newconf), "%s." DESTR_PREFIX, conf);
	action == BACKUP ? rename(conf, newconf) : unlink(newconf);

	return 0;
}

#endif

static void free_str_param(struct vzctl_str_param *p)
{
	free(p->str);
}

void free_str(list_head_t *head)
{
	struct vzctl_str_param *tmp, *it;

	if (list_empty(head))
		return;
	list_for_each_safe(it, tmp, head, list) {
		list_del(&it->list);
		free_str_param(it);
		free(it);
	}
	list_head_init(head);
}

struct vzctl_str_param *add_str_param(list_head_t *head, const char *str)
{
	struct vzctl_str_param *p;

	if ((p = malloc(sizeof(struct vzctl_str_param))) == NULL)
		goto err;
	if ((p->str = strdup(str)) == NULL) {
		free(p);
		goto err;
	}
	list_add_tail(&p->list, head);
	return p;
err:
	vzctl_err(-1, ENOMEM, "Unable to allocate memory");
	return NULL;
}

const struct vzctl_str_param *find_str(list_head_t *head, const char *str)
{
	struct vzctl_str_param *it;

	list_for_each(it, head, list) {
		if (!strcmp(it->str, str))
			return it;
	}
	return NULL;
}

int parse_str_param(list_head_t *head, const char *val)
{
	int ret;
	char *token;
	char *tmp;
	char *savedptr;

	ret = 0;
	if ((tmp = strdup(val)) == NULL)
		return VZCTL_E_NOMEM;
	if ((token = strtok_r(tmp, LIST_DELIMITERS, &savedptr)) != NULL) {
		do {
			if (find_str(head, token))
				continue;
			if (add_str_param(head, token) == NULL) {
				ret = VZCTL_E_NOMEM;
				break;
			}
		} while ((token = strtok_r(NULL, LIST_DELIMITERS, &savedptr)));
	}
	free(tmp);

	return ret;
}

int copy_str(list_head_t *dst, list_head_t *src)
{
	struct vzctl_str_param *it;

	free_str(dst);
	list_for_each(it, src, list) {
		add_str_param(dst, it->str);
	}
	return 0;
}

int merge_str_list(list_head_t *old, list_head_t *add,
		list_head_t *del, int delall, list_head_t *merged)
{
	struct vzctl_str_param *str;

	if (!delall && list_empty(add) && list_empty(del))
		return 0;
	if (!delall && !list_empty(old)) {
		/* add old values */
		list_for_each(str, old, list) {
			if (find_str(del, str->str))
				continue;
			add_str_param(merged, str->str);
		}
	}
	if (!list_empty(add)) {
		list_for_each(str, add, list) {
			if (find_str(merged, str->str))
				continue;
			if (find_str(del, str->str))
				continue;
			add_str_param(merged, str->str);
		}
	}
	return 0;
}

char *list2str(const char *prefix, list_head_t *head)
{
	struct vzctl_str_param *it;
	char *str, *sp;
	int len = 0;

	if (prefix!= NULL)
		len += strlen(prefix);

	list_for_each(it, head, list) {
		len += strlen(it->str) + 1;
	}
	str = malloc(len + 1);
	if (str == NULL) {
		logger(-1, ENOMEM, "list2str");
		return NULL;
	}
	*str = '\0';
	sp = str;
	if (prefix != NULL)
		sp += sprintf(sp, "%s", prefix);
	list_for_each(it, head, list) {
		sp += sprintf(sp, "%s ", it->str);
	}

	strip_end(str);

	return str;
}

char **list2ar_str(list_head_t *head)
{
	struct vzctl_str_param *it;
	char **ar;
	int cnt = 0;

	list_for_each(it, head, list) { cnt++; }
	ar = malloc(++cnt * sizeof(char *));
	if (ar == NULL) {
		logger(-1, ENOMEM, "list2ar_str");
		return NULL;
	}
	cnt = 0;
	list_for_each(it, head, list) {
		if ((ar[cnt++] = strdup(it->str)) == NULL) {
			ar[cnt] = 0;
			free_ar_str(ar);
			free(ar);
			logger(-1, ENOMEM, "list2ar_str");
			return NULL;
		}
	}
	ar[cnt] = 0;
	return ar;
}

char *get_mnt_root(const char *path)
{
	struct stat st;
	dev_t prev_dev = 0;
	char *p, *end, *prev;

	if (path == NULL)
		return NULL;
	p = strdup(path);
	if (p == NULL) {
		logger(-1, ENOMEM, "Unable to get mount point for %s", path);
		return NULL;
	}
	prev = NULL;
	while (1) {
		if ((end = strrchr(p, '/')) == NULL) {
			logger(-1, 0, "Unable to get mount point for %s", path);
			free(p);
			return NULL;
		}
		prev = end;
		*end = 0;
		if (end == p)
			break;
		if (stat(p, &st) == -1)
			continue;
		else if (!prev_dev)
			prev_dev = st.st_dev;
		if (prev_dev != st.st_dev)
			break;
	};
	/* path is not valid, use / */
	if (!prev_dev)
		strcpy(p, "/");
	else if (prev != NULL)
		*prev = '/';
	return p;
}

int is_vswap_mode()
{
	return (stat_file("/proc/vz/vswap") == 1);
}

int vzctl2_get_config_fname(const char *param_conf, char *config, int len)
{
	return snprintf(config, len, VZ_SAMPLE_CONF_PATTERN, param_conf);
}

int vzctl2_get_config_full_fname(const char *param_conf, char *config, int len)
{
	return snprintf(config, len, VZ_ENV_CONF_SAMPLE, param_conf);
}

enum {
	GUID_TYPE,
	UUID_TYPE,
	CTID_TYPE,
};

static int get_normalized_uuid(const char *in, int otype, char *buf, int len)
{
	int i, j, uuid_len = 0;
	char *out = buf;
	int itype = CTID_TYPE;

#define UUID_LEN 36
	if (in[0] == '{') {
		itype = GUID_TYPE;
		in++;
	} else if (in[8] == '-')
		itype = UUID_TYPE;

	switch (otype) {
	case GUID_TYPE:
		out[0] = '{';
		out++;
		uuid_len = UUID_LEN + 2;
		break;
	case UUID_TYPE:
		uuid_len = UUID_LEN;
		break;
	case CTID_TYPE:
		uuid_len = UUID_LEN - 4;
		break;
	}

	if (len <= uuid_len)
		return 1;

	for (i = 0, j = 0; i < UUID_LEN; i++) {
		if (in[i] == '\0')
			break;

		if (itype != CTID_TYPE) {
			if (i == 8 || i == 13 || i == 18 || i == 23) {
				if (in[i] != '-')
					return 1;

				if (otype != CTID_TYPE)
					j++;

				continue;
			}
		} else if (otype != CTID_TYPE) {
			if (i == 8 || i == 12 || i == 16 || i == 20)
				j++;
		}

		if (!isxdigit(in[i]))
			return 1;

		out[j++] = in[i];
	}

	if (in[i] != '\0' && (in[i] != '}' || in[i + 1] != '\0'))
		return 1;

	if (otype == GUID_TYPE)
		out[j++] = '}';

	if (otype != CTID_TYPE) {
		out[8] = '-';
		out[13] = '-';
		out[18] = '-';
		out[23] = '-';
	}

	out[j] = '\0';

	if (strlen(buf) != uuid_len)
		return 1;

	return 0;
}

/* ID -> {fbcdf284-5345-416b-a589-7b5fcaa87673} */
int vzctl2_get_normalized_guid(const char *str, char *out, int len)
{
	return get_normalized_uuid(str, GUID_TYPE, out, len);
}

/* ID -> fbcdf284-5345-416b-a589-7b5fcaa87673 */
int vzctl2_get_normalized_uuid(const char *str, char *out, int len)
{
	return get_normalized_uuid(str, UUID_TYPE, out, len);
}

/* ID -> fbcdf2845345416ba5897b5fcaa87673 */
int vzctl2_get_normalized_ctid(const char *str, char *out, int len)
{
	return get_normalized_uuid(str, CTID_TYPE, out, len);
}

char *vzctl_get_guid_str(const char *str, char *uuid)
{
	const char *p = *str == '{' ? str + 1 : str;

	/* remove '{' '}'  */
	strcpy(uuid, p);
	uuid[36] = '\0';

	return uuid;
}

char *get_fs_root(const char *dir)
{
	struct stat st;
	int dev;
	int len;
	char *ep;
	char path[PATH_MAX];
	char path_r[PATH_MAX];

	len = strlen(dir);
	if (len > sizeof(path) - 1) {
		errno = ERANGE;
		return NULL;
	}
	strcpy(path, dir);
	ep = path + len - 1;

	/* find real dir */
	for (; ep > path; ep--) {
		if (stat(path, &st) == 0)
			break;
		if (errno != ENOENT) {
			logger(-1, errno, "get_fs_root: stat %s",
					path);
			return NULL;
		}
		while (ep > path && *ep != '/') ep--;
		while (ep > path && *ep == '/') ep--;
		ep[1] = '\0';
	}

	if (realpath(path, path_r) == NULL) {
		logger(-1, errno, "Failed to realpath %s", path);
		return NULL;
	}

	dev = st.st_dev;

	strcpy(path, path_r);
	ep = path + strlen(path) - 1;

	for (; ep > path; ep--) {
		while (ep > path && *ep == '/') ep--;
		while (ep > path && *ep != '/') ep--;
		*ep = '\0';

		if (stat(ep != path ? path : "/", &st)) {
			logger(-1, errno, "get_fs_root: stat %s",
					path);
			return NULL;
		}

		if (st.st_dev != dev) {
			*ep = '/';
			return strdup(path);
		}
	}

	return strdup("/");
}

static const char *get_quota_mount_opts(int mode)
{
	if (mode == VZCTL_JQUOTA_MODE)
		return "usrjquota=aquota.user,grpjquota=aquota.group,jqfmt=vfsv0";
	else if (mode == VZCTL_QUOTA_MODE)
		return "usrquota,grpquota";
	return "";
}

int get_global_param(const char *name, char *buf, int size)
{
	const struct vzctl_config *gconf;
	const char *val;
	int ret = -1;

	buf[0] = '\0';
	pthread_mutex_lock(get_global_conf_mtx());
	if ((gconf = vzctl_global_conf()) != NULL &&
			vzctl2_conf_get_param(gconf, name, &val) == 0 &&
			val != NULL)
	{
		snprintf(buf, size, "%s", val);
		ret = 0;
	}
	pthread_mutex_unlock(get_global_conf_mtx());

	return ret;
}

static char *get_pfcache_opts(char *buf, int len)
{
	char opts[PATH_MAX];

	buf[0] = '\0';
	if (get_global_param("PFCACHE", opts, sizeof(opts)) == 0)
		snprintf(buf, len, "pfcache=%s", opts);
	return buf;
}
/* process 'csum,pfcache' mount options
 * disabled only if 'noscum' present
 */
int vzctl2_get_mount_opts(const char *mnt_opts, int user_quota, char *out, int size)
{
	char pfcache_opts[PATH_MAX] = "";
	char *sp = out;
	char *ep = out + size;

	get_pfcache_opts(pfcache_opts, sizeof(pfcache_opts));

	if (mnt_opts == NULL) {
		sp += snprintf(sp, ep - sp, "pfcache_csum,%s,", pfcache_opts);
		if (sp >= ep)
			goto err;
	} else {
		sp += snprintf(sp, ep - sp, "%s,", mnt_opts);
		if (sp >= ep)
			goto err;
		if (strstr(mnt_opts, "nopfcache_csum") == NULL) {
			sp += snprintf(sp, ep - sp, "%s,pfcache_csum,%s,",
					mnt_opts, pfcache_opts);
			if (sp >= ep)
				goto err;
		}
	}

	if (user_quota) {
		sp += snprintf(sp, ep - sp , "%s,",
				get_quota_mount_opts(user_quota));
		if (sp >= ep)
			goto err;
	}

	return 0;
err:

	return vzctl_err(VZCTL_E_SYSTEM, 0, "Not enough buffer size to store mnt_ops result");
}

int configure_sysctl(const char *var, const char *val)
{
	int fd, len, ret;

	fd = open(var, O_WRONLY);
	if (fd == -1)
		return -1;

	len = strlen(val);
	ret = write(fd, val, strlen(val));
	close(fd);

	return ret == len ? 0 : -1;
}

static __thread pid_t vzpopen_pid;

FILE *vzctl_popen(char *argv[], char *env[], int close_std)
{
	int fd, i, j;
	char *cmd = NULL;
	char *envp[ENV_SIZE];
	int out[2];

	if (!stat_file(argv[0])) {
		logger(-1, 0, "executable %s not found", argv[0]);
		return NULL;
	}

	if (pipe(out) == -1) {
		logger(-1, errno, "pipe");
		return NULL;
	}

	cmd = arg2str(argv);
	if (cmd != NULL)
		logger(2, 0, "running: %s", cmd);

	i = 0;
	if (env != NULL) {
		for (i = 0; i < ENV_SIZE - 1 && env[i] != NULL; i++)
			envp[i] = env[i];
	}
	for (j = 0; i < ENV_SIZE - 1 && envp_bash[j] != NULL; i++, j++)
		envp[i] = envp_bash[j];
	envp[i] = NULL;
	if ((vzpopen_pid = fork()) == 0) {
		fd = open("/dev/null", O_WRONLY);
		if (fd == -1) {
			vzctl_err(-1, errno, "Failed to open /dev/null");
			_exit(1);
		}
		dup2(fd, STDIN_FILENO);
		if (close_std & CLOSE_STDOUT)
			dup2(fd, STDOUT_FILENO);
		else
			dup2(out[1], STDOUT_FILENO);

		if (close_std & CLOSE_STDERR)
			dup2(fd, STDERR_FILENO);
		else
			dup2(out[1], STDERR_FILENO);

		close(fd);
		close(out[0]);
		close(out[1]);
		execve(argv[0], argv, envp);
		logger(-1, errno, "Failed to exec %s", cmd);
		_exit(1);
	} else if (vzpopen_pid == -1) {
		logger(-1, errno, "Unable to fork");
		goto err;
	}
	close(out[1]);
	free(cmd);

	return fdopen(out[0], "r");
err:
	close(out[0]);
	close(out[1]);
	free(cmd);

	return NULL;
}

int vzctl_pclose(FILE *fp)
{
	int status, ret;

	while ((ret = waitpid(vzpopen_pid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	if (ret == -1) {
		vzctl_err(-1, errno, "vzctl_pclose: Error in waitpid()");
		status = 1;
	}

	fclose(fp);

	return status;
}

int is_2quota_enabled(const struct vzctl_dq_param *dq)
{
	return (dq->ugidlimit != NULL && *dq->ugidlimit != 0);
}

char *get_script_path(const char *name, char *buf, int size)
{
	snprintf(buf, size, VZCTL_SCRIPT_D_DIR"%s", name);
	if (stat_file(buf))
		return buf;

	snprintf(buf, size, VZCTL_SCRIPT_DIR"%s", name);

	return buf;
}

int is_vz_kernel(void)
{
	return (access(PROC_VZ, F_OK) == 0);
}

#define K_VER(a,b,c)	(((a) << 16) + ((b) << 8) + (c))
int kver_cmp(const char *v1, const char *v2)
{
	int a1 = 0, b1 = 0, c1 = 0;
	int a2 = 0, b2 = 0, c2 = 0;

	sscanf(v1, "%d.%d.%d", &a1, &b1, &c1);
	sscanf(v2, "%d.%d.%d", &a2, &b2, &c2);

	return (K_VER(a1, b1, c1) - K_VER(a2, b2, c2));
}

int is_permanent_disk(struct vzctl_disk *d)
{
	const char scheme[] = "backup://";
	return !d->storage_url || strncmp(d->storage_url, scheme, sizeof(scheme) - 1) != 0;
}

unsigned long long floor2digit(unsigned long long v)
{
	double e, e2;

	e = log10(v);
	e2 = floor(e) - 1;
	return floor(exp10(e - e2)) * exp10(e2);
}

unsigned long long ceil2digit(unsigned long long v)
{
	double e, e2;

	e = log10(v);
	e2 = floor(e) - 1;
	return ceil(exp10(e - e2)) * exp10(e2);
}

int set_fattr(int fd, struct stat *st)
{
	if (fchmod(fd, st->st_mode))
		return vzctl_err(-1, errno, "fchmod()");

	if (fchown(fd, st->st_uid, st->st_gid))
		return vzctl_err(-1, errno, "fchown()");

	return 0;
}

void vzctl2_generate_ctid(ctid_t ctid)
{
	uuid_t u;

	uuid_generate(u);
	uuid_unparse(u, ctid);
}

const char *get_devname(const char *device)
{
	char *p = strrchr(device, '/');

	return p == NULL ? device : ++p;
}

void p_close(int p[2])
{
	if (p[0] != -1)
		close(p[0]);
	if (p[1] != -1)
		close(p[1]);
}

void get_init_pid_path(const ctid_t ctid, char *path)
{
	sprintf(path, VZCTL_VE_RUN_DIR "/%s" VZCTL_VE_INIT_PID_FILE_EXT, ctid);
}

int write_init_pid(const ctid_t ctid, pid_t pid)
{
	int ret = 0;
	char path[PATH_MAX];
	FILE *fp;

	get_init_pid_path(ctid, path);

	logger(10, 0, "Write init pid=%d %s", pid, path);
	if ((ret = make_dir(path, 0)))
		return ret;

	if ((fp = fopen(path, "w")) == NULL)
		return vzctl_err(-1, errno, "Failed to create %s", path);

	if ((fprintf(fp, "%d", pid)) < 0)
		ret = vzctl_err(-1, 0, "Failed to write Container init pid");

	fclose(fp);
	return ret;
}

int read_init_pid(const ctid_t ctid, pid_t *pid)
{
	int ret = 0;
	char path[PATH_MAX];
	FILE *fp;

	*pid = 0;

	get_init_pid_path(ctid, path);

	if ((fp = fopen(path, "r")) == NULL) {
		if (errno != ENOENT)
			vzctl_err(-1, errno, "Unable to open %s", path);

		return -1;
	}

	if (fscanf(fp, "%d", pid) < 1)
		ret = vzctl_err(-1, 0, "Unable to read Container init pid");

	fclose(fp);
	return ret;
}

int clear_init_pid(const ctid_t ctid)
{
	int ret;
	char path[PATH_MAX];

	get_init_pid_path(ctid, path);

	if ((ret = remove(path)) < 0 && errno != ENOENT)
		return vzctl_err(-1, 0, "Unable to clear Container init pid file: %s", path);

	return 0;
}

char *get_netns_path(struct vzctl_env_handle *h, char *buf, int size)
{
	snprintf(buf, size, NETNS_RUN_DIR"/%s", h->ctid);

	return buf;
}

int get_bindmnt_target(const char *dir, char *out, int size)
{
	FILE *fp;
	int ret = 1;
	char buf[PATH_MAX];
	char s[PATH_MAX], t[PATH_MAX];
	char *src, *data = NULL;
	struct stat fs;
	unsigned u, maj, min;

	if (stat(dir, &fs)) {
		if (errno == ENOENT)
			return 1;
		return vzctl_err(-1, errno, "Cannot statfs %s", dir);
	}

	src = realpath(dir, NULL);
	if (src == NULL)
		return vzctl_err(-1, errno, "Failed to get realpath for %s", dir);

	fp = fopen("/proc/self/mountinfo", "r");
	if (fp == NULL)
		return vzctl_err(-1, errno, "Can't open /proc/self/mountinfo");

	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "%u %u %u:%u %s %s",
					&u, &u, &maj, &min, s, t) != 6)
			continue;

		if (maj != gnu_dev_major(fs.st_dev) ||
				min != gnu_dev_minor(fs.st_dev))
			continue;

		if (data == NULL) {
			int l = strlen(t);

			if (l == 1)
				data = src;
			else if (l < strlen(src))
				data = src + l;

			continue;
		}

		if (strcmp(s, data) == 0) {
			if (out != NULL) {
				strncpy(out, t, size - 1);
				out[size - 1] = '\0';
			}
			ret = 0;
			break;
		}
	}
	fclose(fp);
	free(src);

	return ret;
}

int fs_is_mounted_check_by_target(const char *target)
{
	FILE *fp;
	int ret = 1;
	char buf[PATH_MAX];
	char t[PATH_MAX];
	char *data = NULL;
	unsigned u;

	if (access(target, F_OK))
		return 0;

	data = realpath(target, NULL);
	if (data == NULL)
		return vzctl_err(-1, errno, "Failed to get realpath for %s",
				target);

	fp = fopen("/proc/self/mountinfo", "r");
	if (fp == NULL)
		return vzctl_err(-1, errno, "Can't open /proc/self/mountinfo");

	while (fgets(buf, sizeof(buf), fp)) {
		if (sscanf(buf, "%u %u %u:%u %*s %s", &u, &u, &u, &u, t) != 6)
			continue;

		if (strcmp(t, data) == 0) {
			ret = 0;
			break;
		}
	}
	fclose(fp);
	free(data);

	return ret;
}
