/*
 *  Copyright (c) 1999-2017, Parallels International GmbH
 * Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
 * Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */

#ifndef _VZCTL_UTIL_H_
#define	_VZCTL_UTIL_H_

#define BACKUP		0
#define DESTR		1

#define PROCMEM		"/proc/meminfo"
#define PROCTHR		"/proc/sys/kernel/threads-max"

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdio.h>
#include "env.h"
#include "list.h"
#include "logger.h"
#include "common.h"

enum {
	CLOSE_STDOUT    = 0x1,
	CLOSE_STDERR    = 0x2,
	DONT_REDIRECT_ERR2OUT	= 0x4,
};

struct vzctl_idstr_pair {
	int id;
	char *str;
};

struct vzctl_conf_simple {
	char *ve_root;
	char *ve_root_orig;
	char *ve_private;
	char *ve_private_orig;
	char *lockdir;
	char *dumpdir;
	char *name;
	int *veid;
};

#define VZCTL_LOCK_EX	0x1
#define VZCTL_LOCK_SH	0x2
#define VZCTL_LOCK_NB	0x4

#define VZCTL_CLOSE_STD         0x1
#define VZCTL_CLOSE_NOCHECK     0x2

/* Usage: printf("MAC=" MAC2STR_FMT, MAC2STR(dev)); */
#define MAC2STR_FMT     "%02X:%02X:%02X:%02X:%02X:%02X"
#define MAC2STR(dev)    \
	((unsigned char *)dev)[0],      \
	((unsigned char *)dev)[1],      \
	((unsigned char *)dev)[2],      \
	((unsigned char *)dev)[3],      \
	((unsigned char *)dev)[4],      \
	((unsigned char *)dev)[5]


struct vzctl_ip_param;
#ifdef __cplusplus
extern "C" {
#endif

void *xmalloc(size_t size);
void xfree(void *p);
int xstrdup(char **dst, const char *src);
int vzctl2_get_env_conf_path_orig(struct vzctl_env_handle *h, char *buf, int len);

/** Convert text to UTF-8 from current locale
 *
 * @param src		source text
 * @param dst		destination text should have enougth space
 * @param dst_size	destination buffer size
 * @return		0 on success
 */
int strtoutf8(const char *src, char *dst, int dst_size, const char *enc);

/** Convert text from UTF-8 to current locale
 *
 * @param src		source text
 * @param dst		destination text should have enougth space
 * @param dst_size	destination buffer size
 * @return		0 on success
 */
int utf8tostr(const char *src, char *dst, int dst_size, const char *enc);

char *parse_line(char *str, char *ltoken, int lsz);
char *subst_VEID(const ctid_t ctid, const char *src);
int check_var(const void *val, const char *message);
int make_dir(const char *path, int full);
int destroydir(const char *dir);
int set_not_blk(int fd);
int reset_std(void);
int yesno2id(const char *str);
const char *id2yesno(int id);
int get_netaddr(const char *ip_str, unsigned int *addr);
int check_ipv4(const char *ip);
int make_sockaddr(int family, unsigned int *addr, struct sockaddr *sa);
int parse_ul(const char *str, unsigned long *val);

void str_tolower(const char *from, char *to);

double max(double val1, double val2);
unsigned long max_ul(unsigned long val1, unsigned long val2);
unsigned long min_ul(unsigned long val1, unsigned long val2);

/** Close all fd.
 * @param close_std     flag for closing the [0-2] fds
 * @param ...           list of fds are skiped, (-1 is the end mark)
*/
void close_fds(int close_std, ...);


int parse_hwaddr(const char *str, char *addr);
int set_hwaddr(const char *str, char **dst);
char *hwaddr2str(char *hwaddr);
int _lock(char *lockfile, int mode);
void _unlock(int fd, char *lockfile);
int execvep(const char *path, char *const argv[], char *const envp[]);
void free_str(list_head_t *head);
int copy_str(list_head_t *dst, list_head_t *src);
int parse_str_param(list_head_t *head, const char *val);
struct vzctl_str_param *add_str_param(list_head_t *head, const char *str);
const struct vzctl_str_param *find_str(list_head_t *head, const char *str);

/** Function for fast parsing only restricted set of parameters supported **/
int vzctl_parse_conf_simple(const ctid_t ctid, char *path,
	struct vzctl_conf_simple *conf);
void vzctl_merge_conf_simple(struct vzctl_conf_simple *src,
	struct vzctl_conf_simple *dst);
void vzctl_free_conf_simple(struct vzctl_conf_simple *conf);
int is_str_valid(const char *name);
int vzctl_get_dump_file(struct vzctl_env_handle *h, char *buf, int size);
int vzctl_check_owner(const char *ve_private);
char *get_ip4_name(unsigned int ip);
char *get_mnt_root(const char *path);
void free_ar_str(char **ar);
const char *find_ar_str(char *ar[], const char *str);
int merge_str_list(list_head_t *old, list_head_t *add,
		list_head_t *del, int delall, list_head_t *merged);
char *list2str(const char *prefix, list_head_t *head);
char **list2ar_str(list_head_t *head);
struct vzctl_config *global_conf();
int parse_ip(const char *str, struct vzctl_ip_param **ip);
int parse_ip_str(list_head_t *head, const char *val, int replace);
int read_service_name(char *path, char *service_name, int size);
int read_script(const char *fname, const char *include, char **buf);
int cp_file(const char *src, const char *dst);
int get_ip_name(const char *ipstr, char *buf, int size);
const char *state2str(int state);
const char *get_state(struct vzctl_env_handle *h);
void get_action_script_path(struct vzctl_env_handle *h, const char *name,
		char *out, int len);
int get_num_cpu(void);
int parse_twoul_sfx(const char *str, struct vzctl_2UL_res *res,
		int divisor, int def_divisor);
int get_pagesize();
const char *vzctl_get_str(int id, struct vzctl_idstr_pair *map);
int vzctl_is_env_name_valid(const char *name);
int set_description(char **dst, const char *desc);
char *get_description(char *desc);
int str2env_type(struct vzctl_misc_param *p, const char *str);
const char* env_type2str(struct vzctl_misc_param *p);
int get_mul(char c, unsigned long long *n);
int get_env_conf_lockfile(struct vzctl_env_handle *h, char *buf, int len);
int vzctl2_get_config_fname(const char *param_conf, char *config, int len);
int vzctl2_get_config_full_fname(const char *param_conf, char *config, int len);
int vzctl2_get_normalized_guid(const char *str, char *buf, int len);
int vzctl2_get_normalized_uuid(const char *str, char *buf, int len);
int vzctl2_get_normalized_ctid(const char *str, char *out, int len);
char *vzctl_get_guid_str(const char *str, char *uuid);
int get_mount_opts(const char *opts, int user_quota, char *out, int size);
int vzctl2_get_mount_opts(const char *mnt_opts, int user_quota, char *out, int size);
int configure_sysctl(const char *var, const char *val);
FILE *vzctl_popen(char *argv[], char *env[], int quiet);
int vzctl_pclose(FILE *fp);
int vztmpl_get_osrelease(const char *ostemplate, char *buf, int size);
int run_action_scripts(struct vzctl_env_handle *h, int action);
const char* get_jquota_format(int mode);
int get_user_quota_mode(const struct vzctl_dq_param *dq);
char *get_fs_root(const char *dirk);
char *get_script_path(const char *name, char *buf, int size);
int onoff2id(const char *str);
const char *id2onoff(int id);
int is_vz_kernel(void);
int kver_cmp(const char *v1, const char *v2);
int is_permanent_disk(struct vzctl_disk *d);
int vzctl2_get_dump_file(struct vzctl_env_handle *h, char *buf, int size);
int set_fattr(int fd, struct stat *st);
int add_dq_param(struct vzctl_2UL_res **addr, struct vzctl_2UL_res *res);
void free_dq_param(struct vzctl_dq_param *dq);
int is_ip6(const char *ip);
int get_eid(const char *uuid, ctid_t out);
void generate_eid(ctid_t ctid);
const char *get_devname(const char *device);
int get_dir_list(list_head_t *head, const char *root, int level);
void p_close(int p[2]);
int read_p(int fd);
const char *get_init_pidfile(const ctid_t ctid, char *path);
const char *get_criu_pidfile(const ctid_t ctid, char *path);
int write_init_pid(const ctid_t ctid, pid_t pid);
int read_init_pid(const ctid_t ctid, pid_t *pid);
int clear_init_pid(const ctid_t ctid);
char *get_netns_path(struct vzctl_env_handle *h, char *buf, int size);
int get_bindmnt_target(const char *dir, char *out, int size);
int fs_is_mounted_check_by_target(const char *target);
int vzctl_get_mount_opts(struct vzctl_disk *d, char *out, int size);
int init_runtime_ctx(struct vzctl_runtime_ctx *ctx);
void deinit_runtime_ctx(struct vzctl_runtime_ctx *ctx);
void get_dumpfile(struct vzctl_env_handle *h, struct vzctl_cpt_param *param,
		char *dumpfile, int size);
#ifdef __cplusplus
}
#endif
#endif /* _VZCTL_UTIL_H_ */
