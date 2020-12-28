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

#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>

#include "cleanup.h"
#include "logger.h"
#include "env.h"
#include "util.h"

#include "vzctl.h"

#ifdef __i386__
#include <pthread.h>

/* Workaround for non NPTL glibc
 * Private thread specific data */
static pthread_key_t cleanup_ctx_key;
static pthread_once_t cleanup_ctx_key_once = PTHREAD_ONCE_INIT;

static void buffer_destroy(void *buf)
{
	free(buf);
}

static void buffer_key_alloc(void)
{
	pthread_key_create(&cleanup_ctx_key, buffer_destroy);
}

static cleanup_ctx_t *get_cleanup_ctx(void)
{
	cleanup_ctx_t *ctx;
	pthread_once(&cleanup_ctx_key_once, buffer_key_alloc);

	ctx = pthread_getspecific(cleanup_ctx_key);
	if (ctx == NULL) {

		ctx = calloc(1, sizeof(cleanup_ctx_t));
		if (ctx != NULL)
			list_head_init(ctx);

		pthread_setspecific(cleanup_ctx_key, ctx);
	}
	return ctx;

}
#else

static __thread cleanup_ctx_t _cleanup_ctx;

static cleanup_ctx_t *get_cleanup_ctx(void)
{
	if (_cleanup_ctx.next == NULL)
		list_head_init(&_cleanup_ctx);
	return &_cleanup_ctx;
}
#endif

void vzctl2_cancel_last_operation(void)
{
	struct vzctl_cleanup_hook *it;

	list_for_each(it, get_cleanup_ctx(), list) {
		it->fn(it->data);
	}
}

struct vzctl_cleanup_hook *register_cleanup_hook(cleanup_FN fn, void *data)
{
	struct vzctl_cleanup_hook *h;
	cleanup_ctx_t *ctx = get_cleanup_ctx();

	h = malloc(sizeof(struct vzctl_cleanup_hook));
	if (h == NULL)
		return NULL;
	h->fn = fn;
	h->data = data;
	list_add(&h->list, ctx);

	return h;
}

void unregister_cleanup_hook(struct vzctl_cleanup_hook *h)
{
	if (h != NULL) {
		list_del(&h->list);
		free(h);
	}
}

void cleanup_kill_process(void *data)
{
	pid_t pid = *(pid_t *) data;

	kill(pid, SIGTERM);
}

void cleanup_kill_force(void *data)
{
	pid_t pid = *(pid_t *) data;

	kill(pid, SIGKILL);
}

void cleanup_destroydir(void *data)
{
	char *dir = (char *) data;

	destroydir(dir);
}

void cleanup_kill_ve(void *data)
{
	struct vzctl_env_handle *h = (struct vzctl_env_handle *) data;

	vzctl2_env_stop(h, M_KILL, 0);
}
