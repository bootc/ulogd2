/*
 * plugin.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Holger Eitzenberger <holger@eitzenberger.org>  Astaro AG 2008
 */
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>

static struct ulogd_timer stack_fsm_timer;
static LLIST_HEAD(stack_fsm_list);

/**
 * State handling
 *
 * The notion P>start means "call function 'start' of plugin P".
 *
 * STATE DIAGRAM
 *
 *      ^        PsInit
 *      |             |
 *      |             |
 *      |             <
 *      |        PsConfiguring <------
 *      | fail        |              | %ULOGD_IRET_AGAIN
 *      |<----------- | configure() --
 *      |             <
 *      |        PsConfigured
 *      |             |
 *      |             <
 *      |          PsStarting <---
 *      |  fail       |          |  %ULOGD_IRET_AGAIN
 *      |<----------- | start() --
 *      |             <
 *      ---------  PsStarted
 *                    |
 *                    | close()
 *                    |
 *           ^---------
 *              to PsInit
 *
 * TRANSITIONS
 *
 *   T: <state>
 *   T_fail: <state_fail>
 *   A: <action>
 *
 * Conceptually <state> is reached after successfully doing
 * <action>.  <state_fail> is reached if an error occurs.
 *
 *  I       the plugin instance
 *  P       the plugin
 *
 *
 *              PsInit          PsConfigured    PsStarting		PsStarted
 *
 * configure()  A: P>config     ---             ---            ---
 *              T: PsConfigured
 *
 * start()      ---             T: PsStarting   ---            ---
 *
 *              ---             ---             A: P>start     ---
 *                                              T: PsStarted
 *                                              T_fail: PsInit
                                                  or PsStarting
 *
 * I>interp     ---             ---             ---            A: P>interp
 *                                                             T_fail: PsInit
 */
static const enum UpiState next_state[__PsMax + 1] = {
	[PsInit] = PsConfigured,
	[PsConfiguring] = PsConfigured,
	[PsConfigured] = PsStarted,
	[PsStarting] = PsStarted,
	[PsStarted] = PsInit,
};

static int
stack_set_state(struct ulogd_pluginstance_stack *stack,
				enum UpiState state)
{
	if (stack->state == state)
		return 0;

	pr_fn_debug("%d -> %d\n", stack->state, state);

	stack->state = state;

	return 0;
}

/**
 * The actual finite state machine.
 */
static int
stack_fsm_move(struct ulogd_pluginstance_stack *stack)
{
	struct ulogd_pluginstance *pi;
	int ret;

	llist_for_each_entry_reverse(pi, &stack->list, list) {
		if (pi->state == next_state[stack->state])
			continue;

		pr_fn_debug("stack=%p pi='%s'\n", stack, pi->id);

		switch (pi->state) {
		case PsInit:
		case PsConfiguring:
			if ((ret = ulogd_upi_configure(pi, stack)) < 0) {
				if (ret != ULOGD_IRET_AGAIN)
					goto err;
			}
			break;

		case PsConfigured:
		case PsStarting:
			if ((ret = ulogd_upi_start(pi)) < 0) {
				if (ret != ULOGD_IRET_AGAIN)
					goto err;
			}
			break;

		case PsStarted:
			break;
        }
    }

	return 0;

err:
	return -1;
}

/**
 * Add to finite state machinery, start timer if necessary.
 */
int
stack_fsm_add(struct ulogd_pluginstance_stack *stack)
{
	bool need_start = !!llist_empty(&stack_fsm_list);

	if (stack->flags & ULOGD_PF_FSM)
		return 0;

	pr_fn_debug("stack=%p\n", stack);

	llist_add_tail(&stack->state_link, &stack_fsm_list);

	stack->flags |= ULOGD_PF_FSM;

	if (!need_start)
		return 0;

	if (ulogd_register_timer(&stack_fsm_timer) < 0)
        return -1;

    return 0;
}

/**
 * Finite state machine loop.  Continue until stack reaches PsStarted
 * or until there is no progress.
 *
 * It is called after a stack is created initially and possibly later
 * from the periodic FSM timer.
 */
int
stack_fsm(struct ulogd_pluginstance_stack *stack)
{
	for (;;) {
		enum UpiState oldstate = stack->state;

		if (stack_fsm_move(stack) < 0)
			break;

		if (stack->state == oldstate)
			break;

		if (stack->state == PsConfigured) {
			if (stack_resolve_keys(stack) < 0)
				return -1;
		} else if (stack->state == PsStarted)
			break;
	}

	return 0;
}

/**
 * Periodic timer for stack state management, removes itself when
 * done.
 */
static void
stack_fsm_timer_cb(struct ulogd_timer *t)
{
  struct ulogd_pluginstance_stack *stack, *tmp;

  pr_fn_debug("timer=%p\n", t);

  llist_for_each_entry_safe(stack, tmp, &stack_fsm_list, state_link) {
	  if (stack_fsm(stack) < 0) {
		  ulogd_log(ULOGD_ERROR, "%s: error\n", __func__);
		  return;
	  }

	  if (stack->state == PsStarted) {
		  llist_del(&stack->state_link);
		  stack->flags &= ~ULOGD_PF_FSM;

		  if (llist_empty(&stack_fsm_list))
			  ulogd_unregister_timer(&stack_fsm_timer);
      }
  }
}

/**
 * Configure a plugin.
 *
 * An instance might return %ULOGD_IRET_AGAIN, in which case a configure
 * is retried later.
 */
int
ulogd_upi_configure(struct ulogd_pluginstance *pi,
					struct ulogd_pluginstance_stack *stack)
{
	int ret;

	assert(pi->state == PsInit || pi->state == PsConfiguring);

	ulogd_log(ULOGD_DEBUG, "configuring '%s'\n", pi->id);

	if (pi->plugin->configure == NULL)
		goto done;

	ulogd_upi_set_state(pi, PsConfiguring);

	if ((ret = pi->plugin->configure(pi, stack)) < 0) {
		if (ret == ULOGD_IRET_AGAIN)
			stack_fsm_add(pi->stack);

		ulogd_upi_reset_cfg(pi);

		return ret;
	}

done:
	ulogd_upi_set_state(pi, PsConfigured);

	return 0;
}

/**
 * Start a plugin instance.
 *
 * An instance might return %ULOGD_IRET_AGAIN, in which case a start
 * is retried later.
 */
int
ulogd_upi_start(struct ulogd_pluginstance *pi)
{
	int ret;

	assert(pi->state == PsConfigured || pi->state == PsStarting);

	ulogd_log(ULOGD_DEBUG, "starting '%s'\n", pi->id);

	if (pi->plugin->start == NULL)
		goto done;

	ulogd_upi_set_state(pi, PsStarting);

	if ((ret = pi->plugin->start(pi)) < 0) {
		if (ret == ULOGD_IRET_AGAIN)
			stack_fsm_add(pi->stack);

		return ret;
	}

done:
	ulogd_upi_set_state(pi, PsStarted);

	return 0;
}

int
ulogd_upi_stop(struct ulogd_pluginstance *pi)
{
	assert(pi->state == PsStarted);

	ulogd_log(ULOGD_DEBUG, "stopping '%s'\n", pi->id);

	if (pi->plugin->stop == NULL)
		goto done;

	pi->plugin->stop(pi);

done:
	ulogd_upi_set_state(pi, PsInit);

	return 0;
}

int
ulogd_upi_interp(struct ulogd_pluginstance *pi)
{
	int ret;

	if (pi->state != PsStarted)
		return 0;

	if ((ret = pi->plugin->interp(pi)) < 0) {
		ulogd_upi_stop(pi);

		if (ret == ULOGD_IRET_AGAIN) {
			stack_fsm_add(pi->stack);

			return 0;
		}

		return -1;
	}

	return 0;
}

void
ulogd_upi_signal(struct ulogd_pluginstance *pi, int signo)
{
	int ret;

	if (pi->plugin->signal == NULL)
		return;

	if (pi->plugin->signal(pi, signo) < 0) {
		ulogd_upi_stop(pi);

		if (ret == ULOGD_IRET_AGAIN)
			stack_fsm_add(pi->stack);
	}
}

int
ulogd_upi_error(struct ulogd_pluginstance *pi, int err)
{
	assert(err != ULOGD_IRET_OK);

	if (pi->state == PsStarted)
		ulogd_upi_stop(pi);

	if (err == ULOGD_IRET_AGAIN)
		stack_fsm_add(pi->stack);

	return 0;
}

void
ulogd_upi_set_state(struct ulogd_pluginstance *pi, enum UpiState state)
{
	struct ulogd_pluginstance *curr;
	struct ulogd_pluginstance_stack *stack = pi->stack;
	enum UpiState sstate;

	if (pi->state == state)
		return;

	sstate = pi->state = state;

	llist_for_each_entry_reverse(curr, &stack->list, list) {
		if (curr->state < sstate)
			sstate = curr->state;
	}

	stack_set_state(pi->stack, sstate);
}

/**
 * Reset configuration data.
 */
int
ulogd_upi_reset_cfg(struct ulogd_pluginstance *pi)
{
	size_t size;

	assert(pi->plugin != NULL);

	size = sizeof(struct config_keyset)
		+ pi->plugin->config_kset->num_ces * sizeof(struct config_entry);

	memcpy(pi->config_kset, pi->plugin->config_kset, size);

	return 0;
}

/* key API */
static void
__check_get(const struct ulogd_key *key, unsigned type)
{
#ifdef DEBUG
	if (key == NULL || key->u.source == NULL)
		abort();

	if ((key->u.source->type & type) == 0) {
		pr_fn_debug("%s: type check failed (%d <-> %d)\n",
					key->name, key->type, type);
		abort();
	}
#endif /* DEBUG */
}

static void
__check(const struct ulogd_key *key, unsigned type)
{
#ifdef DEBUG
	if (key == NULL)
		abort();

	if ((key->type & type) == 0) {
		pr_fn_debug("%s: type check failed (%d <-> %d)\n",
					key->name, key->type, type);
		abort();
	}
#endif /* DEBUG */
}

void
key_i8(struct ulogd_key *key, int v)
{
	__check(key, ULOGD_RET_INT8);

	key->u.value.i8 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_i16(struct ulogd_key *key, int v)
{
	__check(key, ULOGD_RET_INT16);

	key->u.value.i16 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_i32(struct ulogd_key *key, int v)
{
	__check(key, ULOGD_RET_INT32);

	key->u.value.i32 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_u8(struct ulogd_key *key, unsigned v)
{
	__check(key, ULOGD_RET_UINT8);

	key->u.value.ui8 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_u16(struct ulogd_key *key, unsigned v)
{
	__check(key, ULOGD_RET_UINT16);

	key->u.value.ui16 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_u32(struct ulogd_key *key, unsigned v)
{
	__check(key, ULOGD_RET_UINT32 | ULOGD_RET_IPADDR);

	key->u.value.ui32 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_bool(struct ulogd_key *key, bool v)
{
	__check(key, ULOGD_RET_BOOL);

	key->u.value.b = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_ptr(struct ulogd_key *key, void *ptr)
{
	__check(key, ULOGD_RET_RAW);

	key->u.value.ptr = ptr;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_str(struct ulogd_key *key, char *str)
{
	__check(key, ULOGD_RET_STRING);

	key->u.value.str = str;
	key->flags |= ULOGD_RETF_VALID;
}

int
key_get_i8(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT8);

	return key->u.source->u.value.i8;
}

int
key_get_i16(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT16);

	return key->u.source->u.value.i16;
}

int
key_get_i32(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT32);

	return key->u.source->u.value.i32;
}

unsigned
key_get_u8(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_UINT8);

	return key->u.source->u.value.ui8;
}

unsigned
key_get_u16(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_UINT16);

	return key->u.source->u.value.ui16;
}

unsigned
key_get_u32(const struct ulogd_key *key)
{
	/* currently, IP addresses are encoded as u32.  A strong typesafety
	   might require to add key_get_ipaddr() as well. */
	__check_get(key, ULOGD_RET_UINT32 | ULOGD_RET_IPADDR);

	return key->u.source->u.value.ui32;
}

bool
key_get_bool(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_BOOL);

	return !!key->u.source->u.value.b;
}

void *
key_get_ptr(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_RAW);

	return key->u.source->u.value.ptr;
}

char *
key_get_str(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_STRING);

	return key->u.source->u.value.str;
}

/**
 * Allocate a keyset for use with ulogd_pluginstance.  The keys are
 * optionally setup with private data.
 *
 * @arg num_keys  Number of keys to use.
 * @arg priv_size Size of private area per key.
 * @return Newly allocated key space or %NULL.
 */
struct ulogd_key *
ulogd_alloc_keyset(int num_keys, size_t priv_size)
{
	struct ulogd_key *keys;
	void *priv;
	size_t size;
	int i;

	if (num_keys <= 0)
		return NULL;

	size = num_keys * (sizeof(struct ulogd_key) + priv_size);
	if ((priv = keys = malloc(size)) == NULL)
		return NULL;

	memset(keys, 0, size);

	if (priv_size > 0) {
		priv += num_keys * sizeof(struct ulogd_key);
		for (i = 0; i < num_keys; i++)
			keys[i].priv = priv + i * priv_size;
	}

	return keys;
}

struct ulogd_key *
ulogd_key_find(const struct ulogd_keyset *set, const char *name)
{
	int i;

	for (i = 0; i < set->num_keys; i++) {
		if (strcmp(set->keys[i].name, name) == 0)
			return &set->keys[i];
	}

	return NULL;
}

int
ulogd_plugin_init(void)
{
	INIT_LLIST_HEAD(&stack_fsm_list);

	stack_fsm_timer.cb = &stack_fsm_timer_cb;
	stack_fsm_timer.ival = 5 SEC;
	stack_fsm_timer.flags = TIMER_F_PERIODIC;

	return 0;
}
