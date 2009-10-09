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
#include "config.h"
#include <ulogd/ulogd.h>
#include <ulogd/common.h>
#include <ulogd/plugin.h>

#include <arpa/inet.h>

/* linked list for all registered plugins */
static LLIST_HEAD(ulogd_plugins);
static LLIST_HEAD(ulogd_pi_stacks);

static struct ulogd_timer stack_fsm_timer;
static LLIST_HEAD(stack_fsm_list);


/**
 * Find an output key in a given stack, starting at 'start'.
 *
 * @arg name	Name to search for.
 * @arg start	Plugin to start search at.
 * @arg src		Plugin which contains the found key, only valid if
 *				function does not return %NULL.
 * @return Key found.
 */
static struct ulogd_key *
find_okey_in_stack(const char *name,
				   const struct ulogd_pluginstance *start,
				   struct ulogd_pluginstance **src)
{
	const struct ulogd_pluginstance_stack *stack = start->stack;
	struct ulogd_pluginstance *pi;

	llist_for_each_entry_reverse(pi, &start->list, list) {
		int i;

		if ((void *)&pi->list == &stack->list)
			return NULL;

		for (i = 0; i < pi->output.num_keys; i++) {
			struct ulogd_key *okey = &pi->output.keys[i];
			if (!strcmp(name, okey->name)) {
				if (src != NULL)
					*src = pi;

				return okey;
			}
		}
	}

	return NULL;
}

void
stack_add(struct ulogd_pluginstance_stack *stack)
{
	/* add head of pluginstance stack to list of stacks */
	llist_add(&stack->stack_list, &ulogd_pi_stacks);
}

void
stack_dump(const struct ulogd_pluginstance_stack *stack)
{
	const struct ulogd_pluginstance *pi;

	llist_for_each_entry(pi, &stack->list, list) {
		ulogd_log(ULOGD_INFO, " stack: pi=%p/%s\n", pi, pi->id);
	}
}

bool
stack_have_stacks(void)
{
	return !llist_empty(&ulogd_pi_stacks);
}

/**
 * Resolve input key connections from top to bottom of stack.
 */
static int
stack_resolve_keys(const struct ulogd_pluginstance_stack *stack)
{
	struct ulogd_pluginstance *pi_cur, *pi_src;
	struct ulogd_key *ikey;
	int i = 0;

	BUG_ON(stack->state != PsConfigured);

	/* PASS 2: */
	ulogd_log(ULOGD_DEBUG, "connecting input/output keys of stack:\n");
	llist_for_each_entry_reverse(pi_cur, &stack->list, list) {
		struct ulogd_pluginstance *pi_prev =
					llist_entry(pi_cur->list.prev,
						   struct ulogd_pluginstance,
						   list);
		i++;

		ulogd_log(ULOGD_DEBUG, "traversing instance '%s'\n", pi_cur->id);

		if (i == 1) {
			/* first round: output plugin */
			if (!(pi_cur->plugin->output.type & ULOGD_DTYPE_SINK)) {
				ulogd_log(ULOGD_ERROR, "last plugin in stack "
					  "has to be output plugin\n");
				return -EINVAL;
			}
			/* continue further down */
		} /* no "else' since first could be the last one, too ! */

		if (&pi_prev->list == &stack->list) {
			/* this is the last one in the stack */
			if (!(pi_cur->plugin->input.type
						& ULOGD_DTYPE_SOURCE)) {
				ulogd_log(ULOGD_ERROR, "first plugin in stack "
					  "has to be source plugin\n");
				return -EINVAL;
			}
			/* no need to match keys */
		} else {
			int j;

			/* not the last one in the stack */
			if (!(pi_cur->plugin->input.type &
					pi_prev->plugin->output.type)) {
				ulogd_log(ULOGD_ERROR, "type mismatch between "
					  "%s and %s in stack\n",
					  pi_cur->plugin->name,
					  pi_prev->plugin->name);
			}

			for (j = 0; j < pi_cur->input.num_keys; j++) {
				struct ulogd_key *okey;

				ikey = &pi_cur->input.keys[j];

				/* skip those marked as 'inactive' by
				 * pl->configure() */
				if (ikey->flags & ULOGD_KEYF_INACTIVE)
					continue;

				okey = find_okey_in_stack(ikey->name, pi_cur, &pi_src);
				if (!okey) {
					if (ikey->flags & ULOGD_KEYF_OPTIONAL) {
						ikey->source = NULL;
						continue;
					}

					ulogd_log(ULOGD_ERROR, "cannot find key '%s' in stack\n",
							  ikey->name);
					goto err;
				}

				if (!key_type_eq(ikey, okey)) {
					ulogd_log(ULOGD_FATAL, "type mismatch %s(%s) <-> %s(%s)\n",
							  ikey->name, pi_cur->id,
							  okey->name, pi_src->id);
					goto err;
				}

				ulogd_log(ULOGD_DEBUG, "  %s(%s) -> %s(%s)\n",
						  ikey->name, pi_cur->id, okey->name, pi_src->id);
				ikey->source = okey;
			}
		}
	}

	return 0;

err:
	ikey->source = NULL;
	return -1;
}

/**
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
 * The notion P>start means "call function 'start' of plugin P".
 *
 * Note that currently the action in I>configure handler should be
 * completely stateless, as there currently is no I>unconfigure handler.
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
 * Generic stack iterator.
 */
int
stack_for_each(int (* cb)(struct ulogd_pluginstance_stack *, void *),
			   void *arg)
{
	struct ulogd_pluginstance_stack *stack;
	int sum = 0;

	llist_for_each_entry(stack, &ulogd_pi_stacks, stack_list) {
		int ret;

		if ((ret = cb(stack, arg)) < 0)
			return -1;

		sum += ret;
	}

	return sum;
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
			if ((ret = ulogd_upi_configure(pi)) < 0) {
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

	if (stack->flags & ULOGD_SF_FSM)
		return 0;

	pr_fn_debug("stack=%p\n", stack);

	llist_add_tail(&stack->state_link, &stack_fsm_list);

	stack->flags |= ULOGD_SF_FSM;

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
	  if (stack_fsm(stack) < 0)
		  return;

	  if (stack->state == PsStarted) {
		  llist_del(&stack->state_link);
		  stack->flags &= ~ULOGD_SF_FSM;

		  if (llist_empty(&stack_fsm_list))
			  ulogd_unregister_timer(&stack_fsm_timer);
      }
  }
}

int
stack_reconfigure(struct ulogd_pluginstance_stack *stack)
{
	struct ulogd_pluginstance *pi;

	llist_for_each_entry(pi, &stack->list, list) {
		if (pi->state != PsInit)
			ulogd_upi_stop(pi);
	}

	return stack_fsm(stack);
}

int
upi_for_each(int (* cb)(struct ulogd_pluginstance *, void *), void *arg)
{
	struct ulogd_pluginstance_stack *stack;
	int sum = 0;

	pr_debug("%s: cb=%p\n", __func__, cb);

	llist_for_each_entry(stack, &ulogd_pi_stacks, stack_list) {
		struct ulogd_pluginstance *pi;

		llist_for_each_entry(pi, &stack->list, list) {
			int ret;

			if ((ret = cb(pi, arg)) < 0)
				return -1;

			sum += ret;
		}
	}

	return sum;
}

struct ulogd_pluginstance *
ulogd_upi_alloc_init(struct ulogd_plugin *pl, const char *pi_id,
					 struct ulogd_pluginstance_stack *stack)
{
	unsigned int size;
	struct ulogd_pluginstance *pi;
	void *ptr;

	size = sizeof(struct ulogd_pluginstance);
	size += pl->priv_size;
	if (pl->config_kset) {
		size += sizeof(struct config_keyset);
		if (pl->config_kset->num_ces)
			size += pl->config_kset->num_ces *
						sizeof(struct config_entry);
	}
	size += pl->input.num_keys * sizeof(struct ulogd_key);
	size += pl->output.num_keys * sizeof(struct ulogd_key);

	if ((pi = malloc(size)) == NULL)
		return NULL;

	/* initialize */
	memset(pi, 0, size);

	INIT_LLIST_HEAD(&pi->list);
	INIT_LLIST_HEAD(&pi->state_link);

	pi->plugin = pl;
	pi->stack = stack;
	memcpy(pi->id, pi_id, sizeof(pi->id));

	ptr = (void *)pi + sizeof(*pi);

	ptr += pl->priv_size;
	/* copy config keys */
	if (pl->config_kset) {
		pi->config_kset = ptr;
		ptr += sizeof(struct config_keyset);
		pi->config_kset->num_ces = pl->config_kset->num_ces;
		if (pi->config_kset->num_ces) {
			ptr += pi->config_kset->num_ces
						* sizeof(struct config_entry);
			memcpy(pi->config_kset->ces, pl->config_kset->ces,
			       pi->config_kset->num_ces
			       			*sizeof(struct config_entry));
		}
	} else
		pi->config_kset = NULL;

	/* copy input keys */
	if (pl->input.num_keys) {
		pi->input.num_keys = pl->input.num_keys;
		pi->input.keys = ptr;
		memcpy(pi->input.keys, pl->input.keys,
		       pl->input.num_keys * sizeof(struct ulogd_key));
		ptr += pl->input.num_keys * sizeof(struct ulogd_key);
	}

	/* copy input keys */
	if (pl->output.num_keys) {
		pi->output.num_keys = pl->output.num_keys;
		pi->output.keys = ptr;
		memcpy(pi->output.keys, pl->output.keys,
		       pl->output.num_keys * sizeof(struct ulogd_key));
	}

	ulogd_upi_set_state(pi, PsInit);

	return pi;
}

int
ulogd_wildcard_inputkeys(struct ulogd_pluginstance *upi)
{
	struct ulogd_pluginstance_stack *stack = upi->stack;
	struct ulogd_pluginstance *pi_cur;
	unsigned int num_keys = 0;
	unsigned int index = 0;

	/* ok, this is a bit tricky, and probably requires some documentation.
	 * Since we are a output plugin (SINK), we can only be the last one
	 * in the stack.  Therefore, all other (input/filter) plugins, area
	 * already linked into the stack.  This means, we can iterate over them,
	 * get a list of all the keys, and create one input key for every output
	 * key that any of the upstream plugins provide.  By the time we resolve
	 * the inter-key pointers, everything will work as expected. */

	if (upi->input.keys)
		free(upi->input.keys);

	/* first pass: count keys */
	llist_for_each_entry(pi_cur, &stack->list, list) {
		ulogd_log(ULOGD_DEBUG, "iterating over pluginstance '%s'\n",
			  pi_cur->id);
		num_keys += pi_cur->plugin->output.num_keys;
	}

	ulogd_log(ULOGD_DEBUG, "allocating %u input keys\n", num_keys);
	upi->input.keys = malloc(sizeof(struct ulogd_key) * num_keys);
	if (!upi->input.keys)
		return -ENOMEM;

	/* second pass: copy key names */
	llist_for_each_entry(pi_cur, &stack->list, list) {
		const struct ulogd_keyset *keyset = &pi_cur->plugin->output;
		int i;

		for (i = 0; i < keyset->num_keys; i++) {
			pr_debug("%s: copy key '%s' from plugin '%s'\n", upi->id,
					 keyset->keys[i].name, pi_cur->id);

			upi->input.keys[index++] = pi_cur->output.keys[i];
		}
	}

	upi->input.num_keys = num_keys;

	return 0;
}

/* clean results (set all values to 0 and free pointers) */
static void
stack_clean_results(const struct ulogd_pluginstance_stack *stack)
{
	struct ulogd_pluginstance *pi;

	/* iterate through plugin stack */
	llist_for_each_entry(pi, &stack->list, list) {
		int i;

		/* iterate through input keys of pluginstance */
		for (i = 0; i < pi->output.num_keys; i++) {
			struct ulogd_key *key = &pi->output.keys[i];

			key_reset(key);
		}
	}
}

/**
 * Propagate results to all downstream plugins in the stack
 *
 * @arg pi		%ulogd_pluginstance to propagate
 * @arg flags	additional flags to pass to downstream flags
 */
void
ulogd_propagate_results(struct ulogd_pluginstance *pi, unsigned *flags)
{
	struct ulogd_pluginstance_stack *stack = pi->stack;

	/* iterate over remaining plugin stack */
	llist_for_each_entry_continue(pi, &stack->list, list) {
		int ret;

		ret = ulogd_upi_interp(pi, flags);
		switch (ret) {
		case ULOGD_IRET_OK:
			/* we shall continue travelling down the stack */
			continue;

		case ULOGD_IRET_ERR:
			upi_log(pi, ULOGD_NOTICE, "error propagating results\n");
			/* fallthrough */

		case ULOGD_IRET_AGAIN:
		case ULOGD_IRET_STOP:
			/* we shall abort further iteration of the stack */
			goto out;

		default:
			BUG();
		}
	}

out:
	stack_clean_results(stack);
}

/* try to lookup a registered plugin for a given name */
struct ulogd_plugin *
ulogd_find_plugin(const char *name)
{
	struct ulogd_plugin *pl;

	llist_for_each_entry(pl, &ulogd_plugins, list) {
		if (strcmp(name, pl->name) == 0)
			return pl;
	}

	return NULL;
}

/* the function called by all plugins for registering themselves */
void
ulogd_register_plugin(struct ulogd_plugin *me)
{
	if (me->rev != ULOGD_PLUGIN_REVISION) {
		ulogd_log(ULOGD_NOTICE, "plugin '%s' has incompatible revision %d\n",
				  me->name, me->rev);
		return;
	}

	if (ulogd_find_plugin(me->name)) {
		ulogd_log(ULOGD_NOTICE, "plugin '%s' already registered\n",
				me->name);
		exit(EXIT_FAILURE);
	}

	llist_add(&me->list, &ulogd_plugins);

	ulogd_log(ULOGD_DEBUG, "registered plugin '%s'\n", me->name);
}

/**
 * Configure a plugin.
 *
 * An instance might return %ULOGD_IRET_AGAIN, in which case a configure
 * is tried later.
 */
int
ulogd_upi_configure(struct ulogd_pluginstance *pi)
{
	int ret;

	BUG_ON(pi->state != PsInit && pi->state != PsConfiguring);

	ulogd_log(ULOGD_DEBUG, "configuring '%s'\n", pi->id);

	if (pi->config_kset != NULL) {
		ulogd_upi_reset_cfg(pi);

		if (config_parse_file(pi->id, pi->config_kset) < 0)
			return ULOGD_IRET_ERR;
	}

	if (pi->plugin->configure == NULL)
		goto done;

	ulogd_upi_set_state(pi, PsConfiguring);

	if ((ret = pi->plugin->configure(pi)) < 0) {
		if (ret == ULOGD_IRET_AGAIN)
			stack_fsm_add(pi->stack);

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
 * is tried again later.
 */
int
ulogd_upi_start(struct ulogd_pluginstance *pi)
{
	int ret;
	
	BUG_ON(pi->state != PsConfigured && pi->state != PsStarting);
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

/**
 * Stop a plugin instance.
 */
int
ulogd_upi_stop(struct ulogd_pluginstance *pi)
{
	int i;

	ulogd_log(ULOGD_DEBUG, "stopping '%s'\n", pi->id);

	if (pi->plugin->stop != NULL)
		pi->plugin->stop(pi);

	/* clear source links */
	for (i = 0; i < pi->input.num_keys; i++)
		pi->input.keys[i].source = NULL;

	ulogd_upi_set_state(pi, PsInit);

	return 0;
}

/**
 * Packet interpreter called per packet.
 *
 * If an error occurs the plugin is stopped.  If the plugin returns
 * %ULOGD_IRET_AGAIN it will additionally be scheduled for a restart
 * later.
 */
int
ulogd_upi_interp(struct ulogd_pluginstance *pi, unsigned *flags)
{
	int ret;

	if (pi->state != PsStarted)
		return 0;

	if ((ret = pi->plugin->interp(pi, flags)) < 0) {
		ulogd_upi_stop(pi);

		if (ret == ULOGD_IRET_AGAIN) {
			if (stack_fsm_add(pi->stack) < 0)
				return ULOGD_IRET_ERR;

			return 0;
		}

		return ret;
	}

	return 0;
}

/**
 * Call a plugin-specific signal handler.
 *
 * If an error occurs the plugin is stopped.  If the plugin returns
 * %ULOGD_IRET_AGAIN it will additionally be scheduled for a restart
 * later.
 */
void
ulogd_upi_signal(struct ulogd_pluginstance *pi, int signo)
{
	int ret;

	if (pi->plugin->signal == NULL)
		return;

	if ((ret = pi->plugin->signal(pi, signo)) < 0) {
		ulogd_upi_stop(pi);

		if (ret == ULOGD_IRET_AGAIN)
			stack_fsm_add(pi->stack);
	}
}

int
ulogd_upi_error(struct ulogd_pluginstance *pi, int err)
{
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

	size = sizeof(struct config_keyset)
		+ pi->plugin->config_kset->num_ces * sizeof(struct config_entry);

	memcpy(pi->config_kset, pi->plugin->config_kset, size);

	return 0;
}

/* key API */
int
ulogd_value_to_ascii(const struct ulogd_value *val, char *buf, size_t len)
{
	int nchars = 0;

	switch (val->type) {
	case ULOGD_RET_INT8:
	case ULOGD_RET_INT16:
	case ULOGD_RET_INT32:
	case ULOGD_RET_UINT8:
	case ULOGD_RET_UINT16:
	case ULOGD_RET_UINT32:
	case ULOGD_RET_BOOL:
		nchars = utoa(val->ui32, buf, len);
		break;

	case ULOGD_RET_INT64:
	case ULOGD_RET_UINT64:
		nchars = utoa(val->ui64, buf, len);
		break;

	case ULOGD_RET_STRING:
		strncpy(buf, val->str, len - 1);
		buf[len - 1] = '\0';
		nchars = strlen(val->str);
		break;

	case ULOGD_RET_IPADDR:
		inet_ntop(AF_INET, &val->ui32, buf, len);
		nchars = strlen(buf);
		break;

	case ULOGD_RET_IP6ADDR:
		inet_ntop(AF_INET6, &val->in6, buf, len);
		nchars = strlen(buf);
		break;

	default:
		break;
	}

	return nchars;
}

static void
__check_set(const struct ulogd_key *key, unsigned type)
{
	BUG_ON(!key);

#ifndef NDEBUG
	if (UNLIKELY(!(key_type(key) & type))) {
		ulogd_log(ULOGD_FATAL, "%s: invalid key set (%d <-> %d)\n",
				  key->name, key_type(key), type);
		BUG();
	}
#endif
}

void
key_set_i8(struct ulogd_key *key, int v)
{
	__check_set(key, ULOGD_RET_INT8);

	key->val.i8 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_i16(struct ulogd_key *key, int v)
{
	__check_set(key, ULOGD_RET_INT16);

	key->val.i16 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_i32(struct ulogd_key *key, int v)
{
	__check_set(key, ULOGD_RET_INT32);

	key->val.i32 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_u8(struct ulogd_key *key, unsigned v)
{
	__check_set(key, ULOGD_RET_UINT8);

	key->val.i8 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_u16(struct ulogd_key *key, unsigned v)
{
	__check_set(key, ULOGD_RET_UINT16);

	key->val.ui16 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_u32(struct ulogd_key *key, unsigned v)
{
	__check_set(key, ULOGD_RET_UINT32 | ULOGD_RET_IPADDR);

	key->val.ui32 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_i64(struct ulogd_key *key, int64_t v)
{
	__check_set(key, ULOGD_RET_INT64);

	key->val.i64 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_u64(struct ulogd_key *key, uint64_t v)
{
	__check_set(key, ULOGD_RET_UINT64);

	key->val.ui64 = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_bool(struct ulogd_key *key, bool v)
{
	__check_set(key, ULOGD_RET_BOOL);

	key->val.b = v;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_ptr(struct ulogd_key *key, void *ptr)
{
	__check_set(key, ULOGD_RET_RAW);

	key->val.ptr = ptr;	
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_str(struct ulogd_key *key, char *str)
{
	__check_set(key, ULOGD_RET_STRING);

	key->val.str = str;
	key->flags |= ULOGD_RETF_VALID;
}

void
key_set_in6(struct ulogd_key *key, const struct in6_addr *addr)
{
	__check_set(key, ULOGD_RET_IP6ADDR);

	memcpy(&key->val.in6, addr, sizeof(struct in6_addr));
	key->flags |= ULOGD_RETF_VALID;
}

static void
__check_get(const struct ulogd_key *key, unsigned type)
{
	BUG_ON(!key);
	BUG_ON(!key_valid(key));

#ifndef NDEBUG
	if (UNLIKELY(!(key_type(key) & type))) {
		ulogd_log(ULOGD_FATAL, "%s: invalid key access (%d <-> %d)\n",
				  key->name, key_type(key), type);
		BUG();
	}
#endif
}

int
key_i8(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT8);

	return key->val.i8;
}

int
key_i16(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT16);

	return key->val.i16;
}

int
key_i32(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT32);

	return key->val.i32;
}

unsigned
key_u8(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_UINT8);

	return key->val.i8;
}

unsigned
key_u16(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_UINT16);

	return key->val.i16;
}

unsigned
key_u32(const struct ulogd_key *key)
{
	/* currently, IP addresses are encoded as u32.  A strong typesafety
	   might require to add key_get_ipaddr() as well. */
	__check_get(key, ULOGD_RET_UINT32 | ULOGD_RET_IPADDR);

	return key->val.i32;
}

int64_t
key_i64(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_INT64);

	return key->val.i64;
}

uint64_t
key_u64(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_UINT64);

	return key->val.i64;
}

bool
key_bool(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_BOOL);

	return !!key->val.b;
}

void *
key_ptr(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_RAW);

	return key->val.ptr;
}

char *
key_str(const struct ulogd_key *key)
{
	__check_get(key, ULOGD_RET_STRING);

	return key->val.str;
}

void
key_in6(const struct ulogd_key *key, struct in6_addr *addr)
{
	__check_get(key, ULOGD_RET_IP6ADDR);

	memcpy(addr, &key->val.in6, sizeof(*addr));
}

int key_src_i8(const struct ulogd_key *key)
{
	return key_i8(key_src(key));
}

int
key_src_i16(const struct ulogd_key *key)
{
	return key_i16(key_src(key));
}

int
key_src_i32(const struct ulogd_key *key)
{
	return key_i32(key_src(key));
}

int64_t
key_src_i64(const struct ulogd_key *key)
{
	return key_i64(key_src(key));
}

unsigned
key_src_u8(const struct ulogd_key *key)
{
	return key_u8(key_src(key));
}

unsigned
key_src_u16(const struct ulogd_key *key)
{
	return key_u16(key_src(key));
}

unsigned
key_src_u32(const struct ulogd_key *key)
{
	return key_u32(key_src(key));
}

uint64_t
key_src_u64(const struct ulogd_key *key)
{
	return key_u64(key_src(key));
}

bool
key_src_bool(const struct ulogd_key *key)
{
	return key_bool(key_src(key));
}

void *
key_src_ptr(const struct ulogd_key *key)
{
	return key_ptr(key_src(key));
}

char *
key_src_str(const struct ulogd_key *key)
{
	return key_str(key_src(key));
}

void
key_src_in6(const struct ulogd_key *key, struct in6_addr *addr)
{
	return key_in6(key_src(key), addr);
}

enum ulogd_ktype
key_type(const struct ulogd_key *key)
{
	return key->val.type;
}

void
key_free(struct ulogd_key *key)
{
	if (key->flags & ULOGD_RETF_FREE) {
		free(key->val.ptr);
		key->val.ptr = NULL;
	}
}

void
key_reset(struct ulogd_key *key)
{
	if (!(key->flags & ULOGD_RETF_VALID))
		return;

	if (key->flags & ULOGD_RETF_FREE)
		key_free(key);

	/* use in6, because this happens to be the largest type */
	memset(&key->val.in6, 0, sizeof(key->val.in6));
	key->flags &= ~ULOGD_RETF_VALID;
}

/**
 * Compare two keys.
 *
 * Handle IP addresses and unsigned int 32bit as equal.  The check for
 * %ULOGD_RET_NONE is necessary for plugins which do not set key type
 * on keys, e. g. database plugins which determine keys from the table
 * schema on startup.
 */
bool
key_type_eq(const struct ulogd_key *k1, const struct ulogd_key *k2)
{
	unsigned t1, t2;

	if (key_type(k1) == ULOGD_RET_NONE || key_type(k2) == ULOGD_RET_NONE)
		return true;

	t1 = (key_type(k1) == ULOGD_RET_IPADDR) ? ULOGD_RET_UINT32 : key_type(k1);
	t2 = (key_type(k2) == ULOGD_RET_IPADDR) ? ULOGD_RET_UINT32 : key_type(k2);

	return t1 == t2;
}

int
ulogd_key_size(const struct ulogd_key *key)
{
	int ret;

	switch (key_type(key)) {
	case ULOGD_RET_NONE:
		BUG();
		break;

	case ULOGD_RET_INT8:
	case ULOGD_RET_UINT8:
	case ULOGD_RET_BOOL:
		ret = 1;
		break;

	case ULOGD_RET_INT16:
	case ULOGD_RET_UINT16:
		ret = 2;
		break;

	case ULOGD_RET_INT32:
	case ULOGD_RET_UINT32:
	case ULOGD_RET_IPADDR:
		ret = 4;
		break;

	case ULOGD_RET_INT64:
	case ULOGD_RET_UINT64:
		ret = 8;
		break;

	case ULOGD_RET_IP6ADDR:
		ret = 16;
		break;

	case ULOGD_RET_STRING:
		ret = strlen(key_str(key));
		break;

	case ULOGD_RET_RAW:
		ret = key->len;
		break;
	}

	return ret;
}

int
ulogd_init_keyset(struct ulogd_keyset *set, unsigned flags)
{
	if (!set || set->num_keys <= 0)
		return -1;

	set->keys = calloc(set->num_keys, sizeof(struct ulogd_key));
	if (!set->keys) {
		ulogd_log(ULOGD_FATAL, "%s: %s\n", __func__, strerror(ENOMEM));
		return -1;
	}

	set->flags = flags;

	return 0;
}

void
ulogd_dump_keyset(const struct ulogd_keyset *set)
{
	int i;

	if (!set)
		return;

	for (i = 0; i < set->num_keys; i++) {
		struct ulogd_key *key = &set->keys[i];
		printf("key[%02d]: name='%s' type='%d'\n", i, key->name,
			   key_type(key));
	}
}

void
ulogd_free_keyset(struct ulogd_keyset *set)
{
	int i;

	if (!set || !set->num_keys)
		return;

	if (set->flags & KEYSET_F_ALLOC) {
		for (i = 0; i < set->num_keys; i++)
			free(set->keys[i].name);
	}

	free(set->keys);
	set->num_keys = 0;
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

	ulogd_init_timer(&stack_fsm_timer, 5 SEC, stack_fsm_timer_cb, NULL,
		TIMER_F_PERIODIC);

	return 0;
}

/* accessors to the plugin configuration space */
struct config_entry *
ulogd_config_get(const struct ulogd_pluginstance *pi, int off)
{
	struct config_keyset *set = pi->config_kset;

	if (off < 0 || off >= set->num_ces)
		return NULL;
	
	return &set->ces[off];
}

int
ulogd_config_int(const struct ulogd_pluginstance *pi, int off)
{
	struct config_entry *ce = ulogd_config_get(pi, off);

	return config_int(ce);
}

char *
ulogd_config_str(const struct ulogd_pluginstance *pi, int off)
{
	struct config_entry *ce = ulogd_config_get(pi, off);

	return config_str(ce);
}

void
ulogd_config_set_int(struct ulogd_pluginstance *pi, int off, int v)
{
	struct config_entry *ce = ulogd_config_get(pi, off);

	config_set_int(ce, v);
}

void
ulogd_config_set_str(struct ulogd_pluginstance *pi, int off, const char *str)
{
	struct config_entry *ce = ulogd_config_get(pi, off);

	return config_set_str(ce, str);
}
