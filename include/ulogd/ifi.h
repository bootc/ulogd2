/*
 * ifi.h
 *
 * Maintain a list of network interfaces.
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
 *
 * Holger Eitzenberger, 2006.
 */
#ifndef IFI_H
#define IFI_H

#include <net/if.h>
#include <sys/queue.h>


struct ifi {
	TAILQ_ENTRY(ifi) link;
	unsigned idx;			/* interface index */
	unsigned flags;
	char name[IFNAMSIZ];
	unsigned char lladdr[6];
};


int ifi_init(void);
void ifi_fini(void);

struct ifi *ifi_find_by_idx(unsigned);


#endif /* IFI_H */
