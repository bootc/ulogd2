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
#include <netinet/ether.h>


int ifi_init(void);
void ifi_fini(void);

char *ifi_index2name(int, char *dst, size_t);

/**
 * Get hardware address for interface
 */
uint8_t *ifi_get_hwaddr(int ifi, uint8_t *dst);

/**
 * Get hardware address as string for interface
 */
char *ifi_hwaddr2str(int ifi, char *dst, size_t len);

#endif /* IFI_H */
