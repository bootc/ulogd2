/*
 * common.h
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
#ifndef COMMON_H
#define COMMON_H

#define min(x, y) ({ \
        typeof(x) _x = (x);  typeof(y) _y = (y); \
        _x < _y ? _x : _y; })
#define max(x, y) ({ \
        typeof(x) _x = (x);  typeof(y) _y = (y); \
        _x > _y ? _x : _y; })


#define SEC		* 1
#define MIN		* 60 SEC
#define HOUR	* 60 MIN
#define DAY		* 24 HOUR

#endif /* COMMON_H */
