/* bubblewrap-oci
 * Copyright (C) 2016 Giuseppe Scrivano
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef SAFE_BWRAP_OCI_READ_WRITE
# define SAFE_BWRAP_OCI_READ_WRITE

# include <unistd.h>

size_t safe_read (int fd, void *buf, size_t count);
size_t safe_write (int fd, const void *buf, size_t count);

#endif
