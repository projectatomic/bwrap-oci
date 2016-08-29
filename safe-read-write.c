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

#include "safe-read-write.h"
#include <errno.h>

#define safe_io_op(OP)                                  \
  do                                                    \
    {                                                   \
      ssize_t result;                                   \
      do                                                \
        result = OP (fd, buf, count);                   \
      while (result < 0 && errno == EINTR);             \
      return result;                                    \
    }                                                   \
  while (0)

size_t
safe_read (int fd, void *buf, size_t count)
{
  safe_io_op(read);
}

size_t
safe_write (int fd, const void *buf, size_t count)
{
  safe_io_op(write);
}
