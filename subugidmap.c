/* bubblewrap-oci
 * Copyright (C) 2016, 2017 Giuseppe Scrivano
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

#include <config.h>
#include "subugidmap.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>

static void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

static void
cleanup_file (FILE **f)
{
  FILE *file = *f;
  if (file)
    (void) fclose (file);
}

#define cleanup_free __attribute__((cleanup (cleanup_freep)))
#define cleanup_file __attribute__((cleanup (cleanup_file)))

/*if subuid or subgid exist, take the first range for the user */
int
getsubidrange (uid_t id, int is_uid, uint32_t *from, uint32_t *len)
{
  cleanup_file FILE *input = NULL;
  cleanup_free char *lineptr = NULL;
  size_t lenlineptr = 0, len_name;
  const char *name;

  if (is_uid)
    {
      struct passwd *pwd = getpwuid (id);
      if (pwd == NULL)
        return -1;
      name = pwd->pw_name;
    }
  else
    {
      struct group *grp = getgrgid (id);
      if (grp == NULL)
        return -1;
      name = grp->gr_name;
    }

  len_name = strlen (name);

  input = fopen (is_uid ? "/etc/subuid" : "/etc/subgid", "r");
  if (input == NULL)
    return -1;

  for (;;)
    {
      char *endptr;
      int read = getline (&lineptr, &lenlineptr, input);
      if (read < 0)
        return -1;

      if (read < len_name + 2)
        continue;

      if (memcmp (lineptr, name, len_name) || lineptr[len_name] != ':')
        continue;

      *from = strtoull (&lineptr[len_name + 1], &endptr, 10);

      if (endptr >= &lineptr[read])
        return -1;

      *len = strtoull (&endptr[1], &endptr, 10);

      return 0;
    }
}
