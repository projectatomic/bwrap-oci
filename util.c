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
#include <unistd.h>
#include <stdlib.h>
#include <error.h>
#include <stdio.h>
#include <glib.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <seccomp.h>
#include <errno.h>
#include <glib/gprintf.h>
#include <string.h>
#include <sys/socket.h>
#include <gio/gunixinputstream.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "safe-read-write.h"
#include "subugidmap.h"

gchar *
get_run_directory ()
{
  gchar run_directory_buffer[64], *ret;
  const char *root = getenv ("XDG_RUNTIME_DIR");
  struct stat st;
  int r;

  if (root == NULL)
    {
      g_sprintf (run_directory_buffer, "/run/user/%d", getuid ());
      root = run_directory_buffer;
    }


  ret = g_strdup_printf ("%s/%s", root, "bwrap-oci");
  r = lstat (ret, &st);
  if (r != 0)
    {
      if (errno == ENOENT)
        mkdir (ret, 0700);
      else
        error (EXIT_FAILURE, errno, "error lstat %s", ret);
    }
  return ret;
}
