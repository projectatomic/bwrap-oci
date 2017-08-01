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
#include "util.h"
#include "kill.h"
#include <error.h>
#include <stdlib.h>
#include <errno.h>

void
kill_container (const char *name, const char *signal)
{
  cleanup_free gchar *run_directory = get_run_directory ();
  cleanup_free gchar *path = NULL;
  pid_t pid;
  int r;
  long signal_value;
  char *endptr = NULL;

  path = g_strdup_printf ("%s/%s/status.json", run_directory, name);

  if (! file_exist_p ("", path))
    error (EXIT_FAILURE, 0, "container %s doesn't exist", name);

  read_container_status_file (path, &pid, NULL);

  if (pid == 0)
    error (EXIT_FAILURE, 0, "container %s doesn't exist", name);

  errno = 0;
  signal_value = strtol (signal, &endptr, 10);
  if (errno != 0 || signal_value == 0 || *endptr != '\0')
    error (EXIT_FAILURE, errno, "invalid signal specified");

  r = kill (pid, signal_value);
  if (r < 0)
    error (EXIT_FAILURE, errno, "kill %lu", signal_value);
}
