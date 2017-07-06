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
#include <dirent.h>
#include "safe-read-write.h"
#include "subugidmap.h"
#include "util.h"


static void
read_container_status_file (const char *path, pid_t *pid, char **bundlePath)
{
  GError *gerror = NULL;
  JsonParser *parser;
  JsonObject *root;
  JsonNode *tmp;

  parser = json_parser_new ();
  json_parser_load_from_file (parser, path, &gerror);
  if (gerror)
    error (EXIT_FAILURE, 0, "unable to parse `%s': %s\n", path, gerror->message);

  root = json_node_get_object (json_parser_get_root (parser));

  tmp = json_object_get_member (root, "pid");
  if (tmp)
    *pid = json_node_get_int (tmp);
  else
    *pid = 0;

  tmp = json_object_get_member (root, "bundlePath");
  if (tmp)
    *bundlePath = g_strdup (json_node_get_string (tmp));
  else
    *bundlePath = NULL;

  if (gerror)
    g_error_free (gerror);
  g_object_unref (parser);
}
void
list_containers ()
{
  gchar *run_directory = get_run_directory ();
  DIR *dir = opendir (run_directory);
  struct dirent *dp;
  if (dir == NULL)
    {
      if (errno == ENOENT)
        {
          g_free (run_directory);
          return;
        }
      error (EXIT_FAILURE, errno, "error opening %s", run_directory);
    }

  printf ("%-30s%-10s%-10s%s\n", "NAME", "PID", "STATUS", "BUNDLE");
  do
    {
      gchar *path, *bundlePath;
      const char *process_status;
      pid_t pid;

      if ((dp = readdir(dir)) != NULL)
        {
          if (dp->d_name[0] == '.')
            continue;

          path = g_strdup_printf ("%s/%s/status.json", run_directory, dp->d_name);
          read_container_status_file (path, &pid, &bundlePath);

          process_status = pid_running_p (pid) ? "running" : "stopped";

          printf ("%-30s%-10d%-10s%s\n", dp->d_name, pid, process_status, bundlePath ? : "(none)");

          g_free (path);
          g_free (bundlePath);
        }
  }
  while (dp != NULL);

  closedir (dir);
  g_free (run_directory);
}
