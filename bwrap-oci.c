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
#include "util.h"
#include "list.h"
#include "run.h"
#include "spec.h"
#include "kill.h"

static gboolean opt_dry_run;
static gboolean opt_version;
static gboolean opt_enable_hooks;
static gboolean opt_systemd_cgroup;
static const char *opt_configuration = "config.json";
static char *opt_bwrap = BWRAP;
static char *opt_pid_file;
static char *opt_bundle;
static gboolean opt_detach;

static GOptionEntry entries[] =
{
  { "configuration", 'c', 0, G_OPTION_ARG_STRING, &opt_configuration, "Configuration file", "FILE" },
  { "dry-run", 0, 0, G_OPTION_ARG_NONE, &opt_dry_run, "Print the command line for bubblewrap", NULL },
  { "enable-hooks", 0, 0, G_OPTION_ARG_NONE, &opt_enable_hooks, "Execute the OCI hooks", NULL },
  { "detach", 'd', 0, G_OPTION_ARG_NONE, &opt_detach, "Do not wait for termination", NULL },
  { "version", 0, 0, G_OPTION_ARG_NONE, &opt_version, "Print version information and exit", NULL },
  { "systemd-cgroup", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &opt_systemd_cgroup, "Use systemd cgroup", NULL}, /* noop, added for compatibility with runC.  */
  { "bwrap", 0, 0, G_OPTION_ARG_STRING, &opt_bwrap, "Specify the path to the bubblewrap executable to use", "PATH" },
  { "pid-file", 0, 0, G_OPTION_ARG_STRING, &opt_pid_file, "Specify the path to the file where write the PID of the sandboxed process", "PIDFILE" },
  { "bundle", 'b', 0, G_OPTION_ARG_STRING, &opt_bundle, "Specify the path to the bundle", "PATH" },
  { NULL }
};

static const char *summary = "\
List of commands:                                               \
\n  delete CONTAINER - delete a stopped container               \
\n  list - list current containers                              \
\n  run [CONTAINER] - run a container with id CONTAINER           \
\n  kill CONTAINER SIGNAL - kill CONTAINER with signal SIGNAL   \
\n  spec - generate a config.json file   \
";

int
main (int argc, char *argv[])
{
  const char *cmd = "run";
  GOptionContext *opt_context;
  GError *gerror = NULL;

  opt_context = g_option_context_new ("[COMMAND] [ARGUMENTS] - converter from OCI configuration to bubblewrap command line");

  g_option_context_set_summary (opt_context, summary);

  g_option_context_add_main_entries (opt_context, entries, PACKAGE_STRING);
  if (!g_option_context_parse (opt_context, &argc, &argv, &gerror))
    {
      error (EXIT_FAILURE, 0, "option parsing failed: %s", gerror->message);
    }
  g_option_context_free (opt_context);

  if (opt_version)
    {
      g_print ("%s\n", PACKAGE_STRING);
      exit (EXIT_SUCCESS);
    }
  if (opt_dry_run)
    set_test_environment (TRUE);
  set_bwrap_path (opt_bwrap);

  if (argc > 1)
    cmd = argv[1];

  if (g_strcmp0 (cmd, "run") == 0)
    {
      const char *id;

      if (opt_bundle && chdir (opt_bundle) < 0)
        error (EXIT_FAILURE, errno, "chdir");

      if (argc > 2)
        id = argv[2];
      else
        {
          cleanup_free char *cwd = get_current_dir_name ();
          if (cwd == NULL)
            error (EXIT_FAILURE, errno, "error cwd");
          id = g_strdup (basename (cwd));
        }
      return run_container (id, opt_configuration,
                            opt_detach,
                            opt_pid_file,
                            opt_enable_hooks,
                            opt_dry_run);
    }
  else if (g_strcmp0 (cmd, "delete") == 0)
    {
      if (argc < 3)
        error (EXIT_FAILURE, 0, "delete needs an argument");

      delete_container (argv[2]);
    }
  else if (g_strcmp0 (cmd, "list") == 0)
    {
      list_containers ();
    }
    else if (g_strcmp0 (cmd, "kill") == 0)
    {
      if (argc < 4)
        error (EXIT_FAILURE, 0, "kill needs two arguments");
      kill_container (argv[2], argv[3]);
    }
  else if (g_strcmp0 (cmd, "spec") == 0)
    {
      spec ();
    }
  else
    {
      error (EXIT_FAILURE, 0, "unknown command %s", cmd);
      _exit (1);
    }
}
