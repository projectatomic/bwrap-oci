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



/***
  This part is taken from systemd:

  Copyright 2010 Lennart Poettering
*/
#if defined __i386__ || defined __x86_64__

/* The precise definition of __O_TMPFILE is arch specific, so let's
 * just define this on x86 where we know the value. */

#ifndef __O_TMPFILE
#define __O_TMPFILE     020000000
#endif

/* a horrid kludge trying to make sure that this will fail on old kernels */
#ifndef O_TMPFILE
#define O_TMPFILE (__O_TMPFILE | O_DIRECTORY)
#endif

#endif

static GHashTable *bwrap_options = NULL;
static const gchar *bwrap_path = BWRAP;

void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

void
cleanup_filep (FILE **f)
{
  FILE *file = *f;
  if (file)
    (void) fclose (file);
}

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

uint32_t
get_seccomp_operator (const char *name)
{
  if (g_strcmp0 (name, "SCMP_CMP_NE") == 0)
    return SCMP_CMP_NE;
  if (g_strcmp0 (name, "SCMP_CMP_LT") == 0)
    return SCMP_CMP_LT;
  if (g_strcmp0 (name, "SCMP_CMP_LE") == 0)
    return SCMP_CMP_LE;
  if (g_strcmp0 (name, "SCMP_CMP_EQ") == 0)
    return SCMP_CMP_EQ;
  if (g_strcmp0 (name, "SCMP_CMP_GE") == 0)
    return SCMP_CMP_GE;
  if (g_strcmp0 (name, "SCMP_CMP_GT") == 0)
    return SCMP_CMP_GT;
  if (g_strcmp0 (name, "SCMP_CMP_MASKED_EQ") == 0)
    return SCMP_CMP_MASKED_EQ;
  else
    error (EXIT_FAILURE, 0, "unsupported seccomp operator %s\n", name);

  return -1;
}

guint64
get_seccomp_action (const char *name)
{
  if (g_strcmp0 (name, "SCMP_ACT_KILL") == 0)
    return SCMP_ACT_KILL;
  if (g_strcmp0 (name, "SCMP_ACT_ALLOW") == 0)
    return SCMP_ACT_ALLOW;
  if (g_strcmp0 (name, "SCMP_ACT_TRAP") == 0)
    return SCMP_ACT_TRAP;
  if (g_strcmp0 (name, "SCMP_ACT_ERRNO") == 0)
    return SCMP_ACT_ERRNO(EPERM);
  if (g_strcmp0 (name, "SCMP_ACT_TRACE") == 0)
    return SCMP_ACT_TRACE(EPERM);
  else
    error (EXIT_FAILURE, 0, "unsupported seccomp action %s\n", name);

  return -1;
}

void
set_bwrap_path (const char *path)
{
  bwrap_path = path;
}

const char *
get_bwrap_path ()
{
  return bwrap_path;
}

static void
read_bwrap_help ()
{
  const gchar *argv[] = {bwrap_path, "--help", NULL};
  gchar *output = NULL;
  gint exit_status;
  gchar *end, *it;

  if (g_spawn_sync (NULL, (gchar **) argv, NULL, G_SPAWN_DEFAULT, NULL,
                    NULL, &output, NULL, &exit_status, NULL) == FALSE)
    {
      error (EXIT_FAILURE, errno, "error running bwrap --help");
    }

  bwrap_options = g_hash_table_new (g_str_hash, g_str_equal);

  for (it = strstr (output, "    --"); it; it = strstr (end + 1, "    --"))
    {
      gchar *value;
      end = strchr (it + 6, ' ');
      if (end == NULL)
        break;
      *end = '\0';

      value = g_strdup (it + 6);
      g_hash_table_insert (bwrap_options, value, value);
    }

  g_free (output);
}

gboolean
bwrap_has_option (const gchar *option)
{
  if (bwrap_options == NULL)
    read_bwrap_help ();
  return g_hash_table_contains (bwrap_options, option);
}

void
write_container_state (const char *container_state, pid_t child_pid, const char *bundle_path)
{
  gchar *path = g_strdup_printf ("%s/status.json", container_state);
  FILE *f = fopen (path, "w");
  if (f != NULL)
    {
      const char *fmt_stdin = "{\"pid\":%i, \"bundlePath\":\"%s\"}";
      char *stdin = g_strdup_printf (fmt_stdin, child_pid, bundle_path);
      fprintf (f, "%s", stdin);
      g_free (stdin);
      fclose (f);
    }
  g_free (path);
}

void
detach_process ()
{
  setsid ();
  if (fork () != 0)
    _exit (EXIT_SUCCESS);
}

static void
write_mapping (const char *program, pid_t pid, uint32_t host_id, uint32_t sandbox_id,
               uint32_t first_subid, uint32_t n_subids)
{
  char arg_buffer[32][16];
  const gchar *argv[32] = { 0 };
  int argc = 0;
  gint exit_status;

#define APPEND_ARGUMENT(x)                        \
  do                                              \
    {                                             \
      g_sprintf (arg_buffer[argc], "%i", x);      \
      argv[argc] = arg_buffer[argc];              \
      argc++;                                     \
    } while (0)

  argv[argc++] = program;
  APPEND_ARGUMENT (pid);

  if (sandbox_id == 0)
    {
      APPEND_ARGUMENT (sandbox_id);
      APPEND_ARGUMENT (host_id);
      APPEND_ARGUMENT (1);

      APPEND_ARGUMENT (1);
      APPEND_ARGUMENT (first_subid);
      APPEND_ARGUMENT (n_subids);
    }
  else if (sandbox_id < n_subids)
    {
      APPEND_ARGUMENT (0);
      APPEND_ARGUMENT (first_subid);
      APPEND_ARGUMENT (sandbox_id);

      APPEND_ARGUMENT (sandbox_id);
      APPEND_ARGUMENT (host_id);
      APPEND_ARGUMENT (1);

      APPEND_ARGUMENT (sandbox_id + 1);
      APPEND_ARGUMENT (first_subid + sandbox_id);
      APPEND_ARGUMENT (n_subids - sandbox_id);
    }
  else
    {
      APPEND_ARGUMENT (0);
      APPEND_ARGUMENT (first_subid);
      APPEND_ARGUMENT (n_subids);

      APPEND_ARGUMENT (sandbox_id);
      APPEND_ARGUMENT (host_id);
      APPEND_ARGUMENT (1);
    }

  argv[argc] = NULL;

  if (g_spawn_sync (NULL, (gchar **) argv, NULL, G_SPAWN_DEFAULT, NULL,
                    NULL, NULL, NULL, &exit_status, NULL) == FALSE ||
      exit_status != 0)
    {
      error (EXIT_FAILURE, errno, "error running %s", program);
    }
}

void
write_user_group_mappings (struct user_mapping *user_mapping, uid_t uid, gid_t gid, pid_t pid)
{
  uid_t current_uid = getuid ();
  gid_t current_gid = getgid ();

  write_mapping ("/usr/bin/newuidmap", pid, current_uid, uid,
                 user_mapping->first_subuid, user_mapping->n_subuid);
  write_mapping ("/usr/bin/newgidmap", pid, current_gid, gid,
                 user_mapping->first_subgid, user_mapping->n_subgid);
}

static int test_environment = -1;

static gboolean
test_environment_p ()
{
  if (test_environment < 0)
    test_environment = getenv ("TEST") ? 1 : 0;
  return test_environment == 1 ? TRUE : FALSE;
}

void
set_test_environment (gboolean status)
{
  test_environment = status;
}

gchar *
format_fd (gchar *buf, int fd)
{
  if (test_environment_p ())
    g_sprintf (buf, "FD");
  else
    g_sprintf (buf, "%i", fd);
  return buf;
}

gboolean
file_exist_p (const char *root, const char *file)
{
  int res;
  struct stat st;
  cleanup_free gchar *fpath = g_strdup_printf ("%s%s", root, file);
  res = lstat (fpath, &st);
  return res == 0;
}

gboolean
can_mask_or_ro_p (const char *path)
{
  int res;
  struct stat st;

  if (test_environment_p ())
    return TRUE;

  if (!g_str_has_prefix (path, "/sys") && !g_str_has_prefix (path, "/proc"))
    return TRUE;

  res = lstat (path, &st);
  return res == 0 && !S_ISDIR (st.st_mode);
}

gchar *
get_bundle_path (const char *rootfs)
{
  gchar *ret;
  cleanup_free gchar *tmp = g_strdup (rootfs);
  ret = canonicalize_file_name(dirname (tmp));
  return ret;
}

char *
create_container (const char *name)
{
  struct stat st;
  int r;
  gchar *dir;
  cleanup_free gchar *run_directory = get_run_directory ();
  dir = g_strdup_printf ("%s/%s", run_directory, name);

  r = lstat (dir, &st);
  if (r == 0)
    error (EXIT_FAILURE, 0, "container %s already exists", name);
  if (r != 0 && errno != ENOENT)
    error (EXIT_FAILURE, errno, "error lstat %s", dir);


  if (mkdir (dir, 0700) < 0)
    error (EXIT_FAILURE, errno, "error mkdir");

  return dir;
}

void
delete_container (const char *name)
{
  cleanup_free gchar *dir = NULL;
  cleanup_free gchar *status = NULL;
  cleanup_free gchar *run_directory = get_run_directory ();
  struct stat st;
  pid_t pid;

  dir = g_strdup_printf ("%s/%s", run_directory, name);
  status = g_strdup_printf ("%s/%s/status.json", run_directory, name);

  if (lstat (dir, &st) < 0 && errno == ENOENT)
    error (EXIT_FAILURE, 0, "container %s does not exist", name);

  read_container_status_file (status, &pid, NULL);
  if (pid_running_p (pid))
    {
      error (EXIT_FAILURE, 0, "can't delete a running container");
    }

  if (unlink (status) < 0)
    error (EXIT_FAILURE, errno, "unlink status file for container %s", name);

  if (rmdir (dir) < 0)
    error (EXIT_FAILURE, errno, "rmdir for container %s", name);
}

int
generate_seccomp_rules_file (scmp_filter_ctx seccomp)
{
  int fd = -1;
  if (seccomp)
    {
      fd = open ("/tmp", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
      if (fd < 0)
        {
          if (errno != EOPNOTSUPP)
            error (EXIT_FAILURE, errno, "error opening temp file");
          else
            {
              char *template = strdup ("/tmp/bwrap-oci-XXXXXX");
              fd = mkstemp (template);
              if (fd < 0)
                error (EXIT_FAILURE, errno, "error opening temp file");
              unlink (template);
              free (template);
            }
        }

      if (seccomp_export_bpf (seccomp, fd) < 0)
        error (EXIT_FAILURE, errno, "error writing seccomp rules file");
      if (lseek (fd, 0, SEEK_SET) < 0)
        error (EXIT_FAILURE, errno, "error seeking seccomp rules file");
    }
  return fd;
}

void
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

  if (pid) {
    tmp = json_object_get_member (root, "pid");
    if (tmp)
      *pid = json_node_get_int (tmp);
    else
      *pid = 0;
  }

  if (bundlePath) {
    tmp = json_object_get_member (root, "bundlePath");
    if (tmp)
      *bundlePath = g_strdup (json_node_get_string (tmp));
    else
      *bundlePath = NULL;
  }

  if (gerror)
    g_error_free (gerror);
  g_object_unref (parser);
}

gboolean
pid_running_p (pid_t pid)
{
  if (pid == 0)
    return FALSE;

  return kill (pid, 0) == 0;
}
