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
#ifdef HAVE_ERROR_H
#include <error.h>
#endif
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
#include "subugidmap.h"
#include "util.h"
#include "run.h"

struct hook
{
  const char *path;
  char **args;
};

static GList *
append_to_list (struct context *context, GList *list, va_list valist)
{
  const char *val;
  while (1)
    {
      val = va_arg (valist, const char *);
      if (val == NULL)
        break;
      list = g_list_append (list, g_strdup (val));
      context->total_elements++;
    }
  return list;
}

static void
collect_options (struct context *context, ...)
{
  va_list valist;
  va_start (valist, context);
  context->options = append_to_list (context, context->options, valist);
  va_end (valist);
}

static void
add_readonly_path (struct context *context, ...)
{
  va_list valist;
  va_start (valist, context);
  context->readonly_paths = append_to_list (context, context->readonly_paths, valist);
  va_end (valist);
}

static void
collect_args (struct context *context, ...)
{
  va_list valist;
  va_start (valist, context);
  context->args = append_to_list (context, context->args, valist);
  va_end (valist);
}

static void
do_hooks (struct context *con, JsonNode *rootval)
{
  const char *kind_name[2] = {"prestart", "poststop"};
  int kind;
  JsonObject *root = json_node_get_object (rootval);
  for (kind = 0; kind < 2; kind++)
    {
      JsonNode *namespaces;
      GList *members;
      GList *iter;
      gsize i;
      if (!json_object_has_member (root, kind_name[kind]))
        continue;

      namespaces = json_object_get_member (root, kind_name[kind]);
      members = json_array_get_elements (json_node_get_array (namespaces));
      for (iter = members; iter; iter = iter->next)
        {
          struct hook *hook = malloc (sizeof *hook);
          GVariant *path, *args, *variant = json_gvariant_deserialize (iter->data, "a{sv}", NULL);

          if (variant == NULL)
            error (EXIT_FAILURE, 0, "error while deserializing hooks\n");

          path = g_variant_lookup_value (variant, "path", G_VARIANT_TYPE_STRING);
          if (path)
            hook->path = g_variant_get_string (path, NULL);

          args = g_variant_lookup_value (variant, "args", G_VARIANT_TYPE_ARRAY);

          if (!args)
            hook->args = NULL;
          else
            {
              hook->args = malloc ((g_variant_n_children (args) + 1) * sizeof (char *));
              for (i = 0; i < g_variant_n_children (args); i++)
                {
                  char *val = NULL;
                  GVariant *child = g_variant_get_child_value (g_variant_get_child_value (args, i), 0);
                  g_variant_get (child, "s", &val);
                  hook->args[i] = val;
                }
              hook->args[i] = NULL;
            }
          if (kind == 0)
            con->prestart_hooks = g_list_append (con->prestart_hooks, hook);
          else
            con->poststop_hooks = g_list_append (con->poststop_hooks, hook);
        }
    }
}

static void
do_linux (struct context *con, JsonNode *rootval)
{
  JsonObject *root = json_node_get_object (rootval);
  if (json_object_has_member (root, "namespaces"))
    {
      JsonNode *namespaces;
      GList *members;
      GList *iter;
      namespaces = json_object_get_member (root, "namespaces");
      members = json_array_get_elements (json_node_get_array (namespaces));
      collect_options (con, "--unshare-cgroup", NULL);
      for (iter = members; iter; iter = iter->next)
        {
          const char *typeval;
          GVariant *type, *variant = json_gvariant_deserialize (iter->data, "a{sv}", NULL);

          if (variant == NULL)
            error (EXIT_FAILURE, 0, "error while deserializing namespaces\n");

          type = g_variant_lookup_value (variant, "type", G_VARIANT_TYPE_STRING);
          typeval = g_variant_get_string (type, NULL);
          if (g_strcmp0 (typeval, "user") == 0)
            collect_options (con, "--unshare-user", NULL);
          else if (g_strcmp0 (typeval, "ipc") == 0)
            collect_options (con, "--unshare-ipc", NULL);
          else if (g_strcmp0 (typeval, "pid") == 0)
            collect_options (con, "--unshare-pid", NULL);
          else if (g_strcmp0 (typeval, "mount") == 0)
            ;
          else if (g_strcmp0 (typeval, "network") == 0)
            collect_options (con, "--unshare-net", NULL);
          else if (g_strcmp0 (typeval, "uts") == 0)
            collect_options (con, "--unshare-uts", NULL);
          else
            error (EXIT_FAILURE, 0, "unknown namespace %s\n", typeval);
        }
    }
  if (json_object_has_member (root, "maskedPaths"))
    {
      JsonNode *namespaces;
      GList *members;
      GList *iter;
      namespaces = json_object_get_member (root, "maskedPaths");
      members = json_array_get_elements (json_node_get_array (namespaces));
      for (iter = members; iter; iter = iter->next)
        {
          GVariant *variant = json_gvariant_deserialize (iter->data, "s", NULL);
          const char *path = g_variant_get_string (variant, NULL);

          if (can_mask_or_ro_p (path))
            add_readonly_path (con, "--bind", "/dev/null", path, NULL);

        }
    }
  if (json_object_has_member (root, "readonlyPaths"))
    {
      JsonNode *namespaces;
      GList *members;
      GList *iter;
      namespaces = json_object_get_member (root, "readonlyPaths");
      members = json_array_get_elements (json_node_get_array (namespaces));
      for (iter = members; iter; iter = iter->next)
        {
          GVariant *variant = json_gvariant_deserialize (iter->data, "s", NULL);
          const char *path = g_variant_get_string (variant, NULL);

          if (can_mask_or_ro_p (path))
            add_readonly_path (con, "--ro-bind", path, path, NULL);
        }
    }
  if (json_object_has_member (root, "mountLabel"))
    {
      JsonNode *label = json_object_get_member (root, "mountLabel");
      if (bwrap_has_option ("--mount-label"))
        collect_options (con, "--mount-label", json_node_get_string (label), NULL);
      collect_options (con, "--file-label", json_node_get_string (label), NULL);
    }
  if (json_object_has_member (root, "seccomp"))
    {
      GList *members;
      GList *iter;
      JsonObject *seccomp = json_node_get_object (json_object_get_member (root, "seccomp"));
      JsonNode *defaultAction = json_object_get_member (seccomp, "defaultAction");
      JsonNode *architectures = json_object_get_member (seccomp, "architectures");
      JsonNode *syscalls = json_object_get_member (seccomp, "syscalls");
      const char *defActionString = "SCMP_ACT_ALLOW";

      if (defaultAction)
        defActionString = json_node_get_string (defaultAction);

      con->seccomp = seccomp_init (get_seccomp_action (defActionString));
      if (con->seccomp == NULL)
        error (EXIT_FAILURE, 0, "error while setting up seccomp");

      if (architectures)
        {
          members = json_array_get_elements (json_node_get_array (architectures));
          for (iter = members; iter; iter = iter->next)
            {
              int ret;
              uint32_t arch_token;
              const char *arch = json_node_get_string (iter->data);
              cleanup_free gchar *arch_lowercase = NULL;

              if (g_str_has_prefix (arch, "SCMP_ARCH_"))
                arch += 10;

              arch_lowercase = g_ascii_strdown (arch, -1);
              arch_token = seccomp_arch_resolve_name (arch_lowercase);
              if (arch_token == 0)
                error (EXIT_FAILURE, 0, "error while setting up seccomp, unknown architecture %s", arch_lowercase);
              ret = seccomp_arch_add (con->seccomp, arch_token);
              if (ret < 0 && ret != -EEXIST)
                error (EXIT_FAILURE, errno, "error while setting up seccomp");
            }
        }

      members = json_array_get_elements (json_node_get_array (syscalls));
      for (iter = members; iter; iter = iter->next)
        {
          gsize child;
          int name_it;
          GVariant *names, *actionvar, *args;
          const char *action = NULL;
          GVariant *variant = json_gvariant_deserialize (iter->data, "a{sv}", NULL);

          actionvar = g_variant_lookup_value (variant, "action", G_VARIANT_TYPE_STRING);
          action = g_variant_get_string (actionvar, NULL);
          args = g_variant_lookup_value (variant, "args", G_VARIANT_TYPE_ARRAY);

          names = g_variant_lookup_value (variant, "names", G_VARIANT_TYPE_ARRAY);

          for (name_it = 0; name_it < g_variant_n_children (names); name_it++)
            {
              cleanup_free char *name = NULL;
              GVariant *name_variant = g_variant_get_child_value (g_variant_get_child_value (names, name_it), 0);
              g_variant_get (name_variant, "s", &name);
              if (args == NULL)
                {
                  if (seccomp_rule_add (con->seccomp,
                                        get_seccomp_action (action),
                                        seccomp_syscall_resolve_name (name), 0) < 0)
                    {
                      error (EXIT_FAILURE, 0, "error while setting up seccomp");
                    }
                }
              else
                {
                  int ret;
                  size_t n_arg = 0;
                  struct scmp_arg_cmp arg_cmp[6];

                  for (child = 0; child < 6 && child < g_variant_n_children (args); child++)
                    {
                      GVariant *valuevar, *valueTwovar, *opvar;
                      guint64 value, valueTwo = 0;
                      const char *op = NULL;
                      GVariant *arg = g_variant_get_variant (g_variant_get_child_value (args, child));

                      valuevar = g_variant_lookup_value (arg, "value", G_VARIANT_TYPE_INT64);
                      value = g_variant_get_int64 (valuevar);
                      valueTwovar = g_variant_lookup_value (arg, "valueTwo", G_VARIANT_TYPE_INT64);
                      if (valueTwovar)
                        valueTwo = g_variant_get_int64 (valueTwovar);
                      opvar = g_variant_lookup_value (arg, "op", G_VARIANT_TYPE_STRING);
                      op = g_variant_get_string (opvar, NULL);

                      arg_cmp[n_arg].arg = n_arg;
                      arg_cmp[n_arg].op = get_seccomp_operator (op);
                      arg_cmp[n_arg].datum_a = value;
                      arg_cmp[n_arg].datum_b = valueTwo;
                      n_arg++;
                    }

                  ret = seccomp_rule_add_array (con->seccomp,
                                                get_seccomp_action (action),
                                                seccomp_syscall_resolve_name (name),
                                                n_arg,
                                                arg_cmp);
                  if (ret < 0)
                      error (EXIT_FAILURE, -ret, "error while setting up seccomp");
                }
            }
        }
    }
}

static void
do_root (struct context *con, JsonNode *rootval)
{
  JsonObject *root = json_node_get_object (rootval);
  gboolean readonly = FALSE;
  JsonNode *path = json_object_get_member (root, "path");
  const gchar *rootfs = json_node_get_string (path);

  if (json_object_has_member (root, "readonly"))
    readonly = json_node_get_boolean (json_object_get_member (root, "readonly"));

  collect_options (con, "--bind", json_node_get_string (path), "/", NULL);

  con->rootfs = g_strdup (rootfs);
  if (readonly)
    {
      if (bwrap_has_option ("remount-ro"))
        con->remount_ro_rootfs = TRUE;
      else
        error (0, 0, "warning: readonly rootfs are not supported yet");
    }
}

static void
do_hostname (struct context *con, JsonNode *rootval)
{
  if (bwrap_has_option ("hostname"))
    collect_options (con, "--hostname", json_node_get_string (rootval), NULL);
}

static gboolean
find_child_value (GVariant *root, const char *value)
{
  if (root)
    {
      gsize i;
      for (i = 0; i < g_variant_n_children (root); i++)
        {
          char *child_val = NULL;
          GVariant *child = g_variant_get_child_value (g_variant_get_child_value (root, i), 0);
          g_variant_get (child, "s", &child_val);
          if (g_strcmp0 (child_val, value) == 0)
            return TRUE;
        }
    }
  return FALSE;
}

static void
check_required_mounts (struct context *con, GHashTable *mounts)
{
    if (! g_hash_table_contains (mounts, "/tmp"))
      collect_options (con, "--tmpfs", "/tmp", NULL);
    if (con->has_terminal)
      collect_options (con, "--dev-bind", "/dev/tty", "/dev/tty", NULL);
}

static void
check_systemd_required_mounts (struct context *con, GHashTable *mounts)
{
  gboolean is_systemd = FALSE;
  if (con->args != NULL && con->args->next != NULL)
    is_systemd = g_strcmp0 (con->args->data, "/usr/lib/systemd/systemd") == 0 && g_strcmp0 (con->args->next->data, "--system") == 0;
  if (! is_systemd)
    return;

  if (! g_hash_table_contains (mounts, "/sys/fs/cgroup/systemd"))
    collect_options (con, "--bind", "/sys/fs/cgroup/systemd", "/sys/fs/cgroup/systemd", NULL);

  if (! g_hash_table_contains (mounts, "/var/lib"))
      collect_options (con, "--tmpfs", "/var/lib", NULL);

  if (! g_hash_table_contains (mounts, "/var/log"))
      collect_options (con, "--tmpfs", "/var/log", NULL);

  if (! g_hash_table_contains (mounts, "/var/tmp"))
      collect_options (con, "--tmpfs", "/var/tmp", NULL);

  if (! g_hash_table_contains (mounts, "/etc/machine-id") && !file_exist_p (con->rootfs, "/etc/machine-id"))
    collect_options (con, "--symlink", "/tmp/machine-id", "/etc/machine-id", NULL);

  if (! con->has_container_env)
    collect_options (con, "--setenv", "container", "bwrap-oci", NULL);
}

static void
do_mounts (struct context *con, JsonNode *rootval)
{
  GList *members;
  GList *iter;
  GHashTable *explicit_mounts = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  members = json_array_get_elements (json_node_get_array (rootval));
  for (iter = members; iter; iter = iter->next)
    {
      const char *typeval = NULL, *destinationval = NULL;
      GVariant *destination, *type, *variant = json_gvariant_deserialize (iter->data, "a{sv}", NULL);

      if (variant == NULL)
        error (EXIT_FAILURE, 0, "error while deserializing mounts\n");

      type = g_variant_lookup_value (variant, "type", G_VARIANT_TYPE_STRING);
      if (type)
        typeval = g_variant_get_string (type, NULL);

      destination = g_variant_lookup_value (variant, "destination", G_VARIANT_TYPE_STRING);
      if (destination)
        destinationval = g_variant_get_string (destination, NULL);

      if (typeval == NULL || destinationval == NULL)
        error (EXIT_FAILURE, 0, "invalid mount type or destination\n");

      g_hash_table_insert (explicit_mounts, g_strdup (destinationval), g_strdup (destinationval));

      if (g_strcmp0 (typeval, "proc") == 0)
        collect_options (con, "--proc", destinationval, NULL);
      else if (g_strcmp0 (typeval, "mqueue") == 0)
        collect_options (con, "--mqueue", destinationval, NULL);
      else if (g_strcmp0 (typeval, "tmpfs") == 0)
        {
          if (g_strcmp0 (destinationval, "/dev") == 0)
            collect_options (con, "--dev", destinationval, NULL);
          else
            collect_options (con, "--tmpfs", destinationval, NULL);
        }
      else if (g_strcmp0 (typeval, "devtmpfs") == 0)
        collect_options (con, "--dev", destinationval, NULL);
      else if (g_strcmp0 (typeval, "cgroup") == 0)
        {
          GVariant *options;
          gboolean readonly = FALSE;
          options = g_variant_lookup_value (variant, "options", G_VARIANT_TYPE_ARRAY);
          readonly = find_child_value (options, "ro");
          collect_options (con, readonly ? "--ro-bind" : "--bind", "/sys/fs/cgroup", destinationval, NULL);
        }
      else if (g_strcmp0 (typeval, "devpts") == 0)
        collect_options (con, "--bind", "/dev/pts", destinationval, NULL);
      else if (g_strcmp0 (typeval, "sysfs") == 0)
        {
          GVariant *options;
          gboolean readonly = FALSE;
          options = g_variant_lookup_value (variant, "options", G_VARIANT_TYPE_ARRAY);
          readonly = find_child_value (options, "ro");
          collect_options (con, readonly ? "--ro-bind" : "--bind", "/sys", destinationval, NULL);
        }
      else  /* assume it is a bind mount.  */
        {
          const char *sourceval = NULL;
          GVariant *source, *options;
          gboolean readonly = FALSE;

          source = g_variant_lookup_value (variant, "source", G_VARIANT_TYPE_STRING);
          if (! source)
            error (EXIT_FAILURE, 0, "invalid source for bind mount\n");
          sourceval = g_variant_get_string (source, NULL);
          options = g_variant_lookup_value (variant, "options", G_VARIANT_TYPE_ARRAY);
          readonly = find_child_value (options, "ro");
          collect_options (con, readonly ? "--ro-bind" : "--bind", sourceval, destinationval, NULL);
        }
    }

  check_required_mounts (con, explicit_mounts);
  check_systemd_required_mounts (con, explicit_mounts);

  g_hash_table_unref (explicit_mounts);
}

static void
do_capabilities (struct context *con, JsonNode *rootval)
{
  JsonNode *caps;
  JsonObject *root = json_node_get_object (rootval);
  const char *kind_name[5] = {"bounding", "effective", "inheritable", "ambient", "permitted"};
  GList *members;
  GList *iter;
  int kind;
  GHashTable *needed_caps = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  for (kind = 0; kind < 5; kind++)
    {
      caps = json_object_get_member (root, kind_name[kind]);
      members = json_array_get_elements (json_node_get_array (caps));
      for (iter = members; iter; iter = iter->next)
        {
          GVariant *v = json_gvariant_deserialize (iter->data, "s", NULL);
          const char *cap = g_variant_get_string (v, NULL);

          g_hash_table_insert (needed_caps, g_strdup (cap), g_strdup (cap));
        }
      g_list_free (members);
    }

  {
    GHashTableIter iter;
    gpointer key, value;
    gboolean caps_initialized = FALSE;
    g_hash_table_iter_init (&iter, needed_caps);
    while (g_hash_table_iter_next (&iter, &key, &value))
      {
        if (! caps_initialized)
          {
            collect_options (con, "--unshare-user", NULL);
            collect_options (con, "--cap-drop", "ALL", NULL);
            caps_initialized = TRUE;
          }
        collect_options (con, "--cap-add", value, NULL);
      }
  }
  g_hash_table_unref (needed_caps);
}

static void
do_process (struct context *con, JsonNode *rootval)
{
  JsonObject *root = json_node_get_object (rootval);
  if (json_object_has_member (root, "capabilities") && bwrap_has_option ("cap-add"))
    {
      JsonNode *capabilities = json_object_get_member (root, "capabilities");
      do_capabilities (con, capabilities);
    }
  if (json_object_has_member (root, "terminal"))
    {
      con->has_terminal = json_node_get_boolean (json_object_get_member (root, "terminal"));
    }
  if (json_object_has_member (root, "cwd"))
    {
      JsonNode *cwd = json_object_get_member (root, "cwd");
      collect_options (con, "--chdir", json_node_get_string (cwd), NULL);
    }
  if (json_object_has_member (root, "env"))
    {
      GList *members;
      GList *iter;
      members = json_array_get_elements (json_node_get_array (json_object_get_member (root, "env")));
      for (iter = members; iter; iter = iter->next)
        {
          GVariant *env = json_gvariant_deserialize (iter->data, "s", NULL);
          cleanup_free char *val = g_variant_dup_string (env, NULL);
          gchar *sep = g_strstr_len (val, strlen(val), "=");
          if (!sep)
            error (EXIT_FAILURE, 0, "invalid env setting\n");
          *sep = '\0';
          collect_options (con, "--setenv", val, sep + 1, NULL);
          if (g_strcmp0 (val, "container") == 0)
            con->has_container_env = TRUE;
        }
      g_list_free (members);
    }
  if (json_object_has_member (root, "selinuxLabel"))
    {
      JsonNode *label = json_object_get_member (root, "selinuxLabel");
      collect_options (con, "--exec-label", json_node_get_string (label), NULL);
    }
  if (json_object_has_member (root, "user"))
    {
      JsonNode *user = json_object_get_member (root, "user");
      JsonObject *userobj = json_node_get_object (user);
      if (json_object_has_member (userobj, "uid"))
        {
          gint64 uid = json_node_get_int (json_object_get_member (userobj, "uid"));
          cleanup_free gchar *argument = g_strdup_printf ("%" G_GINT64_FORMAT, uid);
          collect_options (con, "--uid", argument, NULL);
          con->uid = uid;
        }
      if (json_object_has_member (userobj, "gid"))
        {
          gint64 gid = json_node_get_int (json_object_get_member (userobj, "gid"));
          cleanup_free gchar *argument = g_strdup_printf ("%" G_GINT64_FORMAT, gid);
          collect_options (con, "--gid", argument, NULL);
          con->gid = gid;
        }
    }
  if (json_object_has_member (root, "args"))
    {
      GList *members;
      GList *iter;
      members = json_array_get_elements (json_node_get_array (json_object_get_member (root, "args")));
      for (iter = members; iter; iter = iter->next)
        {
          GVariant *arg = json_gvariant_deserialize (iter->data, "s", NULL);
          const char *val = g_variant_get_string (arg, NULL);
          collect_args (con, val, NULL);
        }
      g_list_free (members);
    }
}

static void
dump_argv (char **argv)
{
  gboolean first = TRUE;
  while (*argv)
    {
      g_print ("%s%s", first ? "" : " ", *argv);
      first = FALSE;
      argv++;
    }
  g_print ("\n");
}

static void
finalize (struct context *context)
{
  int fd = generate_seccomp_rules_file (context->seccomp);
  if (fd >= 0)
    {
      char fdstr[16];
      collect_options (context, "--seccomp", format_fd (fdstr, fd));
    }

  if (context->remount_ro_rootfs)
    add_readonly_path (context, "--remount-ro", "/", NULL);
}

static char **
generate_bwrap_argv (struct context *context)
{
  int bwrap_argc = 0;
  char **bwrap_argv = bwrap_argv = g_new0 (char *, context->total_elements + 2);
  int current_list = 0;
  GList **lists[] = {&context->options, &context->readonly_paths, &context->args, NULL};

  bwrap_argv[bwrap_argc++] = g_strdup (get_bwrap_path ());
  while (lists[current_list])
    {
      GList *l = *lists[current_list];
      while (l != NULL)
        {
          bwrap_argv[bwrap_argc++] = (char *) l->data;
          l = l->next;
        }
      current_list++;
    }

  g_list_free (context->options);
  g_list_free (context->readonly_paths);
  g_list_free (context->args);
  context->options = context->readonly_paths = context->args = NULL;
  return bwrap_argv;
}

static void
run_hooks (GList *hooks, const char *stdin)
{
  GList *it;
  size_t stdin_len = strlen (stdin);
  for (it = hooks; it != NULL; it = it->next)
    {
      pid_t pid;
      struct hook *hook = (struct hook *) it->data;
      int pipes[2];
      if (pipe (pipes) < 0)
        error (EXIT_FAILURE, errno, "pipe");

      pid = fork ();
      if (pid < 0)
        error (EXIT_FAILURE, errno, "pipe");
      if (pid == 0)
        {
          int devnull = open ("/dev/null", O_RDWR);
          close (pipes[1]);
          dup2 (pipes[0], 0);
          dup2 (devnull, 1);
          dup2 (devnull, 2);
          execv (hook->path, hook->args);
          exit (EXIT_FAILURE);
        }
      else
        {
          int status;
          close (pipes[0]);
          if (safe_write (pipes[1], stdin, stdin_len) < 0)
            error (0, errno, "error writing to hook process pipe");
          close (pipes[1]);
          while (waitpid (pid, &status, 0) < 0 && errno == EINTR);
        }
    }
}

static gboolean
check_running_in_user_namespace ()
{
  cleanup_free char *buffer = NULL;
  size_t len;
  gboolean ret;
  FILE *f = fopen ("/proc/self/uid_map", "r");
  char buf[128];
  if (f == 0)
    error (EXIT_FAILURE, errno, "opening /proc/self/uid_map");

  len = fread (buf, 1, sizeof (buf) - 1, f);
  buf[len] = '\0';
  ret = strstr (buf, "4294967295") ? FALSE : TRUE;
  fclose (f);
  return ret;
}

static gboolean
initialize_user_mappings (struct context *context, gboolean dry_run)
{
  char pipe_fmt[16];
  gboolean has_subuid_map, has_subgid_map;

  if (!bwrap_has_option ("userns-block-fd"))
    {
      context->has_user_mappings = FALSE;
      return context->has_user_mappings;
    }

  if (check_running_in_user_namespace ())
    {
      context->has_user_mappings = FALSE;
      return FALSE;
    }

  if (dry_run)
    has_subuid_map = has_subgid_map = FALSE;
  else
    {
      has_subuid_map = getsubidrange (getuid (), TRUE, &context->user_mapping.first_subuid, &context->user_mapping.n_subuid) == 0 ? TRUE : FALSE;
      has_subgid_map = getsubidrange (getgid (), FALSE, &context->user_mapping.first_subgid, &context->user_mapping.n_subgid) == 0 ? TRUE : FALSE;
    }

  if (has_subuid_map != has_subgid_map)
    error (EXIT_FAILURE, 0, "invalid configuration for subuids and subgids");

  context->has_user_mappings = has_subuid_map;
  if (!context->has_user_mappings)
    return FALSE;

  if (pipe (context->userns_block_pipe) < 0)
    error (EXIT_FAILURE, errno, "pipe");

  format_fd (pipe_fmt, context->userns_block_pipe[0]);

  collect_options (context, "--userns-block-fd", pipe_fmt, NULL);
  return context->has_user_mappings;
}

int
run_container (const char *container_id,
               const char *configuration_file,
               gboolean detach,
               const char *pid_file,
               gboolean enable_hooks,
               gboolean dry_run)
{
  JsonNode *rootval;
  JsonObject *root;
  GError *gerror = NULL;
  struct context *context;
  char **bwrap_argv = NULL;
  JsonParser *parser;
  int block_fd[2] = {-1, -1};
  int info_fd[2] = {-1, -1};
  int sync_fd[2] = {-1, -1};
  pid_t pid;
  cleanup_free char *container_state = NULL;
  char pipe_fmt[16];

  context = g_new0 (struct context, 1);
  parser = json_parser_new ();
  json_parser_load_from_file (parser, configuration_file, &gerror);
  if (gerror)
    error (EXIT_FAILURE, 0, "unable to parse `%s': %s", configuration_file, gerror->message);

  context->detach = detach;

  initialize_user_mappings (context, dry_run);

  rootval = json_parser_get_root (parser);
  root = json_node_get_object (rootval);

  if (bwrap_has_option ("as-pid-1"))
    collect_options (context, "--as-pid-1", NULL);

  if (bwrap_has_option ("die-with-parent"))
    collect_options (context, "--die-with-parent", NULL);

  if (json_object_has_member (root, "root"))
    do_root (context, json_object_get_member (root, "root"));

  if (json_object_has_member (root, "linux"))
    do_linux (context, json_object_get_member (root, "linux"));

  if (enable_hooks && json_object_has_member (root, "hooks"))
    {
      if (bwrap_has_option ("block-fd") && bwrap_has_option ("info-fd"))
        do_hooks (context, json_object_get_member (root, "hooks"));
    }

  if (json_object_has_member (root, "process"))
    do_process (context, json_object_get_member (root, "process"));

  if (json_object_has_member (root, "mounts"))
    do_mounts (context, json_object_get_member (root, "mounts"));

  if (json_object_has_member (root, "hostname"))
    do_hostname (context, json_object_get_member (root, "hostname"));

  g_object_unref (parser);

  if (context->prestart_hooks || context->poststop_hooks || !context->detach)
    {
      if (pipe (block_fd) != 0)
        error (EXIT_FAILURE, errno, "pipe");

      collect_options (context, "--block-fd", format_fd (pipe_fmt, block_fd[0]), NULL);

      if (context->poststop_hooks || !context->detach)
        {
          if (pipe (sync_fd) != 0)
            error (EXIT_FAILURE, errno, "pipe");
          collect_options (context, "--sync-fd", format_fd (pipe_fmt, sync_fd[1]), NULL);
        }
    }

  if (pipe (info_fd) != 0)
    error (EXIT_FAILURE, errno, "pipe");
  collect_options (context, "--info-fd", format_fd (pipe_fmt, info_fd[1]), NULL);

  finalize (context);
  bwrap_argv = generate_bwrap_argv (context);

  if (dry_run)
    {
      dump_argv (bwrap_argv);
      return EXIT_SUCCESS;
    }

  container_state = create_container (container_id);

  pid = fork ();
  if (pid < 0)
    error (EXIT_FAILURE, errno, "error forking");
  if (pid == 0)
    {
      gchar *rootfs = context->rootfs;
      cleanup_free gchar *stdin = NULL;
      gchar *bundle_path;
      gint64 child_pid = 0;
      const char *fmt_stdin = "{\"ociVersion\":\"1.0\", \"id\":\"%s\", \"pid\":%i, \"root\":\"%s\", \"bundle\":\"%s\"}";

      close (info_fd[1]);
      if (context->prestart_hooks)
        {
          close (block_fd[0]);
        }
      if (context->poststop_hooks || !context->detach)
        close (sync_fd[1]);

      detach_process ();

      bundle_path = get_bundle_path (rootfs);

      /* Handle info-fd output.  */
      {
        JsonNode *rootval_info;
        JsonObject *root_info;
        JsonParser *parser_info;
        GInputStream *stream;
        parser_info = json_parser_new ();
        stream = g_unix_input_stream_new (info_fd[0], TRUE);
        json_parser_load_from_stream (parser_info, stream, NULL, &gerror);

        rootval_info = json_parser_get_root (parser_info);
        root_info = json_node_get_object (rootval_info);

        child_pid = json_node_get_int (json_object_get_member (root_info, "child-pid"));

        g_object_unref (stream);
        g_object_unref (parser_info);
      }

      write_container_state (container_state, child_pid, bundle_path);

      if (pid_file)
        {
          FILE *pidfile = fopen (pid_file, "w");
          if (pidfile == NULL)
            error (EXIT_FAILURE, errno, "error opening pid file");
          fprintf (pidfile, "%" G_GINT64_FORMAT "\n", child_pid);
          fclose (pidfile);
        }
      if (context->has_user_mappings)
        {
          close (context->userns_block_pipe[0]);
          write_user_group_mappings (&context->user_mapping, context->uid, context->gid, child_pid);
          safe_write (context->userns_block_pipe[1], "1", 1);
        }

      if (context->poststop_hooks || !context->detach)
        {
          stdin = g_strdup_printf (fmt_stdin, container_id, child_pid, rootfs, bundle_path);
          run_hooks (context->prestart_hooks, stdin);

          if (safe_write (block_fd[1], "1", 1) < 0)
            error (0, errno, "error while unblocking the bubblewrap process");

          /* Wait for the process to terminate.  */
          {
            char b;
            if (safe_read (sync_fd[0], &b, 1) < 0)
              error (0, errno, "error while waiting for bubblewrap to terminate");

            /* The child process may have close'd the block_fd, so make sure the process
               is really terminated.  If it is not do polling.  */
            while (pid_running_p (child_pid))
              sleep (1);
          }

          if (context->poststop_hooks)
            {
              stdin = g_strdup_printf (fmt_stdin, container_id, 0, rootfs, bundle_path);
              run_hooks (context->poststop_hooks, stdin);
            }

          if (!context->detach)
            delete_container (container_id);
        }

      _exit (EXIT_SUCCESS);
    }
  else
    {
      int status;
      if (context->prestart_hooks)
        {
          close (info_fd[0]);
          close (block_fd[1]);
        }
      if (context->poststop_hooks || !context->detach)
        close (sync_fd[0]);
      if (context->has_user_mappings)
        close (context->userns_block_pipe[1]);

      /* Wait for the first detach.  */
      while (waitpid (pid, &status, 0) < 0 && errno == EINTR);

      if (context->detach)
        detach_process ();
      execv (get_bwrap_path (), bwrap_argv);
    }

  _exit (EXIT_FAILURE);
}
