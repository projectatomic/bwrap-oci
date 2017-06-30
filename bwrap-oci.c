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

#include "config.h"
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
#include "safe-read-write.h"
#include "subugidmap.h"


/***
  This part is taken from systemd:

  Copyright 2010 Lennart Poettering
*/
#if defined(__i386__) || defined(__x86_64__)

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


static gboolean opt_dry_run;
static gboolean opt_version;
static gboolean opt_enable_hooks;
static const char *opt_configuration = "config.json";
static char *opt_bwrap = BWRAP;

static GOptionEntry entries[] =
{
  { "configuration", 'c', 0, G_OPTION_ARG_STRING, &opt_configuration, "Configuration file", "FILE" },
  { "dry-run", 'd', 0, G_OPTION_ARG_NONE, &opt_dry_run, "Print the command line for bubblewrap", NULL },
  { "enable-hooks", 0, 0, G_OPTION_ARG_NONE, &opt_enable_hooks, "Execute the OCI hooks", NULL },
  { "version", 0, 0, G_OPTION_ARG_NONE, &opt_version, "Print version information and exit", NULL },
  { "bwrap", 0, 0, G_OPTION_ARG_STRING, &opt_bwrap, "Specify the path to the bubblewrap executable to use", NULL },
  { NULL }
};

struct hook
{
  const char *path;
  char **args;
};

struct context
{
  GList *options;
  GList *readonly_paths;
  GList *args;
  size_t total_elements;
  gboolean remount_ro_rootfs;
  scmp_filter_ctx seccomp;
  gchar *rootfs;
  GList *prestart_hooks;
  GList *poststop_hooks;

  uid_t uid;
  gid_t gid;

  gboolean has_user_mappings;

  int userns_block_pipe[2];

  uint32_t first_subuid, n_subuid;
  uint32_t first_subgid, n_subgid;
};

static uint32_t
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

static guint64
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

static GHashTable *bwrap_options = NULL;

static void
read_bwrap_help ()
{
  const gchar *argv[] = {opt_bwrap, "--help", NULL};
  gchar *output = NULL;
  gint exit_status;
  gchar *end, *it;

  if (g_spawn_sync (NULL, (gchar **) argv, NULL, G_SPAWN_DEFAULT, NULL,
                    NULL, &output, NULL, &exit_status, NULL) == FALSE)
    {
      error (EXIT_FAILURE, errno, "Error running bwrap --help");
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

static gboolean
bwrap_has_option (const gchar *option)
{
  if (bwrap_options == NULL)
    read_bwrap_help ();
  return g_hash_table_contains (bwrap_options, option);
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
          else if (g_strcmp0 (typeval, "cgroup") == 0)
            collect_options (con, "--unshare-cgroup", NULL);
          else if (g_strcmp0 (typeval, "uts") == 0)
            collect_options (con, "--unshare-uts", NULL);
          else
            error (EXIT_FAILURE, 0, "unknown namespace %s\n", typeval);
          g_variant_unref (variant);
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

          add_readonly_path (con, "--ro-bind", path, path, NULL);

          g_variant_unref (variant);
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

          add_readonly_path (con, "--bind", "/dev/null", path, NULL);

          g_variant_unref (variant);
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
              gchar *arch_lowercase;

              if (g_str_has_prefix (arch, "SCMP_ARCH_"))
                arch += 10;

              arch_lowercase = g_ascii_strdown (arch, -1);
              arch_token = seccomp_arch_resolve_name (arch_lowercase);
              if (arch_token == 0)
                error (EXIT_FAILURE, 0, "error while setting up seccomp, unknown architecture %s", arch_lowercase);
              ret = seccomp_arch_add (con->seccomp, arch_token);
              if (ret < 0 && ret != -EEXIST)
                error (EXIT_FAILURE, errno, "error while setting up seccomp");
              g_free (arch_lowercase);
            }
        }

      members = json_array_get_elements (json_node_get_array (syscalls));
      for (iter = members; iter; iter = iter->next)
        {
          gsize child;
          int name_it;
          GVariant *names, *actionvar, *args;
          const char *name = NULL, *action = NULL;
          GVariant *variant = json_gvariant_deserialize (iter->data, "a{sv}", NULL);

          actionvar = g_variant_lookup_value (variant, "action", G_VARIANT_TYPE_STRING);
          action = g_variant_get_string (actionvar, NULL);
          args = g_variant_lookup_value (variant, "args", G_VARIANT_TYPE_ARRAY);

          names = g_variant_lookup_value (variant, "names", G_VARIANT_TYPE_ARRAY);

          for (name_it = 0; name_it < g_variant_n_children (names); name_it++)
            {
              char *name = NULL;
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
                      GVariant *indexvar, *valuevar, *valueTwovar, *opvar;
                      guint64 index, value, valueTwo;
                      const char *op = NULL;
                      GVariant *arg = g_variant_get_variant (g_variant_get_child_value (args, child));

                      indexvar = g_variant_lookup_value (arg, "index", G_VARIANT_TYPE_INT64);
                      index = g_variant_get_int64 (indexvar);
                      valuevar = g_variant_lookup_value (arg, "value", G_VARIANT_TYPE_INT64);
                      value = g_variant_get_int64 (valuevar);
                      valueTwovar = g_variant_lookup_value (arg, "valueTwo", G_VARIANT_TYPE_INT64);
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
                    {
                      error (EXIT_FAILURE, -ret, "error while setting up seccomp");
                    }

                }

              g_free (name);
              g_variant_unref (name_variant);
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

static void
do_mounts (struct context *con, JsonNode *rootval)
{
  GList *members;
  GList *iter;
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

      if (g_strcmp0 (typeval, "proc") == 0)
        collect_options (con, "--proc", destinationval, NULL);
      else if (g_strcmp0 (typeval, "mqueue") == 0)
        collect_options (con, "--mqueue", destinationval, NULL);
      else if (g_strcmp0 (typeval, "tmpfs") == 0)
        collect_options (con, "--tmpfs", destinationval, NULL);
      else if (g_strcmp0 (typeval, "bind") == 0)
        {
          const char *sourceval = NULL;
          GVariant *source, *options;
          gboolean readonly = FALSE;

          source = g_variant_lookup_value (variant, "source", G_VARIANT_TYPE_STRING);
          if (! source)
            error (EXIT_FAILURE, 0, "invalid source for bind mount\n");
          sourceval = g_variant_get_string (source, NULL);
          options = g_variant_lookup_value (variant, "options", G_VARIANT_TYPE_ARRAY);
          if (options)
            {
              gsize i;
              for (i = 0; i < g_variant_n_children (options); i++)
                {
                  char *val = NULL;
                  GVariant *child = g_variant_get_child_value (g_variant_get_child_value (options, i), 0);
                  g_variant_get (child, "s", &val);
                  if (g_strcmp0 (val, "ro") == 0)
                    readonly = TRUE;
                }
            }
          collect_options (con, readonly ? "--ro-bind" : "--bind", sourceval, destinationval, NULL);
        }
      else if (g_strcmp0 (typeval, "devtmpfs") == 0)
        collect_options (con, "--dev", destinationval, NULL);
      else if (g_strcmp0 (typeval, "cgroup") == 0)
        ;
      else if (g_strcmp0 (typeval, "devpts") == 0)
        ;
      else if (g_strcmp0 (typeval, "sysfs") == 0)
        ;
      else
        error (EXIT_FAILURE, 0, "unknown mount type %s\n", typeval);
      g_variant_unref (variant);
    }
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
          g_variant_unref (v);
        }
    }

  {
    GHashTableIter iter;
    gpointer key, value;
    gboolean unshared_user = FALSE;
    g_hash_table_iter_init (&iter, needed_caps);
    while (g_hash_table_iter_next (&iter, &key, &value))
      {
        if (! unshared_user)
          {
            collect_options (con, "--unshare-user", NULL);
            unshared_user = TRUE;
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
      gboolean terminal = json_node_get_boolean (json_object_get_member (root, "terminal"));
      if (terminal)
        collect_options (con, "--dev-bind", "/dev/tty", "/dev/tty", NULL);
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
          char *val = g_variant_dup_string (env, NULL);
          gchar *sep = g_strrstr (val, "=");
          if (!sep)
            error (EXIT_FAILURE, 0, "invalid env setting\n");
          *sep = '\0';
          collect_options (con, "--setenv", val, sep + 1, NULL);
          g_free (val);
          g_variant_unref (env);
        }
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
          gchar *argument = g_strdup_printf ("%" G_GINT64_FORMAT, uid);
          collect_options (con, "--uid", argument, NULL);
          con->uid = uid;
          g_free (argument);
        }
      if (json_object_has_member (userobj, "gid"))
        {
          gint64 gid = json_node_get_int (json_object_get_member (userobj, "gid"));
          gchar *argument = g_strdup_printf ("%" G_GINT64_FORMAT, gid);
          collect_options (con, "--gid", argument, NULL);
          con->gid = gid;
          g_free (argument);
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
generate_seccomp_rules_file (struct context *context)
{
  if (context->seccomp)
    {
      char fdstr[10];
      int fd = open (".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
      if (fd < 0)
        error (EXIT_FAILURE, errno, "error opening temp file");

      if (seccomp_export_bpf (context->seccomp, fd) < 0)
        error (EXIT_FAILURE, errno, "error writing seccomp rules file");
      if (lseek (fd, 0, SEEK_SET) < 0)
        error (EXIT_FAILURE, errno, "error seeking seccomp rules file");

      g_sprintf (fdstr, "%i", fd);
      collect_options (context, "--seccomp", fdstr);
    }
}

static void
finalize (struct context *context)
{
  generate_seccomp_rules_file (context);

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

  bwrap_argv[bwrap_argc++] = opt_bwrap;
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
initialize_user_mappings (struct context *context)
{
  char pipe_fmt[16];
  gboolean has_subuid_map, has_subgid_map;

  if (!bwrap_has_option ("userns-block-fd"))
    {
      context->has_user_mappings = FALSE;
      return context->has_user_mappings;
    }

  has_subuid_map = getsubidrange (getuid (), TRUE, &context->first_subuid, &context->n_subuid) == 0 ? TRUE : FALSE;
  has_subgid_map = getsubidrange (getgid (), FALSE, &context->first_subgid, &context->n_subgid) == 0 ? TRUE : FALSE;

  if (has_subuid_map != has_subgid_map)
    error (EXIT_FAILURE, 0, "invalid configuration for subuids and subgids");

  context->has_user_mappings = has_subuid_map;

  if (pipe (context->userns_block_pipe) < 0)
    error (EXIT_FAILURE, errno, "pipe");

  sprintf (pipe_fmt, "%i", context->userns_block_pipe[0]);

  collect_options (context, "--userns-block-fd", pipe_fmt, NULL);
  return context->has_user_mappings;
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
      error (EXIT_FAILURE, errno, "Error running %s", program);
    }
}

static void
write_user_group_mappings (struct context *context, pid_t pid)
{
  uid_t uid = getuid ();
  gid_t gid = getgid ();

  write_mapping ("/usr/bin/newuidmap", pid, uid, context->uid,
                 context->first_subuid, context->n_subuid);
  write_mapping ("/usr/bin/newgidmap", pid, gid, context->gid,
                 context->first_subgid, context->n_subgid);
}

int
main (int argc, char *argv[])
{
  JsonNode *rootval;
  JsonObject *root;
  GError *gerror = NULL;
  struct context *context;
  char **bwrap_argv = NULL;
  JsonParser *parser;
  GOptionContext *opt_context;
  int block_fd[2];
  int info_fd[2];
  int sync_fd[2];
  gboolean need_info_fd = FALSE;

  opt_context = g_option_context_new ("- converter from OCI configuration to bubblewrap command line");
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

  context = g_new0 (struct context, 1);
  parser = json_parser_new ();
  json_parser_load_from_file (parser, opt_configuration, &gerror);
  if (gerror)
    {
      g_print ("Unable to parse `%s': %s\n", opt_configuration, gerror->message);
      g_error_free (gerror);
      g_object_unref (parser);
      return EXIT_FAILURE;
    }

  need_info_fd |= initialize_user_mappings (context);

  rootval = json_parser_get_root (parser);
  root = json_node_get_object (rootval);

  if (bwrap_has_option ("as-pid-1"))
    collect_options (context, "--as-pid-1", NULL);

  if (json_object_has_member (root, "root"))
    do_root (context, json_object_get_member (root, "root"));

  if (json_object_has_member (root, "linux"))
    do_linux (context, json_object_get_member (root, "linux"));

  if (opt_enable_hooks && json_object_has_member (root, "hooks"))
    {
      if (bwrap_has_option ("block-fd") && bwrap_has_option ("info-fd"))
        do_hooks (context, json_object_get_member (root, "hooks"));
    }

  if (json_object_has_member (root, "mounts"))
    do_mounts (context, json_object_get_member (root, "mounts"));

  if (json_object_has_member (root, "hostname"))
    do_hostname (context, json_object_get_member (root, "hostname"));

  if (json_object_has_member (root, "process"))
    do_process (context, json_object_get_member (root, "process"));

  g_object_unref (parser);

  if (context->prestart_hooks || context->poststop_hooks)
    {
      char pipe_fmt[16];
      if (pipe (block_fd) != 0)
        error (EXIT_FAILURE, errno, "pipe");

      sprintf (pipe_fmt, "%i", block_fd[0]);
      collect_options (context, "--block-fd", pipe_fmt, NULL);

      need_info_fd = TRUE;

      if (context->poststop_hooks)
        {
          if (pipe (sync_fd) != 0)
            error (EXIT_FAILURE, errno, "pipe");
          sprintf (pipe_fmt, "%i", sync_fd[1]);
          collect_options (context, "--sync-fd", pipe_fmt, NULL);
        }
  }

  if (need_info_fd)
    {
      char pipe_fmt[16];

      if (pipe (info_fd) != 0)
        error (EXIT_FAILURE, errno, "pipe");

      sprintf (pipe_fmt, "%i", info_fd[1]);
      collect_options (context, "--info-fd", pipe_fmt, NULL);
  }

  finalize (context);
  bwrap_argv = generate_bwrap_argv (context);

  if (opt_dry_run)
    {
      dump_argv (bwrap_argv);
      return EXIT_SUCCESS;
    }

  if (context->prestart_hooks == NULL && context->poststop_hooks == NULL && !context->has_user_mappings)
    {
      execv (opt_bwrap, bwrap_argv);
    }
  else
    {
      pid_t pid = fork ();
      if (pid < 0)
        error (EXIT_FAILURE, errno, "error forking");
      if (pid == 0)
        {
          gchar *rootfs = context->rootfs;
          gchar *stdin;
          gchar *bundle_path;
          gchar *id;
          gint64 child_pid = 0;
          const char *fmt_stdin = "{\"ociVersion\":\"1.0\", \"id\":\"%s\", \"pid\":%i, \"root\":\"%s\", \"bundlePath\":\"%s\"}";

          if (need_info_fd)
            {
              close (info_fd[1]);
            }
          if (context->prestart_hooks)
            {
              close (block_fd[0]);
            }
          if (context->poststop_hooks)
            close (sync_fd[1]);

          setsid ();
          if (fork () != 0)
            _exit (EXIT_SUCCESS);

          id = basename (g_strdup (rootfs));
          bundle_path = dirname (g_strdup (rootfs));

          if (need_info_fd)
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

          if (context->has_user_mappings)
            {
              close (context->userns_block_pipe[0]);
              write_user_group_mappings (context, child_pid);
              safe_write (context->userns_block_pipe[1], "1", 1);
            }

          if (context->prestart_hooks)
            {
              stdin = g_strdup_printf (fmt_stdin, id, child_pid, rootfs, bundle_path);
              run_hooks (context->prestart_hooks, stdin);
              g_free (stdin);

              if (safe_write (block_fd[1], "1", 1) < 0)
                error (0, errno, "error while unblocking the bubblewrap process");
            }

          if (context->poststop_hooks)
            {
              char b;
              if (safe_read (sync_fd[0], &b, 1) < 0)
                error (0, errno, "error while waiting for bubblewrap to terminate");
              else
                {
                  stdin = g_strdup_printf (fmt_stdin, id, 0, rootfs, bundle_path);
                  run_hooks (context->poststop_hooks, stdin);
                  g_free (stdin);
                }
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
          if (context->poststop_hooks)
            close (sync_fd[0]);
          if (context->has_user_mappings)
            close (context->userns_block_pipe[1]);

          while (waitpid (pid, &status, 0) < 0 && errno == EINTR);
          execv (opt_bwrap, bwrap_argv);
        }
    return -1;
  }

  return EXIT_FAILURE;
}
