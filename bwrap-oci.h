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
#ifndef _BWRAP_OCI_H
# define _BWRAP_OCI_H

# include <config.h>
# include <glib.h>
# include <unistd.h>
# include <seccomp.h>
# include "util.h"

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

  struct user_mapping user_mapping;

  gboolean has_terminal;
  gboolean has_container_env;

  gboolean detach;
};

#endif
