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
#ifndef _UTIL_H
# define _UTIL_H
# include <config.h>
# include "bwrap-oci.h"
# include <glib.h>

gchar *get_run_directory (void);
guint64 get_seccomp_action (const char *name);
uint32_t get_seccomp_operator (const char *name);
gboolean bwrap_has_option (const char *opt_bwrap, const gchar *option);
void write_container_state (const char *container_state, pid_t child_pid, const char *bundle_path);
void detach_process ();
void write_user_group_mappings (struct context *context, pid_t pid);
gboolean file_exist_p (const char *root, const char *file);
gboolean can_mask_or_ro_p (const char *path);
gchar *get_bundle_path (const char *rootfs);
char *create_container (const char *name);
void delete_container (const char *name);
void format_fd (gchar *buf, int fd);
void set_test_environment (gboolean status);
int generate_seccomp_rules_file (struct context *context);

#endif
