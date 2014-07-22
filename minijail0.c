/* Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libminijail.h"
#include "libsyscalls.h"

#include "elfparse.h"
#include "util.h"

static void add_binding(struct minijail *j, char *arg)
{
	char *src = strtok(arg, ",");
	char *dest = strtok(NULL, ",");
	char *flags = strtok(NULL, ",");
	if (!src || !dest) {
		fprintf(stderr, "Bad binding: %s %s\n", src, dest);
		exit(1);
	}
	if (minijail_bind(j, src, dest, flags ? atoi(flags) : 0)) {
		fprintf(stderr, "Bind failure.\n");
		exit(1);
	}
}

static void usage(const char *progn)
{
	size_t i;

	printf("Usage: %s [-Ghinprsvt] [-b <src>,<dest>[,<writeable>]] "
	       "[-c <caps>] [-C <dir>] [-g <group>] [-S <file>] [-u <user>] "
	       "<program> [args...]\n"
	       "  -b:         binds <src> to <dest> in chroot. Multiple "
	       "instances allowed\n"
	       "  -C <dir>:   chroot to <dir>\n"
	       "  -d <dir>:   chdir to <dir> (requires -C)\n"
	       "  -G:         inherit secondary groups from uid\n"
	       "  -g <group>: change gid to <group>\n"
	       "  -h:         help (this message)\n"
	       "  -H:         seccomp filter help message\n"
	       "  -L:         log blocked syscalls when using seccomp filter. "
	       "Forces the following syscalls to be allowed:\n"
	       "              ", progn);
	for (i = 0; i < log_syscalls_len; i++)
		printf("%s ", log_syscalls[i]);

	printf("\n"
	       "  -s:         use seccomp\n"
	       "  -S <file>:  set seccomp filter using <file>\n"
	       "              E.g., -S /usr/share/filters/<prog>.$(uname -m)\n"
	       "  -t:         mount tmpfs at /tmp inside chroot\n");
}

static void seccomp_filter_usage(const char *progn)
{
	const struct syscall_entry *entry = syscall_table;
	printf("Usage: %s -S <policy.file> <program> [args...]\n\n"
	       "System call names supported:\n", progn);
	for (; entry->name && entry->nr >= 0; ++entry)
		printf("  %s [%d]\n", entry->name, entry->nr);
	printf("\nSee minijail0(5) for example policies.\n");
}

static int parse_args(struct minijail *j, int argc, char *argv[])
{
	int opt;
	if (argc > 1 && argv[1][0] != '-')
		return 1;
	while ((opt = getopt(argc, argv, "u:g:sS:c:C:d:b:vrGhHinpLet:O:m:M:0:1:2:")) != -1) {
		switch (opt) {
		case 's':
			minijail_use_seccomp(j);
			break;
		case 'S':
			minijail_parse_seccomp_filters(j, optarg);
			minijail_use_seccomp_filter(j);
			break;
		case 'L':
			minijail_log_seccomp_filter_failures(j);
			break;
		case 'b':
			add_binding(j, optarg);
			break;
		case 'C':
			if (0 != minijail_enter_chroot(j, optarg))
				exit(1);
			break;
		case 'd':
			if (0 != minijail_chroot_chdir(j, optarg))
				exit(1);
			break;
		case 'G':
			minijail_inherit_usergroups(j);
			break;
		case 'H':
			seccomp_filter_usage(argv[0]);
			exit(1);
		case 't':
			minijail_time_limit(j, atoi(optarg));
			break;
		case 'O':
			minijail_output_limit(j, atoi(optarg));
			break;
		case 'm':
			minijail_memory_limit(j, atoi(optarg));
			break;
		case 'M':
			if (minijail_meta_file(j, optarg)) {
				fprintf(stderr,
					"Could not open %s for writing\n", optarg);
				exit(1);
			}
			break;
		case '0':
			close(0);
			if (open(optarg, O_RDONLY) != 0) {
				perror("open");
				exit(1);
			}
			break;
		case '1':
			close(1);
			if (open(optarg, O_WRONLY | O_CREAT | O_TRUNC, 0644) != 1) {
				perror("open");
				exit(1);
			}
			break;
		case '2':
			close(2);
			if (open(optarg, O_WRONLY | O_CREAT | O_TRUNC, 0644) != 2) {
				perror("open");
				exit(1);
			}
			break;
		default:
			usage(argv[0]);
			exit(1);
		}
		if (optind < argc && argv[optind][0] != '-')
			break;
	}

	if (argc == optind) {
		usage(argv[0]);
		exit(1);
	}

	return optind;
}

int main(int argc, char *argv[])
{
	char* caller = getenv("SUDO_USER");
	if (caller == NULL) {
		die("Not calling from sudo");
	}
	struct passwd* passwd = getpwnam(caller);
	if (passwd == NULL) {
		die("User %s not found", caller);
	}

	// Set a minimalistic environment
	clearenv();
	setenv("HOME", "/home", 1);

	struct minijail *j = minijail_new();
	// Change credentials to the original user so this never runs as root.
	minijail_change_uid(j, passwd->pw_uid);
	minijail_change_gid(j, passwd->pw_gid);
	minijail_use_caps(j, 0);
	minijail_namespace_pids(j);
	minijail_remount_readonly(j);
	minijail_namespace_vfs(j);
	minijail_no_new_privs(j);
	minijail_namespace_net(j);

	// Temporarily drop privileges to redirect files.
	if (setegid(passwd->pw_gid)) {
		die("setegid user");
	}
	if (seteuid(passwd->pw_uid)) {
		die("seteuid user");
	}

	int consumed = parse_args(j, argc, argv);
	argc -= consumed;
	argv += consumed;
	char *dl_mesg = NULL;
	char filepath[PATH_MAX+1];
	if (0 != minijail_get_path(j, filepath, sizeof(filepath), argv[0])) {
		fprintf(stderr, "Invalid path\n");
		return 1;
	}
	ElfType elftype = ELFERROR;
	/* Check that we can access the target program. */
	if (access(filepath, X_OK)) {
		fprintf(stderr, "Target program '%s' is not accessible.\n",
			argv[0]);
		return 1;
	}
	/* Check if target is statically or dynamically linked. */
	elftype = get_elf_linkage(filepath);
	if (elftype == ELFSTATIC) {
		/* Target binary is static. */
		// Become root again to set the jail up.
		if (seteuid(0)) {
			die("seteuid root");
		}
		if (setegid(0)) {
			die("setegid root");
		}
		minijail_run_static(j, argv[0], argv);
	} else if (elftype == ELFDYNAMIC) {
		/*
		 * Target binary is dynamically linked so we can
		 * inject libminijailpreload.so into it.
		 */

		/* Check that we can dlopen() libminijailpreload.so. */
		if (!dlopen(PRELOADPATH, RTLD_LAZY | RTLD_LOCAL)) {
			    dl_mesg = dlerror();
			    fprintf(stderr, "dlopen(): %s\n", dl_mesg);
			    return 1;
		}
		// Become root again to set the jail up.
		if (seteuid(0)) {
			die("seteuid root");
		}
		if (setegid(0)) {
			die("setegid root");
		}
		minijail_run(j, argv[0], argv);
	} else {
		fprintf(stderr,
			"Target program '%s' is not a valid ELF file.\n",
			argv[0]);
		return 1;
	}

	return minijail_wait(j);
}
