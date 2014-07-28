/*
 * Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _BSD_SOURCE
#define _GNU_SOURCE

#include <asm/unistd.h>
#include <ctype.h>
#include <errno.h>
#include <grp.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/capability.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "libminijail.h"
#include "libminijail-private.h"

#include "signal.h"
#include "syscall_filter.h"
#include "util.h"

#ifdef HAVE_SECUREBITS_H
#include <linux/securebits.h>
#else
#define SECURE_ALL_BITS         0x15
#define SECURE_ALL_LOCKS        (SECURE_ALL_BITS << 1)
#endif

/* Until these are reliably available in linux/prctl.h */
#ifndef PR_SET_SECCOMP
# define PR_SET_SECCOMP 22
#endif

/* For seccomp_filter using BPF. */
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif
#ifndef SECCOMP_MODE_FILTER
# define SECCOMP_MODE_FILTER 2 /* uses user-supplied filter. */
#endif

struct binding {
	char *src;
	char *dest;
	int writeable;
	struct binding *next;
};

struct minijail {
	/*
	 * WARNING: if you add a flag here you need to make sure it's
	 * accounted for in minijail_pre{enter|exec}() below.
	 */
	struct {
		int uid:1;
		int gid:1;
		int caps:1;
		int vfs:1;
		int pids:1;
		int net:1;
		int seccomp:1;
		int readonly:1;
		int usergroups:1;
		int ptrace:1;
		int no_new_privs:1;
		int seccomp_filter:1;
		int log_seccomp_filter:1;
		int chroot:1;
		int mount_tmp:1;
		int chdir:1;
		/* The following are only used for omegaUp */
		int stack_limit:1;
		int time_limit:1;
		int output_limit:1;
		int memory_limit:1;
		int meta_file:1;
	} flags;
	uid_t uid;
	gid_t gid;
	gid_t usergid;
	char *user;
	uint64_t caps;
	pid_t initpid;
	int filter_len;
	int binding_count;
	char *chrootdir;
	char *chdir;
	struct sock_fprog *filter_prog;
	struct binding *bindings_head;
	struct binding *bindings_tail;

	/* The following fields are only used for omegaUp */
	int stack_limit;
	int time_limit;
	int memory_limit;
	int output_limit;
	FILE *meta_file;
};

/*
 * Strip out flags meant for the parent.
 * We keep things that are not inherited across execve(2) (e.g. capabilities),
 * or are easier to set after execve(2) (e.g. seccomp filters).
 */
void minijail_preenter(struct minijail *j)
{
	j->flags.vfs = 0;
	j->flags.readonly = 0;
	j->flags.pids = 0;
	j->flags.chroot = 0;
}

/*
 * Strip out flags meant for the child.
 * We keep things that are inherited across execve(2).
 */
void minijail_preexec(struct minijail *j)
{
	int vfs = j->flags.vfs;
	int readonly = j->flags.readonly;
	int stack_limit = j->flags.stack_limit;
	int time_limit = j->flags.time_limit;
	int memory_limit = j->flags.memory_limit;
	int output_limit = j->flags.output_limit;
	int meta_file = j->flags.meta_file;
	if (j->user)
		free(j->user);
	j->user = NULL;
	memset(&j->flags, 0, sizeof(j->flags));
	/* Now restore anything we meant to keep. */
	j->flags.vfs = vfs;
	j->flags.readonly = readonly;
	/* Note, |pids| will already have been used before this call. */
	j->flags.stack_limit = stack_limit;
	j->flags.time_limit = time_limit;
	j->flags.memory_limit = memory_limit;
	j->flags.output_limit = output_limit;
	j->flags.meta_file = meta_file;
}

/* Minijail API. */

struct minijail API *minijail_new(void)
{
	return calloc(1, sizeof(struct minijail));
}

void API minijail_change_uid(struct minijail *j, uid_t uid)
{
	if (uid == 0)
		die("useless change to uid 0");
	j->uid = uid;
	j->flags.uid = 1;
}

void API minijail_change_gid(struct minijail *j, gid_t gid)
{
	if (gid == 0)
		die("useless change to gid 0");
	j->gid = gid;
	j->flags.gid = 1;
}

int API minijail_change_user(struct minijail *j, const char *user)
{
	char *buf = NULL;
	struct passwd pw;
	struct passwd *ppw = NULL;
	ssize_t sz = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (sz == -1)
		sz = 65536;	/* your guess is as good as mine... */

	/*
	 * sysconf(_SC_GETPW_R_SIZE_MAX), under glibc, is documented to return
	 * the maximum needed size of the buffer, so we don't have to search.
	 */
	buf = malloc(sz);
	if (!buf)
		return -ENOMEM;
	getpwnam_r(user, &pw, buf, sz, &ppw);
	/*
	 * We're safe to free the buffer here. The strings inside pw point
	 * inside buf, but we don't use any of them; this leaves the pointers
	 * dangling but it's safe. ppw points at pw if getpwnam_r succeeded.
	 */
	free(buf);
	/* getpwnam_r(3) does *not* set errno when |ppw| is NULL. */
	if (!ppw)
		return -1;
	minijail_change_uid(j, ppw->pw_uid);
	j->user = strdup(user);
	if (!j->user)
		return -ENOMEM;
	j->usergid = ppw->pw_gid;
	return 0;
}

int API minijail_change_group(struct minijail *j, const char *group)
{
	char *buf = NULL;
	struct group gr;
	struct group *pgr = NULL;
	ssize_t sz = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (sz == -1)
		sz = 65536;	/* and mine is as good as yours, really */

	/*
	 * sysconf(_SC_GETGR_R_SIZE_MAX), under glibc, is documented to return
	 * the maximum needed size of the buffer, so we don't have to search.
	 */
	buf = malloc(sz);
	if (!buf)
		return -ENOMEM;
	getgrnam_r(group, &gr, buf, sz, &pgr);
	/*
	 * We're safe to free the buffer here. The strings inside gr point
	 * inside buf, but we don't use any of them; this leaves the pointers
	 * dangling but it's safe. pgr points at gr if getgrnam_r succeeded.
	 */
	free(buf);
	/* getgrnam_r(3) does *not* set errno when |pgr| is NULL. */
	if (!pgr)
		return -1;
	minijail_change_gid(j, pgr->gr_gid);
	return 0;
}

void API minijail_use_seccomp(struct minijail *j)
{
	j->flags.seccomp = 1;
}

void API minijail_no_new_privs(struct minijail *j)
{
	j->flags.no_new_privs = 1;
}

void API minijail_use_seccomp_filter(struct minijail *j)
{
	j->flags.seccomp_filter = 1;
}

void API minijail_log_seccomp_filter_failures(struct minijail *j)
{
	j->flags.log_seccomp_filter = 1;
}

void API minijail_use_caps(struct minijail *j, uint64_t capmask)
{
	j->caps = capmask;
	j->flags.caps = 1;
}

void API minijail_namespace_vfs(struct minijail *j)
{
	j->flags.vfs = 1;
}

void API minijail_namespace_pids(struct minijail *j)
{
	j->flags.vfs = 1;
	j->flags.readonly = 1;
	j->flags.pids = 1;
}

void API minijail_namespace_net(struct minijail *j)
{
	j->flags.net = 1;
}

void API minijail_remount_readonly(struct minijail *j)
{
	j->flags.vfs = 1;
	j->flags.readonly = 1;
}

void API minijail_inherit_usergroups(struct minijail *j)
{
	j->flags.usergroups = 1;
}

void API minijail_disable_ptrace(struct minijail *j)
{
	j->flags.ptrace = 1;
}

int API minijail_enter_chroot(struct minijail *j, const char *dir)
{
	if (j->chrootdir)
		return -EINVAL;
	j->chrootdir = strdup(dir);
	if (!j->chrootdir)
		return -ENOMEM;
	j->flags.chroot = 1;
	return 0;
}

void API minijail_mount_tmp(struct minijail *j)
{
	j->flags.mount_tmp = 1;
}

int API minijail_chroot_chdir(struct minijail *j, const char *dir) {
	if (!j->chrootdir)
		return -EINVAL;
	if (j->chdir)
		return -EINVAL;
	if (!dir || dir[0] != '/')
		return -EINVAL;
	j->chdir = strdup(dir);
	if (!j->chdir)
		return -ENOMEM;
	j->flags.chdir = 1;
	return 0;
}

int API minijail_bind(struct minijail *j, const char *src, const char *dest,
		      int writeable)
{
	struct binding *b;

	if (*dest != '/')
		return -EINVAL;
	b = calloc(1, sizeof(*b));
	if (!b)
		return -ENOMEM;
	b->dest = strdup(dest);
	if (!b->dest)
		goto error;
	b->src = strdup(src);
	if (!b->src)
		goto error;
	b->writeable = writeable;

	info("bind %s -> %s", src, dest);

	/*
	 * Force vfs namespacing so the bind mounts don't leak out into the
	 * containing vfs namespace.
	 */
	minijail_namespace_vfs(j);

	if (j->bindings_tail)
		j->bindings_tail->next = b;
	else
		j->bindings_head = b;
	j->bindings_tail = b;
	j->binding_count++;

	return 0;

error:
	free(b->src);
	free(b->dest);
	free(b);
	return -ENOMEM;
}

void API minijail_parse_seccomp_filters(struct minijail *j, const char *path)
{
	FILE *file = fopen(path, "r");
	if (!file) {
		pdie("failed to open seccomp filter file '%s'", path);
	}

	struct sock_fprog *fprog = malloc(sizeof(struct sock_fprog));
	if (compile_filter(file, fprog, j->flags.log_seccomp_filter)) {
		die("failed to compile seccomp filter BPF program in '%s'",
		    path);
	}

	j->filter_len = fprog->len;
	j->filter_prog = fprog;

	fclose(file);
}

struct marshal_state {
	size_t available;
	size_t total;
	char *buf;
};

void marshal_state_init(struct marshal_state *state,
			char *buf, size_t available)
{
	state->available = available;
	state->buf = buf;
	state->total = 0;
}

void marshal_append(struct marshal_state *state,
		    char *src, size_t length)
{
	size_t copy_len = MIN(state->available, length);

	/* Up to |available| will be written. */
	if (copy_len) {
		memcpy(state->buf, src, copy_len);
		state->buf += copy_len;
		state->available -= copy_len;
	}
	/* |total| will contain the expected length. */
	state->total += length;
}

void minijail_marshal_helper(struct marshal_state *state,
			     const struct minijail *j)
{
	struct binding *b = NULL;
	marshal_append(state, (char *)j, sizeof(*j));
	if (j->user)
		marshal_append(state, j->user, strlen(j->user) + 1);
	if (j->chrootdir)
		marshal_append(state, j->chrootdir, strlen(j->chrootdir) + 1);
	if (j->chdir)
		marshal_append(state, j->chdir, strlen(j->chdir) + 1);
	if (j->flags.seccomp_filter && j->filter_prog) {
		struct sock_fprog *fp = j->filter_prog;
		marshal_append(state, (char *)fp->filter,
				fp->len * sizeof(struct sock_filter));
	}
	for (b = j->bindings_head; b; b = b->next) {
		marshal_append(state, b->src, strlen(b->src) + 1);
		marshal_append(state, b->dest, strlen(b->dest) + 1);
		marshal_append(state, (char *)&b->writeable,
				sizeof(b->writeable));
	}
}

size_t API minijail_size(const struct minijail *j)
{
	struct marshal_state state;
	marshal_state_init(&state, NULL, 0);
	minijail_marshal_helper(&state, j);
	return state.total;
}

int minijail_marshal(const struct minijail *j, char *buf, size_t available)
{
	struct marshal_state state;
	marshal_state_init(&state, buf, available);
	minijail_marshal_helper(&state, j);
	return (state.total > available);
}

/* consumebytes: consumes @length bytes from a buffer @buf of length @buflength
 * @length    Number of bytes to consume
 * @buf       Buffer to consume from
 * @buflength Size of @buf
 *
 * Returns a pointer to the base of the bytes, or NULL for errors.
 */
void *consumebytes(size_t length, char **buf, size_t *buflength)
{
	char *p = *buf;
	if (length > *buflength)
		return NULL;
	*buf += length;
	*buflength -= length;
	return p;
}

/* consumestr: consumes a C string from a buffer @buf of length @length
 * @buf    Buffer to consume
 * @length Length of buffer
 *
 * Returns a pointer to the base of the string, or NULL for errors.
 */
char *consumestr(char **buf, size_t *buflength)
{
	size_t len = strnlen(*buf, *buflength);
	if (len == *buflength)
		/* There's no null-terminator */
		return NULL;
	return consumebytes(len + 1, buf, buflength);
}

int minijail_unmarshal(struct minijail *j, char *serialized, size_t length)
{
	int i;
	int count;
	int ret = -EINVAL;

	if (length < sizeof(*j))
		goto out;
	memcpy((void *)j, serialized, sizeof(*j));
	serialized += sizeof(*j);
	length -= sizeof(*j);

	/* Potentially stale pointers not used as signals. */
	j->bindings_head = NULL;
	j->bindings_tail = NULL;
	j->filter_prog = NULL;

	if (j->user) {		/* stale pointer */
		char *user = consumestr(&serialized, &length);
		if (!user)
			goto clear_pointers;
		j->user = strdup(user);
		if (!j->user)
			goto clear_pointers;
	}

	if (j->chrootdir) {	/* stale pointer */
		char *chrootdir = consumestr(&serialized, &length);
		if (!chrootdir)
			goto bad_chrootdir;
		j->chrootdir = strdup(chrootdir);
		if (!j->chrootdir)
			goto bad_chrootdir;
	}

	if (j->chdir) {	/* stale pointer */
		char *chdirstr = consumestr(&serialized, &length);
		if (!chdirstr)
			goto bad_chdir;
		j->chdir = strdup(chdirstr);
		if (!j->chdir)
			goto bad_chdir;
	}

	if (j->flags.seccomp_filter && j->filter_len > 0) {
		size_t ninstrs = j->filter_len;
		if (ninstrs > (SIZE_MAX / sizeof(struct sock_filter)) ||
		    ninstrs > USHRT_MAX)
			goto bad_filters;

		size_t program_len = ninstrs * sizeof(struct sock_filter);
		void *program = consumebytes(program_len, &serialized, &length);
		if (!program)
			goto bad_filters;

		j->filter_prog = malloc(sizeof(struct sock_fprog));
		j->filter_prog->len = ninstrs;
		j->filter_prog->filter = malloc(program_len);
		memcpy(j->filter_prog->filter, program, program_len);
	}

	if (j->meta_file) {
		j->meta_file = NULL;
	}

	count = j->binding_count;
	j->binding_count = 0;
	for (i = 0; i < count; ++i) {
		int *writeable;
		const char *dest;
		const char *src = consumestr(&serialized, &length);
		if (!src)
			goto bad_bindings;
		dest = consumestr(&serialized, &length);
		if (!dest)
			goto bad_bindings;
		writeable = consumebytes(sizeof(*writeable), &serialized, &length);
		if (!writeable)
			goto bad_bindings;
		if (minijail_bind(j, src, dest, *writeable))
			goto bad_bindings;
	}

	return 0;

bad_bindings:
	if (j->flags.seccomp_filter && j->filter_len > 0) {
		free(j->filter_prog->filter);
		free(j->filter_prog);
	}
bad_filters:
	if (j->chrootdir)
		free(j->chrootdir);
bad_chdir:
	if (j->chdir)
		free(j->chdir);
bad_chrootdir:
	if (j->user)
		free(j->user);
clear_pointers:
	j->user = NULL;
	j->chrootdir = NULL;
	j->chdir = NULL;
out:
	return ret;
}

/* bind_one: Applies bindings from @b for @j, recursing as needed.
 * @j Minijail these bindings are for
 * @b Head of list of bindings
 *
 * Returns 0 for success.
 */
int bind_one(const struct minijail *j, struct binding *b)
{
	int ret = 0;
	char *dest = NULL;
	if (ret)
		return ret;
	/* dest has a leading "/" */
	if (asprintf(&dest, "%s%s", j->chrootdir, b->dest) < 0)
		return -ENOMEM;
	ret = mount(b->src, dest, NULL, MS_BIND, NULL);
	if (ret)
		pdie("bind: %s -> %s", b->src, dest);
	if (!b->writeable) {
		ret = mount(b->src, dest, NULL,
			    MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
		if (ret)
			pdie("bind ro: %s -> %s", b->src, dest);
	}
	free(dest);
	if (b->next)
		return bind_one(j, b->next);
	return ret;
}

int enter_chroot(const struct minijail *j)
{
	int ret;
	if (j->bindings_head && (ret = bind_one(j, j->bindings_head)))
		return ret;

	if (chroot(j->chrootdir))
		return -errno;

	if (chdir(j->chdir ? j->chdir : "/"))
		return -errno;

	return 0;
}

int mount_tmp(void)
{
	return mount("none", "/tmp", "tmpfs", 0, "size=128M,mode=777");
}

int remount_readonly(const struct minijail *j)
{
	int ret = 0;
	char *procPath = NULL;
	const unsigned int kSafeFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID;
	if (asprintf(&procPath, "%s/proc", j->chrootdir ? j->chrootdir : "") < 0)
		return -ENOMEM;
	/*
	 * Right now, we're holding a reference to our parent's old mount of
	 * /proc in our namespace, which means using MS_REMOUNT here would
	 * mutate our parent's mount as well, even though we're in a VFS
	 * namespace (!). Instead, remove their mount from our namespace
	 * and make our own.
	 */
	/* Some distros have JDK mount this. Unmount it without erroring out */
	umount("/proc/sys/fs/binfmt_misc");
	errno = 0;
	if (umount("/proc"))
		ret = -errno;
	else if (mount("", procPath, "proc", kSafeFlags | MS_RDONLY, ""))
		ret = -errno;
	free(procPath);
	return ret;
}

void drop_ugid(const struct minijail *j)
{
	if (j->flags.usergroups) {
		if (initgroups(j->user, j->usergid))
			pdie("initgroups");
	} else {
		/* Only attempt to clear supplemental groups if we are changing
		 * users. */
		if ((j->uid || j->gid) && setgroups(0, NULL))
			pdie("setgroups");
	}

	if (j->flags.gid && setresgid(j->gid, j->gid, j->gid))
		pdie("setresgid");

	if (j->flags.uid && setresuid(j->uid, j->uid, j->uid))
		pdie("setresuid");
}

/*
 * We specifically do not use cap_valid() as that only tells us the last
 * valid cap we were *compiled* against (i.e. what the version of kernel
 * headers says).  If we run on a different kernel version, then it's not
 * uncommon for that to be less (if an older kernel) or more (if a newer
 * kernel).  So suck up the answer via /proc.
 */
static int run_cap_valid(unsigned int cap)
{
	static unsigned int last_cap;

	if (!last_cap) {
		const char cap_file[] = "/proc/sys/kernel/cap_last_cap";
		FILE *fp = fopen(cap_file, "re");
		if (fscanf(fp, "%u", &last_cap) != 1)
			pdie("fscanf(%s)", cap_file);
		fclose(fp);
	}

	return cap <= last_cap;
}

void drop_caps(const struct minijail *j)
{
	cap_t caps = cap_get_proc();
	cap_value_t flag[1];
	const uint64_t one = 1;
	unsigned int i;
	if (!caps)
		die("can't get process caps");
	if (cap_clear_flag(caps, CAP_INHERITABLE))
		die("can't clear inheritable caps");
	if (cap_clear_flag(caps, CAP_EFFECTIVE))
		die("can't clear effective caps");
	if (cap_clear_flag(caps, CAP_PERMITTED))
		die("can't clear permitted caps");
	for (i = 0; i < sizeof(j->caps) * 8 && run_cap_valid(i); ++i) {
		/* Keep CAP_SETPCAP for dropping bounding set bits. */
		if (i != CAP_SETPCAP && !(j->caps & (one << i)))
			continue;
		flag[0] = i;
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, flag, CAP_SET))
			die("can't add effective cap");
		if (cap_set_flag(caps, CAP_PERMITTED, 1, flag, CAP_SET))
			die("can't add permitted cap");
		if (cap_set_flag(caps, CAP_INHERITABLE, 1, flag, CAP_SET))
			die("can't add inheritable cap");
	}
	if (cap_set_proc(caps))
		die("can't apply initial cleaned capset");

	/*
	 * Instead of dropping bounding set first, do it here in case
	 * the caller had a more permissive bounding set which could
	 * have been used above to raise a capability that wasn't already
	 * present. This requires CAP_SETPCAP, so we raised/kept it above.
	 */
	for (i = 0; i < sizeof(j->caps) * 8 && run_cap_valid(i); ++i) {
		if (j->caps & (one << i))
			continue;
		if (prctl(PR_CAPBSET_DROP, i))
			pdie("prctl(PR_CAPBSET_DROP)");
	}

	/* If CAP_SETPCAP wasn't specifically requested, now we remove it. */
	if ((j->caps & (one << CAP_SETPCAP)) == 0) {
		flag[0] = CAP_SETPCAP;
		if (cap_set_flag(caps, CAP_EFFECTIVE, 1, flag, CAP_CLEAR))
			die("can't clear effective cap");
		if (cap_set_flag(caps, CAP_PERMITTED, 1, flag, CAP_CLEAR))
			die("can't clear permitted cap");
		if (cap_set_flag(caps, CAP_INHERITABLE, 1, flag, CAP_CLEAR))
			die("can't clear inheritable cap");
	}

	if (cap_set_proc(caps))
		die("can't apply final cleaned capset");

	cap_free(caps);
}

void set_seccomp_filter(const struct minijail *j)
{
	/*
	 * Set no_new_privs. See </kernel/seccomp.c> and </kernel/sys.c>
	 * in the kernel source tree for an explanation of the parameters.
	 */
	if (j->flags.no_new_privs) {
		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
			pdie("prctl(PR_SET_NO_NEW_PRIVS)");
	}

	/*
	 * If we're logging seccomp filter failures,
	 * install the SIGSYS handler first.
	 */
	if (j->flags.seccomp_filter && j->flags.log_seccomp_filter) {
		if (install_sigsys_handler())
			pdie("install SIGSYS handler");
		warn("logging seccomp filter failures");
	}

	/*
	 * Install the syscall filter.
	 */
	if (j->flags.seccomp_filter) {
		if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, j->filter_prog))
			pdie("prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)");
	}
}

void API minijail_enter(const struct minijail *j)
{
	if (j->flags.pids)
		die("tried to enter a pid-namespaced jail;"
		    "try minijail_run()?");

	if (j->flags.usergroups && !j->user)
		die("usergroup inheritance without username");

	/*
	 * We can't recover from failures if we've dropped privileges partially,
	 * so we don't even try. If any of our operations fail, we abort() the
	 * entire process.
	 */
	if (j->flags.vfs && unshare(CLONE_NEWNS))
		pdie("unshare(vfs)");

	if (j->flags.net && unshare(CLONE_NEWNET))
		pdie("unshare(net)");

	if (j->flags.chroot && enter_chroot(j))
		pdie("chroot");

	if (j->flags.chroot && j->flags.mount_tmp && mount_tmp())
		pdie("mount_tmp");

	if (j->flags.readonly && remount_readonly(j))
		pdie("remount");

	if (j->flags.caps) {
		/*
		 * POSIX capabilities are a bit tricky. If we drop our
		 * capability to change uids, our attempt to use setuid()
		 * below will fail. Hang on to root caps across setuid(), then
		 * lock securebits.
		 */
		if (prctl(PR_SET_KEEPCAPS, 1))
			pdie("prctl(PR_SET_KEEPCAPS)");
		if (prctl
		    (PR_SET_SECUREBITS, SECURE_ALL_BITS | SECURE_ALL_LOCKS))
			pdie("prctl(PR_SET_SECUREBITS)");
	}

	/*
	 * If we're setting no_new_privs, we can drop privileges
	 * before setting seccomp filter. This way filter policies
	 * don't need to allow privilege-dropping syscalls.
	 */
	if (j->flags.no_new_privs) {
		drop_ugid(j);
		if (j->flags.caps)
			drop_caps(j);

		set_seccomp_filter(j);
	} else {
		/*
		 * If we're not setting no_new_privs,
		 * we need to set seccomp filter *before* dropping privileges.
		 * WARNING: this means that filter policies *must* allow
		 * setgroups()/setresgid()/setresuid() for dropping root and
		 * capget()/capset()/prctl() for dropping caps.
		 */
		set_seccomp_filter(j);

		drop_ugid(j);
		if (j->flags.caps)
			drop_caps(j);
	}

	/*
	 * seccomp has to come last since it cuts off all the other
	 * privilege-dropping syscalls :)
	 */
	if (j->flags.seccomp && prctl(PR_SET_SECCOMP, 1))
		pdie("prctl(PR_SET_SECCOMP)");
}

/* TODO(wad) will visibility affect this variable? */
static int init_exitstatus = 0;
static pid_t child_pid = 0;
static int signal_override = 0;

void init_term(int __attribute__ ((unused)) sig)
{
	_exit(init_exitstatus);
}

void timeout(int __attribute__ ((unused)) sig)
{
	/* Something went wrong or the child ignored SIGALRM. */
	signal_override = SIGXCPU;
	kill(-child_pid, SIGKILL);
}

int init(struct minijail *j, pid_t rootpid)
{
	pid_t pid;
	int exit_status;
	int exit_signal;
	int status;
	struct rusage usage;
	struct timespec t0, t1;
	/* Measure wall-time when outputting metadata information */
	if (j->flags.meta_file) {
		clock_gettime(CLOCK_REALTIME, &t0);
	}
	/* Backup for timeouts */
	if (j->flags.time_limit) {
		child_pid = rootpid;
		signal(SIGALRM, timeout);
		alarm((j->time_limit + 1999) / 1000);
	}
	/* so that we exit with the right status */
	signal(SIGTERM, init_term);
	/* TODO(wad) self jail with seccomp_filters here. */
	while ((pid = wait3(&status, 0, &usage)) > 0) {
		/*
		 * This loop will only end when either there are no processes
		 * left inside our pid namespace or we get a signal.
		 */
		if (pid == rootpid)
			init_exitstatus = status;
	}
	if (j->flags.meta_file) {
		clock_gettime(CLOCK_REALTIME, &t1);
		t1.tv_sec -= t0.tv_sec;
		if (t1.tv_nsec < t0.tv_nsec) {
			t1.tv_sec--;
			t1.tv_nsec = 1000000000L + t1.tv_nsec - t0.tv_nsec;
		} else {
			t1.tv_nsec -= t0.tv_nsec;
		}
		fprintf(j->meta_file,
				"time:%ld\ntime-wall:%ld\nmem:%ld\n",
				1000000 * usage.ru_utime.tv_sec + usage.ru_utime.tv_usec,
				(1000000000L * t1.tv_sec + t1.tv_nsec) / 1000L,
				usage.ru_maxrss * 1024);
	}

	exit_signal = 0;
	if (signal_override) {
		exit_signal = signal_override;
		exit_status = MINIJAIL_ERR_INIT;
	} else if (!WIFEXITED(init_exitstatus)) {
		exit_signal = -1;
		if (WIFSIGNALED(init_exitstatus)) {
			exit_signal = WTERMSIG(init_exitstatus);
		}
		exit_status = MINIJAIL_ERR_INIT;
	} else {
		exit_status = WEXITSTATUS(init_exitstatus);
	}
	if (j->flags.meta_file) {
		if (exit_signal != 0) {
			fprintf(j->meta_file, "signal:%d\n", exit_signal);
		} else {
			fprintf(j->meta_file, "status:%d\n", exit_status);
		}
		fclose(j->meta_file);
	}
	if (exit_signal == SIGSYS) {
		warn("illegal syscall");
	} else {
		info("normal exit");
	}
	_exit(exit_status);
}

int API minijail_from_fd(int fd, struct minijail *j)
{
	size_t sz = 0;
	size_t bytes = read(fd, &sz, sizeof(sz));
	char *buf;
	int r;
	if (sizeof(sz) != bytes)
		return -EINVAL;
	if (sz > USHRT_MAX)	/* Arbitrary sanity check */
		return -E2BIG;
	buf = malloc(sz);
	if (!buf)
		return -ENOMEM;
	bytes = read(fd, buf, sz);
	if (bytes != sz) {
		free(buf);
		return -EINVAL;
	}
	r = minijail_unmarshal(j, buf, sz);
	free(buf);
	return r;
}

int API minijail_to_fd(struct minijail *j, int fd)
{
	char *buf;
	size_t sz = minijail_size(j);
	ssize_t written;
	int r;

	if (!sz)
		return -EINVAL;
	buf = malloc(sz);
	r = minijail_marshal(j, buf, sz);
	if (r) {
		free(buf);
		return r;
	}
	/* Sends [size][minijail]. */
	written = write(fd, &sz, sizeof(sz));
	if (written != sizeof(sz)) {
		free(buf);
		return -EFAULT;
	}
	written = write(fd, buf, sz);
	if (written < 0 || (size_t) written != sz) {
		free(buf);
		return -EFAULT;
	}
	free(buf);
	return 0;
}

int setup_preload(void)
{
	char *oldenv = getenv(kLdPreloadEnvVar) ? : "";
	char *newenv = malloc(strlen(oldenv) + 2 + strlen(PRELOADPATH));
	if (!newenv)
		return -ENOMEM;

	/* Only insert a separating space if we have something to separate... */
	sprintf(newenv, "%s%s%s", oldenv, strlen(oldenv) ? " " : "",
		PRELOADPATH);

	/* setenv() makes a copy of the string we give it */
	setenv(kLdPreloadEnvVar, newenv, 1);
	free(newenv);
	return 0;
}

int setup_pipe(int fds[2])
{
	int r = pipe(fds);
	char fd_buf[11];
	if (r)
		return r;
	r = snprintf(fd_buf, sizeof(fd_buf), "%d", fds[0]);
	if (r <= 0)
		return -EINVAL;
	setenv(kFdEnvVar, fd_buf, 1);
	return 0;
}

int setup_pipe_end(int fds[2], size_t index)
{
	if (index > 1)
		return -1;

	close(fds[1 - index]);
	return fds[index];
}

int setup_and_dupe_pipe_end(int fds[2], size_t index, int fd)
{
	if (index > 1)
		return -1;

	close(fds[1 - index]);
	/* dup2(2) the corresponding end of the pipe into |fd|. */
	return dup2(fds[index], fd);
}

int setup_limits(struct minijail *j) {
	struct rlimit limit;

	if (j->flags.memory_limit) {
		limit.rlim_cur = limit.rlim_max = j->memory_limit;
		if (setrlimit(RLIMIT_AS, &limit)) {
			return -1;
		}
	}

	if (j->flags.output_limit) {
		limit.rlim_cur = limit.rlim_max = j->output_limit;
		if (setrlimit(RLIMIT_FSIZE, &limit)) {
			return -1;
		}

		/* Diable core dumping if there is an output limit. */
		limit.rlim_cur = limit.rlim_max = 0;
		if (setrlimit(RLIMIT_CORE, &limit)) {
			return -1;
		}
	}

	if (j->flags.stack_limit) {
		limit.rlim_cur = limit.rlim_max = j->stack_limit;
		if (setrlimit(RLIMIT_STACK, &limit)) {
			return -1;
		}
	}

	if (j->flags.time_limit) {
		limit.rlim_cur = (999 + j->time_limit) / 1000;
		limit.rlim_max = limit.rlim_cur + 1;
		if (setrlimit(RLIMIT_CPU, &limit)) {
			return -1;
		}

		ualarm(j->time_limit * 1000, 0);
	}

	return 0;
}

int API minijail_run(struct minijail *j, const char *filename,
		     char *const argv[])
{
	return minijail_run_pid_pipes(j, filename, argv,
				      NULL, NULL, NULL, NULL);
}

int API minijail_run_pid(struct minijail *j, const char *filename,
			 char *const argv[], pid_t *pchild_pid)
{
	return minijail_run_pid_pipes(j, filename, argv, pchild_pid,
				      NULL, NULL, NULL);
}

int API minijail_run_pipe(struct minijail *j, const char *filename,
			  char *const argv[], int *pstdin_fd)
{
	return minijail_run_pid_pipes(j, filename, argv, NULL, pstdin_fd,
				      NULL, NULL);
}

int API minijail_run_pid_pipe(struct minijail *j, const char *filename,
			      char *const argv[], pid_t *pchild_pid,
			      int *pstdin_fd)
{
	return minijail_run_pid_pipes(j, filename, argv, pchild_pid, pstdin_fd,
				      NULL, NULL);
}

int API minijail_run_pid_pipes(struct minijail *j, const char *filename,
			       char *const argv[], pid_t *pchild_pid,
			       int *pstdin_fd, int *pstdout_fd, int *pstderr_fd)
{
	char *oldenv, *oldenv_copy = NULL;
	pid_t child_pid;
	int pipe_fds[2];
	int stdin_fds[2];
	int stdout_fds[2];
	int stderr_fds[2];
	int ret;
	/* We need to remember this across the minijail_preexec() call. */
	int pid_namespace = j->flags.pids;
	int chroot = j->flags.chroot;

	oldenv = getenv(kLdPreloadEnvVar);
	if (oldenv) {
		oldenv_copy = strdup(oldenv);
		if (!oldenv_copy)
			return -ENOMEM;
	}

	if (setup_preload())
		return -EFAULT;

	/*
	 * Before we fork(2) and execve(2) the child process, we need to open
	 * a pipe(2) to send the minijail configuration over.
	 */
	if (setup_pipe(pipe_fds))
		return -EFAULT;

	/*
	 * If we want to write to the child process' standard input,
	 * create the pipe(2) now.
	 */
	if (pstdin_fd) {
		if (pipe(stdin_fds))
			return -EFAULT;
	}

	/*
	 * If we want to read from the child process' standard output,
	 * create the pipe(2) now.
	 */
	if (pstdout_fd) {
		if (pipe(stdout_fds))
			return -EFAULT;
	}

	/*
	 * If we want to read from the child process' standard error,
	 * create the pipe(2) now.
	 */
	if (pstderr_fd) {
		if (pipe(stderr_fds))
			return -EFAULT;
	}

	/* Use sys_clone() if and only if we're creating a pid namespace.
	 *
	 * tl;dr: WARNING: do not mix pid namespaces and multithreading.
	 *
	 * In multithreaded programs, there are a bunch of locks inside libc,
	 * some of which may be held by other threads at the time that we call
	 * minijail_run_pid(). If we call fork(), glibc does its level best to
	 * ensure that we hold all of these locks before it calls clone()
	 * internally and drop them after clone() returns, but when we call
	 * sys_clone(2) directly, all that gets bypassed and we end up with a
	 * child address space where some of libc's important locks are held by
	 * other threads (which did not get cloned, and hence will never release
	 * those locks). This is okay so long as we call exec() immediately
	 * after, but a bunch of seemingly-innocent libc functions like setenv()
	 * take locks.
	 *
	 * Hence, only call sys_clone() if we need to, in order to get at pid
	 * namespacing. If we follow this path, the child's address space might
	 * have broken locks; you may only call functions that do not acquire
	 * any locks.
	 *
	 * Unfortunately, fork() acquires every lock it can get its hands on, as
	 * previously detailed, so this function is highly likely to deadlock
	 * later on (see "deadlock here") if we're multithreaded.
	 *
	 * We might hack around this by having the clone()d child (init of the
	 * pid namespace) return directly, rather than leaving the clone()d
	 * process hanging around to be init for the new namespace (and having
	 * its fork()ed child return in turn), but that process would be crippled
	 * with its libc locks potentially broken. We might try fork()ing in the
	 * parent before we clone() to ensure that we own all the locks, but
	 * then we have to have the forked child hanging around consuming
	 * resources (and possibly having file descriptors / shared memory
	 * regions / etc attached). We'd need to keep the child around to avoid
	 * having its children get reparented to init.
	 *
	 * TODO(ellyjones): figure out if the "forked child hanging around"
	 * problem is fixable or not. It would be nice if we worked in this
	 * case.
	 */
	if (pid_namespace)
		child_pid = syscall(SYS_clone, CLONE_NEWPID | SIGCHLD, NULL);
	else
		child_pid = fork();

	if (child_pid < 0) {
		free(oldenv_copy);
		die("failed to fork child");
	}

	if (child_pid) {
		/* Restore parent's LD_PRELOAD. */
		if (oldenv_copy) {
			setenv(kLdPreloadEnvVar, oldenv_copy, 1);
			free(oldenv_copy);
		} else {
			unsetenv(kLdPreloadEnvVar);
		}
		unsetenv(kFdEnvVar);

		j->initpid = child_pid;

		/* Send marshalled minijail. */
		close(pipe_fds[0]);	/* read endpoint */
		ret = minijail_to_fd(j, pipe_fds[1]);
		close(pipe_fds[1]);	/* write endpoint */
		if (ret) {
			kill(j->initpid, SIGKILL);
			die("failed to send marshalled minijail");
		}

		if (pchild_pid)
			*pchild_pid = child_pid;

		/*
		 * If we want to write to the child process' standard input,
		 * set up the write end of the pipe.
		 */
		if (pstdin_fd)
			*pstdin_fd = setup_pipe_end(stdin_fds,
						    1	/* write end */);

		/*
		 * If we want to read from the child process' standard output,
		 * set up the read end of the pipe.
		 */
		if (pstdout_fd)
			*pstdout_fd = setup_pipe_end(stdout_fds,
						     0	/* read end */);

		/*
		 * If we want to read from the child process' standard error,
		 * set up the read end of the pipe.
		 */
		if (pstderr_fd)
			*pstderr_fd = setup_pipe_end(stderr_fds,
						     0	/* read end */);

		return 0;
	}
	free(oldenv_copy);

	/*
	 * If we want to write to the jailed process' standard input,
	 * set up the read end of the pipe.
	 */
	if (pstdin_fd) {
		if (setup_and_dupe_pipe_end(stdin_fds, 0 /* read end */,
					    STDIN_FILENO) < 0)
			die("failed to set up stdin pipe");
	}

	/*
	 * If we want to read from the jailed process' standard output,
	 * set up the write end of the pipe.
	 */
	if (pstdout_fd) {
		if (setup_and_dupe_pipe_end(stdout_fds, 1 /* write end */,
					    STDOUT_FILENO) < 0)
			die("failed to set up stdout pipe");
	}

	/*
	 * If we want to read from the jailed process' standard error,
	 * set up the write end of the pipe.
	 */
	if (pstderr_fd) {
		if (setup_and_dupe_pipe_end(stderr_fds, 1 /* write end */,
					    STDERR_FILENO) < 0)
			die("failed to set up stderr pipe");
	}

	/* Strip out flags that cannot be inherited across execve. */
	minijail_preexec(j);
	/* Jail this process and its descendants... */
	minijail_enter(j);

	if (pid_namespace) {
		/*
		 * pid namespace: this process will become init inside the new
		 * namespace, so fork off a child to actually run the program
		 * (we don't want all programs we might exec to have to know
		 * how to be init).
		 *
		 * If we're multithreaded, we'll probably deadlock here. See
		 * WARNING above.
		 */
		child_pid = fork();
		if (child_pid < 0)
			_exit(child_pid);
		else if (child_pid > 0)
			init(j, child_pid);	/* never returns */
	}

	/* Move the child into its own process group to kill it easily */
	if (setsid() == -1) {
		die("setsid");
	}

	/*
	 * If we aren't pid-namespaced:
	 *   calling process
	 *   -> chroot()-ing process
	 *      -> execve()-ing process
	 * If we are:
	 *   calling process
	 *   -> init()-ing process
	 *      -> chroot()-int process
	 *         -> execve()-ing process
	 */
	if (chroot && enter_chroot(j)) {
		pdie("chroot");
	}

	_exit(execve(filename, argv, environ));
}

int API minijail_run_static(struct minijail *j, const char *filename,
			    char *const argv[])
{
	pid_t child_pid;
	int pid_namespace = j->flags.pids;

	if (j->flags.caps)
		die("caps not supported with static targets");

	if (pid_namespace)
		child_pid = syscall(SYS_clone, CLONE_NEWPID | SIGCHLD, NULL);
	else
		child_pid = fork();

	if (child_pid < 0) {
		die("failed to fork child");
	}
	if (child_pid > 0 ) {
		j->initpid = child_pid;
		return 0;
	}

	/*
	 * We can now drop this child into the sandbox
	 * then execve the target.
	 */

	j->flags.pids = 0;
	minijail_enter(j);

	if (pid_namespace) {
		/*
		 * pid namespace: this process will become init inside the new
		 * namespace, so fork off a child to actually run the program
		 * (we don't want all programs we might exec to have to know
		 * how to be init).
		 *
		 * If we're multithreaded, we'll probably deadlock here. See
		 * WARNING above.
		 */
		child_pid = fork();
		if (child_pid < 0)
			_exit(child_pid);
		else if (child_pid > 0)
			init(j, child_pid);	/* never returns */
	}

	if (j->flags.chroot && enter_chroot(j)) {
		pdie("chroot");
	}

	if (setup_limits(j)) {
		die("failed to set execution limits");
	}

	if (j->flags.meta_file) {
		fclose(j->meta_file);
	}

	_exit(execve(filename, argv, environ));
}

int API minijail_kill(struct minijail *j)
{
	int st;
	if (kill(j->initpid, SIGTERM))
		return -errno;
	if (waitpid(j->initpid, &st, 0) < 0)
		return -errno;
	return st;
}

int API minijail_wait(struct minijail *j)
{
	int st;
	if (waitpid(j->initpid, &st, 0) < 0)
		return -errno;

	if (!WIFEXITED(st)) {
		int error_status = st;
		if (WIFSIGNALED(st)) {
			int signum = WTERMSIG(st);
			warn("child process %d received signal %d",
			     j->initpid, signum);
			/*
			 * We return MINIJAIL_ERR_JAIL if the process received
			 * SIGSYS, which happens when a syscall is blocked by
			 * seccomp filters.
			 * If not, we do what bash(1) does:
			 * $? = 128 + signum
			 */
			if (signum == SIGSYS) {
				error_status = MINIJAIL_ERR_JAIL;
			} else {
				error_status = 128 + signum;
			}
		}
		return error_status;
	}

	int exit_status = WEXITSTATUS(st);
	if (exit_status != 0)
		info("child process %d exited with status %d",
		     j->initpid, exit_status);

	return exit_status;
}

void API minijail_destroy(struct minijail *j)
{
	if (j->flags.seccomp_filter && j->filter_prog) {
		free(j->filter_prog->filter);
		free(j->filter_prog);
	}
	while (j->bindings_head) {
		struct binding *b = j->bindings_head;
		j->bindings_head = j->bindings_head->next;
		free(b->dest);
		free(b->src);
		free(b);
	}
	j->bindings_tail = NULL;
	if (j->user)
		free(j->user);
	if (j->chrootdir)
		free(j->chrootdir);
	if (j->chdir)
		free(j->chdir);
	free(j);
}

int concat_path(char *buffer, size_t buffer_len, const char *path)
{
	if (buffer == NULL || path == NULL)
		return 1;
	size_t len = strlen(buffer);
	size_t pathlen = strlen(path);
	if (len && buffer[len - 1] != '/' && path[0] != '/') {
		if (len + pathlen + 1 >= buffer_len)
			return -1;
		snprintf(buffer + len, buffer_len - len - 1, "/%s", path);
	} else if (len && buffer[len - 1] == '/' && path[0] == '/') {
		if (len + pathlen >= buffer_len)
			return -1;
		strncpy(buffer + len, path + 1, buffer_len - len);
	} else {
		if (len + pathlen >= buffer_len)
			return -1;
		strncpy(buffer + len, path, buffer_len - len);
	}
	return 0;
}

int API minijail_get_path(struct minijail *j, char *buffer, size_t buffer_len,
			   const char *path)
{
	struct stat st;
	buffer[0] = '\0';

	// Get the absolute path of the file, including the chdir if this is a
	// relative path.
	if (path[0] != '/') {
		if (j->flags.chdir) {
			if (0 != concat_path(buffer, buffer_len, j->chdir))
				return 1;
		} else if (j->flags.chroot) {
			if (0 != concat_path(buffer, buffer_len, "/"))
				return 1;
		} else {
			if (getcwd(buffer, buffer_len) == NULL)
				return 1;
		}
	}
	size_t len = strlen(buffer);
	if (0 != concat_path(buffer, buffer_len - len, path))
		return 1;
	len = strlen(buffer);

	// Get the binding with the longest match.
	struct binding *cur = j->bindings_head, *best = NULL;
	size_t best_len = 0, mount_len = 0;
	while (j->bindings_tail) {
		mount_len = strlen(cur->dest);
		if (strncmp(cur->dest, buffer, mount_len) == 0 && mount_len > best_len) {
			best_len = mount_len;
			best = cur;
		}
		if (cur == j->bindings_tail)
			break;
		cur = cur->next;
	}

	const char* src_path = NULL;
	if (best != NULL) {
		src_path = best->src;
	} else if (j->flags.chroot) {
		src_path = j->chrootdir;
		best_len = 1;
	} else {
		src_path = "/";
		best_len = 1;
	}
	size_t src_len = strlen(src_path);
	// Trim the trailing /, if any
	if (src_path[src_len - 1] == '/') {
		src_len--;
	}
	if (len - best_len + src_len + 2 >= buffer_len) {
		fprintf(stderr, "Not enough space\n");
		return 1;
	}

	memmove(buffer + src_len + 1, buffer + best_len, len - best_len);
	strncpy(buffer, src_path, src_len);
	buffer[src_len] = '/';

	if (lstat(buffer, &st) == -1) {
		return 1;
	}

	// Regular file. All is good.
	if (S_ISREG(st.st_mode)) {
		return 0;
	}

	// Not a symbolic link. Disallowing.
	if (!S_ISLNK(st.st_mode)) {
		return 1;
	}

	char linkpath[PATH_MAX+1];
	ssize_t linklen;
	linklen = readlink(buffer, linkpath, sizeof(linkpath) - 1);
	if (linklen == -1) {
		fprintf(stderr, "Invalid symlink\n");
		return 1;
	}
	linkpath[linklen] = '\0';

	// Recursively try to figure out the real path.
	return minijail_get_path(j, buffer, buffer_len, linkpath);
}

/* The following are only used for omegaUp */
void API minijail_stack_limit(struct minijail *j, int stack_limit)
{
	j->flags.stack_limit = 1;
	j->stack_limit = stack_limit;
}

void API minijail_time_limit(struct minijail *j, int msec_limit)
{
	j->flags.time_limit = 1;
	j->time_limit = msec_limit;
}

void API minijail_output_limit(struct minijail *j, int byte_limit)
{
	j->flags.output_limit = 1;
	j->output_limit = byte_limit;
}

void API minijail_memory_limit(struct minijail *j, int byte_limit)
{
	j->flags.memory_limit = 1;
	j->memory_limit = byte_limit;
}

int API minijail_meta_file(struct minijail *j, const char *meta_path)
{
	j->flags.meta_file = 1;
	j->meta_file = fopen(meta_path, "w");
	if (j->meta_file == NULL) {
		return -1;
	}
	return 0;
}
