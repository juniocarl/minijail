#include <ctype.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>

#include "libsyscalls.h"

const char* path = "/var/log/syslog";
char notify_buf[4096]
	__attribute__ ((aligned(__alignof__(struct inotify_event))));
int notify_len;
char* notify_ptr;
int notify_fd;
int notify_wd;
const struct inotify_event* event;
ssize_t read_len;
int read_fd = -1;
char read_buf[4096];
ssize_t read_bytes = 0;
ssize_t read_pos = 0;
int should_reopen = 0;

/* Waits until read_fd is ready to be read. This also detects when the file was
 * truncated, which is useful for logfiles.
 */
int wait_for_activity() {
	struct stat stats;
	while (1) {
		notify_len = read(notify_fd, notify_buf, sizeof(notify_buf));
		if (notify_len <= 0) {
			perror("read");
			return -1;
		}
		// TODO(lhchavez): actually do something with notify_buf.
		// At the very least having the file deleted should return -1, and
		// if the file moved, we should sleep a little while and then reopen.

		if (fstat(read_fd, &stats) < 0) {
			perror("fstat");
			return -1;
		}
		if (stats.st_size > read_len) {
			// Normal case. The file grew and we have new data available.
			return 0;
		} else if (stats.st_size < read_len) {
			// File was truncated. Close and re-open the file.
			if (inotify_rm_watch(notify_fd, notify_wd) == -1) {
				perror("inotify_rm_watch");
				return -1;
			}
			if (close(read_fd) == -1) {
				perror("close");
				return -1;
			}
			read_fd = open(path, O_RDONLY);
			if (read_fd == -1) {
				perror("open");
				return -1;
			}
			notify_wd = inotify_add_watch(notify_fd, path,
					IN_MODIFY | IN_MOVE_SELF | IN_DELETE);
			if (notify_wd == -1) {
				perror("inotify_add_watch");
				return -1;
			}
			read_len = 0;
		}
	}
}

/* Reads one line from read_fd or until buf is full. Always makes sure to leave
 * space for the NUL terminator.
 */
ssize_t readline(char* buf, ssize_t len) {
	ssize_t pos = 0;
	while (pos < len - 1) {
		while (read_pos >= read_bytes) {
			// Need to read another buffer from the file.
			read_bytes = read(read_fd, read_buf, sizeof(read_buf));

			if (read_bytes == -1) {
				perror("read");
				return -1;
			} else if (read_bytes == 0) {
				if (wait_for_activity() == -1) {
					return -1;
				}
				read_pos = sizeof(read_buf);
			} else {
				read_pos = 0;
				read_len += read_bytes;
			}
		}
		buf[pos] = read_buf[read_pos++];
		if (buf[pos] == '\n') {
			break;
		}
		pos++;
	}
	buf[pos] = '\0';

	return pos;
}

/* Opens the file, positions it at the end, and sets up the inotify structures
 */
int init() {
	read_fd = open(path, O_RDONLY);
	if (read_fd == -1) {
		perror("open");
		return -1;
	}
	read_len = lseek(read_fd, 0, SEEK_END);
	if (read_len == -1) {
		perror("lseek");
		return -1;
	}

	notify_fd = inotify_init();
	if (notify_fd == -1) {
		perror("inotify_init");
		return -1;
	}
	notify_wd = inotify_add_watch(notify_fd, path,
			IN_MODIFY | IN_MOVE_SELF | IN_DELETE);
	if (notify_wd == -1) {
		perror("inotify_add_watch");
		return -1;
	}

	return 0;
}

int main() {
	const char* kNormalExit = "libminijail: normal exit";
	const char* kKernel = "kernel:";
	const char* kAudit = "audit";
	const char* kSyscall = "syscall=";
	const char* syscall_text;
	const char* syscall_name;

	char buf[1024];
	ssize_t line_length;
	int syscall_nr = 0;
	int i;

	if (init() == -1) {
		return 1;
	}

	while ((line_length = readline(buf, sizeof(buf))) != -1) {
		if (strstr(buf, kNormalExit) != NULL) {
			// Normal exit. Don't print anything, just return.
			break;
		} else if (strstr(buf, kKernel) != NULL && strstr(buf, kAudit) != NULL &&
				(syscall_text = strstr(buf, kSyscall)) != NULL) {
			// A kernel audit line. Look for the syscall number, look it up in the
			// syscall table, and print out the name.
			syscall_text += strlen(kSyscall);
			while (isdigit(*syscall_text)) {
				syscall_nr = syscall_nr * 10 + (*syscall_text - '0');
				syscall_text++;
			}
			syscall_name = "????";
			for (i = 0; syscall_table[i].name != NULL; i++) {
				if (syscall_table[i].nr == syscall_nr) {
					syscall_name = syscall_table[i].name;
					break;
				}
			}

			printf("%s\n", syscall_name);
			break;
		}
	}

	return line_length == -1 ? 1 : 0;
}
