/* Oracle for the sandbox differential test: the system libalpm's alpm_sandbox_setup_child.
 * usage: sandboxcheck <allowed-dir> <outside-path> [nofs|nosys]  (run as uid 0, e.g. under `unshare -Ur`)
 * The final setgid/setuid to the sandbox user fails in a user namespace, after the filesystem and syscall
 * restrictions are in place; the probes then show what is restricted. */
#include <alpm.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <unistd.h>

static void logcb(void *ctx, alpm_loglevel_t level, const char *fmt, va_list args)
{
	(void)ctx;
	if(level & (ALPM_LOG_ERROR | ALPM_LOG_WARNING | ALPM_LOG_DEBUG)) {
		char buf[512];
		vsnprintf(buf, sizeof(buf), fmt, args);
		/* the Landlock ABI depends on the kernel, not on the port: hide the number */
		char *p = strstr(buf, "Landlock ABI is ");
		if(p) { p[strlen("Landlock ABI is ")] = 0; strcat(buf, "N\n"); }
		/* only the sandbox messages */
		if(strstr(buf, "restrict") || strstr(buf, "seccomp") || strstr(buf, "Landlock")) {
			printf("log %d: %s", level, buf);
		}
	}
}

int main(int argc, char **argv)
{
	if(argc < 3) { return 2; }
	alpm_errno_t err;
	char dbpath[] = "/tmp/sandboxcheck-db-XXXXXX";
	if(!mkdtemp(dbpath)) { return 2; }
	char local[300]; snprintf(local, sizeof(local), "%s/local", dbpath); mkdir(local, 0755);
	alpm_handle_t *h = alpm_initialize("/", dbpath, &err);
	if(!h) { printf("init failed\n"); return 1; }
	alpm_option_set_logcb(h, logcb, NULL);
	if(argc > 3 && !strcmp(argv[3], "nofs")) { alpm_option_set_disable_sandbox_filesystem(h, 1); }
	if(argc > 3 && !strcmp(argv[3], "nosys")) { alpm_option_set_disable_sandbox_syscalls(h, 1); }
	int ret = alpm_sandbox_setup_child(h, "nobody", argv[1], true);
	printf("setup ret=%d\n", ret);
	char in[600]; snprintf(in, sizeof(in), "%s/inside", argv[1]);
	int fd = open(in, O_CREAT | O_WRONLY, 0644);
	printf("probe write-inside fd_ok=%d errno=%d\n", fd >= 0, fd >= 0 ? 0 : errno);
	fd = open(argv[2], O_CREAT | O_WRONLY, 0644);
	printf("probe write-outside fd_ok=%d errno=%d\n", fd >= 0, fd >= 0 ? 0 : errno);
	fd = open("/etc/hostname", O_RDONLY);
	printf("probe read-etc fd_ok=%d\n", fd >= 0);
	errno = 0; ret = mount("none", "/tmp", "tmpfs", 0, NULL);
	printf("probe mount ret=%d errno=%d\n", ret, errno);
	errno = 0; struct timeval tv = {0, 0}; ret = settimeofday(&tv, NULL);
	printf("probe settimeofday ret=%d errno=%d\n", ret, errno);
	printf("probe getpid ok=%d\n", getpid() > 0);
	rmdir(dbpath);
	return 0;
}
