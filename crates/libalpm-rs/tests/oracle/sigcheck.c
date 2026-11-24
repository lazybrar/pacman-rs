/* Oracle for the signing differential test: the system libalpm. Output format is shared with
 * examples/sigcheck.rs.  usage: sigcheck <mode> <gpgdir> <dbpath> <level> <path>
 * modes: pkgload | pkgsig | dbvalid | dbsig | syncpkg (path = sync package file name, cwd = its directory) */
#include <alpm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void logcb(void *ctx, alpm_loglevel_t level, const char *fmt, va_list args)
{
	(void)ctx;
	if(level & (ALPM_LOG_ERROR | ALPM_LOG_WARNING)) {
		printf("log %c: ", level & ALPM_LOG_ERROR ? 'E' : 'W');
		vprintf(fmt, args);
	}
}

static void show_list(alpm_siglist_t *l)
{
	for(size_t i = 0; i < l->count; i++) {
		alpm_sigresult_t *r = l->results + i;
		printf("result %zu: status=%d validity=%d fpr=%s uid=%s\n", i, r->status, r->validity,
				r->key.fingerprint ? r->key.fingerprint : "(null)", r->key.uid ? r->key.uid : "(null)");
	}
	alpm_siglist_cleanup(l);
}

int main(int argc, char **argv)
{
	if(argc != 6) { return 2; }
	const char *mode = argv[1], *gpgdir = argv[2], *dbpath = argv[3], *path = argv[5];
	int level = atoi(argv[4]);
	alpm_errno_t err;
	alpm_handle_t *h = alpm_initialize("/", dbpath, &err);
	if(!h) { printf("init failed %d\n", err); return 1; }
	alpm_option_set_logcb(h, logcb, NULL);
	alpm_option_set_gpgdir(h, gpgdir);
	alpm_siglist_t list = {0};
	int ret;
	if(!strcmp(mode, "pkgload")) {
		alpm_pkg_t *pkg = NULL;
		ret = alpm_pkg_load(h, path, 0, level, &pkg);
		printf("ret=%d errno=%d\n", ret, alpm_errno(h));
		if(pkg) { printf("validation=%d\n", alpm_pkg_get_validation(pkg)); }
	} else if(!strcmp(mode, "pkgsig")) {
		alpm_pkg_t *pkg = NULL;
		if(alpm_pkg_load(h, path, 0, 0, &pkg)) { printf("load failed %d\n", alpm_errno(h)); return 1; }
		ret = alpm_pkg_check_pgp_signature(pkg, &list);
		printf("ret=%d errno=%d\n", ret, alpm_errno(h));
		show_list(&list);
	} else if(!strcmp(mode, "dbvalid") || !strcmp(mode, "dbsig")) {
		alpm_db_t *db = alpm_register_syncdb(h, "foo", level);
		if(!db) { printf("register failed %d\n", alpm_errno(h)); return 1; }
		if(!strcmp(mode, "dbvalid")) {
			ret = alpm_db_get_valid(db);
			printf("ret=%d errno=%d\n", ret, alpm_errno(h));
		} else {
			ret = alpm_db_check_pgp_signature(db, &list);
			printf("ret=%d errno=%d\n", ret, alpm_errno(h));
			show_list(&list);
		}
	} else if(!strcmp(mode, "syncpkg")) {
		alpm_db_t *db = alpm_register_syncdb(h, "foo", 0);
		alpm_pkg_t *pkg = alpm_db_get_pkg(db, "sp");
		if(!pkg) { printf("no pkg %d\n", alpm_errno(h)); return 1; }
		ret = alpm_pkg_check_pgp_signature(pkg, &list);
		printf("ret=%d errno=%d\n", ret, alpm_errno(h));
		show_list(&list);
	}
	(void)path;
	alpm_release(h);
	return 0;
}
