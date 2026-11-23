//! Port of src/pacman/pacman-conf.c.
use pacman_rs::conf::*;
use pacman_rs::getopt::{Arg, Getopt, LongOpt};
use std::io::Write;

const MYNAME: &str = "pacman-conf";
const MYVER: &str = "1.0.0";

struct Ctx {
    out: std::io::BufWriter<std::io::Stdout>,
    sep: char,
    verbose: bool,
}

impl Ctx {
    fn show_bool(&mut self, d: &str, v: bool) {
        if v {
            let _ = write!(self.out, "{}{}", d, self.sep);
        }
    }
    fn show_str(&mut self, d: &str, v: &str) {
        if self.verbose {
            let _ = write!(self.out, "{d} = ");
        }
        let _ = write!(self.out, "{}{}", v, self.sep);
    }
    fn show_opt(&mut self, d: &str, v: &Option<String>) {
        if let Some(v) = v {
            self.show_str(d, v);
        }
    }
    fn show_int(&mut self, d: &str, v: u32) {
        if self.verbose {
            let _ = write!(self.out, "{d} = ");
        }
        let _ = write!(self.out, "{}{}", v, self.sep);
    }
    fn show_list(&mut self, d: &str, l: &[String]) {
        for s in l {
            self.show_str(d, s);
        }
    }
    fn show_cleanmethod(&mut self, d: &str, m: u32) {
        if m & CLEAN_KEEPINST != 0 {
            self.show_str(d, "KeepInstalled");
        }
        if m & CLEAN_KEEPCUR != 0 {
            self.show_str(d, "KeepCurrent");
        }
    }
    fn show_siglevel(&mut self, d: &str, level: i32, pkgonly: bool) {
        if level == SIG_USE_DEFAULT {
            return;
        }
        if level & SIG_PACKAGE != 0 {
            self.show_str(
                d,
                if level & SIG_PACKAGE_OPTIONAL != 0 {
                    "PackageOptional"
                } else {
                    "PackageRequired"
                },
            );
            self.show_str(
                d,
                if level & SIG_PACKAGE_UNKNOWN_OK != 0 {
                    "PackageTrustAll"
                } else {
                    "PackageTrustedOnly"
                },
            );
        } else {
            self.show_str(d, "PackageNever");
        }
        if pkgonly {
            return;
        }
        if level & SIG_DATABASE != 0 {
            self.show_str(
                d,
                if level & SIG_DATABASE_OPTIONAL != 0 {
                    "DatabaseOptional"
                } else {
                    "DatabaseRequired"
                },
            );
            self.show_str(
                d,
                if level & SIG_DATABASE_UNKNOWN_OK != 0 {
                    "DatabaseTrustAll"
                } else {
                    "DatabaseTrustedOnly"
                },
            );
        } else {
            self.show_str(d, "DatabaseNever");
        }
    }
    fn show_usage(&mut self, d: &str, usage: i32) {
        if usage == DB_USAGE_ALL {
            self.show_str(d, "All");
        } else {
            for (bit, n) in [
                (DB_USAGE_SYNC, "Sync"),
                (DB_USAGE_SEARCH, "Search"),
                (DB_USAGE_INSTALL, "Install"),
                (DB_USAGE_UPGRADE, "Upgrade"),
            ] {
                if usage & bit != 0 {
                    self.show_str(d, n);
                }
            }
        }
    }
    fn dump_repo(&mut self, r: &ConfigRepo) {
        self.show_usage("Usage", r.usage);
        self.show_siglevel("SigLevel", r.siglevel, false);
        self.show_list("CacheServer", &r.cache_servers);
        self.show_list("Server", &r.servers);
    }
    fn dump_config(&mut self, c: &Config) {
        let _ = write!(self.out, "[options]{}", self.sep);
        self.show_opt("RootDir", &c.rootdir);
        self.show_opt("DBPath", &c.dbpath);
        self.show_list("CacheDir", &c.cachedirs);
        self.show_list("HookDir", &c.hookdirs);
        self.show_opt("GPGDir", &c.gpgdir);
        self.show_opt("LogFile", &c.logfile);
        self.show_opt("DownloadUser", &c.sandboxuser);
        self.show_list("HoldPkg", &c.holdpkg);
        self.show_list("IgnorePkg", &c.ignorepkg);
        self.show_list("IgnoreGroup", &c.ignoregrp);
        self.show_list("NoUpgrade", &c.noupgrade);
        self.show_list("NoExtract", &c.noextract);
        self.show_list("Architecture", &c.architectures);
        self.show_opt("XferCommand", &c.xfercommand);
        self.show_bool("UseSyslog", c.usesyslog);
        self.show_bool("Color", c.color != 0);
        self.show_bool("CheckSpace", c.checkspace);
        self.show_bool("VerbosePkgLists", c.verbosepkglists);
        self.show_bool("DisableDownloadTimeout", c.disable_dl_timeout);
        self.show_bool("ILoveCandy", c.chomp);
        self.show_bool("NoProgressBar", c.noprogressbar);
        self.show_bool("DisableSandboxFilesystem", c.disable_sandbox_filesystem);
        self.show_bool("DisableSandboxSyscalls", c.disable_sandbox_syscalls);
        self.show_int("ParallelDownloads", c.parallel_downloads);
        self.show_cleanmethod("CleanMethod", c.cleanmethod);
        self.show_siglevel("SigLevel", c.siglevel, false);
        self.show_siglevel("LocalFileSigLevel", c.localfilesiglevel, true);
        self.show_siglevel("RemoteFileSigLevel", c.remotefilesiglevel, true);
        for r in &c.repos {
            let _ = write!(self.out, "[{}]{}", r.name, self.sep);
            self.dump_repo(r);
        }
    }
    fn list_repo_directives(&mut self, c: &Config, repo_name: &str, directives: &[String]) -> i32 {
        let Some(repo) = c.repos.iter().find(|r| r.name == repo_name) else {
            eprintln!("error: repo '{repo_name}' not configured");
            return 1;
        };
        if directives.is_empty() {
            self.dump_repo(repo);
            return 0;
        }
        let mut ret = 0;
        for d in directives {
            match d.to_ascii_lowercase().as_str() {
                "server" => self.show_list("Server", &repo.servers),
                "cacheserver" => self.show_list("CacheServer", &repo.cache_servers),
                "siglevel" => self.show_siglevel("SigLevel", repo.siglevel, false),
                "usage" => self.show_usage("Usage", repo.usage),
                "include" => {
                    eprintln!("warning: 'Include' directives cannot be queried");
                    ret = 1;
                }
                _ => {
                    eprintln!("warning: unknown directive '{d}'");
                    ret = 1;
                }
            }
        }
        ret
    }
    fn list_directives(&mut self, c: &Config, directives: &[String]) -> i32 {
        if directives.is_empty() {
            self.dump_config(c);
            return 0;
        }
        let mut ret = 0;
        for d in directives {
            match d.to_ascii_lowercase().as_str() {
                "rootdir" => self.show_opt("RootDir", &c.rootdir),
                "dbpath" => self.show_opt("DBPath", &c.dbpath),
                "cachedir" => self.show_list("CacheDir", &c.cachedirs),
                "hookdir" => self.show_list("HookDir", &c.hookdirs),
                "gpgdir" => self.show_opt("GPGDir", &c.gpgdir),
                "logfile" => self.show_opt("LogFile", &c.logfile),
                "downloaduser" => self.show_opt("DownloadUser", &c.sandboxuser),
                "holdpkg" => self.show_list("HoldPkg", &c.holdpkg),
                "ignorepkg" => self.show_list("IgnorePkg", &c.ignorepkg),
                "ignoregroup" => self.show_list("IgnoreGroup", &c.ignoregrp),
                "noupgrade" => self.show_list("NoUpgrade", &c.noupgrade),
                "noextract" => self.show_list("NoExtract", &c.noextract),
                "architecture" => self.show_list("Architecture", &c.architectures),
                "xfercommand" => self.show_opt("XferCommand", &c.xfercommand),
                "usesyslog" => self.show_bool("UseSyslog", c.usesyslog),
                "color" => self.show_bool("Color", c.color != 0),
                "checkspace" => self.show_bool("CheckSpace", c.checkspace),
                "verbosepkglists" => self.show_bool("VerbosePkgLists", c.verbosepkglists),
                "disabledownloadtimeout" => {
                    self.show_bool("DisableDownloadTimeout", c.disable_dl_timeout)
                }
                "ilovecandy" => self.show_bool("ILoveCandy", c.chomp),
                "noprogressbar" => self.show_bool("NoProgressBar", c.noprogressbar),
                "disablesandbox" => {
                    self.show_bool("DisableSandboxFilesystem", c.disable_sandbox_filesystem);
                    self.show_bool("DisableSandboxSyscalls", c.disable_sandbox_syscalls);
                }
                "disablesandboxsyscalls" => {
                    self.show_bool("DisableSandboxSyscalls", c.disable_sandbox_syscalls)
                }
                "paralleldownloads" => self.show_int("ParallelDownloads", c.parallel_downloads),
                "cleanmethod" => self.show_cleanmethod("CleanMethod", c.cleanmethod),
                "siglevel" => self.show_siglevel("SigLevel", c.siglevel, false),
                "localfilesiglevel" => {
                    self.show_siglevel("LocalFileSigLevel", c.localfilesiglevel, true)
                }
                "remotefilesiglevel" => {
                    self.show_siglevel("RemoteFileSigLevel", c.remotefilesiglevel, true)
                }
                "include" => {
                    eprintln!("warning: 'Include' directives cannot be queried");
                    ret = 1;
                }
                _ => {
                    eprintln!("warning: unknown directive '{d}'");
                    ret = 1;
                }
            }
        }
        ret
    }
}

fn usage(ret: i32, to_err: bool) -> ! {
    let text = "pacman-conf - query pacman's configuration file\n\
usage:  pacman-conf [options] [<directive>...]\n\
\x20       pacman-conf (--repo-list|--help|--version)\n\
options:\n\
\x20 -c, --config=<path>  set an alternate configuration file\n\
\x20 -R, --rootdir=<path> set an alternate installation root\n\
\x20 -S, --sysroot=<path> set an alternate system root\n\
\x20 -r, --repo=<remote>  query options for a specific repo\n\
\x20 -v, --verbose        always show directive names\n\
\x20 -l, --repo-list      list configured repositories\n\
\x20 -h, --help           display this help information\n\
\x20 -V, --version        display version information\n";
    if to_err {
        eprint!("{text}");
    } else {
        print!("{text}");
    }
    std::process::exit(ret);
}

fn main() {
    let mut config = config_new();
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let long = [
        LongOpt {
            name: "config",
            has_arg: Arg::Required,
            val: 'c',
        },
        LongOpt {
            name: "rootdir",
            has_arg: Arg::Required,
            val: 'R',
        },
        LongOpt {
            name: "sysroot",
            has_arg: Arg::Required,
            val: 'S',
        },
        LongOpt {
            name: "repo",
            has_arg: Arg::Required,
            val: 'r',
        },
        LongOpt {
            name: "repo-list",
            has_arg: Arg::No,
            val: 'l',
        },
        LongOpt {
            name: "verbose",
            has_arg: Arg::No,
            val: 'v',
        },
        LongOpt {
            name: "help",
            has_arg: Arg::No,
            val: 'h',
        },
        LongOpt {
            name: "version",
            has_arg: Arg::No,
            val: 'V',
        },
    ];
    let mut g = Getopt::new(args, "c:hlR:S:r:Vv", &long);
    let mut config_file = CONFFILE.to_string();
    let (mut repo_list, mut verbose) = (false, false);
    let mut repo_name: Option<String> = None;
    for (c, arg) in g.by_ref() {
        match c {
            'c' => config_file = arg.unwrap(),
            'R' => config.rootdir = arg,
            'S' => config.sysroot = arg,
            'l' => repo_list = true,
            'r' => repo_name = arg,
            'v' => verbose = true,
            'h' => usage(0, false),
            'V' => {
                println!("{MYNAME} v{MYVER}");
                std::process::exit(0);
            }
            _ => usage(1, true),
        }
    }
    if parseconfigfile(&mut config, &config_file) != 0 || setdefaults(&mut config) != 0 {
        eprintln!("error parsing '{config_file}'");
        std::process::exit(1);
    }
    let directives = std::mem::take(&mut g.operands);
    if directives.len() != 1 {
        verbose = true;
    }
    let mut cx = Ctx {
        out: std::io::BufWriter::new(std::io::stdout()),
        sep: '\n',
        verbose,
    };
    let ret = if repo_list {
        if !directives.is_empty() {
            eprintln!("error: directives may not be specified with --repo-list");
            1
        } else {
            for r in &config.repos {
                if repo_name.as_deref().is_none_or(|n| n == r.name) {
                    let _ = write!(cx.out, "{}{}", r.name, cx.sep);
                }
            }
            0
        }
    } else if let Some(n) = &repo_name {
        cx.list_repo_directives(&config, n, &directives)
    } else {
        cx.list_directives(&config, &directives)
    };
    let _ = cx.out.flush();
    std::process::exit(ret);
}
