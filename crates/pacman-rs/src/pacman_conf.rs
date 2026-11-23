//! Port of src/pacman/pacman-conf.c.
use crate::conf::*;
use crate::getopt::{Getopt, LongOpt};
use std::io::Write;

const MYNAME: &str = "pacman-conf";
const MYVER: &str = "1.0.0";

const LONG: &[LongOpt] = &[
    LongOpt { name: "config", has_arg: true, val: 'c' },
    LongOpt { name: "rootdir", has_arg: true, val: 'R' },
    LongOpt { name: "sysroot", has_arg: true, val: 'S' },
    LongOpt { name: "repo", has_arg: true, val: 'r' },
    LongOpt { name: "repo-list", has_arg: false, val: 'l' },
    LongOpt { name: "verbose", has_arg: false, val: 'v' },
    LongOpt { name: "help", has_arg: false, val: 'h' },
    LongOpt { name: "version", has_arg: false, val: 'V' },
];

struct Out<W: Write> {
    w: W,
    sep: char,
    verbose: bool,
}

impl<W: Write> Out<W> {
    fn bool(&mut self, d: &str, v: bool) {
        if v {
            let _ = write!(self.w, "{d}{}", self.sep);
        }
    }
    fn str(&mut self, d: &str, v: Option<&str>) {
        let Some(v) = v else { return };
        if self.verbose {
            let _ = write!(self.w, "{d} = ");
        }
        let _ = write!(self.w, "{v}{}", self.sep);
    }
    fn int(&mut self, d: &str, v: u32) {
        if self.verbose {
            let _ = write!(self.w, "{d} = ");
        }
        let _ = write!(self.w, "{v}{}", self.sep);
    }
    fn list(&mut self, d: &str, l: &[String]) {
        for s in l {
            self.str(d, Some(s));
        }
    }
    fn cleanmethod(&mut self, d: &str, m: u16) {
        if m & CLEAN_KEEPINST != 0 {
            self.str(d, Some("KeepInstalled"));
        }
        if m & CLEAN_KEEPCUR != 0 {
            self.str(d, Some("KeepCurrent"));
        }
    }
    fn siglevel(&mut self, d: &str, level: i32, pkgonly: bool) {
        if level == SIG_USE_DEFAULT {
            return;
        }
        if level & SIG_PACKAGE != 0 {
            self.str(d, Some(if level & SIG_PACKAGE_OPTIONAL != 0 { "PackageOptional" } else { "PackageRequired" }));
            self.str(d, Some(if level & SIG_PACKAGE_UNKNOWN_OK != 0 { "PackageTrustAll" } else { "PackageTrustedOnly" }));
        } else {
            self.str(d, Some("PackageNever"));
        }
        if pkgonly {
            return;
        }
        if level & SIG_DATABASE != 0 {
            self.str(d, Some(if level & SIG_DATABASE_OPTIONAL != 0 { "DatabaseOptional" } else { "DatabaseRequired" }));
            self.str(d, Some(if level & SIG_DATABASE_UNKNOWN_OK != 0 { "DatabaseTrustAll" } else { "DatabaseTrustedOnly" }));
        } else {
            self.str(d, Some("DatabaseNever"));
        }
    }
    fn usage(&mut self, d: &str, usage: i32) {
        if usage == DB_USAGE_ALL {
            self.str(d, Some("All"));
        } else {
            for (bit, name) in [(DB_USAGE_SYNC, "Sync"), (DB_USAGE_SEARCH, "Search"), (DB_USAGE_INSTALL, "Install"), (DB_USAGE_UPGRADE, "Upgrade")] {
                if usage & bit != 0 {
                    self.str(d, Some(name));
                }
            }
        }
    }
    fn dump_repo(&mut self, repo: &ConfigRepo) {
        self.usage("Usage", repo.usage);
        self.siglevel("SigLevel", repo.siglevel, false);
        self.list("CacheServer", &repo.cache_servers);
        self.list("Server", &repo.servers);
    }
    fn dump_config(&mut self, c: &Config) {
        let _ = write!(self.w, "[options]{}", self.sep);
        self.str("RootDir", c.rootdir.as_deref());
        self.str("DBPath", c.dbpath.as_deref());
        self.list("CacheDir", &c.cachedirs);
        self.list("HookDir", &c.hookdirs);
        self.str("GPGDir", c.gpgdir.as_deref());
        self.str("LogFile", c.logfile.as_deref());
        self.str("DownloadUser", c.sandboxuser.as_deref());
        self.list("HoldPkg", &c.holdpkg);
        self.list("IgnorePkg", &c.ignorepkg);
        self.list("IgnoreGroup", &c.ignoregrp);
        self.list("NoUpgrade", &c.noupgrade);
        self.list("NoExtract", &c.noextract);
        self.list("Architecture", &c.architectures);
        self.str("XferCommand", c.xfercommand.as_deref());
        self.bool("UseSyslog", c.usesyslog);
        self.bool("Color", c.color != 0);
        self.bool("CheckSpace", c.checkspace);
        self.bool("VerbosePkgLists", c.verbosepkglists);
        self.bool("DisableDownloadTimeout", c.disable_dl_timeout);
        self.bool("ILoveCandy", c.chomp);
        self.bool("NoProgressBar", c.noprogressbar);
        self.bool("DisableSandboxFilesystem", c.disable_sandbox_filesystem);
        self.bool("DisableSandboxSyscalls", c.disable_sandbox_syscalls);
        self.int("ParallelDownloads", c.parallel_downloads);
        self.cleanmethod("CleanMethod", c.cleanmethod);
        self.siglevel("SigLevel", c.siglevel, false);
        self.siglevel("LocalFileSigLevel", c.localfilesiglevel, true);
        self.siglevel("RemoteFileSigLevel", c.remotefilesiglevel, true);
        for r in &c.repos {
            let _ = write!(self.w, "[{}]{}", r.name, self.sep);
            self.dump_repo(r);
        }
    }
    /// list_repo_directives
    fn repo_directives(&mut self, c: &Config, repo_name: &str, directives: &[String]) -> i32 {
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
                "server" => self.list("Server", &repo.servers),
                "cacheserver" => self.list("CacheServer", &repo.cache_servers),
                "siglevel" => self.siglevel("SigLevel", repo.siglevel, false),
                "usage" => self.usage("Usage", repo.usage),
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
    /// list_directives
    fn directives(&mut self, c: &Config, directives: &[String]) -> i32 {
        if directives.is_empty() {
            self.dump_config(c);
            return 0;
        }
        let mut ret = 0;
        for d in directives {
            match d.to_ascii_lowercase().as_str() {
                "rootdir" => self.str("RootDir", c.rootdir.as_deref()),
                "dbpath" => self.str("DBPath", c.dbpath.as_deref()),
                "cachedir" => self.list("CacheDir", &c.cachedirs),
                "hookdir" => self.list("HookDir", &c.hookdirs),
                "gpgdir" => self.str("GPGDir", c.gpgdir.as_deref()),
                "logfile" => self.str("LogFile", c.logfile.as_deref()),
                "downloaduser" => self.str("DownloadUser", c.sandboxuser.as_deref()),
                "holdpkg" => self.list("HoldPkg", &c.holdpkg),
                "ignorepkg" => self.list("IgnorePkg", &c.ignorepkg),
                "ignoregroup" => self.list("IgnoreGroup", &c.ignoregrp),
                "noupgrade" => self.list("NoUpgrade", &c.noupgrade),
                "noextract" => self.list("NoExtract", &c.noextract),
                "architecture" => self.list("Architecture", &c.architectures),
                "xfercommand" => self.str("XferCommand", c.xfercommand.as_deref()),
                "usesyslog" => self.bool("UseSyslog", c.usesyslog),
                "color" => self.bool("Color", c.color != 0),
                "checkspace" => self.bool("CheckSpace", c.checkspace),
                "verbosepkglists" => self.bool("VerbosePkgLists", c.verbosepkglists),
                "disabledownloadtimeout" => self.bool("DisableDownloadTimeout", c.disable_dl_timeout),
                "ilovecandy" => self.bool("ILoveCandy", c.chomp),
                "noprogressbar" => self.bool("NoProgressBar", c.noprogressbar),
                "disablesandbox" => {
                    self.bool("DisableSandboxFilesystem", c.disable_sandbox_filesystem);
                    self.bool("DisableSandboxSyscalls", c.disable_sandbox_syscalls);
                }
                "disablesandboxsyscalls" => self.bool("DisableSandboxSyscalls", c.disable_sandbox_syscalls),
                "paralleldownloads" => self.int("ParallelDownloads", c.parallel_downloads),
                "cleanmethod" => self.cleanmethod("CleanMethod", c.cleanmethod),
                "siglevel" => self.siglevel("SigLevel", c.siglevel, false),
                "localfilesiglevel" => self.siglevel("LocalFileSigLevel", c.localfilesiglevel, true),
                "remotefilesiglevel" => self.siglevel("RemoteFileSigLevel", c.remotefilesiglevel, true),
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

/// usage (the text is printed to stdout for help, stderr on error)
fn usage(ret: i32) -> i32 {
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
    if ret != 0 {
        eprint!("{text}");
    } else {
        print!("{text}");
    }
    ret
}

/// main
pub fn run(args: Vec<String>) -> i32 {
    let mut config = Config::new();
    let mut config_file = CONFFILE.to_string();
    let (mut repo_list, mut verbose) = (false, false);
    let mut repo_name: Option<String> = None;
    let mut g = Getopt::new(args, "c:hlR:S:r:Vv", LONG);
    while let Some(r) = g.next() {
        match r {
            Ok(('c', a)) => config_file = a.unwrap(),
            Ok(('R', a)) => config.rootdir = a,
            Ok(('S', a)) => config.sysroot = a,
            Ok(('l', _)) => repo_list = true,
            Ok(('r', a)) => repo_name = a,
            Ok(('v', _)) => verbose = true,
            Ok(('h', _)) => return usage(0),
            Ok(('V', _)) => {
                println!("{MYNAME} v{MYVER}");
                return 0;
            }
            _ => return usage(1),
        }
    }
    if parseconfigfile(&mut config, &config_file) != 0 || setdefaults(&mut config) != 0 {
        eprintln!("error parsing '{config_file}'");
        return 1;
    }
    let directives = g.operands().to_vec();
    if directives.len() != 1 {
        verbose = true;
    }
    let stdout = std::io::stdout();
    let mut out = Out { w: std::io::BufWriter::new(stdout.lock()), sep: '\n', verbose };
    let ret = if repo_list {
        if !directives.is_empty() {
            eprintln!("error: directives may not be specified with --repo-list");
            1
        } else {
            for r in &config.repos {
                if repo_name.as_deref().is_none_or(|n| n == r.name) {
                    let _ = write!(out.w, "{}{}", r.name, out.sep);
                }
            }
            0
        }
    } else if let Some(n) = &repo_name {
        out.repo_directives(&config, n, &directives)
    } else {
        out.directives(&config, &directives)
    };
    let _ = out.w.flush();
    ret
}

pub fn main() -> i32 {
    run(std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect())
}
