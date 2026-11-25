//! Port of src/pacman/pacman.c: option parsing and the main flow.
use crate::conf::*;
use crate::getopt::{Arg, Getopt, LongOpt};
use crate::pm_printf;
use crate::pr;
use crate::util::{LOG_DEBUG, LOG_ERROR, flush_stdout, resolve_path};
use crate::util_pacman::{list_display, needs_root};
use std::io::IsTerminal;
use std::sync::atomic::Ordering;

const OP_LONG_FLAG_MIN: u32 = 1000;
const fn op(n: u32) -> char {
    match char::from_u32(OP_LONG_FLAG_MIN + n) {
        Some(c) => c,
        None => '\0',
    }
}
const OP_NOCONFIRM: char = op(1);
const OP_CONFIRM: char = op(2);
const OP_CONFIG: char = op(3);
const OP_IGNORE: char = op(4);
const OP_DEBUG: char = op(5);
const OP_NOPROGRESSBAR: char = op(6);
const OP_NOSCRIPTLET: char = op(7);
const OP_ASK: char = op(8);
const OP_CACHEDIR: char = op(9);
const OP_HOOKDIR: char = op(10);
const OP_ASDEPS: char = op(11);
const OP_LOGFILE: char = op(12);
const OP_IGNOREGROUP: char = op(13);
const OP_NEEDED: char = op(14);
const OP_ASEXPLICIT: char = op(15);
const OP_ARCH: char = op(16);
const OP_PRINTFORMAT: char = op(17);
const OP_GPGDIR: char = op(18);
const OP_DBONLY: char = op(19);
const OP_FORCE: char = op(20);
const OP_OVERWRITE_FILES: char = op(21);
const OP_COLOR: char = op(22);
const OP_DBPATH: char = op(23);
const OP_CASCADE: char = op(24);
const OP_CHANGELOG: char = op(25);
const OP_CLEAN: char = op(26);
const OP_NODEPS: char = op(27);
const OP_DEPS: char = op(28);
const OP_EXPLICIT: char = op(29);
const OP_GROUPS: char = op(30);
#[allow(dead_code)]
const OP_HELP: char = op(31);
const OP_INFO: char = op(32);
const OP_CHECK: char = op(33);
const OP_LIST: char = op(34);
const OP_FOREIGN: char = op(35);
const OP_NATIVE: char = op(36);
const OP_NOSAVE: char = op(37);
const OP_OWNS: char = op(38);
const OP_FILE: char = op(39);
const OP_PRINT: char = op(40);
const OP_QUIET: char = op(41);
const OP_ROOT: char = op(42);
const OP_SYSROOT: char = op(43);
const OP_RECURSIVE: char = op(44);
const OP_SEARCH: char = op(45);
const OP_REGEX: char = op(46);
const OP_MACHINEREADABLE: char = op(47);
const OP_UNREQUIRED: char = op(48);
const OP_UPGRADES: char = op(49);
const OP_SYSUPGRADE: char = op(50);
const OP_UNNEEDED: char = op(51);
const OP_VERBOSE: char = op(52);
const OP_DOWNLOADONLY: char = op(53);
const OP_REFRESH: char = op(54);
const OP_ASSUMEINSTALLED: char = op(55);
const OP_DISABLEDLTIMEOUT: char = op(56);
const OP_DISABLESANDBOX: char = op(57);
const OP_DISABLESANDBOXFILESYSTEM: char = op(58);
const OP_DISABLESANDBOXSYSCALLS: char = op(59);

const PACKAGE_VERSION: &str = "7.1.0";

/// options_cmp: used to sort the options in --help
fn options_cmp(s1: &str, s2: &str) -> std::cmp::Ordering {
    let (mut a, mut b) = (
        s1.trim_start_matches(crate::util_common::c_isspace),
        s2.trim_start_matches(crate::util_common::c_isspace),
    );
    // If we compare a long option (--abcd) and a short one (-a), the short one always wins
    if a.starts_with('-') && b.starts_with('-') {
        a = &a[1..];
        b = &b[1..];
        if a.starts_with('-') && b.starts_with('-') {
            // two long -> strcmp
            a = &a[1..];
            b = &b[1..];
        } else if b.starts_with('-') {
            // s1 short, s2 long
            return std::cmp::Ordering::Less;
        } else if a.starts_with('-') {
            // s1 long, s2 short
            return std::cmp::Ordering::Greater;
        }
    }
    a.as_bytes().cmp(b.as_bytes())
}

/// usage: display usage/syntax for the specified operation
fn usage(opn: u16, myname: &str) {
    let (str_opt, str_file, str_pkg, str_usg, str_opr) =
        ("options", "file(s)", "package(s)", "usage", "operation");
    if opn == PM_OP_MAIN {
        pr!("{}:  {} <{}> [...]\n", str_usg, myname, str_opr);
        pr!("operations:\n");
        pr!("    {} {{-h --help}}\n", myname);
        pr!("    {} {{-V --version}}\n", myname);
        pr!(
            "    {} {{-D --database}} <{}> <{}>\n",
            myname,
            str_opt,
            str_pkg
        );
        pr!(
            "    {} {{-F --files}}    [{}] [{}]\n",
            myname,
            str_opt,
            str_file
        );
        pr!(
            "    {} {{-Q --query}}    [{}] [{}]\n",
            myname,
            str_opt,
            str_pkg
        );
        pr!(
            "    {} {{-R --remove}}   [{}] <{}>\n",
            myname,
            str_opt,
            str_pkg
        );
        pr!(
            "    {} {{-S --sync}}     [{}] [{}]\n",
            myname,
            str_opt,
            str_pkg
        );
        pr!(
            "    {} {{-T --deptest}}  [{}] [{}]\n",
            myname,
            str_opt,
            str_pkg
        );
        pr!(
            "    {} {{-U --upgrade}}  [{}] <{}>\n",
            myname,
            str_opt,
            str_file
        );
        pr!(
            "\nuse '{} {{-h --help}}' with an operation for available options\n",
            myname
        );
        return;
    }
    let mut list: Vec<&str> = Vec::new();
    if opn == PM_OP_REMOVE {
        pr!(
            "{}:  {} {{-R --remove}} [{}] <{}>\n",
            str_usg,
            myname,
            str_opt,
            str_pkg
        );
        pr!("{}:\n", str_opt);
        list.push("  -c, --cascade        remove packages and all packages that depend on them\n");
        list.push("  -n, --nosave         remove configuration files\n");
        list.push("  -s, --recursive      remove unnecessary dependencies\n                       (-ss includes explicitly installed dependencies)\n");
        list.push("  -u, --unneeded       remove unneeded packages\n");
    } else if opn == PM_OP_UPGRADE {
        pr!(
            "{}:  {} {{-U --upgrade}} [{}] <{}>\n",
            str_usg,
            myname,
            str_opt,
            str_file
        );
        list.push("      --needed         do not reinstall up to date packages\n");
        pr!("{}:\n", str_opt);
    } else if opn == PM_OP_QUERY {
        pr!(
            "{}:  {} {{-Q --query}} [{}] [{}]\n",
            str_usg,
            myname,
            str_opt,
            str_pkg
        );
        pr!("{}:\n", str_opt);
        list.push("  -c, --changelog      view the changelog of a package\n");
        list.push("  -d, --deps           list packages installed as dependencies [filter]\n");
        list.push("  -e, --explicit       list packages explicitly installed [filter]\n");
        list.push("  -g, --groups         view all members of a package group\n");
        list.push("  -i, --info           view package information (-ii for backup files)\n");
        list.push(
            "  -k, --check          check that package files exist (-kk for file properties)\n",
        );
        list.push("  -l, --list           list the files owned by the queried package\n");
        list.push(
            "  -m, --foreign        list installed packages not found in sync db(s) [filter]\n",
        );
        list.push(
            "  -n, --native         list installed packages only found in sync db(s) [filter]\n",
        );
        list.push("  -o, --owns <file>    query the package that owns <file>\n");
        list.push("  -p, --file <package> query a package file instead of the database\n");
        list.push("  -q, --quiet          show less information for query and search\n");
        list.push(
            "  -s, --search <regex> search locally-installed packages for matching strings\n",
        );
        list.push("  -t, --unrequired     list packages not (optionally) required by any\n                       package (-tt to ignore optdepends) [filter]\n");
        list.push("  -u, --upgrades       list outdated packages [filter]\n");
    } else if opn == PM_OP_SYNC {
        pr!(
            "{}:  {} {{-S --sync}} [{}] [{}]\n",
            str_usg,
            myname,
            str_opt,
            str_pkg
        );
        pr!("{}:\n", str_opt);
        list.push(
            "  -c, --clean          remove old packages from cache directory (-cc for all)\n",
        );
        list.push("  -g, --groups         view all members of a package group\n                       (-gg to view all groups and members)\n");
        list.push(
            "  -i, --info           view package information (-ii for extended information)\n",
        );
        list.push("  -l, --list <repo>    view a list of packages in a repo\n");
        list.push("  -q, --quiet          show less information for query and search\n");
        list.push("  -s, --search <regex> search remote repositories for matching strings\n");
        list.push("  -u, --sysupgrade     upgrade installed packages (-uu enables downgrades)\n");
        list.push("  -y, --refresh        download fresh package databases from the server\n                       (-yy to force a refresh even if up to date)\n");
        list.push("      --needed         do not reinstall up to date packages\n");
    } else if opn == PM_OP_DATABASE {
        pr!(
            "{}:  {} {{-D --database}} <{}> <{}>\n",
            str_usg,
            myname,
            str_opt,
            str_pkg
        );
        pr!("{}:\n", str_opt);
        list.push("      --asdeps         mark packages as non-explicitly installed\n");
        list.push("      --asexplicit     mark packages as explicitly installed\n");
        list.push(
            "  -k, --check          test local database for validity (-kk for sync databases)\n",
        );
        list.push("  -q, --quiet          suppress output of success messages\n");
    } else if opn == PM_OP_DEPTEST {
        pr!(
            "{}:  {} {{-T --deptest}} [{}] [{}]\n",
            str_usg,
            myname,
            str_opt,
            str_pkg
        );
        pr!("{}:\n", str_opt);
    } else if opn == PM_OP_FILES {
        pr!(
            "{}:  {} {{-F --files}} [{}] [{}]\n",
            str_usg,
            myname,
            str_opt,
            str_file
        );
        pr!("{}:\n", str_opt);
        list.push("  -l, --list           list the files owned by the queried package\n");
        list.push("  -q, --quiet          show less information for query and search\n");
        list.push("  -x, --regex          enable searching using regular expressions\n");
        list.push("  -y, --refresh        download fresh package databases from the server\n                       (-yy to force a refresh even if up to date)\n");
        list.push(
            "      --machinereadable\n                       produce machine-readable output\n",
        );
    }
    // the fallthrough chain: SYNC and UPGRADE share the first block, SYNC/UPGRADE/REMOVE the second
    if opn == PM_OP_SYNC || opn == PM_OP_UPGRADE {
        list.push("  -w, --downloadonly   download packages but do not install/upgrade anything\n");
        list.push("      --overwrite <glob>\n                       overwrite conflicting files (can be used more than once)\n");
        list.push("      --asdeps         install packages as non-explicitly installed\n");
        list.push("      --asexplicit     install packages as explicitly installed\n");
        list.push("      --ignore <pkg>   ignore a package upgrade (can be used more than once)\n");
        list.push("      --ignoregroup <grp>\n                       ignore a group upgrade (can be used more than once)\n");
    }
    if opn == PM_OP_SYNC || opn == PM_OP_UPGRADE || opn == PM_OP_REMOVE {
        list.push(
            "  -d, --nodeps         skip dependency version checks (-dd to skip all checks)\n",
        );
        list.push("      --assume-installed <package=version>\n                       add a virtual package to satisfy dependencies\n");
        list.push("      --dbonly         only modify database entries, not package files\n");
        list.push("      --noprogressbar  do not show a progress bar when downloading files\n");
        list.push("      --noscriptlet    do not execute the install scriptlet if one exists\n");
        list.push("  -p, --print          print the targets instead of performing the operation\n");
        list.push("      --print-format <string>\n                       specify how the targets should be printed\n");
    }
    list.push("  -b, --dbpath <path>  set an alternate database location\n");
    list.push("  -r, --root <path>    set an alternate installation root\n");
    list.push("  -v, --verbose        be verbose\n");
    list.push("      --arch <arch>    set an alternate architecture\n");
    list.push("      --sysroot        operate on a mounted guest system (root-only)\n");
    list.push("      --cachedir <dir> set an alternate package cache location\n");
    list.push("      --hookdir <dir>  set an alternate hook location\n");
    list.push("      --color <when>   colorize the output\n");
    list.push("      --config <path>  set an alternate configuration file\n");
    list.push("      --debug          display debug messages\n");
    list.push("      --gpgdir <path>  set an alternate home directory for GnuPG\n");
    list.push("      --logfile <path> set an alternate log file\n");
    list.push("      --noconfirm      do not ask for any confirmation\n");
    list.push("      --confirm        always ask for confirmation\n");
    list.push("      --disable-download-timeout\n                       use relaxed timeouts for download\n");
    list.push("      --disable-sandbox\n                       disables all sandbox features used for the downloader process\n");
    list.push("      --disable-sandbox-filesystem\n                       disables the filesystem part of the downloader process sandbox\n");
    list.push("      --disable-sandbox-syscalls\n                       disables the syscalls part of the downloader process sandbox\n");
    list.sort_by(|a, b| options_cmp(a, b));
    for l in list {
        pr!("{}", l);
    }
}

/// version: output pacman version and copyright
fn version() {
    pr!("\n");
    pr!(
        " .--.                  Pacman v{} - libalpm v{}\n",
        PACKAGE_VERSION,
        libalpm_rs::alpm::LIB_VERSION
    );
    pr!("/ _.-' .-.  .-.  .-.   Copyright (C) 2006-2025 Pacman Development Team\n");
    pr!("\\  '-. '-'  '-'  '-'   Copyright (C) 2002-2006 Judd Vinet\n");
    pr!(" '--'\n");
    pr!("                       This program may be freely redistributed under\n");
    pr!("                       the terms of the GNU General Public License.\n");
    pr!("\n");
}

/// cleanup: free the resources and exit
fn cleanup(cfg: &mut Config, ret: i32) -> ! {
    console_cursor_show();
    if let Some(alpm) = cfg.alpm.take() {
        // alpm_release: a missing lock file would warn; read-only operations never take it
        drop(alpm);
    }
    flush_stdout();
    std::process::exit(ret);
}

fn console_cursor_show() {
    if std::io::stdout().is_terminal() {
        pr!("\x1b[?25h");
        flush_stdout();
    }
}

fn invalid_opt(cfg: &mut Config, used: bool, opt1: &str, opt2: &str) {
    if used {
        pm_printf!(
            LOG_ERROR,
            "invalid option: '{}' and '{}' may not be used together\n",
            opt1,
            opt2
        );
        cleanup(cfg, 1);
    }
}

/// parsearg_util_addlist: comma separated values
fn addlist(list: &mut Vec<String>, optarg: &str) {
    list.extend(
        optarg
            .split(',')
            .filter(|s| !s.is_empty())
            .map(String::from),
    );
}

/// parsearg_op: 0 if opt was handled, 1 if not
fn parsearg_op(cfg: &mut Config, opt: char, dryrun: bool) -> i32 {
    let setop = |cfg: &mut Config, v: u16| {
        if !dryrun {
            cfg.op = if cfg.op != PM_OP_MAIN { 0 } else { v };
        }
    };
    match opt {
        'D' => setop(cfg, PM_OP_DATABASE),
        'F' => setop(cfg, PM_OP_FILES),
        'Q' => setop(cfg, PM_OP_QUERY),
        'R' => setop(cfg, PM_OP_REMOVE),
        'S' => setop(cfg, PM_OP_SYNC),
        'T' => setop(cfg, PM_OP_DEPTEST),
        'U' => setop(cfg, PM_OP_UPGRADE),
        'V' => {
            if !dryrun {
                cfg.version = true;
            }
        }
        'h' => {
            if !dryrun {
                cfg.help = true;
            }
        }
        _ => return 1,
    }
    0
}

/// strtol-like parse of a whole string (base 10)
fn parse_long(s: &str) -> Option<i64> {
    s.trim_start().parse::<i64>().ok()
}

/// parsearg_global: 0 on success, 1 on unknown option, 2 on invalid argument
fn parsearg_global(cfg: &mut Config, opt: char, optarg: Option<&str>) -> i32 {
    let oa = optarg.unwrap_or("");
    match opt {
        OP_ARCH => config_add_architecture(cfg, oa),
        OP_ASK => match optarg {
            Some(o) => match parse_long(o) {
                Some(ask) if ask <= u32::MAX as i64 => {
                    cfg.noask = true;
                    cfg.ask = ask as u32;
                }
                _ => {
                    pm_printf!(LOG_ERROR, "'{}' is not a valid ask level\n", o);
                    return 2;
                }
            },
            None => {
                pm_printf!(LOG_ERROR, "no value provided for ask level\n");
                return 2;
            }
        },
        OP_CACHEDIR => match resolve_path(oa, "--cachedir") {
            Some(p) => cfg.cachedirs.push(p),
            None => return 2,
        },
        OP_COLOR => {
            match oa {
                "never" => cfg.color = COLOR_OFF,
                "auto" => {
                    cfg.color = if std::io::stdout().is_terminal() {
                        COLOR_ON
                    } else {
                        COLOR_OFF
                    }
                }
                "always" => cfg.color = COLOR_ON,
                _ => {
                    pm_printf!(LOG_ERROR, "invalid argument '{}' for {}\n", oa, "--color");
                    return 2;
                }
            }
            let c = cfg.color;
            enable_colors(cfg, c);
        }
        OP_CONFIG => cfg.configfile = oa.chars().take(4096).collect(),
        OP_DEBUG => {
            // debug levels are made more 'human readable' than using a raw logmask
            if let Some(o) = optarg {
                match parse_long(o) {
                    Some(2) => {
                        crate::util::LOGMASK
                            .fetch_or(crate::util::LOG_DEBUG | 8, Ordering::Relaxed);
                    }
                    Some(1) => {
                        crate::util::LOGMASK.fetch_or(crate::util::LOG_DEBUG, Ordering::Relaxed);
                    }
                    _ => {
                        pm_printf!(LOG_ERROR, "'{}' is not a valid debug level\n", o);
                        return 2;
                    }
                }
            } else {
                crate::util::LOGMASK.fetch_or(crate::util::LOG_DEBUG, Ordering::Relaxed);
            }
            // progress bars get wonky with debug on, shut them off
            cfg.noprogressbar = true;
        }
        OP_GPGDIR => match resolve_path(oa, "--gpgdir") {
            Some(p) => cfg.gpgdir = Some(p),
            None => return 2,
        },
        OP_HOOKDIR => match resolve_path(oa, "--hookdir") {
            Some(p) => cfg.hookdirs.push(p),
            None => return 2,
        },
        OP_LOGFILE => cfg.logfile = Some(oa.chars().take(4096).collect()),
        OP_NOCONFIRM => cfg.noconfirm = true,
        OP_CONFIRM => cfg.noconfirm = false,
        OP_DBPATH | 'b' => match resolve_path(oa, "--dbpath") {
            Some(p) => cfg.dbpath = Some(p),
            None => return 2,
        },
        OP_ROOT | 'r' => match resolve_path(oa, "--root") {
            Some(p) => cfg.rootdir = Some(p),
            None => return 2,
        },
        OP_SYSROOT => match resolve_path(oa, "--sysroot") {
            Some(p) => cfg.sysroot = Some(p),
            None => return 2,
        },
        OP_DISABLEDLTIMEOUT => cfg.disable_dl_timeout = true,
        OP_DISABLESANDBOX => {
            cfg.disable_sandbox_filesystem = true;
            cfg.disable_sandbox_syscalls = true;
        }
        OP_DISABLESANDBOXFILESYSTEM => cfg.disable_sandbox_filesystem = true,
        OP_DISABLESANDBOXSYSCALLS => cfg.disable_sandbox_syscalls = true,
        OP_VERBOSE | 'v' => cfg.verbose += 1,
        _ => return 1,
    }
    0
}

fn parsearg_database(cfg: &mut Config, opt: char) -> i32 {
    match opt {
        OP_ASDEPS => cfg.flags |= TRANS_FLAG_ALLDEPS,
        OP_ASEXPLICIT => cfg.flags |= TRANS_FLAG_ALLEXPLICIT,
        OP_CHECK | 'k' => cfg.op_q_check += 1,
        OP_QUIET | 'q' => cfg.quiet = true,
        _ => return 1,
    }
    0
}

fn checkargs_database(cfg: &mut Config) {
    let f = cfg.flags;
    invalid_opt(
        cfg,
        f & TRANS_FLAG_ALLDEPS != 0 && f & TRANS_FLAG_ALLEXPLICIT != 0,
        "--asdeps",
        "--asexplicit",
    );
    if cfg.op_q_check != 0 {
        invalid_opt(cfg, f & TRANS_FLAG_ALLDEPS != 0, "--asdeps", "--check");
        invalid_opt(
            cfg,
            f & TRANS_FLAG_ALLEXPLICIT != 0,
            "--asexplicit",
            "--check",
        );
    }
}

fn parsearg_query(cfg: &mut Config, opt: char) -> i32 {
    match opt {
        OP_CHANGELOG | 'c' => cfg.op_q_changelog = true,
        OP_DEPS | 'd' => cfg.op_q_deps = true,
        OP_EXPLICIT | 'e' => cfg.op_q_explicit = true,
        OP_GROUPS | 'g' => cfg.group += 1,
        OP_INFO | 'i' => cfg.op_q_info += 1,
        OP_CHECK | 'k' => cfg.op_q_check += 1,
        OP_LIST | 'l' => cfg.op_q_list = true,
        OP_FOREIGN | 'm' => cfg.op_q_locality |= PKG_LOCALITY_FOREIGN,
        OP_NATIVE | 'n' => cfg.op_q_locality |= PKG_LOCALITY_NATIVE,
        OP_OWNS | 'o' => cfg.op_q_owns = true,
        OP_FILE | 'p' => cfg.op_q_isfile = true,
        OP_QUIET | 'q' => cfg.quiet = true,
        OP_SEARCH | 's' => cfg.op_q_search = true,
        OP_UNREQUIRED | 't' => cfg.op_q_unrequired += 1,
        OP_UPGRADES | 'u' => cfg.op_q_upgrade = true,
        _ => return 1,
    }
    0
}

fn checkargs_query_display_opts(cfg: &mut Config, opname: &str) {
    let (a, b, c, d) = (
        cfg.op_q_changelog,
        cfg.op_q_check != 0,
        cfg.op_q_info != 0,
        cfg.op_q_list,
    );
    invalid_opt(cfg, a, opname, "--changelog");
    invalid_opt(cfg, b, opname, "--check");
    invalid_opt(cfg, c, opname, "--info");
    invalid_opt(cfg, d, opname, "--list");
}

fn checkargs_query_filter_opts(cfg: &mut Config, opname: &str) {
    let (a, b, c, d, e, f) = (
        cfg.op_q_deps,
        cfg.op_q_explicit,
        cfg.op_q_upgrade,
        cfg.op_q_unrequired != 0,
        cfg.op_q_locality & PKG_LOCALITY_NATIVE != 0,
        cfg.op_q_locality & PKG_LOCALITY_FOREIGN != 0,
    );
    invalid_opt(cfg, a, opname, "--deps");
    invalid_opt(cfg, b, opname, "--explicit");
    invalid_opt(cfg, c, opname, "--upgrade");
    invalid_opt(cfg, d, opname, "--unrequired");
    invalid_opt(cfg, e, opname, "--native");
    invalid_opt(cfg, f, opname, "--foreign");
}

fn checkargs_query(cfg: &mut Config) {
    let (group, search, owns, isfile) = (
        cfg.group != 0,
        cfg.op_q_search,
        cfg.op_q_owns,
        cfg.op_q_isfile,
    );
    if isfile {
        invalid_opt(cfg, group, "--file", "--groups");
        invalid_opt(cfg, search, "--file", "--search");
        invalid_opt(cfg, owns, "--file", "--owns");
    } else if search {
        invalid_opt(cfg, group, "--search", "--groups");
        invalid_opt(cfg, owns, "--search", "--owns");
        checkargs_query_display_opts(cfg, "--search");
        checkargs_query_filter_opts(cfg, "--search");
    } else if owns {
        invalid_opt(cfg, group, "--owns", "--groups");
        checkargs_query_display_opts(cfg, "--owns");
        checkargs_query_filter_opts(cfg, "--owns");
    } else if group {
        checkargs_query_display_opts(cfg, "--groups");
    }
    let (de, nf) = (
        cfg.op_q_deps && cfg.op_q_explicit,
        cfg.op_q_locality & PKG_LOCALITY_NATIVE != 0
            && cfg.op_q_locality & PKG_LOCALITY_FOREIGN != 0,
    );
    invalid_opt(cfg, de, "--deps", "--explicit");
    invalid_opt(cfg, nf, "--native", "--foreign");
}

/// options common to -S -R -U
fn parsearg_trans(cfg: &mut Config, opt: char, optarg: Option<&str>) -> i32 {
    match opt {
        OP_NODEPS | 'd' => {
            if cfg.flags & TRANS_FLAG_NODEPVERSION != 0 {
                cfg.flags |= TRANS_FLAG_NODEPS;
            } else {
                cfg.flags |= TRANS_FLAG_NODEPVERSION;
            }
        }
        OP_DBONLY => cfg.flags |= TRANS_FLAG_DBONLY | TRANS_FLAG_NOSCRIPTLET | TRANS_FLAG_NOHOOKS,
        OP_NOPROGRESSBAR => cfg.noprogressbar = true,
        OP_NOSCRIPTLET => cfg.flags |= TRANS_FLAG_NOSCRIPTLET,
        OP_PRINT | 'p' => cfg.print = true,
        OP_PRINTFORMAT => {
            cfg.print = true;
            cfg.print_format = optarg.map(String::from);
        }
        OP_ASSUMEINSTALLED => addlist(&mut cfg.assumeinstalled, optarg.unwrap_or("")),
        _ => return 1,
    }
    0
}

fn checkargs_trans(cfg: &mut Config) {
    if cfg.print {
        let (a, b) = (
            cfg.flags & TRANS_FLAG_DBONLY != 0,
            cfg.flags & TRANS_FLAG_NOSCRIPTLET != 0,
        );
        invalid_opt(cfg, a, "--print", "--dbonly");
        invalid_opt(cfg, b, "--print", "--noscriptlet");
    }
}

fn parsearg_remove(cfg: &mut Config, opt: char, optarg: Option<&str>) -> i32 {
    if parsearg_trans(cfg, opt, optarg) == 0 {
        return 0;
    }
    match opt {
        OP_CASCADE | 'c' => cfg.flags |= TRANS_FLAG_CASCADE,
        OP_NOSAVE | 'n' => cfg.flags |= TRANS_FLAG_NOSAVE,
        OP_RECURSIVE | 's' => {
            if cfg.flags & TRANS_FLAG_RECURSE != 0 {
                cfg.flags |= TRANS_FLAG_RECURSEALL;
            } else {
                cfg.flags |= TRANS_FLAG_RECURSE;
            }
        }
        OP_UNNEEDED | 'u' => cfg.flags |= TRANS_FLAG_UNNEEDED,
        _ => return 1,
    }
    0
}

fn checkargs_remove(cfg: &mut Config) {
    checkargs_trans(cfg);
    if cfg.flags & TRANS_FLAG_NOSAVE != 0 {
        let (p, d) = (cfg.print, cfg.flags & TRANS_FLAG_DBONLY != 0);
        invalid_opt(cfg, p, "--nosave", "--print");
        invalid_opt(cfg, d, "--nosave", "--dbonly");
    }
}

/// options common to -S -U
fn parsearg_upgrade(cfg: &mut Config, opt: char, optarg: Option<&str>) -> i32 {
    if parsearg_trans(cfg, opt, optarg) == 0 {
        return 0;
    }
    match opt {
        OP_OVERWRITE_FILES => addlist(&mut cfg.overwrite_files, optarg.unwrap_or("")),
        OP_ASDEPS => cfg.flags |= TRANS_FLAG_ALLDEPS,
        OP_ASEXPLICIT => cfg.flags |= TRANS_FLAG_ALLEXPLICIT,
        OP_NEEDED => cfg.flags |= TRANS_FLAG_NEEDED,
        OP_IGNORE => addlist(&mut cfg.ignorepkg, optarg.unwrap_or("")),
        OP_IGNOREGROUP => addlist(&mut cfg.ignoregrp, optarg.unwrap_or("")),
        OP_DOWNLOADONLY | 'w' => {
            cfg.op_s_downloadonly = true;
            cfg.flags |= TRANS_FLAG_DOWNLOADONLY | TRANS_FLAG_NOCONFLICTS;
        }
        _ => return 1,
    }
    0
}

fn checkargs_upgrade(cfg: &mut Config) {
    checkargs_trans(cfg);
    let both = cfg.flags & TRANS_FLAG_ALLDEPS != 0 && cfg.flags & TRANS_FLAG_ALLEXPLICIT != 0;
    invalid_opt(cfg, both, "--asdeps", "--asexplicit");
}

fn parsearg_files(cfg: &mut Config, opt: char, optarg: Option<&str>) -> i32 {
    if parsearg_trans(cfg, opt, optarg) == 0 {
        return 0;
    }
    match opt {
        OP_LIST | 'l' => cfg.op_q_list = true,
        OP_REFRESH | 'y' => cfg.op_s_sync += 1,
        OP_REGEX | 'x' => cfg.op_f_regex = true,
        OP_MACHINEREADABLE => cfg.op_f_machinereadable = true,
        OP_QUIET | 'q' => cfg.quiet = true,
        _ => return 1,
    }
    0
}

fn checkargs_files(cfg: &mut Config) {
    if cfg.op_q_search {
        let l = cfg.op_q_list;
        invalid_opt(cfg, l, "--regex", "--list");
    }
}

fn parsearg_sync(cfg: &mut Config, opt: char, optarg: Option<&str>) -> i32 {
    if parsearg_upgrade(cfg, opt, optarg) == 0 {
        return 0;
    }
    match opt {
        OP_CLEAN | 'c' => cfg.op_s_clean += 1,
        OP_GROUPS | 'g' => cfg.group += 1,
        OP_INFO | 'i' => cfg.op_s_info += 1,
        OP_LIST | 'l' => cfg.op_q_list = true,
        OP_QUIET | 'q' => cfg.quiet = true,
        OP_SEARCH | 's' => cfg.op_s_search = true,
        OP_SYSUPGRADE | 'u' => cfg.op_s_upgrade += 1,
        OP_REFRESH | 'y' => cfg.op_s_sync += 1,
        _ => return 1,
    }
    0
}

fn checkargs_sync(cfg: &mut Config) {
    checkargs_upgrade(cfg);
    let (group, info, list, sync, search, upgrade, dlonly) = (
        cfg.group != 0,
        cfg.op_s_info != 0,
        cfg.op_q_list,
        cfg.op_s_sync != 0,
        cfg.op_s_search,
        cfg.op_s_upgrade != 0,
        cfg.op_s_downloadonly,
    );
    if cfg.op_s_clean != 0 {
        invalid_opt(cfg, group, "--clean", "--groups");
        invalid_opt(cfg, info, "--clean", "--info");
        invalid_opt(cfg, list, "--clean", "--list");
        invalid_opt(cfg, sync, "--clean", "--refresh");
        invalid_opt(cfg, search, "--clean", "--search");
        invalid_opt(cfg, upgrade, "--clean", "--sysupgrade");
        invalid_opt(cfg, dlonly, "--clean", "--downloadonly");
    } else if info {
        invalid_opt(cfg, group, "--info", "--groups");
        invalid_opt(cfg, list, "--info", "--list");
        invalid_opt(cfg, search, "--info", "--search");
        invalid_opt(cfg, upgrade, "--info", "--sysupgrade");
        invalid_opt(cfg, dlonly, "--info", "--downloadonly");
    } else if search {
        invalid_opt(cfg, group, "--search", "--groups");
        invalid_opt(cfg, list, "--search", "--list");
        invalid_opt(cfg, upgrade, "--search", "--sysupgrade");
        invalid_opt(cfg, dlonly, "--search", "--downloadonly");
    } else if list {
        invalid_opt(cfg, group, "--list", "--groups");
        invalid_opt(cfg, upgrade, "--list", "--sysupgrade");
        invalid_opt(cfg, dlonly, "--list", "--downloadonly");
    } else if group {
        invalid_opt(cfg, upgrade, "--groups", "--sysupgrade");
        invalid_opt(cfg, dlonly, "--groups", "--downloadonly");
    }
}

const LONG_OPTS: &[(&str, Arg, char)] = &[
    ("database", Arg::No, 'D'),
    ("files", Arg::No, 'F'),
    ("query", Arg::No, 'Q'),
    ("remove", Arg::No, 'R'),
    ("sync", Arg::No, 'S'),
    ("deptest", Arg::No, 'T'),
    ("upgrade", Arg::No, 'U'),
    ("version", Arg::No, 'V'),
    ("help", Arg::No, 'h'),
    ("dbpath", Arg::Required, OP_DBPATH),
    ("cascade", Arg::No, OP_CASCADE),
    ("changelog", Arg::No, OP_CHANGELOG),
    ("clean", Arg::No, OP_CLEAN),
    ("nodeps", Arg::No, OP_NODEPS),
    ("deps", Arg::No, OP_DEPS),
    ("explicit", Arg::No, OP_EXPLICIT),
    ("groups", Arg::No, OP_GROUPS),
    ("info", Arg::No, OP_INFO),
    ("check", Arg::No, OP_CHECK),
    ("list", Arg::No, OP_LIST),
    ("foreign", Arg::No, OP_FOREIGN),
    ("native", Arg::No, OP_NATIVE),
    ("nosave", Arg::No, OP_NOSAVE),
    ("owns", Arg::No, OP_OWNS),
    ("file", Arg::No, OP_FILE),
    ("print", Arg::No, OP_PRINT),
    ("quiet", Arg::No, OP_QUIET),
    ("root", Arg::Required, OP_ROOT),
    ("sysroot", Arg::Required, OP_SYSROOT),
    ("recursive", Arg::No, OP_RECURSIVE),
    ("search", Arg::No, OP_SEARCH),
    ("regex", Arg::No, OP_REGEX),
    ("machinereadable", Arg::No, OP_MACHINEREADABLE),
    ("unrequired", Arg::No, OP_UNREQUIRED),
    ("upgrades", Arg::No, OP_UPGRADES),
    ("sysupgrade", Arg::No, OP_SYSUPGRADE),
    ("unneeded", Arg::No, OP_UNNEEDED),
    ("verbose", Arg::No, OP_VERBOSE),
    ("downloadonly", Arg::No, OP_DOWNLOADONLY),
    ("refresh", Arg::No, OP_REFRESH),
    ("noconfirm", Arg::No, OP_NOCONFIRM),
    ("confirm", Arg::No, OP_CONFIRM),
    ("config", Arg::Required, OP_CONFIG),
    ("ignore", Arg::Required, OP_IGNORE),
    ("assume-installed", Arg::Required, OP_ASSUMEINSTALLED),
    ("debug", Arg::Optional, OP_DEBUG),
    ("force", Arg::No, OP_FORCE),
    ("overwrite", Arg::Required, OP_OVERWRITE_FILES),
    ("noprogressbar", Arg::No, OP_NOPROGRESSBAR),
    ("noscriptlet", Arg::No, OP_NOSCRIPTLET),
    ("ask", Arg::Required, OP_ASK),
    ("cachedir", Arg::Required, OP_CACHEDIR),
    ("hookdir", Arg::Required, OP_HOOKDIR),
    ("asdeps", Arg::No, OP_ASDEPS),
    ("logfile", Arg::Required, OP_LOGFILE),
    ("ignoregroup", Arg::Required, OP_IGNOREGROUP),
    ("needed", Arg::No, OP_NEEDED),
    ("asexplicit", Arg::No, OP_ASEXPLICIT),
    ("arch", Arg::Required, OP_ARCH),
    ("print-format", Arg::Required, OP_PRINTFORMAT),
    ("gpgdir", Arg::Required, OP_GPGDIR),
    ("dbonly", Arg::No, OP_DBONLY),
    ("color", Arg::Required, OP_COLOR),
    ("disable-download-timeout", Arg::No, OP_DISABLEDLTIMEOUT),
    ("disable-sandbox", Arg::No, OP_DISABLESANDBOX),
    (
        "disable-sandbox-filesystem",
        Arg::No,
        OP_DISABLESANDBOXFILESYSTEM,
    ),
    (
        "disable-sandbox-syscalls",
        Arg::No,
        OP_DISABLESANDBOXSYSCALLS,
    ),
];

/// parseargs: 0 on success, 1 on error
fn parseargs(cfg: &mut Config, args: &[String], targets: &mut Vec<String>) -> i32 {
    let optstring = "DFQRSTUVb:cdefghiklmnopqr:stuvwxy";
    let long: Vec<LongOpt> = LONG_OPTS
        .iter()
        .map(|&(name, has_arg, val)| LongOpt { name, has_arg, val })
        .collect();

    // parse operation
    let mut g = Getopt::new(args.to_vec(), optstring, &long);
    for (opt, _) in g.by_ref() {
        if opt == '?' {
            // unknown option, getopt printed an error
            return 1;
        }
        parsearg_op(cfg, opt, false);
    }
    if cfg.op == 0 {
        pm_printf!(LOG_ERROR, "only one operation may be used at a time\n");
        return 1;
    }
    if cfg.help {
        let myname = args[0].rsplit('/').next().unwrap_or(&args[0]).to_string();
        usage(cfg.op, &myname);
        cleanup(cfg, 0);
    }
    if cfg.version {
        version();
        cleanup(cfg, 0);
    }

    // parse all other options
    let mut g = Getopt::new(args.to_vec(), optstring, &long);
    for (opt, optarg) in g.by_ref() {
        if opt == '?' {
            // this should have failed during first pass already
            return 1;
        } else if parsearg_op(cfg, opt, true) == 0 {
            // opt is an operation
            continue;
        }
        let oa = optarg.as_deref();
        let mut result = match cfg.op {
            PM_OP_DATABASE => parsearg_database(cfg, opt),
            PM_OP_QUERY => parsearg_query(cfg, opt),
            PM_OP_REMOVE => parsearg_remove(cfg, opt, oa),
            PM_OP_SYNC => parsearg_sync(cfg, opt, oa),
            PM_OP_UPGRADE => parsearg_upgrade(cfg, opt, oa),
            PM_OP_FILES => parsearg_files(cfg, opt, oa),
            _ => 1,
        };
        if result == 0 {
            continue;
        }
        // fall back to global options
        result = parsearg_global(cfg, opt, oa);
        if result != 0 {
            if result == 1 {
                // global option parsing failed, abort
                if (opt as u32) < OP_LONG_FLAG_MIN {
                    pm_printf!(LOG_ERROR, "invalid option '-{}'\n", opt);
                } else {
                    let name = LONG_OPTS.iter().find(|o| o.2 == opt).map_or("", |o| o.0);
                    pm_printf!(LOG_ERROR, "invalid option '--{}'\n", name);
                }
            }
            return 1;
        }
    }
    targets.extend(g.operands.iter().cloned());

    match cfg.op {
        PM_OP_DATABASE => checkargs_database(cfg),
        PM_OP_SYNC => checkargs_sync(cfg),
        PM_OP_QUERY => checkargs_query(cfg),
        PM_OP_REMOVE => checkargs_remove(cfg),
        PM_OP_UPGRADE => checkargs_upgrade(cfg),
        PM_OP_FILES => checkargs_files(cfg),
        _ => {}
    }
    0
}

/// main
pub fn main() -> ! {
    let args: Vec<String> = std::env::args_os()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    // SAFETY: getuid cannot fail
    let myuid = unsafe { libc::getuid() };

    if std::io::stdout().is_terminal() {
        pr!("\x1b[?25l");
    }
    // i18n init
    crate::ffi::init_locale();

    // init config data
    let mut config = config_new();
    if !std::io::stdout().is_terminal() {
        // disable progressbar if the output is redirected
        config.noprogressbar = true;
    }

    // Priority of options: 1. command line 2. config file 3. compiled-in defaults
    let mut pm_targets: Vec<String> = Vec::new();
    let ret = parseargs(&mut config, &args, &mut pm_targets);
    if ret != 0 {
        cleanup(&mut config, ret);
    }

    // check if we have sufficient permission for the requested operation
    if myuid > 0 && needs_root(&config) {
        pm_printf!(
            LOG_ERROR,
            "you cannot perform this operation unless you are root.\n"
        );
        cleanup(&mut config, 1);
    }

    // we support reading targets from stdin if a cmdline parameter is '-'
    if pm_targets.iter().any(|t| t == "-") {
        if !std::io::stdin().is_terminal() {
            // remove the '-' from the list
            if let Some(p) = pm_targets.iter().position(|t| t == "-") {
                pm_targets.remove(p);
            }
            let mut target_found = false;
            let mut input = Vec::new();
            use std::io::Read;
            if let Err(e) = std::io::stdin().read_to_end(&mut input) {
                pm_printf!(
                    LOG_ERROR,
                    "failed to read arguments from stdin: ({})\n",
                    libalpm_rs::util::strerror(&e)
                );
                cleanup(&mut config, 1);
            }
            for line in input.split(|&c| c == b'\n') {
                if line.is_empty() {
                    // skip empty lines
                    continue;
                }
                pm_targets.push(String::from_utf8_lossy(line).into_owned());
                target_found = true;
            }
            // freopen(ctermid(NULL), "r", stdin)
            if let Err(e) = std::fs::File::open("/dev/tty") {
                pm_printf!(
                    LOG_ERROR,
                    "failed to reopen stdin for reading: ({})\n",
                    libalpm_rs::util::strerror(&e)
                );
            }
            if !target_found {
                pm_printf!(LOG_ERROR, "argument '-' specified with empty stdin\n");
                cleanup(&mut config, 1);
            }
        } else {
            // do not read stdin from terminal
            pm_printf!(LOG_ERROR, "argument '-' specified without input on stdin\n");
            cleanup(&mut config, 1);
        }
    }

    pm_printf!(
        LOG_DEBUG,
        "pacman v{} - libalpm v{}\n",
        PACKAGE_VERSION,
        libalpm_rs::alpm::LIB_VERSION
    );

    crate::callback::set_cfg(&config);
    // parse the config file
    let file = config.configfile.clone();
    let ret = parseconfig(&mut config, &file);
    if ret != 0 {
        cleanup(&mut config, ret);
    }

    // noask is meant to be non-interactive
    if config.noask {
        config.noconfirm = true;
    }

    // set up the print operations
    if config.print && config.op_s_clean == 0 {
        config.noconfirm = true;
        config.flags |= TRANS_FLAG_NOCONFLICTS;
        config.flags |= TRANS_FLAG_NOLOCK;
        // Display only errors
        crate::util::LOGMASK.fetch_and(!crate::util::LOG_WARNING, Ordering::Relaxed);
    }

    if config.verbose > 0 {
        let h = config.alpm.as_ref().unwrap().handle.clone();
        pr!("Root      : {}\n", h.root());
        pr!("Conf File : {}\n", config.configfile);
        pr!("DB Path   : {}\n", h.dbpath);
        pr!("Cache Dirs: ");
        for j in h.cachedirs() {
            pr!("{}  ", j);
        }
        pr!("\n");
        pr!("Hook Dirs : ");
        for j in h.hookdirs() {
            pr!("{}  ", j);
        }
        pr!("\n");
        pr!("Lock File : {}\n", h.lockfile());
        pr!("Log File  : {}\n", h.logfile().unwrap_or_default());
        pr!("GPG Dir   : {}\n", h.gpgdir().unwrap_or_default());
        list_display(&config, Some("Targets   :"), &pm_targets, 0);
    }

    // Log command line
    if crate::util_pacman::needs_root(&config) {
        config
            .alpm
            .as_ref()
            .unwrap()
            .handle
            .logaction("PACMAN", format_args!("Running '{}'\n", args.join(" ")));
    }
    crate::callback::set_cfg(&config);
    // start the requested operation
    let ret = match config.op {
        PM_OP_QUERY => crate::query::pacman_query(&config, &pm_targets),
        PM_OP_SYNC => crate::sync::pacman_sync(&mut config, &pm_targets),
        PM_OP_DEPTEST => crate::deptest::pacman_deptest(&config, &pm_targets),
        PM_OP_FILES => crate::files::pacman_files(&mut config, &pm_targets),
        PM_OP_DATABASE | PM_OP_REMOVE | PM_OP_UPGRADE => crate::not_implemented("this operation"),
        _ => {
            pm_printf!(LOG_ERROR, "no operation specified (use -h for help)\n");
            1
        }
    };
    cleanup(&mut config, ret);
}
