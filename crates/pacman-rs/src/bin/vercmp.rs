//! Port of src/util/vercmp.c.
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

const USAGE: &str = "vercmp (pacman) v7.1.0\n\n\
Compare package version numbers using pacman's version comparison logic.\n\n\
Usage: vercmp <ver1> <ver2>\n\n\
Output values:\n  < 0 : if ver1 < ver2\n    0 : if ver1 == ver2\n  > 0 : if ver1 > ver2\n";

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() {
        eprint!("{USAGE}");
        std::process::exit(2);
    }
    if args[0] == "-h" || args[0] == "--help" {
        eprint!("{USAGE}");
        return;
    }
    if args.len() != 2 {
        eprint!(
            "error: {} argument(s) specified\n\nUsage: vercmp <ver1> <ver2>\n",
            args.len()
        );
        std::process::exit(1);
    }
    let r = libalpm_rs::version::pkg_vercmp(Some(args[0].as_bytes()), Some(args[1].as_bytes()));
    let _ = writeln!(std::io::stdout(), "{r}");
}
