pub mod check;
pub mod conf;
pub mod deptest;
pub mod ffi;
pub mod files;
pub mod getopt;
pub mod ini;
pub mod package;
pub mod pacman;
pub mod query;
pub mod sync;
pub mod util;
pub mod util_common;
pub mod util_pacman;

/// Operations that change the system (installing, removing, downloading) are not implemented yet.
pub fn not_implemented(what: &str) -> i32 {
    pm_printf!(util::LOG_ERROR, "{} is not implemented yet\n", what);
    1
}
