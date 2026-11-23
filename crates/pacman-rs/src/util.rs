//! Port of src/pacman/util.c (pm_printf, resolve_path; the rest comes with the code that needs it).
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub const LOG_ERROR: u32 = 1;
pub const LOG_WARNING: u32 = 2;
pub const LOG_DEBUG: u32 = 4;

/// config->logmask (global like upstream's `config`).
pub static LOGMASK: AtomicU32 = AtomicU32::new(LOG_ERROR | LOG_WARNING);
/// config->colstr is either all plain or the colored set; only err/warn/nocolor matter for prefixes.
pub static COLORS: AtomicBool = AtomicBool::new(false);

const BOLDRED: &str = "\x1b[1;31m";
const BOLDYELLOW: &str = "\x1b[1;33m";
const NOCOLOR: &str = "\x1b[0m";

/// pm_printf / pm_vfprintf (stderr, C locale).
pub fn pm_printf(level: u32, args: std::fmt::Arguments) {
    if LOGMASK.load(Ordering::Relaxed) & level == 0 {
        return;
    }
    let col = COLORS.load(Ordering::Relaxed);
    let (c, n) = if col { (true, NOCOLOR) } else { (false, "") };
    let prefix = match level {
        LOG_ERROR => format!("{}error: {}", if c { BOLDRED } else { "" }, n),
        LOG_WARNING => format!("{}warning: {}", if c { BOLDYELLOW } else { "" }, n),
        LOG_DEBUG => "debug: ".to_string(),
        8 => "function: ".to_string(),
        _ => String::new(),
    };
    eprint!("{prefix}{args}");
}

#[macro_export]
macro_rules! pm_printf {
    ($lvl:expr, $($a:tt)*) => { $crate::util::pm_printf($lvl, format_args!($($a)*)) };
}

/// resolve_path: realpath with an error message.
pub fn resolve_path(path: &str, option: &str) -> Option<String> {
    match std::fs::canonicalize(path) {
        Ok(p) => Some(p.to_string_lossy().into_owned()),
        Err(e) => {
            pm_printf!(
                LOG_ERROR,
                "'failed to resolve path '{}' passed to '{}': {}\n",
                path,
                option,
                crate::util_common::strerror(&e)
            );
            None
        }
    }
}

/// Write to stdout, ignoring errors (a closed pipe must not panic).
#[macro_export]
macro_rules! pr {
    ($($a:tt)*) => {{
        use std::io::Write;
        let _ = write!(std::io::stdout().lock(), $($a)*);
    }};
}

/// fflush(stdout)
pub fn flush_stdout() {
    use std::io::Write;
    let _ = std::io::stdout().flush();
}
