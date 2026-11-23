//! Port of lib/libalpm/log.c: `_alpm_log` (the callback part; `alpm_logaction` comes with the write side).

pub const LOG_ERROR: u32 = 1;
pub const LOG_WARNING: u32 = 1 << 1;
pub const LOG_DEBUG: u32 = 1 << 2;
pub const LOG_FUNCTION: u32 = 1 << 3;

/// _alpm_log: format and hand to the handle's log callback (no-op without one).
#[macro_export]
macro_rules! alpm_log {
    ($handle:expr, $lvl:expr, $($a:tt)*) => {
        $handle.log($lvl, format_args!($($a)*))
    };
}
