//! Constants from alpm.h shared between modules.
pub const DB_USAGE_SYNC: i32 = 1;
pub const DB_USAGE_SEARCH: i32 = 1 << 1;
pub const DB_USAGE_INSTALL: i32 = 1 << 2;
pub const DB_USAGE_UPGRADE: i32 = 1 << 3;
pub const DB_USAGE_ALL: i32 = (1 << 4) - 1;
