//! Port of src/pacman/files.c (-F): not yet.
use crate::conf::Config;

/// pacman_files
pub fn pacman_files(_cfg: &Config, _targets: &[String]) -> i32 {
    crate::not_implemented("-F")
}
