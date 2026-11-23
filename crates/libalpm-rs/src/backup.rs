//! Port of lib/libalpm/backup.c.
use crate::package::Pkg;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    pub name: String,
    pub hash: Option<String>,
}

/// _alpm_split_backup: "file\thash"
pub fn split_backup(s: &str) -> Backup {
    match s.split_once('\t') {
        Some((n, h)) => Backup {
            name: n.to_string(),
            hash: Some(h.to_string()),
        },
        None => Backup {
            name: s.to_string(),
            hash: None,
        },
    }
}

/// _alpm_needbackup
pub fn needbackup<'a>(file: &str, pkg: &'a Pkg) -> Option<&'a Backup> {
    pkg.backup().iter().find(|b| b.name == file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split() {
        assert_eq!(split_backup("etc/a\tabc").hash.as_deref(), Some("abc"));
        assert_eq!(split_backup("etc/a").hash, None);
        assert_eq!(split_backup("etc/a\tb\tc").hash.as_deref(), Some("b\tc"));
    }
}
