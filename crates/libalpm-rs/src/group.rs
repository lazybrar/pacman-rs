//! Port of lib/libalpm/group.c. `packages` are indices into the owning database's package cache.

#[derive(Debug, Clone)]
pub struct Group {
    pub name: String,
    pub packages: Vec<usize>,
}

/// _alpm_group_new
pub fn group_new(name: &str) -> Group {
    Group {
        name: name.to_string(),
        packages: Vec::new(),
    }
}
