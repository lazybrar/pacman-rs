//! Port of lib/libalpm/deps.c (so far: alpm_dep_from_string, alpm_dep_compute_string).
use crate::util::{hash_sdbm, lossy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepMod {
    Any = 1,
    Eq,
    Ge,
    Le,
    Gt,
    Lt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dep {
    pub name: String,
    pub version: Option<String>,
    pub desc: Option<String>,
    pub name_hash: u64,
    pub depmod: DepMod,
}

/// alpm_dep_from_string
pub fn dep_from_string(depstring: &str) -> Dep {
    let b = depstring.as_bytes();
    // Note the extra space in ": " to avoid matching the epoch
    let (desc, deplen, desc_pos) = match depstring.find(": ") {
        Some(p) => (Some(depstring[p + 2..].to_string()), p, p),
        None => (None, b.len(), b.len()),
    };
    let dep = &b[..deplen];
    let find = |c: u8| dep.iter().position(|&x| x == c);
    let (depmod, ptr, version) = if let Some(p) = find(b'<') {
        if b.get(p + 1) == Some(&b'=') {
            (DepMod::Le, p, Some(p + 2))
        } else {
            (DepMod::Lt, p, Some(p + 1))
        }
    } else if let Some(p) = find(b'>') {
        if b.get(p + 1) == Some(&b'=') {
            (DepMod::Ge, p, Some(p + 2))
        } else {
            (DepMod::Gt, p, Some(p + 1))
        }
    } else if let Some(p) = find(b'=') {
        (DepMod::Eq, p, Some(p + 1))
    } else {
        (DepMod::Any, deplen, None)
    };
    let name = lossy(&b[..ptr]);
    // STRNDUP(version, desc - version): may be empty when version starts past the description
    let version = version.map(|v| lossy(&b[v.min(desc_pos)..desc_pos]));
    Dep {
        name_hash: hash_sdbm(&name),
        name,
        version,
        desc,
        depmod,
    }
}

/// alpm_dep_compute_string
pub fn dep_compute_string(dep: &Dep) -> String {
    let opr = match dep.depmod {
        DepMod::Any => "",
        DepMod::Ge => ">=",
        DepMod::Le => "<=",
        DepMod::Eq => "=",
        DepMod::Lt => "<",
        DepMod::Gt => ">",
    };
    let ver = if dep.depmod != DepMod::Any {
        dep.version.as_deref().unwrap_or("")
    } else {
        ""
    };
    let (delim, desc) = match &dep.desc {
        Some(d) => (": ", d.as_str()),
        None => ("", ""),
    };
    format!("{}{}{}{}{}", dep.name, opr, ver, delim, desc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for s in [
            "foo",
            "foo>=1:2.0-1",
            "foo<2",
            "foo=1",
            "foo: a thing",
            "foo>1: x: y",
            "a<=3: d",
        ] {
            assert_eq!(dep_compute_string(&dep_from_string(s)), s, "{s}");
        }
        let d = dep_from_string("bar>=1:2");
        assert_eq!(
            (d.name.as_str(), d.version.as_deref(), d.depmod),
            ("bar", Some("1:2"), DepMod::Ge)
        );
    }
}
