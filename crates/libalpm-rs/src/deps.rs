//! Port of lib/libalpm/deps.c. Package lists are slices of `&Pkg` (identity is pointer identity, as with
//! `alpm_list_find_ptr`); list order is kept exactly as upstream builds it.
use crate::alpm::Alpm;
use crate::alpm_log;
use crate::consts::{DB_USAGE_INSTALL, DB_USAGE_UPGRADE};
use crate::db::Db;
use crate::error::Error;
use crate::graph::{Graph, GraphState};
use crate::handle::{Handle, Question};
use crate::log::{LOG_DEBUG, LOG_WARNING};
use crate::package::{Pkg, PkgReason, pkg_cmp, pkg_should_ignore};
use crate::util::{hash_sdbm, lossy};
use crate::version::pkg_vercmp;
use std::borrow::Cow;

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

/// dep_vercmp
fn dep_vercmp(version1: &str, m: DepMod, version2: Option<&str>) -> bool {
    if m == DepMod::Any {
        return true;
    }
    let cmp = pkg_vercmp(Some(version1.as_bytes()), version2.map(str::as_bytes));
    match m {
        DepMod::Eq => cmp == 0,
        DepMod::Ge => cmp >= 0,
        DepMod::Le => cmp <= 0,
        DepMod::Lt => cmp < 0,
        DepMod::Gt => cmp > 0,
        DepMod::Any => true,
    }
}

/// _alpm_depcmp_literal
pub fn depcmp_literal(pkg: &Pkg, dep: &Dep) -> bool {
    if pkg.name_hash != dep.name_hash || pkg.name != dep.name {
        // skip more expensive checks
        return false;
    }
    dep_vercmp(&pkg.version, dep.depmod, dep.version.as_deref())
}

/// _alpm_depcmp_provides: does any provision satisfy `dep`
pub fn depcmp_provides(dep: &Dep, provisions: &[Dep]) -> bool {
    for provision in provisions {
        // check provisions, name and version if available
        let same = provision.name_hash == dep.name_hash && provision.name == dep.name;
        if dep.depmod == DepMod::Any {
            // any version will satisfy the requirement
            if same {
                return true;
            }
        } else if provision.depmod == DepMod::Eq {
            // provision specifies a version, so try it out
            if same
                && dep_vercmp(
                    provision.version.as_deref().unwrap_or(""),
                    dep.depmod,
                    dep.version.as_deref(),
                )
            {
                return true;
            }
        }
    }
    false
}

/// _alpm_depcmp
pub fn depcmp(pkg: &Pkg, dep: &Dep) -> bool {
    depcmp_literal(pkg, dep) || depcmp_provides(dep, &pkg.desc().provides)
}

/// find_dep_satisfier
pub(crate) fn find_dep_satisfier<'a>(
    pkgs: impl IntoIterator<Item = &'a Pkg>,
    dep: &Dep,
) -> Option<&'a Pkg> {
    pkgs.into_iter().find(|p| depcmp(p, dep))
}

/// alpm_find_satisfier
pub fn find_satisfier<'a>(
    pkgs: impl IntoIterator<Item = &'a Pkg>,
    depstring: &str,
) -> Option<&'a Pkg> {
    let dep = dep_from_string(depstring);
    find_dep_satisfier(pkgs, &dep)
}

/// alpm_depmissing_t
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepMissing {
    pub target: String,
    pub depend: Dep,
    pub causingpkg: Option<String>,
}

/// _alpm_pkg_depends_on: check if pkg2 satisfies a dependency of pkg1
fn pkg_depends_on(pkg1: &Pkg, pkg2: &Pkg) -> bool {
    pkg1.desc().depends.iter().any(|d| depcmp(pkg2, d))
}

/// alpm_pkg_find over a list of pointers
fn list_has_name(list: &[&Pkg], name: &str) -> bool {
    let h = hash_sdbm(name);
    list.iter().any(|p| p.name_hash == h && p.name == name)
}

/// alpm_list_find_ptr
fn list_has_ptr(list: &[&Pkg], p: &Pkg) -> bool {
    list.iter().any(|q| std::ptr::eq(*q, p))
}

/// alpm_list_diff: elements of lhs missing from rhs, both sorted (stably) by _alpm_pkg_cmp first
fn pkg_list_diff<'a>(lhs: &[&'a Pkg], rhs: &[&Pkg]) -> Vec<&'a Pkg> {
    let mut left = lhs.to_vec();
    left.sort_by(|a, b| pkg_cmp(a, b));
    let mut right = rhs.to_vec();
    right.sort_by(|a, b| pkg_cmp(a, b));
    let (mut l, mut r) = (0, 0);
    let mut ret = Vec::new();
    while l < left.len() && r < right.len() {
        match pkg_cmp(left[l], right[r]) {
            std::cmp::Ordering::Less => {
                ret.push(left[l]);
                l += 1;
            }
            std::cmp::Ordering::Greater => r += 1,
            std::cmp::Ordering::Equal => {
                l += 1;
                r += 1;
            }
        }
    }
    ret.extend_from_slice(&left[l..]);
    ret
}

/// dep_graph_init: convert a list of packages to a graph with an edge for each dependency
fn dep_graph_init<'a>(alpm: &'a Alpm, targets: &[&'a Pkg], ignore: &[&Pkg]) -> Vec<Graph<&'a Pkg>> {
    let cache: Vec<&Pkg> = alpm.localdb.get_pkgcache().unwrap_or(&[]).iter().collect();
    let mut localpkgs = pkg_list_diff(&cache, targets);
    if !ignore.is_empty() {
        localpkgs = pkg_list_diff(&localpkgs, ignore);
    }
    // We create the vertices
    let mut vertices: Vec<Graph<&Pkg>> = targets.iter().map(|p| Graph::new(*p)).collect();
    // We compute the edges
    // upstream walks the list while appending local vertices, so they get edges too
    let mut i = 0;
    while i < vertices.len() {
        let p_i = vertices[i].data;
        // TODO (upstream) this should be somehow combined with alpm_checkdeps
        for j in 0..vertices.len() {
            if pkg_depends_on(p_i, vertices[j].data) {
                vertices[i].children.push(j);
            }
        }
        // lazily add local packages to the dep graph so they don't get resolved unnecessarily
        let mut rest = Vec::new();
        for lp in localpkgs {
            if pkg_depends_on(p_i, lp) {
                vertices.push(Graph::new(lp));
                let j = vertices.len() - 1;
                vertices[i].children.push(j);
            } else {
                rest.push(lp);
            }
        }
        localpkgs = rest;
        vertices[i].iterator = 0;
        i += 1;
    }
    vertices
}

/// _alpm_warn_dep_cycle
fn warn_dep_cycle(
    handle: &Handle,
    targets: &[&Pkg],
    vertices: &[Graph<&Pkg>],
    ancestor: usize,
    vertex: usize,
    reverse: bool,
) {
    // vertex depends on and is required by ancestor
    if !list_has_ptr(targets, vertices[vertex].data) {
        // child is not part of the transaction, not a problem
        return;
    }
    // find the nearest ancestor that's part of the transaction
    let mut anc = Some(ancestor);
    while let Some(a) = anc {
        if list_has_ptr(targets, vertices[a].data) {
            break;
        }
        anc = vertices[a].parent;
    }
    match anc {
        // no transaction package in our ancestry or a circular dependency with itself, not a problem
        None => {}
        Some(a) if a == vertex => {}
        Some(a) => {
            let (ancestorpkg, childpkg) = (vertices[a].data, vertices[vertex].data);
            alpm_log!(handle, LOG_DEBUG, "dependency cycle detected:\n");
            if reverse {
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "{} will be removed after its {} dependency\n",
                    ancestorpkg.name,
                    childpkg.name
                );
            } else {
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "{} will be installed before its {} dependency\n",
                    ancestorpkg.name,
                    childpkg.name
                );
            }
        }
    }
}

/// _alpm_sortbydeps: re-order a list of target packages with respect to their dependencies.
/// Packages listed in `ignore` will not be used to detect indirect dependencies; with `reverse` the
/// dependency order is reversed.
pub fn sortbydeps<'a>(
    alpm: &'a Alpm,
    targets: &[&'a Pkg],
    ignore: &[&Pkg],
    reverse: bool,
) -> Vec<&'a Pkg> {
    if targets.is_empty() {
        return Vec::new();
    }
    let handle = &alpm.handle;
    alpm_log!(handle, LOG_DEBUG, "started sorting dependencies\n");
    let mut v = dep_graph_init(alpm, targets, ignore);
    let mut newtargs = Vec::new();
    let n = v.len();
    let (mut i, mut vertex) = (0, 0);
    while i < n {
        // mark that we touched the vertex
        v[vertex].state = GraphState::Processing;
        let mut switched_to_child = false;
        while v[vertex].iterator < v[vertex].children.len() && !switched_to_child {
            let nextchild = v[vertex].children[v[vertex].iterator];
            v[vertex].iterator += 1;
            match v[nextchild].state {
                GraphState::Unprocessed => {
                    switched_to_child = true;
                    v[nextchild].parent = Some(vertex);
                    vertex = nextchild;
                }
                GraphState::Processing => {
                    warn_dep_cycle(handle, targets, &v, vertex, nextchild, reverse)
                }
                GraphState::Processed => {}
            }
        }
        if !switched_to_child {
            if list_has_ptr(targets, v[vertex].data) {
                newtargs.push(v[vertex].data);
            }
            // mark that we've left this vertex
            v[vertex].state = GraphState::Processed;
            match v[vertex].parent {
                Some(p) => vertex = p,
                None => {
                    // top level vertex reached, move to the next unprocessed vertex
                    i += 1;
                    while i < n {
                        vertex = i;
                        if v[i].state == GraphState::Unprocessed {
                            break;
                        }
                        i += 1;
                    }
                }
            }
        }
    }
    alpm_log!(handle, LOG_DEBUG, "sorting dependencies finished\n");
    if reverse {
        newtargs.reverse();
    }
    newtargs
}

/// the dependency as checked: with no-dep-version the comparison operator is dropped
fn effective(dep: &Dep, nodepversion: bool) -> Cow<'_, Dep> {
    if nodepversion {
        Cow::Owned(Dep {
            depmod: DepMod::Any,
            ..dep.clone()
        })
    } else {
        Cow::Borrowed(dep)
    }
}

/// alpm_checkdeps: look for unsatisfied dependencies of `upgrade` and, with `reversedeps`, the
/// dependencies of `pkglist` that removing `rem`/upgrading would break.
pub fn checkdeps(
    handle: &Handle,
    pkglist: &[&Pkg],
    rem: &[&Pkg],
    upgrade: &[&Pkg],
    reversedeps: bool,
) -> Vec<DepMissing> {
    let (mut dblist, mut modified) = (Vec::new(), Vec::new());
    for &pkg in pkglist {
        if list_has_name(rem, &pkg.name) || list_has_name(upgrade, &pkg.name) {
            modified.push(pkg);
        } else {
            dblist.push(pkg);
        }
    }
    let nodepversion = handle.no_dep_version.get();
    let assumed = handle.opts.borrow().assumeinstalled.clone();
    let mut baddeps = Vec::new();

    // look for unsatisfied dependencies of the upgrade list
    for &tp in upgrade {
        alpm_log!(
            handle,
            LOG_DEBUG,
            "checkdeps: package {}-{}\n",
            tp.name,
            tp.version
        );
        for orig in &tp.desc().depends {
            let depend = effective(orig, nodepversion);
            // 1. we check the upgrade list
            // 2. we check database for untouched satisfying packages
            // 3. we check the dependency ignore list
            if find_dep_satisfier(upgrade.iter().copied(), &depend).is_none()
                && find_dep_satisfier(dblist.iter().copied(), &depend).is_none()
                && !depcmp_provides(&depend, &assumed)
            {
                // Unsatisfied dependency in the upgrade list
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "checkdeps: missing dependency '{}' for package '{}'\n",
                    dep_compute_string(&depend),
                    tp.name
                );
                baddeps.push(DepMissing {
                    target: tp.name.clone(),
                    depend: (*depend).clone(), // upstream copies after the mod override
                    causingpkg: None,
                });
            }
        }
    }

    if reversedeps {
        // reversedeps handles the backwards dependencies, ie, the packages listed in the requiredby field.
        for &lp in &dblist {
            for orig in &lp.desc().depends {
                let depend = effective(orig, nodepversion);
                let causingpkg = find_dep_satisfier(modified.iter().copied(), &depend);
                // we won't break this depend, if it is already broken, we ignore it
                // 1. check upgrade list for satisfiers 2. check dblist for satisfiers
                // 3. we check the dependency ignore list
                if let Some(causingpkg) = causingpkg
                    && find_dep_satisfier(upgrade.iter().copied(), &depend).is_none()
                    && find_dep_satisfier(dblist.iter().copied(), &depend).is_none()
                    && !depcmp_provides(&depend, &assumed)
                {
                    alpm_log!(
                        handle,
                        LOG_DEBUG,
                        "checkdeps: transaction would break '{}' dependency of '{}'\n",
                        dep_compute_string(&depend),
                        lp.name
                    );
                    baddeps.push(DepMissing {
                        target: lp.name.clone(),
                        depend: (*depend).clone(), // upstream copies after the mod override
                        causingpkg: Some(causingpkg.name.clone()),
                    });
                }
            }
        }
    }
    baddeps
}

/// _alpm_select_depends: move package dependencies from one list to another.
/// If `explicit` is false, explicitly installed packages are not moved.
fn select_depends<'a>(from: &mut Vec<&'a Pkg>, to: &mut Vec<&'a Pkg>, pkg: &Pkg, explicit: bool) {
    if pkg.desc().depends.is_empty() {
        return;
    }
    let mut kept = Vec::with_capacity(from.len());
    for &deppkg in from.iter() {
        if (explicit || deppkg.desc().reason == PkgReason::Depend) && pkg_depends_on(pkg, deppkg) {
            to.push(deppkg);
        } else {
            kept.push(deppkg);
        }
    }
    *from = kept;
}

/// _alpm_recursedeps: add unneeded dependencies (only required by packages in the target list) to
/// `targs`. A topologically sorted input gives a topologically sorted output.
/// Deviation: upstream appends `_alpm_pkg_dup` copies; here the added entries borrow the database's packages.
pub fn recursedeps<'a>(db: &'a Db, targs: &mut Vec<&'a Pkg>, include_explicit: bool) -> i32 {
    let mut keep: Vec<&Pkg> = db.get_pkgcache().unwrap_or(&[]).iter().collect();
    for t in targs.iter() {
        // alpm_list_remove: first item comparing equal
        if let Some(p) = keep.iter().position(|k| pkg_cmp(k, t).is_eq()) {
            keep.remove(p);
        }
    }
    let mut rem: Vec<&Pkg> = Vec::new();
    // recursively select all dependencies for removal
    for t in targs.iter() {
        select_depends(&mut keep, &mut rem, t, include_explicit);
    }
    let mut i = 0;
    while i < rem.len() {
        let p = rem[i];
        select_depends(&mut keep, &mut rem, p, include_explicit);
        i += 1;
    }
    // recursively select any still needed packages to keep
    let mut i = 0;
    while i < keep.len() && !rem.is_empty() {
        let p = keep[i];
        select_depends(&mut rem, &mut keep, p, true);
        i += 1;
    }
    // copy selected packages into the target list
    for pkg in rem {
        alpm_log!(
            db.handle,
            LOG_DEBUG,
            "adding '{}' to the targets\n",
            pkg.name
        );
        targs.push(pkg);
    }
    0
}

/// the "install an ignored package?" question of resolvedep
fn ignored_install_ok(handle: &Handle, pkg: &Pkg, prompt: bool) -> bool {
    let mut q = Question::InstallIgnorepkg {
        install: false,
        pkg,
    };
    if prompt {
        handle.question(&mut q);
    } else {
        alpm_log!(
            handle,
            LOG_WARNING,
            "ignoring package {}-{}\n",
            pkg.name,
            pkg.version
        );
    }
    matches!(q, Question::InstallIgnorepkg { install: true, .. })
}

/// resolvedep: search for the dep satisfier in `dbs` (`localdb` is handle->db_local)
fn resolvedep<'a>(
    localdb: &Db,
    dep: &Dep,
    dbs: &[&'a Db],
    excluding: &[&Pkg],
    prompt: bool,
) -> Option<&'a Pkg> {
    let handle = &localdb.handle;
    let mut ignored = false;
    let mut providers: Vec<&'a Pkg> = Vec::new();
    let usable = |db: &Db| db.usage.get() & (DB_USAGE_INSTALL | DB_USAGE_UPGRADE) != 0;

    // 1. literals
    for db in dbs.iter().copied().filter(|d| usable(d)) {
        if let Some(pkg) = db.pkg_from_cache(&dep.name)
            && depcmp_literal(pkg, dep)
            && !list_has_name(excluding, &pkg.name)
        {
            if pkg_should_ignore(handle, pkg) && !ignored_install_ok(handle, pkg, prompt) {
                ignored = true;
                continue;
            }
            return Some(pkg);
        }
    }
    // 2. satisfiers (skip literals here)
    for db in dbs.iter().copied().filter(|d| usable(d)) {
        for pkg in db.get_pkgcache().unwrap_or(&[]) {
            if (pkg.name_hash != dep.name_hash || pkg.name != dep.name)
                && depcmp_provides(dep, &pkg.desc().provides)
                && !list_has_name(excluding, &pkg.name)
            {
                if pkg_should_ignore(handle, pkg) && !ignored_install_ok(handle, pkg, prompt) {
                    ignored = true;
                    continue;
                }
                alpm_log!(
                    handle,
                    LOG_DEBUG,
                    "provider found ({} provides {})\n",
                    pkg.name,
                    dep.name
                );
                // provide is already installed so return early instead of prompting later
                if localdb.pkg_from_cache(&pkg.name).is_some() {
                    return Some(pkg);
                }
                providers.push(pkg);
                // keep looking for other providers in the all dbs
            }
        }
    }
    let count = providers.len();
    if count >= 1 {
        // default to first provider if there is no QUESTION callback
        let mut q = Question::SelectProvider {
            use_index: 0,
            providers: providers.clone(),
            depend: dep,
        };
        if count > 1 {
            // if there is more than one provider, we ask the user
            handle.question(&mut q);
        }
        if let Question::SelectProvider { use_index, .. } = q
            && use_index >= 0
            && (use_index as usize) < count
        {
            return Some(providers[use_index as usize]);
        }
    }
    handle.pm_errno.set(Some(if ignored {
        Error::PkgIgnored
    } else {
        Error::PkgNotFound
    }));
    None
}

/// alpm_find_dbs_satisfier
pub fn find_dbs_satisfier<'a>(
    alpm: &Alpm,
    dbs: &[&'a Db],
    depstring: &str,
) -> Result<Option<&'a Pkg>, Error> {
    if dbs.is_empty() {
        return alpm.handle.err(Error::WrongArgs);
    }
    let dep = dep_from_string(depstring);
    Ok(resolvedep(&alpm.localdb, &dep, dbs, &[], true))
}

/// _alpm_resolvedeps: add `pkg` and its resolvable dependencies to `packages`. Returns 0, or -1 on an
/// unresolvable dependency (then `packages` is unmodified and the culprit is added to `data`).
pub fn resolvedeps<'a>(
    alpm: &'a Alpm,
    localpkgs: &[&'a Pkg],
    pkg: &'a Pkg,
    preferred: &[&'a Pkg],
    packages: &mut Vec<&'a Pkg>,
    rem: &[&Pkg],
    mut data: Option<&mut Vec<DepMissing>>,
) -> i32 {
    let handle = &alpm.handle;
    let mut ret = 0;
    if list_has_name(packages, &pkg.name) {
        return 0;
    }
    // Create a copy of the packages list, so that it can be restored on error
    let packages_copy = packages.clone();
    // [pkg] has not already been resolved into the packages list, so put it on that list
    packages.push(pkg);

    alpm_log!(handle, LOG_DEBUG, "started resolving dependencies\n");
    let deps = checkdeps(handle, localpkgs, rem, &[pkg], false);
    let syncdbs: Vec<&Db> = alpm.syncdbs.iter().collect();

    for miss in deps {
        let missdep = &miss.depend;
        // check if one of the packages in the [*packages] list already satisfies this dependency
        if find_dep_satisfier(packages.iter().copied(), missdep).is_some() {
            continue;
        }
        // check if one of the packages in the [preferred] list already satisfies this dependency
        let mut spkg = find_dep_satisfier(preferred.iter().copied(), missdep);
        if spkg.is_none() {
            // find a satisfier package in the given repositories
            spkg = resolvedep(&alpm.localdb, missdep, &syncdbs, packages, false);
        }
        if let Some(spkg) = spkg
            && resolvedeps(
                alpm,
                localpkgs,
                spkg,
                preferred,
                packages,
                rem,
                data.as_deref_mut(),
            ) == 0
        {
            alpm_log!(
                handle,
                LOG_DEBUG,
                "pulling dependency {} (needed by {})\n",
                spkg.name,
                pkg.name
            );
        } else if resolvedep(&alpm.localdb, missdep, &[&alpm.localdb], rem, false).is_some() {
            // satisfied by an installed package
        } else {
            handle.pm_errno.set(Some(Error::UnsatisfiedDeps));
            alpm_log!(
                handle,
                LOG_WARNING,
                "cannot resolve \"{}\", a dependency of \"{}\"\n",
                dep_compute_string(missdep),
                pkg.name
            );
            if let Some(d) = data.as_deref_mut() {
                d.push(miss);
            }
            ret = -1;
        }
    }
    if ret != 0 {
        *packages = packages_copy;
    }
    alpm_log!(handle, LOG_DEBUG, "finished resolving dependencies\n");
    ret
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

    // ---- in-memory databases: checkdeps / sortbydeps / resolvedeps / recursedeps

    use crate::db::{DB_STATUS_VALID, DbOps};
    use crate::handle::Handle;
    use crate::package::{Desc, PkgFrom};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Mem(RefCell<Vec<Pkg>>);
    impl DbOps for Mem {
        fn validate(&self, _: &Db) -> i32 {
            0
        }
        fn populate(&self, _: &Db) -> Result<Vec<Pkg>, Error> {
            let mut v = self.0.take();
            v.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(v)
        }
    }

    /// "name" or "name=ver", then "dep,dep" depends, "prov,prov" provides, reason
    fn pkg(h: &Rc<Handle>, spec: &str, deps: &str, prov: &str, reason: PkgReason) -> Pkg {
        let (n, v) = spec.split_once('=').unwrap_or((spec, "1-1"));
        let p = Pkg::new(h.clone(), n.into(), v.into(), hash_sdbm(n), PkgFrom::SyncDb);
        let list = |s: &str| {
            s.split(',')
                .filter(|x| !x.is_empty())
                .map(dep_from_string)
                .collect()
        };
        p.set_desc(Desc {
            depends: list(deps),
            provides: list(prov),
            reason,
            ..Default::default()
        });
        p
    }

    fn mkdb(h: &Rc<Handle>, name: &str, local: bool, pkgs: Vec<Pkg>) -> Db {
        let db = Db::new(h.clone(), name, local, Box::new(Mem(RefCell::new(pkgs))));
        db.status.set(db.status.get() | DB_STATUS_VALID);
        db
    }

    fn names(l: &[&Pkg]) -> Vec<String> {
        l.iter().map(|p| p.name.clone()).collect()
    }

    #[test]
    fn sortbydeps_orders_and_cycles() {
        let h = Handle::new("/nonexistent");
        let n = PkgReason::Explicit;
        // A depends on C, B on A; targets A,B,C,D -> C,A,B,D (comment in deps.c)
        let t: Vec<Pkg> = vec![
            pkg(&h, "A", "C", "", n),
            pkg(&h, "B", "A", "", n),
            pkg(&h, "C", "", "", n),
            pkg(&h, "D", "", "", n),
        ];
        let alpm = Alpm {
            localdb: mkdb(&h, "local", true, vec![]),
            syncdbs: vec![],
            handle: h.clone(),
        };
        let tr: Vec<&Pkg> = t.iter().collect();
        assert_eq!(
            names(&sortbydeps(&alpm, &tr, &[], false)),
            ["C", "A", "B", "D"]
        );
        assert_eq!(
            names(&sortbydeps(&alpm, &tr, &[], true)),
            ["D", "B", "A", "C"]
        );
        assert!(sortbydeps(&alpm, &[], &[], false).is_empty());
        // cycle A <-> B: terminates, children first as far as the DFS allows
        let c = [
            pkg(&h, "A", "B", "", n),
            pkg(&h, "B", "A", "", n),
            pkg(&h, "Z", "", "", n),
        ];
        let cr: Vec<&Pkg> = c.iter().collect();
        assert_eq!(names(&sortbydeps(&alpm, &cr, &[], false)), ["B", "A", "Z"]);
    }

    #[test]
    fn sortbydeps_indirect_through_local() {
        // A -> L (local) -> B: upstream adds L lazily and still gives it edges, so B sorts first
        let h = Handle::new("/nonexistent");
        let n = PkgReason::Explicit;
        let alpm = Alpm {
            localdb: mkdb(&h, "local", true, vec![pkg(&h, "L", "B", "", n)]),
            syncdbs: vec![],
            handle: h.clone(),
        };
        let t = [pkg(&h, "A", "L", "", n), pkg(&h, "B", "", "", n)];
        let tr: Vec<&Pkg> = t.iter().collect();
        assert_eq!(names(&sortbydeps(&alpm, &tr, &[], false)), ["B", "A"]);
    }

    #[test]
    fn sortbydeps_local_packages_not_in_output() {
        let h = Handle::new("/nonexistent");
        let n = PkgReason::Explicit;
        let alpm = Alpm {
            localdb: mkdb(
                &h,
                "local",
                true,
                vec![pkg(&h, "L", "", "", n), pkg(&h, "M", "", "", n)],
            ),
            syncdbs: vec![],
            handle: h.clone(),
        };
        let t = [pkg(&h, "X", "L", "", n), pkg(&h, "Y", "X", "", n)];
        let tr: Vec<&Pkg> = t.iter().collect();
        assert_eq!(names(&sortbydeps(&alpm, &tr, &[], false)), ["X", "Y"]);
    }

    #[test]
    fn checkdeps_remove_and_nodepversion() {
        let h = Handle::new("/nonexistent");
        let n = PkgReason::Explicit;
        let a = [
            pkg(&h, "foo", "bar>=2", "", n),
            pkg(&h, "bar=1-1", "", "", n),
        ];
        let all: Vec<&Pkg> = a.iter().collect();
        // upgrade list with an unsatisfied versioned dep
        let up = [all[0]];
        let miss = checkdeps(&h, &all[1..], &[], &up, false);
        assert_eq!(miss.len(), 1);
        assert_eq!(dep_compute_string(&miss[0].depend), "bar>=2");
        assert_eq!(
            (miss[0].target.as_str(), miss[0].causingpkg.as_deref()),
            ("foo", None)
        );
        h.no_dep_version.set(true);
        assert!(checkdeps(&h, &all[1..], &[], &up, false).is_empty());
        // still missing without a version: reported unversioned, as upstream copies after the override
        let miss = checkdeps(&h, &[], &[], &up, false);
        assert_eq!(dep_compute_string(&miss[0].depend), "bar");
        h.no_dep_version.set(false);
        // removing bar breaks foo (remove001-like), reported with the causing package
        let b3 = pkg(&h, "bar=3-1", "", "", n);
        let all = [all[0], &b3];
        let miss = checkdeps(&h, &all, &[all[1]], &[], true);
        assert_eq!(miss.len(), 1);
        assert_eq!(
            (miss[0].target.as_str(), miss[0].causingpkg.as_deref()),
            ("foo", Some("bar"))
        );
        // assumeinstalled satisfies
        h.add_assumeinstalled(&dep_from_string("bar=2"));
        assert!(checkdeps(&h, &all, &[all[1]], &[], true).is_empty());
    }

    #[test]
    fn resolvedeps_basic_and_unresolvable() {
        let h2 = Handle::new("/nonexistent");
        let n = PkgReason::Explicit;
        let sync = vec![
            pkg(&h2, "app", "lib,tool", "", n),
            pkg(&h2, "lib", "base", "", n),
            pkg(&h2, "base", "", "", n),
            pkg(&h2, "tool", "", "", n),
            pkg(&h2, "bad", "nothing", "", n),
        ];
        let alpm = Alpm {
            localdb: mkdb(&h2, "local", true, vec![]),
            syncdbs: vec![mkdb(&h2, "core", false, sync)],
            handle: h2.clone(),
        };
        let core = &alpm.syncdbs[0];
        let app = core.get_pkg("app").unwrap();
        let mut pk = Vec::new();
        assert_eq!(resolvedeps(&alpm, &[], app, &[], &mut pk, &[], None), 0);
        // pkg first, then dependencies in checkdeps order, depth first
        assert_eq!(names(&pk), ["app", "lib", "base", "tool"]);
        // unresolvable: list restored, culprit reported
        let bad = core.get_pkg("bad").unwrap();
        let mut pk2 = vec![app];
        let mut data = Vec::new();
        assert_eq!(
            resolvedeps(&alpm, &[], bad, &[], &mut pk2, &[], Some(&mut data)),
            -1
        );
        assert_eq!(names(&pk2), ["app"]);
        assert_eq!(dep_compute_string(&data[0].depend), "nothing");
        assert_eq!(h2.errno(), Some(Error::UnsatisfiedDeps));
    }

    #[test]
    fn resolvedeps_providers_and_ignore() {
        let n = PkgReason::Explicit;
        let h = Handle::new("/nonexistent");
        let sync = vec![
            pkg(&h, "app", "sh", "", n),
            pkg(&h, "bash", "", "sh", n),
            pkg(&h, "dash", "", "sh", n),
        ];
        let mut alpm = Alpm {
            localdb: mkdb(&h, "local", true, vec![]),
            syncdbs: vec![mkdb(&h, "core", false, sync)],
            handle: h.clone(),
        };
        let app = alpm.syncdbs[0].get_pkg("app").unwrap();
        // no callback: first provider
        let mut pk = Vec::new();
        assert_eq!(resolvedeps(&alpm, &[], app, &[], &mut pk, &[], None), 0);
        assert_eq!(names(&pk), ["app", "bash"]);
        // callback picks the second
        *h.questioncb.borrow_mut() = Some(Box::new(|q| {
            if let Question::SelectProvider {
                use_index,
                providers,
                ..
            } = q
            {
                assert_eq!(providers.len(), 2);
                *use_index = 1;
            }
        }));
        let mut pk = Vec::new();
        assert_eq!(resolvedeps(&alpm, &[], app, &[], &mut pk, &[], None), 0);
        assert_eq!(names(&pk), ["app", "dash"]);
        *h.questioncb.borrow_mut() = None;
        // find_dbs_satisfier asks for ignored packages; default answer is no
        h.opts.borrow_mut().ignorepkg = vec!["bash".into(), "dash".into()];
        let dbs: Vec<&Db> = alpm.syncdbs.iter().collect();
        assert!(find_dbs_satisfier(&alpm, &dbs, "sh").unwrap().is_none());
        assert_eq!(h.errno(), Some(Error::PkgIgnored));
        assert_eq!(
            find_dbs_satisfier(&alpm, &dbs, "app")
                .unwrap()
                .map(|p| p.name.as_str()),
            Some("app")
        );
        assert!(find_dbs_satisfier(&alpm, &[], "sh").is_err());
        alpm.syncdbs.clear();
    }

    #[test]
    fn recursedeps_selects_unneeded() {
        let h = Handle::new("/nonexistent");
        let (e, d) = (PkgReason::Explicit, PkgReason::Depend);
        let local = vec![
            pkg(&h, "app", "lib,shared", "", e),
            pkg(&h, "lib", "base", "", d),
            pkg(&h, "base", "", "", d),
            pkg(&h, "shared", "", "", d),
            pkg(&h, "other", "shared,xp", "", e),
            pkg(&h, "xp", "", "", e),
        ];
        let db = mkdb(&h, "local", true, local);
        let mut targs = vec![db.get_pkg("app").unwrap()];
        assert_eq!(recursedeps(&db, &mut targs, false), 0);
        // shared is still required by other; xp is explicit
        assert_eq!(names(&targs), ["app", "lib", "base"]);
        let mut targs = vec![db.get_pkg("other").unwrap()];
        recursedeps(&db, &mut targs, true);
        assert_eq!(names(&targs), ["other", "xp"]);
    }
}
