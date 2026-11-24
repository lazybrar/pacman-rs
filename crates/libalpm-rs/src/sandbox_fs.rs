//! Port of lib/libalpm/sandbox_fs.c: restrict filesystem writes to one directory with Landlock.
use crate::alpm_log;
use crate::handle::Handle;
use crate::log::{LOG_DEBUG, LOG_ERROR};
use crate::util::strerror;
use landlock::BitFlags;
use landlock::{
    ABI, AccessFs, LandlockStatus, PathBeneath, PathFd, RestrictionStatus, Ruleset, RulesetAttr,
    RulesetCreatedAttr, RulesetStatus,
};

fn errno_text(e: &(dyn std::error::Error + 'static)) -> String {
    // the innermost io::Error carries the strerror text upstream prints
    let mut cur: Option<&dyn std::error::Error> = Some(e);
    let mut text = e.to_string();
    while let Some(c) = cur {
        if let Some(io) = c.downcast_ref::<std::io::Error>() {
            text = strerror(io);
        }
        cur = c.source();
    }
    text
}

/// _alpm_sandbox_fs_restrict_writes_to: `/` read-only, `path` read-write (all writes), nothing else writable.
pub fn restrict_writes_to(handle: &Handle, path: &str) -> bool {
    let read: BitFlags<AccessFs> = AccessFs::ReadFile | AccessFs::ReadDir;
    let write: BitFlags<AccessFs> = AccessFs::WriteFile
        | AccessFs::RemoveDir
        | AccessFs::RemoveFile
        | AccessFs::MakeChar
        | AccessFs::MakeDir
        | AccessFs::MakeReg
        | AccessFs::MakeSock
        | AccessFs::MakeFifo
        | AccessFs::MakeBlock
        | AccessFs::MakeSym;
    let handled = read | write | AccessFs::Refer | AccessFs::Truncate | AccessFs::Execute;

    // best effort drops the flags the kernel's ABI lacks (REFER before ABI 2, TRUNCATE before ABI 3)
    let created = Ruleset::default()
        .handle_access(handled)
        .and_then(|r| r.create());
    let mut created = match created {
        Ok(c) => c,
        Err(e) => {
            alpm_log!(
                handle,
                LOG_ERROR,
                "restricting filesystem access failed because the Landlock ruleset could not be created: {}\n",
                errno_text(&e)
            );
            return false;
        }
    };
    // allow / as read-only
    match PathFd::new("/") {
        Ok(fd) => {
            created = match created.add_rule(PathBeneath::new(fd, read)) {
                Ok(c) => c,
                Err(e) => {
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "restricting filesystem access failed because the Landlock rule for / could not be added: {}\n",
                        errno_text(&e)
                    );
                    return false;
                }
            };
        }
        Err(e) => {
            alpm_log!(
                handle,
                LOG_ERROR,
                "opening the root filesystem to make it read-only via Landlock failed: {}\n",
                errno_text(&e)
            );
            return false;
        }
    }
    // allow read-write access to the directory passed as parameter
    match PathFd::new(path) {
        Ok(fd) => {
            // allowed access is a subset of the handled access, which may change for older ABIs
            let rw = (read | write | AccessFs::Truncate) & handled;
            created = match created.add_rule(PathBeneath::new(fd, rw)) {
                Ok(c) => c,
                Err(e) => {
                    alpm_log!(
                        handle,
                        LOG_ERROR,
                        "restricting filesystem access failed because the Landlock rule for the temporary download directory could not be added: {}\n",
                        errno_text(&e)
                    );
                    return false;
                }
            };
        }
        Err(e) => {
            alpm_log!(
                handle,
                LOG_ERROR,
                "opening the download directory to make it writable via Landlock failed: {}\n",
                errno_text(&e)
            );
            return false;
        }
    }
    // upstream sets NO_NEW_PRIVS only after this step (restricting then needs CAP_SYS_ADMIN)
    #[allow(deprecated)]
    let restricted = created.set_no_new_privs(false).restrict_self();
    match restricted {
        Ok(RestrictionStatus {
            ruleset: RulesetStatus::NotEnforced,
            ..
        }) => {
            alpm_log!(
                handle,
                LOG_ERROR,
                "restricting filesystem access failed because Landlock is not supported by the kernel!\n"
            );
            false
        }
        Ok(st) => {
            let abi = match st.landlock {
                LandlockStatus::Available { effective_abi, .. } => effective_abi as i32,
                _ => 0,
            };
            alpm_log!(
                handle,
                LOG_DEBUG,
                "filesystem access has been restricted to {}, Landlock ABI is {}\n",
                path,
                abi
            );
            true
        }
        Err(e) => {
            alpm_log!(
                handle,
                LOG_ERROR,
                "restricting filesystem access failed because the Landlock ruleset could not be applied: {}\n",
                errno_text(&e)
            );
            false
        }
    }
}

#[allow(dead_code)]
const _: ABI = ABI::V3;
