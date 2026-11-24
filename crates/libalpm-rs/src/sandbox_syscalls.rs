//! Port of lib/libalpm/sandbox_syscalls.c: deny dangerous system calls with seccomp (EPERM), allow the rest.
use crate::alpm_log;
use crate::handle::Handle;
use crate::log::{LOG_DEBUG, LOG_ERROR};
use libseccomp::{ScmpAction, ScmpFilterContext, ScmpSyscall};

/// the denied system calls, in the order of sandbox_syscalls.c (including its duplicates)
pub const DENIED_SYSCALLS: &[&str] = &[
    "delete_module",
    "finit_module",
    "init_module",
    "chroot",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "mount",
    "mount_setattr",
    "move_mount",
    "open_tree",
    "pivot_root",
    "umount",
    "umount2",
    "add_key",
    "keyctl",
    "request_key",
    "modify_ldt",
    "subpage_prot",
    "switch_endian",
    "vm86",
    "vm86old",
    "kcmp",
    "lookup_dcookie",
    "perf_event_open",
    "pidfd_getfd",
    "ptrace",
    "rtas",
    "sys_debug_setcontext",
    "adjtimex",
    "clock_adjtime",
    "clock_adjtime64",
    "clock_settime",
    "clock_settime64",
    "settimeofday",
    "ioperm",
    "iopl",
    "pciconfig_iobase",
    "pciconfig_read",
    "pciconfig_write",
    "kexec_file_load",
    "kexec_load",
    "reboot",
    "acct",
    "bpf",
    "capset",
    "chroot",
    "fanotify_init",
    "fanotify_mark",
    "nfsservctl",
    "open_by_handle_at",
    "pivot_root",
    "personality",
    "_sysctl",
    "afs_syscall",
    "bdflush",
    "break",
    "create_module",
    "ftime",
    "get_kernel_syms",
    "getpmsg",
    "gtty",
    "idle",
    "lock",
    "mpx",
    "prof",
    "profil",
    "putpmsg",
    "query_module",
    "security",
    "sgetmask",
    "ssetmask",
    "stime",
    "stty",
    "sysfs",
    "tuxcall",
    "ulimit",
    "uselib",
    "ustat",
    "vserver",
    "swapon",
    "swapoff",
];

/// _alpm_sandbox_syscalls_filter
pub fn syscalls_filter(handle: &Handle) -> bool {
    // allow all syscalls that are not listed
    let mut ctx = match ScmpFilterContext::new(ScmpAction::Allow) {
        Ok(c) => c,
        Err(_) => {
            alpm_log!(
                handle,
                LOG_ERROR,
                "error initializing seccomp to filter system calls in the download sandbox!\n"
            );
            return false;
        }
    };
    let mut count = 0;
    for name in DENIED_SYSCALLS {
        if let Ok(sc) = ScmpSyscall::from_name(name) {
            if ctx.add_rule(ScmpAction::Errno(libc::EPERM), sc).is_err() {
                alpm_log!(
                    handle,
                    LOG_ERROR,
                    "error restricting syscall {} via seccomp!\n",
                    name
                );
            } else {
                count += 1;
            }
        }
    }
    match ctx.load() {
        Ok(()) => {
            alpm_log!(
                handle,
                LOG_DEBUG,
                "successfully restricted {} syscalls via seccomp\n",
                count
            );
            true
        }
        Err(e) => {
            let errno = e.errno().map_or(0, |e| e as i32);
            alpm_log!(
                handle,
                LOG_ERROR,
                "error restricting syscalls via seccomp: {}!\n",
                errno
            );
            false
        }
    }
}
