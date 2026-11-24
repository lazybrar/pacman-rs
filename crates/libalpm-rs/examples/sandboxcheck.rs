//! Rust twin of tests/oracle/sandboxcheck.c (same arguments, same output); used by tests/sandbox_diff.rs.
use libalpm_rs::alpm::alpm_initialize;
use libalpm_rs::sandbox::sandbox_setup_child;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 3 {
        std::process::exit(2);
    }
    let dbpath = format!("/tmp/sandboxcheck-db-{}", std::process::id());
    std::fs::create_dir_all(format!("{dbpath}/local")).unwrap();
    let alpm = alpm_initialize("/", &dbpath).expect("init");
    let h = alpm.handle.clone();
    *h.logcb.borrow_mut() = Some(Box::new(|lvl, msg| {
        let mut m = msg.to_string();
        // the Landlock ABI depends on the kernel, not on the port: hide the number
        if let Some(p) = m.find("Landlock ABI is ") {
            m.truncate(p + "Landlock ABI is ".len());
            m.push_str("N\n");
        }
        if m.contains("restrict") || m.contains("seccomp") || m.contains("Landlock") {
            print!("log {lvl}: {m}");
        }
    }));
    match a.get(3).map(String::as_str) {
        Some("nofs") => h.opts.borrow_mut().disable_sandbox_filesystem = true,
        Some("nosys") => h.opts.borrow_mut().disable_sandbox_syscalls = true,
        _ => {}
    }
    let ret = sandbox_setup_child(&h, "nobody", Some(&a[1]), true);
    println!("setup ret={ret}");
    let open = |p: &str| {
        let c = std::ffi::CString::new(p).unwrap();
        // SAFETY: valid C string
        unsafe { libc::open(c.as_ptr(), libc::O_CREAT | libc::O_WRONLY, 0o644) }
    };
    let fd = open(&format!("{}/inside", a[1]));
    println!(
        "probe write-inside fd_ok={} errno={}",
        (fd >= 0) as i32,
        if fd >= 0 { 0 } else { errno() }
    );
    let fd = open(&a[2]);
    println!(
        "probe write-outside fd_ok={} errno={}",
        (fd >= 0) as i32,
        if fd >= 0 { 0 } else { errno() }
    );
    let c = std::ffi::CString::new("/etc/hostname").unwrap();
    // SAFETY: valid C string
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
    println!("probe read-etc fd_ok={}", (fd >= 0) as i32);
    // SAFETY: mount with valid C strings (fails with EPERM under the filter)
    let ret = unsafe {
        libc::mount(
            c"none".as_ptr(),
            c"/tmp".as_ptr(),
            c"tmpfs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    println!(
        "probe mount ret={ret} errno={}",
        if ret < 0 { errno() } else { 0 }
    );
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    // SAFETY: valid timeval
    let ret = unsafe { libc::settimeofday(&tv, std::ptr::null()) };
    println!(
        "probe settimeofday ret={ret} errno={}",
        if ret < 0 { errno() } else { 0 }
    );
    println!("probe getpid ok={}", (std::process::id() > 0) as i32);
    let _ = std::fs::remove_dir_all(&dbpath);
}
