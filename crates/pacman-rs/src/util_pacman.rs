//! Port of the output helpers of src/pacman/util.c.
use crate::conf::{Config, PM_OP_DATABASE, PM_OP_FILES, PM_OP_REMOVE, PM_OP_SYNC, PM_OP_UPGRADE};
use crate::ffi::{mb_chars, wc_width, wcs_width};
use crate::pm_printf;
use crate::pr;
use crate::util::LOG_ERROR;
use std::sync::atomic::{AtomicI32, Ordering};

static CACHED_COLUMNS: AtomicI32 = AtomicI32::new(-1);

/// getcols
pub fn getcols() -> u16 {
    let cached = CACHED_COLUMNS.load(Ordering::Relaxed);
    if cached >= 0 {
        return cached as u16;
    }
    let mut c: i64 = -1;
    if let Ok(e) = std::env::var("COLUMNS")
        && !e.is_empty()
    {
        // strtol: the whole string must be consumed
        c = e.trim_start().parse::<i64>().unwrap_or(-1);
    }
    if c < 0 {
        c = getcols_fd(1) as i64;
    }
    if c < 0 {
        c = 80;
    }
    CACHED_COLUMNS.store(c as i32, Ordering::Relaxed);
    c as u16
}

fn getcols_fd(fd: i32) -> i32 {
    // SAFETY: isatty/ioctl on a descriptor with a properly sized out parameter
    unsafe {
        if libc::isatty(fd) == 0 {
            return 0;
        }
        let mut ws: libc::winsize = std::mem::zeroed();
        if libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) == 0 && ws.ws_col > 0 {
            return ws.ws_col as i32;
        }
    }
    -libc::EIO
}

/// indentprint: output a string, wrapping words with the given indentation
pub fn indentprint(s: &str, indent: u16, cols: u16) {
    // if we're not a tty, or our tty is not wide enough that wrapping even makes sense, print without indenting
    if cols == 0 || indent > cols {
        pr!("{}", s);
        return;
    }
    let chars = mb_chars(s);
    let mut cidx = indent as usize;
    let mut i = 0;
    let n = chars.len();
    while i < n {
        if chars[i].wc == b' ' as u32 {
            i += 1;
            if i >= n {
                // *p == L'\\0': next = p, len = 0
                let len = 0usize;
                if (len + 1) > (cols as usize).wrapping_sub(cidx) {
                    pr!("\n{:width$}", "", width = indent as usize);
                    cidx = indent as usize;
                } else {
                    pr!(" ");
                    cidx += 1;
                }
                continue;
            }
            if chars[i].wc == b' ' as u32 {
                continue;
            }
            let mut next = i;
            while next < n && chars[next].wc != b' ' as u32 {
                next += 1;
            }
            // len captures # cols
            let mut len = 0usize;
            for c in &chars[i..next] {
                len = len.wrapping_add(wc_width(c.wc) as isize as usize);
            }
            if (len.wrapping_add(1)) > (cols as usize).wrapping_sub(cidx) {
                // wrap to a newline and reindent
                pr!("\n{:width$}", "", width = indent as usize);
                cidx = indent as usize;
            } else {
                pr!(" ");
                cidx += 1;
            }
            continue;
        }
        pr!("{}", chars[i].bytes);
        cidx = cidx.wrapping_add(wc_width(chars[i].wc) as isize as usize);
        i += 1;
    }
}

/// string_length: display width, skipping terminal colour escapes
pub fn string_length(s: &str) -> usize {
    if s.is_empty() {
        return 0;
    }
    let owned;
    let t: &str = if s.contains('\x1b') {
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == 0x1b
                && b.get(i + 1) == Some(&b'[')
                && b.get(i + 2).is_some_and(u8::is_ascii_digit)
            {
                let mut t = i + 3;
                while t < b.len() && (b[t].is_ascii_digit() || b[t] == b';') {
                    t += 1;
                }
                if b.get(t) == Some(&b'm') {
                    i = t + 1;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        owned = String::from_utf8_lossy(&out).into_owned();
        &owned
    } else {
        s
    };
    let w = wcs_width(&mb_chars(t));
    w as isize as usize
}

/// string_display
pub fn string_display(cfg: &Config, title: Option<&str>, string: Option<&str>, cols: u16) {
    if let Some(t) = title {
        pr!("{}{}{} ", cfg.colstr.title, t, cfg.colstr.nocolor);
    }
    match string {
        None | Some("") => pr!("None"),
        Some(s) => {
            // compute the length of title + a space
            let len = title.map_or(0, string_length) + 1;
            indentprint(s, len as u16, cols);
        }
    }
    pr!("\n");
}

/// list_display
pub fn list_display<S: AsRef<str>>(cfg: &Config, title: Option<&str>, list: &[S], maxcols: u16) {
    let mut len = 0usize;
    if let Some(t) = title {
        len = string_length(t) + 1;
        pr!("{}{}{} ", cfg.colstr.title, t, cfg.colstr.nocolor);
    }
    if list.is_empty() {
        pr!("None\n");
        return;
    }
    let mut cols = len;
    let first = list[0].as_ref();
    pr!("{}", first);
    cols = cols.wrapping_add(string_length(first));
    for item in &list[1..] {
        let str = item.as_ref();
        let s = string_length(str);
        // wrap only if we have enough usable column space
        if maxcols as usize > len && cols.wrapping_add(s).wrapping_add(2) >= maxcols as usize {
            cols = len;
            pr!("\n{:width$}", "", width = len);
        } else if cols != len {
            // 2 spaces are added if this is not the first element on a line.
            pr!("  ");
            cols += 2;
        }
        pr!("{}", str);
        cols = cols.wrapping_add(s);
    }
    pr!("\n");
}

/// list_display_linebreak
pub fn list_display_linebreak<S: AsRef<str>>(
    cfg: &Config,
    title: Option<&str>,
    list: &[S],
    maxcols: u16,
) {
    let mut len = 0u16;
    if let Some(t) = title {
        len = string_length(t) as u16 + 1;
        pr!("{}{}{} ", cfg.colstr.title, t, cfg.colstr.nocolor);
    }
    if list.is_empty() {
        pr!("None\n");
        return;
    }
    // Print the first element
    indentprint(list[0].as_ref(), len, maxcols);
    pr!("\n");
    // Print the rest
    for item in &list[1..] {
        pr!("{:width$}", "", width = len as usize);
        indentprint(item.as_ref(), len, maxcols);
        pr!("\n");
    }
}

/// humanize_size
pub fn humanize_size(bytes: i64, target_unit: char, precision: i32) -> (f64, &'static str) {
    const LABELS: [&str; 9] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"];
    let mut val = bytes as f64;
    let mut index = 0;
    while index < LABELS.len() - 1 {
        if (target_unit != '\0' && LABELS[index].starts_with(target_unit))
            || (target_unit == '\0' && (-2048.0..=2048.0).contains(&val))
        {
            break;
        }
        val /= 1024.0;
        index += 1;
    }
    // do not display negative zeroes
    if precision >= 0 && val < 0.0 && val > (-0.5 / 10f64.powi(precision)) {
        val = 0.0;
    }
    (val, LABELS[index])
}

/// colon_printf
pub fn colon_printf(cfg: &Config, msg: &str) {
    pr!("{}{}{}", cfg.colstr.colon, msg, cfg.colstr.nocolor);
    crate::util::flush_stdout();
}

/// needs_root
pub fn needs_root(cfg: &Config) -> bool {
    match cfg.op {
        PM_OP_DATABASE => cfg.op_q_check == 0,
        PM_OP_UPGRADE | PM_OP_REMOVE => !cfg.print,
        PM_OP_SYNC => {
            cfg.op_s_clean != 0
                || cfg.op_s_sync != 0
                || (cfg.group == 0
                    && cfg.op_s_info == 0
                    && !cfg.op_q_list
                    && !cfg.op_s_search
                    && !cfg.print)
        }
        PM_OP_FILES => cfg.op_s_sync != 0,
        _ => false,
    }
}

/// check_syncdbs
pub fn check_syncdbs(cfg: &Config, need_repos: usize, check_valid: bool) -> i32 {
    let alpm = cfg.alpm.as_ref().unwrap();
    let mut ret = 0;
    if need_repos != 0 && alpm.syncdbs.is_empty() {
        pm_printf!(LOG_ERROR, "no usable package repositories configured.\n");
        return 1;
    }
    if check_valid {
        // ensure all known dbs are valid
        for db in &alpm.syncdbs {
            if db.get_valid() != 0 {
                let e = alpm
                    .handle
                    .errno()
                    .map_or("unexpected error", |e| e.strerror());
                pm_printf!(LOG_ERROR, "database '{}' is not valid ({})\n", db.name(), e);
                ret = 1;
            }
        }
    }
    ret
}
