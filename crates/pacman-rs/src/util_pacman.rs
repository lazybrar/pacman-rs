//! Port of the output helpers of src/pacman/util.c.
use crate::conf::{Config, PM_OP_DATABASE, PM_OP_FILES, PM_OP_REMOVE, PM_OP_SYNC, PM_OP_UPGRADE};
use libalpm_rs::package::Pkg;
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

/// signature_display
pub fn signature_display(
    cfg: &Config,
    title: Option<&str>,
    siglist: &libalpm_rs::signing::SigList,
    maxcols: u16,
) {
    use libalpm_rs::signing::{SigStatus, SigValidity};
    let mut len = 0usize;
    if let Some(t) = title {
        len = string_length(t) + 1;
        pr!("{}{}{} ", cfg.colstr.title, t, cfg.colstr.nocolor);
    }
    if siglist.is_empty() {
        // sic: upstream prints no newline here
        pr!("None");
        return;
    }
    for (i, result) in siglist.iter().enumerate() {
        // Don't re-indent the first result
        if i != 0 {
            pr!("{:len$}", "");
        }
        let status = match result.status {
            SigStatus::Valid => "Valid",
            SigStatus::KeyExpired => "Key expired",
            SigStatus::SigExpired => "Expired",
            SigStatus::Invalid => "Invalid",
            SigStatus::KeyUnknown => "Key unknown",
            SigStatus::KeyDisabled => "Key disabled",
        };
        let validity = match result.validity {
            SigValidity::Full => "full trust",
            SigValidity::Marginal => "marginal trust",
            SigValidity::Never => "never trust",
            SigValidity::Unknown => "unknown trust",
        };
        let name = result.key.uid.as_deref().unwrap_or(&result.key.fingerprint);
        indentprint(
            &format!("{status}, {validity} from \"{name}\""),
            len as u16,
            maxcols,
        );
        pr!("\n");
    }
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

/// colon_printf for the callbacks, which have no Config: the colours come from the callback settings
pub fn colon_printf_raw(msg: &str) {
    let c = crate::callback::cbcfg();
    pr!("{}{}{}", c.colstr.colon, msg, c.colstr.nocolor);
    crate::util::flush_stdout();
}

/// flush_term_input: discard unhandled input on the terminal's input buffer
fn flush_term_input(fd: i32) {
    // SAFETY: isatty/tcflush on a descriptor
    unsafe {
        if libc::isatty(fd) != 0 {
            libc::tcflush(fd, libc::TCIFLUSH);
        }
    }
}

/// safe_fgets_stdin (without the cursor handling): one line of stdin, at most `size - 1` bytes
fn safe_fgets_stdin(size: usize) -> Option<String> {
    use std::io::BufRead;
    let mut buf = Vec::new();
    let mut stdin = std::io::stdin().lock();
    loop {
        let avail = stdin.fill_buf().ok()?;
        if avail.is_empty() {
            break;
        }
        let take = avail
            .iter()
            .position(|&b| b == b'\n')
            .map_or(avail.len(), |p| p + 1)
            .min(size - 1 - buf.len());
        buf.extend_from_slice(&avail[..take]);
        stdin.consume(take);
        if buf.last() == Some(&b'\n') || buf.len() >= size - 1 {
            break;
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
}

/// question: a Y/N prompt
fn question(preset: bool, args: std::fmt::Arguments) -> bool {
    use std::io::Write;
    let c = crate::callback::cbcfg();
    let to_stdout = c.noconfirm;
    // ensure all text makes it to the screen before we prompt the user
    crate::util::flush_stdout();
    let _ = std::io::stderr().flush();
    let line = format!(
        "{}{} {} {}",
        c.colstr.colon,
        args,
        if preset { "[Y/n]" } else { "[y/N]" },
        c.colstr.nocolor
    );
    let mut out: Box<dyn Write> = if to_stdout {
        Box::new(std::io::stdout())
    } else {
        // Use stderr so questions are always displayed when redirecting output
        Box::new(std::io::stderr())
    };
    let _ = write!(out, "{line}");
    let _ = out.flush();
    if c.noconfirm {
        let _ = writeln!(out);
        let _ = out.flush();
        return preset;
    }
    flush_term_input(0);
    if let Some(response) = safe_fgets_stdin(32) {
        let r = response.trim_matches(|ch: char| ch.is_ascii_whitespace());
        if r.is_empty() {
            return preset;
        }
        // if stdin is piped, response does not get printed out, and as a result a \n is missing
        // SAFETY: isatty on stdin
        if unsafe { libc::isatty(0) } == 0 {
            let _ = writeln!(out, "{r}");
            let _ = out.flush();
        }
        let l = r.to_lowercase();
        if l == "y" || l == "yes" {
            return true;
        } else if l == "n" || l == "no" {
            return false;
        }
    }
    false
}

/// yesno
pub fn yesno(args: std::fmt::Arguments) -> bool {
    question(true, args)
}

/// noyes
pub fn noyes(args: std::fmt::Arguments) -> bool {
    question(false, args)
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

/// display_repo_list
fn display_repo_list(cfg: &Config, dbname: &str, list: &[String], cols: u16) {
    let c = &cfg.colstr;
    colon_printf_raw(&format!("Repository {}{}\n", c.repo, dbname));
    list_display(cfg, Some("  "), list, cols);
}

/// select_display: numbered package names grouped by repository
pub fn select_display(cfg: &Config, pkglist: &[&libalpm_rs::package::Pkg]) {
    let cols = getcols();
    let mut list: Vec<String> = Vec::new();
    let mut dbname: Option<String> = None;
    for (nth, pkg) in pkglist.iter().enumerate() {
        let pdb = pkg.dbname.clone().unwrap_or_default();
        if dbname.is_none() {
            dbname = Some(pdb.clone());
        }
        if Some(&pdb) != dbname.as_ref() {
            display_repo_list(cfg, dbname.as_deref().unwrap_or(""), &list, cols);
            list.clear();
            dbname = Some(pdb);
        }
        list.push(format!("{}) {}", nth + 1, pkg.name));
    }
    display_repo_list(cfg, dbname.as_deref().unwrap_or(""), &list, cols);
}

/// parseindex: strtol of the whole string, within [min, max]
fn parseindex(s: &str, min: i32, max: i32) -> Option<i32> {
    // strtol: optional whitespace and sign, then digits; the whole string must be consumed
    let t = s.trim_start_matches(crate::util_common::c_isspace);
    let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
    let n = if t.is_empty() {
        Some(0)
    } else if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        t.parse::<i64>().ok()
    } else {
        None
    };
    match n {
        Some(n) => {
            if n < min as i64 || n > max as i64 {
                pm_printf!(
                    LOG_ERROR,
                    "invalid value: {} is not between {} and {}\n",
                    n,
                    min,
                    max
                );
                None
            } else {
                Some(n as i32)
            }
        }
        None => {
            pm_printf!(LOG_ERROR, "invalid number: {}\n", s);
            None
        }
    }
}

/// multiselect_parse: false on an invalid answer
fn multiselect_parse(array: &mut [bool], count: i32, response: &str) -> bool {
    let mut first = true;
    for tok in response.split([' ', ',']).filter(|t| !t.is_empty()) {
        let was_first = std::mem::replace(&mut first, false);
        let starts = crate::util_common::strtrim(tok);
        if starts.is_empty() {
            continue;
        }
        let (starts, include) = match starts.strip_prefix('^') {
            Some(r) => (r, false),
            None => {
                if was_first {
                    // if first token is including, we deselect all targets
                    array.iter_mut().for_each(|x| *x = false);
                }
                (starts, true)
            }
        };
        let (starts, ends) = if starts.len() > 1
            && let Some(p) = starts[1..].find('-')
        {
            (&starts[..p + 1], Some(&starts[p + 2..]))
        } else {
            (starts, None)
        };
        let Some(start) = parseindex(starts, 1, count) else {
            return false;
        };
        match ends {
            None => array[start as usize - 1] = include,
            Some(e) => {
                let Some(end) = parseindex(e, start, count) else {
                    return false;
                };
                for i in start..=end {
                    array[i as usize - 1] = include;
                }
            }
        }
    }
    true
}

/// multiselect_question: which of `count` entries to use; None on a read error
pub fn multiselect_question(count: usize) -> Option<Vec<bool>> {
    use std::io::Write;
    let c = crate::callback::cbcfg();
    let mut array = vec![true; count];
    loop {
        array.iter_mut().for_each(|x| *x = true);
        let prompt = "\nEnter a selection (default=all): ";
        if c.noconfirm {
            pr!("{prompt}\n");
            crate::util::flush_stdout();
            break;
        }
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        flush_term_input(0);
        let response = safe_fgets_stdin(64)?;
        let r = crate::util_common::strtrim(&response);
        if !r.is_empty() && !multiselect_parse(&mut array, count as i32, r) {
            // only loop if user gave an invalid answer
            continue;
        }
        break;
    }
    Some(array)
}

/// select_question: index of the chosen entry
pub fn select_question(count: usize) -> i32 {
    use std::io::Write;
    let c = crate::callback::cbcfg();
    let preset = 1;
    loop {
        let prompt = format!("\nEnter a number (default={preset}): ");
        if c.noconfirm {
            pr!("{prompt}\n");
            crate::util::flush_stdout();
            break;
        }
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        flush_term_input(0);
        if let Some(response) = safe_fgets_stdin(32) {
            let r = crate::util_common::strtrim(&response);
            if !r.is_empty() {
                match parseindex(r, 1, count as i32) {
                    Some(n) => return n - 1,
                    None => continue,
                }
            }
        }
        break;
    }
    preset - 1
}

// ---------------------------------------------------------------- transaction summary (tables)

/// table cell modes
const CELL_TITLE: u8 = 1;
const CELL_RIGHT_ALIGN: u8 = 2;

struct Cell {
    label: Option<String>,
    len: usize,
    mode: u8,
}

fn cell(label: Option<String>, mode: u8) -> Cell {
    let len = label.as_deref().map_or(0, string_length);
    Cell { label, len, mode }
}

/// table_print_line
fn table_print_line(cfg: &Config, line: &[Cell], col_padding: usize, colcount: usize, widths: &[usize], has_data: &[bool]) {
    let mut need_padding = false;
    for (i, c) in line.iter().enumerate().take(colcount) {
        let s = c.label.as_deref().unwrap_or("");
        if !has_data[i] {
            continue;
        }
        // calculate cell width, adjusting for multi-byte character strings
        let w = widths[i] as isize - string_length(s) as isize + s.len() as isize;
        let w = w.max(0) as usize;
        if need_padding {
            pr!("{:col_padding$}", "");
        }
        let body = if c.mode & CELL_RIGHT_ALIGN != 0 {
            format!("{s:>w$}")
        } else {
            format!("{s:<w$}")
        };
        if c.mode & CELL_TITLE != 0 {
            pr!("{}{}{}", cfg.colstr.title, body, cfg.colstr.nocolor);
        } else {
            pr!("{body}");
        }
        need_padding = true;
    }
    pr!("\n");
}

/// table_display: -1 when the table does not fit the terminal
fn table_display(cfg: &Config, header: Option<&[Cell]>, rows: &[Vec<Cell>], cols: u16) -> i32 {
    const PADDING: usize = 2;
    if rows.is_empty() {
        return 0;
    }
    // we want the first row. if no headers are provided, use the first entry of the rows array.
    let first = header.unwrap_or(&rows[0]);
    let totalcols = first.len();
    if totalcols == 0 {
        return -1;
    }
    // table_calc_widths
    let mut widths: Vec<usize> = first.iter().map(|c| c.len).collect();
    widths.resize(totalcols, 0);
    let mut has_data = vec![false; totalcols];
    for r in rows {
        for (i, c) in r.iter().enumerate().take(totalcols) {
            widths[i] = widths[i].max(c.len);
            if c.len > 0 {
                has_data[i] = true;
            }
        }
    }
    let mut totalwidth = 0;
    let mut usefulcols = 0;
    for i in 0..first.len() {
        if has_data[i] {
            usefulcols += 1;
            totalwidth += widths[i];
        }
    }
    if usefulcols > 0 {
        totalwidth += PADDING * (usefulcols - 1);
    }
    // return -1 if terminal is not wide enough
    if cols != 0 && totalwidth > cols as usize {
        pm_printf!(
            crate::util::LOG_WARNING,
            "insufficient columns available for table display\n"
        );
        return -1;
    }
    if totalwidth == 0 {
        return -1;
    }
    if let Some(h) = header {
        table_print_line(cfg, h, PADDING, totalcols, &widths, &has_data);
        pr!("\n");
    }
    for r in rows {
        table_print_line(cfg, r, PADDING, totalcols, &widths, &has_data);
    }
    0
}

/// add_transaction_sizes_row
fn add_transaction_sizes_row(rows: &mut Vec<Vec<Cell>>, label: &str, size: i64) {
    let (s, units) = humanize_size(size, 'M', 2);
    rows.push(vec![
        cell(Some(label.to_string()), CELL_TITLE),
        cell(Some(format!("{s:.2} {units}")), CELL_RIGHT_ALIGN),
    ]);
}

/// pm_target_t
struct Target<'a> {
    install: Option<&'a Pkg>,
    remove: Option<&'a Pkg>,
    is_explicit: bool,
}

/// create_verbose_row
fn create_verbose_row(alpm: &libalpm_rs::alpm::Alpm, t: &Target) -> Vec<Cell> {
    let mut row = Vec::new();
    // a row consists of the package name,
    let name = match t.install {
        Some(i) => match alpm.pkg_db(i) {
            Some(db) => format!("{}/{}", db.name(), i.name),
            None => i.name.clone(),
        },
        None => t.remove.map(|r| r.name.clone()).unwrap_or_default(),
    };
    row.push(cell(Some(name), 0));
    // old and new versions
    row.push(cell(Some(t.remove.map_or(String::new(), |r| r.version.clone())), 0));
    row.push(cell(Some(t.install.map_or(String::new(), |r| r.version.clone())), 0));
    // and size
    let mut size = 0i64;
    size -= t.remove.map_or(0, |r| r.desc().isize);
    size += t.install.map_or(0, |r| r.desc().isize);
    let (h, label) = humanize_size(size, 'M', 2);
    row.push(cell(Some(format!("{h:.2} {label}")), CELL_RIGHT_ALIGN));
    let size = t.install.map_or(0, libalpm_rs::sync::pkg_download_size);
    let s = if size != 0 {
        let (h, label) = humanize_size(size, 'M', 2);
        Some(format!("{h:.2} {label}"))
    } else {
        None
    };
    row.push(cell(s, CELL_RIGHT_ALIGN));
    row
}

/// _display_targets
fn _display_targets(cfg: &Config, targets: &[Target], verbose: bool) {
    if targets.is_empty() {
        return;
    }
    let alpm = cfg.alpm.as_ref().unwrap();
    let (mut isize_, mut rsize, mut dlsize) = (0i64, 0i64, 0i64);
    // gather package info
    for t in targets {
        if let Some(i) = t.install {
            dlsize += libalpm_rs::sync::pkg_download_size(i);
            isize_ += i.desc().isize;
        }
        if let Some(r) = t.remove {
            // add up size of all removed packages
            rsize += r.desc().isize;
        }
    }
    // form data for both verbose and non-verbose display
    let mut rows: Vec<Vec<Cell>> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let c = &cfg.colstr;
    for t in targets {
        if verbose {
            rows.push(create_verbose_row(alpm, t));
        }
        names.push(if let Some(i) = t.install {
            format!("{}{}-{}{}", i.name, c.faint, i.version, c.nocolor)
        } else {
            let r = t.remove.unwrap();
            if isize_ == 0 {
                format!("{}{}-{}{}", r.name, c.faint, r.version, c.nocolor)
            } else {
                format!(
                    "{}{}-{} {}[{}]{}",
                    r.name, c.faint, r.version, c.nocolor, "removal", c.nocolor
                )
            }
        });
    }
    // print to screen
    let title = format!("Packages ({})", targets.len());
    pr!("\n");
    let cols = getcols();
    if verbose {
        let header = vec![
            cell(Some(format!("Package ({})", targets.len())), CELL_TITLE),
            cell(Some("Old Version".into()), CELL_TITLE),
            cell(Some("New Version".into()), CELL_TITLE),
            cell(Some("Net Change".into()), CELL_TITLE),
            cell(Some("Download Size".into()), CELL_TITLE),
        ];
        if table_display(cfg, Some(&header), &rows, cols) != 0 {
            // fallback to list display if table wouldn't fit
            list_display(cfg, Some(&title), &names, cols);
        }
    } else {
        list_display(cfg, Some(&title), &names, cols);
    }
    pr!("\n");

    let mut rows: Vec<Vec<Cell>> = Vec::new();
    if dlsize > 0 || cfg.op_s_downloadonly {
        add_transaction_sizes_row(&mut rows, "Total Download Size:", dlsize);
    }
    if !cfg.op_s_downloadonly {
        if isize_ > 0 {
            add_transaction_sizes_row(&mut rows, "Total Installed Size:", isize_);
        }
        if rsize > 0 && isize_ == 0 {
            add_transaction_sizes_row(&mut rows, "Total Removed Size:", rsize);
        }
        // only show this net value if different from raw installed size
        if isize_ > 0 && rsize > 0 {
            add_transaction_sizes_row(&mut rows, "Net Upgrade Size:", isize_ - rsize);
        }
    }
    table_display(cfg, None, &rows, cols);
}

/// display_targets
pub fn display_targets(cfg: &Config, trans: &libalpm_rs::trans::Trans, explicit_adds: &[&Pkg]) {
    let alpm = cfg.alpm.as_ref().unwrap();
    let mut targets: Vec<Target> = Vec::new();
    for &pkg in &trans.add {
        targets.push(Target {
            install: Some(pkg),
            // alpm_db_get_pkg (sets pm_errno like upstream)
            remove: alpm.localdb.get_pkg(&pkg.name).ok(),
            is_explicit: explicit_adds.iter().any(|p| p.name == pkg.name),
        });
    }
    for &pkg in &trans.remove {
        targets.push(Target {
            install: None,
            remove: Some(pkg),
            // explicit_removes is only filled by -R
            is_explicit: false,
        });
    }
    // explicit are always sorted after implicit (e.g. deps, pulled targets)
    targets.sort_by(|a, b| {
        a.is_explicit.cmp(&b.is_explicit).then_with(|| {
            let n = |t: &Target| t.install.or(t.remove).map(|p| p.name.clone()).unwrap_or_default();
            n(a).as_bytes().cmp(n(b).as_bytes())
        })
    });
    _display_targets(cfg, &targets, cfg.verbosepkglists);
}

/// pkg_get_size
fn pkg_get_size(cfg: &Config, pkg: &Pkg) -> i64 {
    match cfg.op {
        PM_OP_SYNC => libalpm_rs::sync::pkg_download_size(pkg),
        PM_OP_UPGRADE => pkg.size,
        _ => pkg.desc().isize,
    }
}

/// pkg_get_location
fn pkg_get_location(cfg: &Config, pkg: &Pkg) -> String {
    let alpm = cfg.alpm.as_ref().unwrap();
    match pkg.origin {
        libalpm_rs::package::PkgFrom::SyncDb => {
            let fname = pkg.filename.clone().unwrap_or_default();
            if libalpm_rs::sync::pkg_download_size(pkg) == 0 {
                // file is already in the package cache
                for d in alpm.handle.cachedirs() {
                    let path = format!("{d}{fname}");
                    if std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
                        return format!("file://{path}");
                    }
                }
            }
            if let Some(db) = alpm.pkg_db(pkg)
                && let Some(s) = db.servers.borrow().first()
            {
                return format!("{s}/{fname}");
            }
            // fallthrough - for theoretical serverless repos
            fname
        }
        libalpm_rs::package::PkgFrom::File => pkg.filename.clone().unwrap_or_default(),
        _ => format!("{}-{}", pkg.name, pkg.version),
    }
}

/// print_packages: the --print output
pub fn print_packages(cfg: &Config, packages: &[&Pkg]) {
    use libalpm_rs::deps::dep_compute_string;
    let fmt = cfg.print_format.clone().unwrap_or_else(|| "%l".to_string());
    let alpm = cfg.alpm.as_ref().unwrap();
    for &pkg in packages {
        let d = pkg.desc();
        let mut s = fmt.clone();
        // PRINT_FORMAT_STRING: replace each occurrence with the value (empty when missing)
        let rep = |s: &mut String, f: &str, v: &str| {
            if s.contains(f) {
                *s = s.replace(f, v);
            }
        };
        // %a : arch
        rep(&mut s, "%a", d.arch.as_deref().unwrap_or(""));
        // %b : build date
        if s.contains("%b") && d.builddate != -1 {
            let b = crate::ffi::strftime_c(d.builddate);
            s = s.replace("%b", &b);
        }
        rep(&mut s, "%d", d.desc.as_deref().unwrap_or(""));
        rep(&mut s, "%e", d.base.as_deref().unwrap_or(""));
        rep(&mut s, "%f", pkg.filename.as_deref().unwrap_or(""));
        rep(&mut s, "%g", pkg.base64_sig.as_deref().unwrap_or(""));
        rep(&mut s, "%h", pkg.sha256sum.as_deref().unwrap_or(""));
        rep(&mut s, "%n", &pkg.name);
        rep(&mut s, "%p", d.packager.as_deref().unwrap_or(""));
        rep(&mut s, "%v", &pkg.version);
        rep(&mut s, "%m", pkg.md5sum.as_deref().unwrap_or(""));
        // %l : location
        if s.contains("%l") {
            let loc = pkg_get_location(cfg, pkg);
            s = s.replace("%l", &loc);
        }
        // %r : repo
        if s.contains("%r") {
            let repo = alpm.pkg_db(pkg).map_or("local", |db| db.name());
            s = s.replace("%r", repo);
        }
        // %s : size
        if s.contains("%s") {
            let size = pkg_get_size(cfg, pkg).to_string();
            s = s.replace("%s", &size);
        }
        rep(&mut s, "%u", d.url.as_deref().unwrap_or(""));
        let deps = |l: &[libalpm_rs::deps::Dep]| {
            l.iter().map(dep_compute_string).collect::<Vec<_>>().join(" ")
        };
        rep(&mut s, "%C", &deps(&d.checkdepends));
        rep(&mut s, "%D", &deps(&d.depends));
        rep(&mut s, "%G", &d.groups.join(" "));
        rep(&mut s, "%H", &deps(&d.conflicts));
        rep(&mut s, "%M", &deps(&d.makedepends));
        rep(&mut s, "%O", &deps(&d.optdepends));
        rep(&mut s, "%P", &deps(&d.provides));
        rep(&mut s, "%R", &deps(&d.replaces));
        rep(&mut s, "%L", &d.licenses.join(" "));
        pr!("{s}\n");
    }
}
