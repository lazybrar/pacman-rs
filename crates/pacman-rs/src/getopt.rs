//! GNU getopt_long (with argument permutation), message texts as in glibc.

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Arg {
    No,
    Required,
    /// only `--name=value`
    Optional,
}

pub struct LongOpt {
    pub name: &'static str,
    pub has_arg: Arg,
    pub val: char,
}

pub struct Getopt<'a> {
    args: Vec<String>,
    prog: String,
    short: &'a str,
    long: &'a [LongOpt],
    i: usize,
    /// remaining chars of a bundled short-option argument
    cluster: Option<(String, usize)>,
    done: bool,
    posix: bool,
    pub operands: Vec<String>,
}

impl<'a> Getopt<'a> {
    /// `args[0]` is the program name (used in messages).
    pub fn new(args: Vec<String>, short: &'a str, long: &'a [LongOpt]) -> Self {
        Getopt {
            prog: args.first().cloned().unwrap_or_default(),
            args,
            short,
            long,
            i: 1,
            cluster: None,
            done: false,
            posix: std::env::var_os("POSIXLY_CORRECT").is_some(),
            operands: Vec::new(),
        }
    }

    fn err(&self, msg: String) {
        eprintln!("{}: {}", self.prog, msg);
    }

    /// short option spec: Some(takes_arg) if known
    fn short_spec(&self, c: char) -> Option<bool> {
        if c == ':' {
            return None;
        }
        let p = self.short.find(c)?;
        Some(self.short[p + c.len_utf8()..].starts_with(':'))
    }

    fn next_opt(&mut self) -> Option<(char, Option<String>)> {
        if let Some((cl, pos)) = self.cluster.take() {
            return Some(self.short_in(cl, pos));
        }
        loop {
            if self.done || self.i >= self.args.len() {
                return None;
            }
            let a = self.args[self.i].clone();
            self.i += 1;
            if a == "--" {
                self.done = true;
                self.operands.extend(self.args[self.i..].iter().cloned());
                return None;
            }
            if !a.starts_with('-') || a == "-" {
                self.operands.push(a);
                if self.posix {
                    self.done = true;
                    self.operands.extend(self.args[self.i..].iter().cloned());
                    return None;
                }
                continue;
            }
            if let Some(body) = a.strip_prefix("--") {
                return Some(self.long_opt(body));
            }
            return Some(self.short_in(a, 1));
        }
    }

    fn short_in(&mut self, cl: String, pos: usize) -> (char, Option<String>) {
        let c = cl[pos..].chars().next().unwrap();
        let next = pos + c.len_utf8();
        match self.short_spec(c) {
            None => {
                self.err(format!("invalid option -- '{c}'"));
                if next < cl.len() {
                    self.cluster = Some((cl, next));
                }
                ('?', None)
            }
            Some(false) => {
                if next < cl.len() {
                    self.cluster = Some((cl, next));
                }
                (c, None)
            }
            Some(true) => {
                if next < cl.len() {
                    (c, Some(cl[next..].to_string()))
                } else if self.i < self.args.len() {
                    self.i += 1;
                    (c, Some(self.args[self.i - 1].clone()))
                } else {
                    self.err(format!("option requires an argument -- '{c}'"));
                    ('?', None)
                }
            }
        }
    }

    fn long_opt(&mut self, body: &str) -> (char, Option<String>) {
        let (name, inline) = match body.find('=') {
            Some(p) => (&body[..p], Some(body[p + 1..].to_string())),
            None => (body, None),
        };
        let cands: Vec<&LongOpt> = match self.long.iter().find(|o| o.name == name) {
            Some(o) => vec![o],
            None => self
                .long
                .iter()
                .filter(|o| o.name.starts_with(name))
                .collect(),
        };
        if cands.is_empty() {
            self.err(format!("unrecognized option '--{body}'"));
            return ('?', None);
        }
        if cands.len() > 1
            && cands
                .iter()
                .any(|o| o.val != cands[0].val || o.has_arg != cands[0].has_arg)
        {
            let mut m = format!("option '--{name}' is ambiguous; possibilities:");
            for o in &cands {
                m += &format!(" '--{}'", o.name);
            }
            self.err(m);
            return ('?', None);
        }
        let o = cands[0];
        match (o.has_arg, inline) {
            (Arg::Required | Arg::Optional, Some(v)) => (o.val, Some(v)),
            (Arg::Optional, None) => (o.val, None),
            (Arg::Required, None) => {
                if self.i < self.args.len() {
                    self.i += 1;
                    (o.val, Some(self.args[self.i - 1].clone()))
                } else {
                    self.err(format!("option '--{}' requires an argument", o.name));
                    ('?', None)
                }
            }
            (Arg::No, Some(_)) => {
                self.err(format!("option '--{}' doesn't allow an argument", o.name));
                ('?', None)
            }
            (Arg::No, None) => (o.val, None),
        }
    }
}

/// Yields (option char, optarg), '?' on error; `operands` is complete once it returns None.
impl Iterator for Getopt<'_> {
    type Item = (char, Option<String>);
    fn next(&mut self) -> Option<Self::Item> {
        self.next_opt()
    }
}
