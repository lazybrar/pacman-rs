use std::process::Command;

const SYS: &str = "/usr/bin/vercmp";

fn run(bin: &str, a: &str, b: &str) -> (String, i32) {
    let o = Command::new(bin).args([a, b]).output().unwrap();
    (
        String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr),
        o.status.code().unwrap(),
    )
}

#[test]
fn differential() {
    if !std::path::Path::new(SYS).exists() {
        eprintln!("skip: {SYS} missing");
        return;
    }
    let ours = env!("CARGO_BIN_EXE_vercmp");
    let mut seed = 0x2545F4914F6CDD1Du64;
    let mut rnd = move |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    let toks = [
        "0",
        "1",
        "2",
        "10",
        "007",
        "99999999999999999999",
        "a",
        "b",
        "alpha",
        "rc",
        "beta",
        "X",
        ".",
        "..",
        "_",
        "+",
        "~",
        "-",
        ":",
        "1:",
        "0:",
        ":",
        "",
        " ",
        "é",
    ];
    let mut cases: Vec<(String, String)> = vec![
        ("".into(), "".into()),
        ("".into(), "1".into()),
        ("1".into(), "".into()),
        ("-".into(), "".into()),
        (":".into(), "0".into()),
        ("1.0~rc1".into(), "1.0".into()),
        ("1.0~rc1".into(), "1.0rc1".into()),
        ("1:1-1".into(), "1:1-1".into()),
        ("a:1".into(), "0:1".into()),
        ("1-2-3".into(), "1-2-4".into()),
    ];
    for _ in 0..3000 {
        let gen_one = |rnd: &mut dyn FnMut(u64) -> u64| {
            (0..1 + rnd(7))
                .map(|_| toks[rnd(toks.len() as u64) as usize])
                .collect::<String>()
        };
        let a = gen_one(&mut rnd);
        let b = if rnd(4) == 0 {
            a.clone() + toks[rnd(toks.len() as u64) as usize]
        } else {
            gen_one(&mut rnd)
        };
        cases.push((a, b));
    }
    for (a, b) in cases {
        assert_eq!(run(ours, &a, &b), run(SYS, &a, &b), "{a:?} {b:?}");
    }
    // usage / arg handling
    for args in [
        vec![],
        vec!["-h"],
        vec!["--help"],
        vec!["x"],
        vec!["a", "b", "c"],
    ] {
        let f = |bin: &str| {
            let o = Command::new(bin).args(&args).output().unwrap();
            (o.stdout, o.stderr, o.status.code())
        };
        assert_eq!(f(ours), f(SYS), "{args:?}");
    }
}
