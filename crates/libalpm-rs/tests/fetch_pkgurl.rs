//! alpm_fetch_pkgurl against a throw-away local HTTP server (127.0.0.1 only): a .pkg URL lands in the cache under
//! its own name, a second call is served from the cache, and a URL without a package name goes to an
//! `alpmtmp.*` temporary file. No network, no root.
use libalpm_rs::dload::fetch_pkgurl;
use libalpm_rs::handle::Handle;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn serve(hits: Arc<AtomicUsize>, stop: Arc<AtomicBool>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.set_nonblocking(true).unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            if let Ok((mut s, _)) = l.accept() {
                s.set_nonblocking(false).unwrap();
                let mut b = [0u8; 2048];
                let n = s.read(&mut b).unwrap_or(0);
                let req = String::from_utf8_lossy(&b[..n]).into_owned();
                hits.fetch_add(1, Ordering::SeqCst);
                let body = if req.contains("/missing") {
                    None
                } else {
                    Some("package-bytes")
                };
                let resp = match body {
                    Some(b) => format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                        b.len()
                    ),
                    None => {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .into()
                    }
                };
                let _ = s.write_all(resp.as_bytes());
            } else {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    });
    port
}

#[test]
fn fetch_pkgurl_downloads_and_caches() {
    let base = std::env::temp_dir().join(format!("pacman-rs-fetch-{}", std::process::id()));
    let cache = base.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    let (hits, stop) = (
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    let port = serve(hits.clone(), stop.clone());
    let h = Handle::new(base.to_str().unwrap());
    assert_eq!(h.set_cachedirs(&[cache.to_string_lossy().into_owned()]), 0);

    let url = format!("http://127.0.0.1:{port}/x/foo-1-1-any.pkg.tar.zst");
    let got = fetch_pkgurl(&h, std::slice::from_ref(&url)).unwrap();
    assert_eq!(got.len(), 1);
    assert!(
        got[0].ends_with("/cache/foo-1-1-any.pkg.tar.zst"),
        "{got:?}"
    );
    assert_eq!(std::fs::read_to_string(&got[0]).unwrap(), "package-bytes");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    // the second call is satisfied from the cache without a request
    let again = fetch_pkgurl(&h, std::slice::from_ref(&url)).unwrap();
    assert_eq!(again, got);
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    // no package name in the URL: temporary file in the cache
    let u2 = format!("http://127.0.0.1:{port}/dl?id=7");
    let got = fetch_pkgurl(&h, &[u2]).unwrap();
    assert!(got[0].contains("/cache/alpmtmp."), "{got:?}");
    assert_eq!(std::fs::read_to_string(&got[0]).unwrap(), "package-bytes");

    // a missing file fails with the retrieve error
    let u3 = format!("http://127.0.0.1:{port}/missing/bar-1-1-any.pkg.tar.zst");
    let e = fetch_pkgurl(&h, &[u3]).unwrap_err();
    assert_eq!(e, libalpm_rs::error::Error::Retrieve);
    assert!(!cache.join("bar-1-1-any.pkg.tar.zst").exists());
    stop.store(true, Ordering::Relaxed);
    let _ = std::fs::remove_dir_all(&base);
}
