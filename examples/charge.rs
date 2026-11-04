//! Banc de charge du gestionnaire : N connexions HTTP/1.1 simultanées (gardées ouvertes) qui
//! enchaînent des requêtes pendant une durée donnée ; rend le débit et les latences.
//!
//! cargo run --release -p rc-manager --example charge -- --addr 127.0.0.1:8581 \
//!     --mode me --cookie "rcm_session=..." --conns 50 --secs 10
//! Modes : `health` (GET /api/health), `me` (GET /api/auth/me, session exigée), `index`
//! (GET / compressé), `login` (POST /api/auth/login, `--user` et `--pass` : Argon2 sous charge ;
//! prévoir `RCM_LOGIN_MAX_FAILURES` large si le mot de passe est faux exprès).

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Opts {
    addr: String,
    mode: String,
    cookie: String,
    user: String,
    pass: String,
    conns: usize,
    secs: u64,
}

fn opts() -> Opts {
    let mut o = Opts {
        addr: "127.0.0.1:8580".into(),
        mode: "health".into(),
        cookie: String::new(),
        user: String::new(),
        pass: String::new(),
        conns: 50,
        secs: 10,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        let v = it.next().unwrap_or_default();
        match a.as_str() {
            "--addr" => o.addr = v,
            "--mode" => o.mode = v,
            "--cookie" => o.cookie = v,
            "--user" => o.user = v,
            "--pass" => o.pass = v,
            "--conns" => o.conns = v.parse().expect("--conns"),
            "--secs" => o.secs = v.parse().expect("--secs"),
            _ => panic!("argument inconnu : {a}"),
        }
    }
    o
}

fn request(o: &Opts) -> Vec<u8> {
    let host = &o.addr;
    match o.mode.as_str() {
        "health" => format!("GET /api/health HTTP/1.1\r\nHost: {host}\r\n\r\n"),
        "index" => format!("GET / HTTP/1.1\r\nHost: {host}\r\nAccept-Encoding: gzip\r\n\r\n"),
        "me" => format!("GET /api/auth/me HTTP/1.1\r\nHost: {host}\r\nCookie: {}\r\n\r\n", o.cookie),
        "login" => {
            let body = format!(r#"{{"username":"{}","password":"{}"}}"#, o.user, o.pass);
            format!(
                "POST /api/auth/login HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
        }
        m => panic!("mode inconnu : {m}"),
    }
    .into_bytes()
}

/// Lit une réponse complète (en-têtes + `Content-Length`), rend le statut.
async fn read_response(s: &mut TcpStream, buf: &mut Vec<u8>) -> Option<u16> {
    buf.clear();
    let mut tmp = [0u8; 16384];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let status: u16 = head.split(' ').nth(1)?.parse().ok()?;
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            while buf.len() < end + 4 + len {
                let n = s.read(&mut tmp).await.ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            return Some(status);
        }
        let n = s.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

#[tokio::main]
async fn main() {
    let o = opts();
    let req = std::sync::Arc::new(request(&o));
    let deadline = Instant::now() + Duration::from_secs(o.secs);
    let mut tasks = Vec::new();
    for _ in 0..o.conns {
        let req = req.clone();
        let addr = o.addr.clone();
        tasks.push(tokio::spawn(async move {
            let mut lat = Vec::new();
            let mut errors = 0u64;
            let mut s = TcpStream::connect(&addr).await.expect("connexion");
            let mut buf = Vec::new();
            while Instant::now() < deadline {
                let t = Instant::now();
                if s.write_all(&req).await.is_err() {
                    errors += 1;
                    s = TcpStream::connect(&addr).await.expect("reconnexion");
                    continue;
                }
                match read_response(&mut s, &mut buf).await {
                    Some(st) if st < 400 || st == 401 => lat.push(t.elapsed()),
                    Some(_) => {
                        lat.push(t.elapsed());
                        errors += 1;
                    }
                    None => {
                        errors += 1;
                        s = TcpStream::connect(&addr).await.expect("reconnexion");
                    }
                }
            }
            (lat, errors)
        }));
    }
    let mut all = Vec::new();
    let mut errors = 0;
    for t in tasks {
        let (l, e) = t.await.unwrap();
        all.extend(l);
        errors += e;
    }
    all.sort();
    let n = all.len().max(1);
    let pct = |p: f64| all[((n as f64 * p) as usize).min(n - 1)].as_secs_f64() * 1000.0;
    println!(
        "mode {} : {} connexions, {} s, {} requêtes ({:.0}/s), erreurs {}, p50 {:.2} ms, p99 {:.2} ms, max {:.2} ms",
        o.mode,
        o.conns,
        o.secs,
        all.len(),
        all.len() as f64 / o.secs as f64,
        errors,
        pct(0.50),
        pct(0.99),
        pct(1.0)
    );
}
