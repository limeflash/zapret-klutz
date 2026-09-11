use serde::Serialize;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub ok: bool,
    pub ms: u64,
    pub reason: Option<String>,
}

/// Настоящий HTTPS-запрос через curl.
///
/// Важно, почему не TCP-хендшейк: блокировка Discord/YouTube срабатывает на
/// TLS ClientHello (SNI), который уходит уже ПОСЛЕ того, как TCP-хендшейк
/// завершился. Голая TCP-проба поэтому возвращает «ОК» ровно до того места,
/// где соединение и убивают, и показывает зелёный статус при нерабочем
/// сервисе. Полный запрос доходит до TLS и видит реальную картину.
pub fn http_probe(url: &str, timeout_sec: u64) -> ProbeResult {
    let started = Instant::now();
    #[allow(unused_mut)]
    let mut cmd = Command::new("curl.exe");
    cmd.args([
        "-s",
        "-o",
        "NUL",
        "-w",
        "%{http_code}",
        "-m",
        &timeout_sec.to_string(),
        "-I",
        url,
    ]);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    match cmd.output() {
        Ok(out) => {
            let code = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let ok = code.len() == 3 && code.chars().all(|c| c.is_ascii_digit()) && !code.starts_with('0');
            ProbeResult {
                ok,
                ms: started.elapsed().as_millis() as u64,
                reason: if ok { None } else { Some(if code.is_empty() { "no-response".into() } else { code }) },
            }
        }
        Err(e) => ProbeResult {
            ok: false,
            ms: started.elapsed().as_millis() as u64,
            reason: Some(e.to_string()),
        },
    }
}

/// TCP-хендшейк — для игровых серверов, где HTTP отсутствует как таковой.
/// Даёт осмысленную задержку, но НЕ видит блокировку на уровне TLS.
pub fn tcp_probe(host: &str, port: u16, timeout_ms: u64) -> ProbeResult {
    let started = Instant::now();
    let addr_iter = match (host, port).to_socket_addrs() {
        Ok(it) => it,
        Err(e) => {
            return ProbeResult {
                ok: false,
                ms: started.elapsed().as_millis() as u64,
                reason: Some(format!("dns: {e}")),
            }
        }
    };
    // Бюджет один на весь вызов. Раньше таймаут отсчитывался заново для
    // каждого адреса из DNS, и хост с восемью A-записями отваливался не за
    // 4 секунды, а за 32 — «Проверить связь» висла на полминуты.
    let budget = Duration::from_millis(timeout_ms);
    for addr in addr_iter {
        let left = budget.saturating_sub(started.elapsed());
        if left.is_zero() {
            break;
        }
        if TcpStream::connect_timeout(&addr, left).is_ok() {
            return ProbeResult {
                ok: true,
                ms: started.elapsed().as_millis() as u64,
                reason: None,
            };
        }
    }
    ProbeResult {
        ok: false,
        ms: started.elapsed().as_millis() as u64,
        reason: Some("timeout".into()),
    }
}
