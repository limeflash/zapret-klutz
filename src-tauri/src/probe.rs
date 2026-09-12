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
/// Успех — только настоящий ответ сервера: 2xx и 3xx.
///
/// Раньше успехом считались любые три цифры, не начинающиеся с нуля, — то
/// есть 403, 451 и 502 тоже. 451 это буквально «Unavailable For Legal
/// Reasons», штатный ответ блокировщика: красить его зелёным значит писать
/// «работает» ровно там, где не работает.
///
/// 3xx оставляем успехом сознательно: перенаправление отдаёт живой сервер, и
/// TLS до него доехал — а доехал ли TLS, проба и меряет. Часть целей на
/// редиректах и живёт (youtu.be → www.youtube.com), так что «уехал на другой
/// хост» здесь не признак блокировки.
///
/// Чего эта проба по-прежнему НЕ видит: подмену на странице провайдера,
/// отданную с кодом 200. Для этого нужен разбор тела или сертификата, а не
/// код ответа.
pub fn code_is_answer(code: u16) -> bool {
    (200..400).contains(&code)
}

/// HEAD любят не все: часть хостов отвечает на него 405 или 501, отвечая при
/// этом на GET. Это нелюбовь к методу, а не блокировка, — переспрашиваем.
pub fn head_refused(code: u16) -> bool {
    code == 405 || code == 501
}

/// Код ответа от curl. `None` — ответа не было вообще (curl пишет «000»):
/// именно так выглядит обрыв на TLS ClientHello, то есть сама блокировка.
fn curl_code(url: &str, timeout_sec: u64, head: bool) -> Option<u16> {
    #[allow(unused_mut)]
    let mut cmd = Command::new(crate::sys::system_exe("curl.exe"));
    cmd.args(["-s", "-o", "NUL", "-w", "%{http_code}", "-m", &timeout_sec.to_string()]);
    if head {
        cmd.arg("-I");
    } else {
        // GET, но забираем один байт: нам нужен код, а не страница.
        cmd.args(["-r", "0-0"]);
    }
    cmd.arg(url);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim().parse::<u16>().ok().filter(|c| *c > 0)
}

pub fn http_probe(url: &str, timeout_sec: u64) -> ProbeResult {
    let started = Instant::now();
    let mut code = curl_code(url, timeout_sec, true);

    if code.is_some_and(head_refused) {
        // Бюджет времени уже частично потрачен на HEAD — второй запрос не
        // должен удваивать ожидание «Проверить связь».
        let left = timeout_sec.saturating_sub(started.elapsed().as_secs()).max(1);
        code = curl_code(url, left, false);
    }

    let ms = started.elapsed().as_millis() as u64;
    match code {
        Some(c) if code_is_answer(c) => ProbeResult { ok: true, ms, reason: None },
        Some(c) => ProbeResult { ok: false, ms, reason: Some(c.to_string()) },
        None => ProbeResult { ok: false, ms, reason: Some("no-response".into()) },
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

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn ответом_считается_только_2xx_и_3xx() {
        for c in [200, 204, 206, 301, 302, 304, 399] {
            assert!(code_is_answer(c), "{c} должен считаться ответом");
        }
        for c in [400, 403, 404, 429, 500, 502, 503] {
            assert!(!code_is_answer(c), "{c} не должен считаться ответом");
        }
    }

    #[test]
    fn код_блокировщика_451_больше_не_зелёный() {
        // Старое условие «три цифры, не с нуля» пропускало его как успех.
        let старое = |code: &str| code.len() == 3 && code.chars().all(|c| c.is_ascii_digit()) && !code.starts_with('0');
        assert!(старое("451"), "старое условие 451 пропускало — тест о том и есть");
        assert!(!code_is_answer(451));
    }

    #[test]
    fn отказ_от_head_это_не_блокировка() {
        assert!(head_refused(405));
        assert!(head_refused(501));
        assert!(!head_refused(403));
        assert!(!head_refused(200));
    }
}
