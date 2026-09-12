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
/// Ответил ли сервер вообще.
///
/// Здесь меряется ровно одно: пережил ли TLS ClientHello дорогу до сервера.
/// Блокировка выглядит как отсутствие ответа — curl возвращает «000», а не
/// какой-нибудь код. Поэтому ЛЮБОЙ разобранный HTTP-код значит «связь есть»:
/// он не мог приехать иначе как по уже установленному TLS.
///
/// Это не теория. Вот что наши цели отвечают на HEAD по корню при рабочем
/// обходе: gateway.discord.gg — 404, cdn.discordapp.com — 403,
/// updates.discord.com — 404, redirector.googlevideo.com — 404,
/// api.steampowered.com и auth.riotgames.com — 404. Это штатные ответы, а не
/// блокировка: ни один из этих хостов не обязан отдавать 200 на «/».
///
/// В 1.2.0 здесь стояло `(200..400)`, и четыре цели из семи горели «нет
/// связи» при полностью рабочем обходе. Не сужать этот диапазон.
///
/// Исключение одно — 451 Unavailable For Legal Reasons: единственный код,
/// которым блокировку объявляют прямо.
///
/// Чего проба по-прежнему НЕ видит: подмену на страницу провайдера с кодом
/// 200. Для этого нужен разбор тела или сертификата, а не код ответа.
pub fn code_is_answer(code: u16) -> bool {
    code >= 100 && code != 451
}

/// Код ответа от curl. `None` — ответа не было вообще (curl пишет «000»):
/// именно так выглядит обрыв на TLS ClientHello, то есть сама блокировка.
fn curl_code(url: &str, timeout_sec: u64) -> Option<u16> {
    #[allow(unused_mut)]
    let mut cmd = Command::new(crate::sys::system_exe("curl.exe"));
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

    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim().parse::<u16>().ok().filter(|c| *c > 0)
}

pub fn http_probe(url: &str, timeout_sec: u64) -> ProbeResult {
    let started = Instant::now();
    let code = curl_code(url, timeout_sec);
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

    /// Настоящие ответы наших целей на HEAD по «/» при РАБОЧЕМ обходе,
    /// снятые curl-ом 12.09.2026. Ни один из этих хостов не обязан отдавать
    /// 200 на корень, и все эти коды приехали по установленному TLS.
    const ЖИВЫЕ_ЦЕЛИ: &[(&str, u16)] = &[
        ("discord.com", 200),
        ("gateway.discord.gg", 404),
        ("cdn.discordapp.com", 403),
        ("updates.discord.com", 404),
        ("www.youtube.com", 200),
        ("redirector.googlevideo.com", 404),
        ("youtu.be", 303),
        ("api.steampowered.com", 404),
        ("auth.riotgames.com", 404),
        ("api.epicgames.dev", 404),
    ];

    #[test]
    fn все_стандартные_цели_при_рабочем_обходе_считаются_живыми() {
        // В 1.2.0 здесь стояло (200..400) — и четыре цели из семи показывали
        // «нет связи», хотя обход работал. Этот тест не даст сузить диапазон
        // снова: он перечисляет коды, которые эти хосты отдают на самом деле.
        for (host, code) in ЖИВЫЕ_ЦЕЛИ {
            assert!(
                code_is_answer(*code),
                "{host} отвечает {code} при рабочем обходе — это связь, а не блокировка"
            );
        }
    }

    #[test]
    fn блокировка_это_отсутствие_ответа_а_не_код_ошибки() {
        // Сервер ответил — значит TLS прошёл, каким бы ни был код.
        for c in [400, 403, 404, 429, 500, 502, 503] {
            assert!(code_is_answer(c), "{c} — ответ сервера, TLS до него доехал");
        }
        // А вот 451 объявляет блокировку прямым текстом.
        assert!(!code_is_answer(451));
        // Ноль curl пишет, когда ответа не было вовсе; до code_is_answer он
        // не доходит (curl_code отсеивает), но правило должно быть верным.
        assert!(!code_is_answer(0));
    }
}
