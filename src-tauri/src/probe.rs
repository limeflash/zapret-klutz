use serde::Serialize;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Имя для контрольного замера. `example.com` зарезервирован IANA под
/// примеры, в блок-листы не попадает и у провайдеров не режется — именно
/// это здесь и нужно.
pub const NEUTRAL_SNI: &str = "example.com";

/// Почему проба не прошла. Раньше на этом месте была строка, куда падало то
/// число из curl, то текст ошибки, то «no-response»: показать можно, а
/// ветвиться нельзя. Код стабильный и разложен по стадиям — по нему
/// принимает решение самолечение.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Ok,
    /// Имя не разрешается.
    Dns,
    /// До порта не достучались: отказано или нет маршрута.
    TcpRefused,
    /// Молчание на любой стадии — самый частый почерк блокировки.
    Timeout,
    /// TCP поднялся, а рукопожатие TLS не состоялось: сброс или обрыв сразу
    /// после ClientHello. Классическая подпись DPI по имени.
    TlsFailed,
    /// Сертификат не прошёл проверку — но он БЫЛ. Значит байты дошли до
    /// сервера и вернулись, путь живой.
    TlsCert,
    /// Соединение установилось и тут же закрылось без единого байта ответа.
    EmptyReply,
    /// HTTP 451 — «недоступно по юридическим причинам». Типизированный
    /// блок: путь для клиента непригоден, но и стратегия его не чинит.
    HttpBlocked,
    Unknown,
}

impl FailureCode {
    /// Сервер жив и ответил сам. Отличать это от блокировки критично: на
    /// собственную политику сервера (403 на HEAD, ошибка сертификата,
    /// требование клиентского сертификата) никакая стратегия обхода не
    /// влияет, и перебирать их бессмысленно.
    /// Отдельного кода «сервер ответил HTTP» здесь нет намеренно: удавшийся
    /// HTTP-обмен — это успех, а не «провал, но сервер жив». Остаётся один
    /// случай: рукопожатие не состоялось, а сертификат мы всё-таки получили.
    pub fn server_reachable(self) -> bool {
        matches!(self, FailureCode::TlsCert)
    }

    /// Дошли ли мы вообще до стадии TLS. Если нет — режут адрес или порт,
    /// и про имя говорить рано.
    fn reached_tls(self) -> bool {
        !matches!(self, FailureCode::Dns | FailureCode::TcpRefused)
    }

    /// Нужен ли контрольный замер. Лишнее рукопожатие платим только там,
    /// где оно что-то решает: имя ушло на провод, а ответа не было.
    pub fn needs_control(self) -> bool {
        self != FailureCode::Ok && self.reached_tls() && !self.server_reachable()
    }

    /// Короткое имя для интерфейса и логов.
    pub fn as_str(self) -> &'static str {
        match self {
            FailureCode::Ok => "ok",
            FailureCode::Dns => "dns",
            FailureCode::TcpRefused => "tcp_refused",
            FailureCode::Timeout => "timeout",
            FailureCode::TlsFailed => "tls_failed",
            FailureCode::TlsCert => "tls_cert",
            FailureCode::EmptyReply => "empty_reply",
            FailureCode::HttpBlocked => "http_451",
            FailureCode::Unknown => "unknown",
        }
    }
}

/// Где блокируют: по имени или по адресу.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathVerdict {
    /// Проба прошла, классифицировать нечего.
    Ok,
    /// Не измерено. Отдельно от всего остального: «не удалось проверить» —
    /// это НЕ «всё хорошо» и НЕ «заблокировано».
    Unknown,
    /// Типизированный блок: сервер (или коробка от его имени) ответил 451.
    /// Смена стратегии такое не лечит.
    Legal,
    /// Путь до сервера живой, режут по имени. Наш случай: десинхронизация
    /// работает именно с этим, перебор стратегий осмыслен.
    Sni,
    /// До адреса не доходит ничего, либо доходит, но сервер молчит на любое
    /// имя. Пакетными техниками это не обходится в принципе — нужен туннель
    /// или другой адрес.
    Ip,
    /// Ответил сам сервер. Его политика, а не цензура.
    Server,
}

/// Решает, где блокируют, по результату основной пробы и контрольной.
///
/// Приём описан в мануале zapret («Проверка блока по IP») и одинаково
/// реализован в z2k (MIT, `z2k-detect/internal/prober`): к ТОМУ ЖЕ адресу
/// стучимся с заведомо не заблокированным именем. Отвечает — путь живой,
/// значит режут имя. Молчит и на нейтральное — режут адрес.
///
/// Контроль обязан быть ДРУГИМ именем на ТОМ ЖЕ адресе. Взяли бы то же
/// самое — молчали бы оба, и «блок по адресу» получился бы из собственной
/// ошибки ввода.
///
/// Чистая функция: сеть дёргает вызывающий и передаёт сюда результат.
pub fn classify_path(
    ok: bool,
    code: FailureCode,
    control: Option<(bool, FailureCode)>,
) -> (PathVerdict, String) {
    if ok && !code.server_reachable() {
        return (PathVerdict::Ok, String::new());
    }
    if code.server_reachable() {
        return (
            PathVerdict::Server,
            "ответил сам сервер — это его политика, а не блокировка".into(),
        );
    }
    if code == FailureCode::HttpBlocked {
        return (
            PathVerdict::Legal,
            "ответ 451 «недоступно по юридическим причинам» — это не DPI, \
             и стратегия обхода такое не чинит"
                .into(),
        );
    }
    if code == FailureCode::Dns {
        return (
            PathVerdict::Ip,
            "имя не разрешается — проблема в DNS, а не в обходе".into(),
        );
    }
    if !code.reached_tls() {
        return (
            PathVerdict::Ip,
            "до порта не достучались — режут адрес или порт, не имя".into(),
        );
    }
    // Контроля нет — значит НЕ ИЗМЕРЕНО. Раньше отсутствие замера кодировалось
    // как «контроль молчал» и превращалось в вердикт «режут адрес»: программа
    // уверенно заявляла то, чего не проверяла.
    let Some((control_ok, control_code)) = control else {
        return (
            PathVerdict::Unknown,
            "контрольный замер не выполнялся — где именно режут, неизвестно".into(),
        );
    };
    if control_ok || control_code.server_reachable() {
        (
            PathVerdict::Sni,
            format!("с нейтральным именем {NEUTRAL_SNI} тот же адрес отвечает — режут по имени"),
        )
    } else {
        (
            PathVerdict::Ip,
            format!("с нейтральным именем {NEUTRAL_SNI} тот же адрес тоже молчит — режут адрес, не имя"),
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub ok: bool,
    pub ms: u64,
    pub reason: Option<String>,
    pub code: FailureCode,
}

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

/// Коды выхода curl — стабильная и документированная таблица, так что
/// раскладывать их по стадиям надёжнее, чем разбирать текст ошибки.
fn code_from_curl(exit: i32, status: Option<u16>) -> (bool, FailureCode) {
    match exit {
        0 => match status {
            // 451 — «недоступно по юридическим причинам». Единственный
            // HTTP-код, который сам по себе означает блокировку.
            Some(451) => (false, FailureCode::HttpBlocked),
            // Любой другой разобранный код доказывает, что сервер жив:
            // правило одно на весь модуль, и оно измерено на живых целях.
            Some(s) if code_is_answer(s) => (true, FailureCode::Ok),
            _ => (false, FailureCode::Unknown),
        },
        6 => (false, FailureCode::Dns),
        7 => (false, FailureCode::TcpRefused),
        28 => (false, FailureCode::Timeout),
        // 35 — обрыв при установке TLS, 56 — сброс при приёме данных.
        35 | 56 => (false, FailureCode::TlsFailed),
        52 => (false, FailureCode::EmptyReply),
        // 51/60 — сертификат не прошёл проверку. Сервер при этом ОТВЕТИЛ.
        51 | 60 => (false, FailureCode::TlsCert),
        _ => (false, FailureCode::Unknown),
    }
}

fn reason_text(code: FailureCode) -> Option<String> {
    match code {
        FailureCode::Ok => None,
        other => Some(other.as_str().to_string()),
    }
}

/// Настоящий HTTPS-запрос через curl.
///
/// Важно, почему не TCP-хендшейк: блокировка Discord/YouTube срабатывает на
/// TLS ClientHello (SNI), который уходит уже ПОСЛЕ того, как TCP-хендшейк
/// завершился. Голая TCP-проба поэтому возвращает «ОК» ровно до того места,
/// где соединение и убивают, и показывает зелёный статус при нерабочем
/// сервисе. Полный запрос доходит до TLS и видит реальную картину.
///
/// `pin_ip` прибивает запрос к конкретному адресу (`--resolve`). Это нужно
/// контрольному замеру: сравнивать имена имеет смысл только на ОДНОМ адресе,
/// иначе разница объясняется разными серверами, а не блокировкой.
pub fn http_probe_pinned(host: &str, port: u16, pin_ip: Option<&str>, timeout_sec: u64) -> ProbeResult {
    let started = Instant::now();
    let scheme = if port == 443 { "https" } else { "http" };
    // Порт обязан попасть в URL: иначе curl шёл бы на стандартный для схемы,
    // а --resolve прибивал совсем другой — и замер мерил бы не то.
    let url = if port == 443 || port == 80 {
        format!("{scheme}://{host}")
    } else {
        format!("{scheme}://{host}:{port}")
    };

    #[allow(unused_mut)]
    let mut cmd = Command::new(crate::sys::system_exe("curl.exe"));
    cmd.args(["-s", "-o", "NUL", "-w", "%{http_code}", "-m", &timeout_sec.to_string()]);
    if let Some(ip) = pin_ip {
        cmd.args(["--resolve", &format!("{host}:{port}:{ip}")]);
    }
    cmd.args(["-I", &url]);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    match cmd.output() {
        Ok(out) => {
            let raw = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let status = raw.parse::<u16>().ok().filter(|s| *s >= 100);
            let exit = out.status.code().unwrap_or(-1);
            let (ok, code) = code_from_curl(exit, status);
            ProbeResult {
                ok,
                ms: started.elapsed().as_millis() as u64,
                reason: reason_text(code),
                code,
            }
        }
        Err(e) => ProbeResult {
            ok: false,
            ms: started.elapsed().as_millis() as u64,
            reason: Some(e.to_string()),
            code: FailureCode::Unknown,
        },
    }
}

/// Первый адрес, в который разрешается имя. Контрольный замер обязан идти в
/// тот же самый — иначе сравнивать нечего.
pub fn first_ip(host: &str, port: u16) -> Option<String> {
    (host, port)
        .to_socket_addrs()
        .ok()?
        .next()
        .map(|a| a.ip().to_string())
}

/// TCP-хендшейк — для игровых серверов, где HTTP отсутствует как таковой.
/// Даёт осмысленную задержку, но НЕ видит блокировку на уровне TLS.
pub fn tcp_probe(host: &str, port: u16, timeout_ms: u64) -> ProbeResult {
    let started = Instant::now();
    let addr_iter = match (host, port).to_socket_addrs() {
        Ok(it) => it,
        Err(_) => {
            return ProbeResult {
                ok: false,
                ms: started.elapsed().as_millis() as u64,
                reason: Some("dns".into()),
                code: FailureCode::Dns,
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
                code: FailureCode::Ok,
            };
        }
    }
    ProbeResult {
        ok: false,
        ms: started.elapsed().as_millis() as u64,
        reason: Some("timeout".into()),
        code: FailureCode::Timeout,
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn контроль_отвечает_значит_режут_имя() {
        let (v, why) = classify_path(false, FailureCode::TlsFailed, Some((true, FailureCode::Ok)));
        assert_eq!(v, PathVerdict::Sni);
        assert!(why.contains(NEUTRAL_SNI));
    }

    #[test]
    fn контроль_тоже_молчит_значит_режут_адрес() {
        let (v, _) = classify_path(false, FailureCode::TlsFailed, Some((false, FailureCode::Timeout)));
        assert_eq!(v, PathVerdict::Ip);
    }

    #[test]
    fn ответ_сервера_не_блокировка() {
        // Сертификат не прошёл проверку — но он БЫЛ, значит сервер жив.
        let (v, _) = classify_path(false, FailureCode::TlsCert, Some((false, FailureCode::Timeout)));
        assert_eq!(v, PathVerdict::Server);
    }

    #[test]
    fn до_порта_не_дошли_контроль_не_спрашиваем() {
        // Контроль тут неинформативен: имени на проводе ещё не было.
        for code in [FailureCode::TcpRefused, FailureCode::Dns] {
            let (v, _) = classify_path(false, code, Some((true, FailureCode::Ok)));
            assert_eq!(v, PathVerdict::Ip, "{code:?}");
        }
    }

    #[test]
    fn успешная_проба_не_классифицируется() {
        let (v, why) = classify_path(true, FailureCode::Ok, Some((false, FailureCode::Timeout)));
        assert_eq!(v, PathVerdict::Ok);
        assert!(why.is_empty());
    }

    #[test]
    fn контроль_с_чужим_сертификатом_считается_ответом() {
        // Нейтральное имя прибито к чужому адресу, сертификат не совпадёт —
        // но ответ TLS-уровня получен, значит путь живой.
        let (v, _) = classify_path(false, FailureCode::TlsFailed, Some((false, FailureCode::TlsCert)));
        assert_eq!(v, PathVerdict::Sni);
    }

    #[test]
    fn без_контроля_вердикт_не_измерено() {
        // Раньше отсутствие замера кодировалось как «контроль молчал» и
        // превращалось в уверенное «режут адрес» — программа заявляла то,
        // чего не проверяла.
        let (v, why) = classify_path(false, FailureCode::TlsFailed, None);
        assert_eq!(v, PathVerdict::Unknown);
        assert!(why.contains("не выполнялся"), "{why}");
    }

    #[test]
    fn код_451_не_повод_перебирать_стратегии() {
        // Контроль на example.com ответит, и по общему правилу вышло бы
        // «режут по имени» — то есть бесполезный перебор.
        let (v, why) = classify_path(false, FailureCode::HttpBlocked, Some((true, FailureCode::Ok)));
        assert_eq!(v, PathVerdict::Legal, "{why}");
        assert!(why.contains("451"), "{why}");
    }

    #[test]
    fn коды_curl_раскладываются_по_стадиям() {
        assert_eq!(code_from_curl(0, Some(200)), (true, FailureCode::Ok));
        assert_eq!(code_from_curl(0, Some(403)), (true, FailureCode::Ok));
        assert_eq!(code_from_curl(0, Some(451)), (false, FailureCode::HttpBlocked));
        assert_eq!(code_from_curl(6, None), (false, FailureCode::Dns));
        assert_eq!(code_from_curl(7, None), (false, FailureCode::TcpRefused));
        assert_eq!(code_from_curl(28, None), (false, FailureCode::Timeout));
        assert_eq!(code_from_curl(35, None), (false, FailureCode::TlsFailed));
        assert_eq!(code_from_curl(56, None), (false, FailureCode::TlsFailed));
        assert_eq!(code_from_curl(60, None), (false, FailureCode::TlsCert));
    }

    #[test]
    fn код_ноль_ноль_ноль_больше_не_успех() {
        // Старое правило «три цифры и не начинается с нуля» пропускало
        // только 000; теперь опираемся на код выхода curl, а не на текст.
        assert!(!code_from_curl(35, Some(0)).0);
        assert!(!code_from_curl(0, None).0);
    }

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
        // не доходит (http_probe_pinned отсеивает всё ниже 100), но правило
        // должно быть верным и там.
        assert!(!code_is_answer(0));
    }
}
