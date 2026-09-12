//! Сканирование трафика игры: куда она на самом деле ходит.
//!
//! Зачем. Списки zapret собраны под сайты, и игра в них попадает в лучшем
//! случае страницей авторизации. Адреса игровых серверов не публикуются,
//! меняются от региона к региону и от патча к патчу — узнать их можно
//! только одним способом: посмотреть, куда ходит сам процесс игры. В
//! сообществе это и делают руками через TCPView, выписывая адреса в
//! блокнот. Здесь то же самое, но само.
//!
//! Как. Пока игра запущена, раз в пару секунд снимается список соединений
//! с номерами процессов, из него берутся только строки нужной игры, а из
//! них — внешние адреса. Накопленное уходит в ipset-список рядом с
//! конфигами релиза, и обход начинает покрывать эти адреса.
//!
//! Чего этот способ НЕ может. Он видит адрес, только если соединение
//! состоялось. Игра, которую режут на подключении, часть своих серверов
//! так и не покажет — до них она не дошла. Поэтому сканировать полезно при
//! уже работающем обходе или хотя бы при включённом Game Filter: сперва
//! дать игре дотянуться, потом закрепить найденное.

use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Одно соединение из таблицы системы.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub pid: u32,
    pub proto: Proto,
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

/// Разбор строки `netstat -ano`.
///
/// Разбираем по СТРУКТУРЕ, а не по словам. Заголовки и состояния у netstat
/// переведены: на русской системе вместо `LISTENING` стоит «ПРОСЛУШИВАНИЕ»,
/// вместо `Active Connections` — «Активные подключения». Любая привязка к
/// тексту сломалась бы на первой же не-английской машине.
///
/// Устойчивая часть такая: первый столбец — протокол, второй — локальный
/// адрес, третий — удалённый, последний — номер процесса. У TCP между ними
/// есть состояние, у UDP его нет, поэтому на число столбцов не смотрим.
pub fn parse_netstat_line(line: &str) -> Option<Conn> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 4 {
        return None;
    }
    let proto = match f[0].to_ascii_uppercase().as_str() {
        "TCP" => Proto::Tcp,
        "UDP" => Proto::Udp,
        _ => return None,
    };
    let pid: u32 = f[f.len() - 1].parse().ok()?;
    let (ip, port) = split_addr(f[2])?;
    Some(Conn { pid, proto, ip, port })
}

/// `1.2.3.4:443` или `[2606:4700::1]:443`. У UDP на месте удалённого адреса
/// может стоять `*:*` — это «ни с кем», а не адрес.
fn split_addr(s: &str) -> Option<(IpAddr, u16)> {
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (h.to_string(), p)
    } else {
        let (h, p) = s.rsplit_once(':')?;
        (h.to_string(), p)
    };
    let port: u16 = port.parse().ok()?;
    let ip: IpAddr = host.parse().ok()?;
    Some((ip, port))
}

/// Стоит ли добавлять этот адрес в обход.
///
/// Отсеиваем всё, что не уходит к провайдеру: петлю, частные сети, link-local,
/// мультикаст и нули. Это не косметика — попади в ipset хотя бы `192.168.1.1`,
/// и обход начнёт заворачивать трафик к домашнему роутеру.
pub fn is_external(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !v.is_loopback()
                && !v.is_private()
                && !v.is_link_local()
                && !v.is_multicast()
                && !v.is_broadcast()
                && !v.is_unspecified()
                // 100.64/10 — CGNAT: это ещё адреса провайдера, но свои, и
                // обходить их незачем.
                && !(v.octets()[0] == 100 && (64..128).contains(&v.octets()[1]))
                // 198.18/15 — диапазон для замеров, так выглядит fake-IP прокси.
                && !(v.octets()[0] == 198 && (v.octets()[1] == 18 || v.octets()[1] == 19))
        }
        IpAddr::V6(v) => {
            !v.is_loopback() && !v.is_multicast() && !v.is_unspecified()
                // fe80::/10 link-local и fc00::/7 unique-local.
                && !matches!(v.segments()[0] & 0xffc0, 0xfe80)
                && (v.segments()[0] & 0xfe00) != 0xfc00
        }
    }
}

/// Полная таблица соединений системы.
pub fn connections() -> Vec<Conn> {
    crate::sys::run("netstat", &["-ano"])
        .lines()
        .filter_map(parse_netstat_line)
        .collect()
}

/// Номера процессов с таким именем образа. Пусто — процесс не запущен.
pub fn pids_of(image: &str) -> HashSet<u32> {
    // Формат CSV, потому что в имени процесса бывают пробелы, а колонки в
    // человекочитаемом выводе ещё и переведены.
    let out = crate::sys::run(
        "tasklist",
        &["/FI", &format!("IMAGENAME eq {image}"), "/FO", "CSV", "/NH"],
    );
    out.lines().filter_map(parse_tasklist_line).collect()
}

/// `"имя.exe","1234","Console","1","12 345 КБ"` — второе поле это PID.
fn parse_tasklist_line(line: &str) -> Option<u32> {
    parse_tasklist_row(line).map(|(_, pid)| pid)
}

/// Имя образа и номер процесса из строки CSV.
fn parse_tasklist_row(line: &str) -> Option<(String, u32)> {
    let mut fields = line.split("\",\"");
    let name = fields.next()?.trim_matches('"').to_string();
    let pid: u32 = fields.next()?.trim_matches('"').parse().ok()?;
    if name.is_empty() {
        return None;
    }
    Some((name, pid))
}

/// Номер процесса → имя образа, для всех процессов разом.
pub fn process_names() -> std::collections::HashMap<u32, String> {
    crate::sys::run("tasklist", &["/FO", "CSV", "/NH"])
        .lines()
        .filter_map(parse_tasklist_row)
        .map(|(n, p)| (p, n))
        .collect()
}

/// Процессы, которые точно не игра. Список короткий намеренно: это не
/// чёрный список «всего лишнего», а защита от очевидного — браузер и
/// системные службы держат внешних соединений больше любой игры и иначе
/// всегда бы выигрывали.
const НЕ_ИГРА: &[&str] = &[
    "chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "browser.exe",
    "svchost.exe", "System", "Idle", "explorer.exe", "SearchApp.exe",
    "OneDrive.exe", "Telegram.exe", "Discord.exe", "klutz.exe", "winws.exe",
    "curl.exe", "MsMpEng.exe", "backgroundTaskHost.exe", "RuntimeBroker.exe",
];

fn похоже_на_игру(name: &str) -> bool {
    !НЕ_ИГРА.iter().any(|b| b.eq_ignore_ascii_case(name))
}

/// Кто из работающих процессов больше похож на игру.
///
/// Признак — внешние соединения на портах, отличных от 80 и 443. Сайты
/// ходят по вебовым портам, игры почти всегда по своим: Steam на 27015-27068,
/// Riot в районе 5000, и так далее. Если таких нет вовсе, берём того, у кого
/// просто больше всего внешних адресов, — это лучше, чем не ответить ничего.
///
/// Чистая функция: соединения и имена собирает вызывающий.
pub fn guess_game(
    conns: &[Conn],
    names: &std::collections::HashMap<u32, String>,
) -> Option<String> {
    use std::collections::HashMap;
    let mut своими: HashMap<&str, BTreeSet<String>> = HashMap::new();
    let mut любыми: HashMap<&str, BTreeSet<String>> = HashMap::new();
    for c in conns {
        if !is_external(&c.ip) {
            continue;
        }
        let Some(name) = names.get(&c.pid) else { continue };
        if !похоже_на_игру(name) {
            continue;
        }
        любыми.entry(name).or_default().insert(c.ip.to_string());
        if c.port != 80 && c.port != 443 {
            своими.entry(name).or_default().insert(c.ip.to_string());
        }
    }
    let лучший = |m: &HashMap<&str, BTreeSet<String>>| -> Option<String> {
        m.iter()
            .max_by_key(|(n, v)| (v.len(), std::cmp::Reverse(n.to_string())))
            .map(|(n, _)| n.to_string())
    };
    лучший(&своими).or_else(|| лучший(&любыми))
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    /// Нашёлся ли вообще процесс игры хоть раз за время скана.
    pub running: bool,
    /// Внешние адреса, отсортированные и без повторов.
    pub addrs: Vec<String>,
    /// Удалённые порты — по ним видно, TCP тут или UDP и какой диапазон.
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
    /// Сколько раз успели снять таблицу.
    pub ticks: u32,
    pub note: String,
}

/// Копит адреса процессов игры, пока идёт время.
///
/// Опрос, а не подписка: событий о новых соединениях система бесплатно не
/// отдаёт, а таблица снимается дёшево. Шаг в пару секунд ловит и короткие
/// соединения — матчмейкинг успевает открыть и закрыть их за это время.
/// Пустой `images` означает «найди сам»: на первом же тике берём процесс,
/// больше всего похожий на игру, и дальше следим только за ним.
pub fn scan(images: &[String], total: Duration, step: Duration) -> ScanResult {
    let started = Instant::now();
    let mut images: Vec<String> = images.to_vec();
    let mut угадан: Option<String> = None;
    if images.is_empty() {
        let names = process_names();
        if let Some(g) = guess_game(&connections(), &names) {
            угадан = Some(g.clone());
            images.push(g);
        }
    }
    let images = images;
    let mut addrs: BTreeSet<String> = BTreeSet::new();
    let mut tcp: BTreeSet<u16> = BTreeSet::new();
    let mut udp: BTreeSet<u16> = BTreeSet::new();
    let mut running = false;
    let mut ticks = 0u32;

    while started.elapsed() < total {
        let pids: HashSet<u32> = images.iter().flat_map(|i| pids_of(i)).collect();
        if !pids.is_empty() {
            running = true;
            for c in connections() {
                if !pids.contains(&c.pid) || !is_external(&c.ip) {
                    continue;
                }
                addrs.insert(c.ip.to_string());
                match c.proto {
                    Proto::Tcp => tcp.insert(c.port),
                    Proto::Udp => udp.insert(c.port),
                };
            }
        }
        ticks += 1;
        let left = total.saturating_sub(started.elapsed());
        if left.is_zero() {
            break;
        }
        std::thread::sleep(step.min(left));
    }

    let mut note = describe(running, addrs.len(), ticks);
    if let Some(g) = &угадан {
        note = format!("процесс: {g}. {note}");
    } else if images.is_empty() {
        note = "не нашлось ни одного процесса, похожего на игру — запусти её и \
                попробуй снова"
            .into();
    }
    ScanResult {
        running,
        addrs: addrs.into_iter().collect(),
        tcp_ports: tcp.into_iter().collect(),
        udp_ports: udp.into_iter().collect(),
        ticks,
        note,
    }
}

/// Что сказать человеку. Отдельно от сети, чтобы можно было проверить.
pub fn describe(running: bool, found: usize, ticks: u32) -> String {
    if ticks == 0 {
        return "сканирование не запускалось".into();
    }
    if !running {
        return "процесс игры не найден — запусти игру и сканируй, пока она работает".into();
    }
    if found == 0 {
        return "игра запущена, но наружу пока не ходила: зайди в меню, начни матч — \
                адреса появляются, когда игра реально подключается"
            .into();
    }
    format!(
        "собрано адресов: {found}. Это те, до которых игра ДОШЛА; если её режут на \
         подключении, часть серверов сюда не попадёт — сканируй при работающем обходе"
    )
}

/// Кладёт собранные адреса в список релиза, не тронув чужие строки.
pub fn save_ips(root: &std::path::Path, addrs: &[String]) -> Result<usize, String> {
    let list = root.join("lists").join("ipset-all.txt");
    let existing = std::fs::read_to_string(&list).unwrap_or_default();
    // К уже собранному добавляем, а не заменяем: сканов бывает несколько —
    // отдельно меню, отдельно матч, отдельно голосовой чат.
    let mut all: BTreeSet<String> = extract_block(&existing).into_iter().collect();
    for a in addrs {
        all.insert(a.clone());
    }
    let all: Vec<String> = all.into_iter().collect();
    let merged = merge_block(&existing, &all);
    std::fs::write(&list, merged).map_err(|e| e.to_string())?;
    Ok(all.len())
}

/// Сколько наших адресов сейчас в списке.
pub fn saved_count(root: &std::path::Path) -> usize {
    std::fs::read_to_string(root.join("lists").join("ipset-all.txt"))
        .map(|c| extract_block(&c).len())
        .unwrap_or(0)
}

/// Убирает наш блок целиком, оставив чужое как было.
pub fn clear_ips(root: &std::path::Path) -> Result<(), String> {
    let list = root.join("lists").join("ipset-all.txt");
    let existing = std::fs::read_to_string(&list).unwrap_or_default();
    std::fs::write(&list, merge_block(&existing, &[])).map_err(|e| e.to_string())
}

// ─────────── блок адресов игр внутри ipset-all.txt ───────────
//
// Список адресов у zapret один — `lists/ipset-all.txt`, и его же целиком
// перезаписывает кнопка «Обновить список IPSet». Держать свои адреса
// отдельным файлом нельзя: конфиги релиза про него не знают. Поэтому свои
// строки живут внутри общего файла, обрамлённые метками, и обе стороны —
// и сканер, и обновление списка — блок берегут.

pub const BLOCK_START: &str = "# ─── klutz: адреса игр, собрано сканированием ───";
pub const BLOCK_END: &str = "# ─── klutz: конец блока ───";

/// Адреса из нашего блока. Пусто — блока нет.
pub fn extract_block(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if t == BLOCK_START {
            inside = true;
            continue;
        }
        if t == BLOCK_END {
            inside = false;
            continue;
        }
        if inside && !t.is_empty() && !t.starts_with('#') {
            out.push(t.to_string());
        }
    }
    out
}

/// Текст без нашего блока — то, что принадлежит не нам.
pub fn without_block(text: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let t = line.trim();
        if t == BLOCK_START {
            inside = true;
            continue;
        }
        if t == BLOCK_END {
            inside = false;
            continue;
        }
        if !inside {
            out.push(line);
        }
    }
    let mut s = out.join("\r\n");
    while s.ends_with("\r\n\r\n") {
        s.truncate(s.len() - 2);
    }
    s
}

/// Собирает файл заново: чужое как было, наш блок в конец.
///
/// Заглушку `203.0.113.113/32` выбрасываем: это «список загружен, но пуст»
/// из TEST-NET-3, и рядом с настоящими адресами она только мешает — режим
/// файла всё равно становится «loaded».
pub fn merge_block(existing: &str, addrs: &[String]) -> String {
    let base: Vec<String> = without_block(existing)
        .lines()
        .filter(|l| !l.trim().starts_with("203.0.113.113"))
        .map(|l| l.to_string())
        .collect();
    let mut out = base.join("\r\n").trim_end().to_string();
    if addrs.is_empty() {
        if out.is_empty() {
            return String::new();
        }
        out.push_str("\r\n");
        return out;
    }
    if !out.is_empty() {
        out.push_str("\r\n");
    }
    out.push_str(BLOCK_START);
    out.push_str("\r\n");
    for a in addrs {
        out.push_str(a);
        out.push_str("\r\n");
    }
    out.push_str(BLOCK_END);
    out.push_str("\r\n");
    out
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn разбор_строк_netstat_не_зависит_от_языка() {
        // Английская система: у TCP есть состояние.
        let c = parse_netstat_line("  TCP    192.168.1.5:51000    104.16.0.1:443    ESTABLISHED    4242").unwrap();
        assert_eq!(c.pid, 4242);
        assert_eq!(c.proto, Proto::Tcp);
        assert_eq!(c.ip.to_string(), "104.16.0.1");
        assert_eq!(c.port, 443);

        // Русская: то же самое, состояние переведено — разбор не должен
        // этого замечать.
        let c = parse_netstat_line("  TCP    192.168.1.5:51001    162.159.135.232:27018    УСТАНОВЛЕНО    777").unwrap();
        assert_eq!((c.pid, c.port), (777, 27018));

        // UDP: столбца состояния нет вовсе.
        let c = parse_netstat_line("  UDP    0.0.0.0:50000    8.8.8.8:27015    1234").unwrap();
        assert_eq!(c.proto, Proto::Udp);
        assert_eq!((c.pid, c.port), (1234, 27015));
    }

    #[test]
    fn ipv6_и_мусор_разбираются_без_паники() {
        let c = parse_netstat_line("  TCP    [::1]:1000    [2606:4700::1]:443    ESTABLISHED    9").unwrap();
        assert_eq!(c.ip.to_string(), "2606:4700::1");
        assert_eq!(c.port, 443);

        // «Ни с кем» — это не адрес.
        assert!(parse_netstat_line("  UDP    0.0.0.0:500    *:*    900").is_none());
        // Заголовки и пустые строки.
        assert!(parse_netstat_line("Active Connections").is_none());
        assert!(parse_netstat_line("  Proto  Local Address  Foreign Address  State  PID").is_none());
        assert!(parse_netstat_line("").is_none());
        assert!(parse_netstat_line("   ").is_none());
        // Номер процесса не число.
        assert!(parse_netstat_line("  TCP  1.1.1.1:1  2.2.2.2:2  ESTABLISHED  нет").is_none());
    }

    #[test]
    fn в_список_попадают_только_чужие_адреса() {
        let внешние = ["104.16.0.1", "162.159.135.232", "8.8.8.8", "2606:4700::1"];
        for ip in внешние {
            assert!(is_external(&ip.parse().unwrap()), "{ip} должен пройти");
        }
        // Попади сюда адрес роутера — обход начал бы заворачивать трафик
        // внутрь домашней сети.
        let свои = [
            "127.0.0.1", "192.168.1.1", "10.0.0.5", "172.16.0.1",
            "169.254.1.1", "224.0.0.1", "0.0.0.0",
            "100.64.0.1",      // CGNAT — адреса провайдера
            "198.18.0.1",      // fake-IP прокси
            "::1", "fe80::1", "fc00::1",
        ];
        for ip in свои {
            assert!(!is_external(&ip.parse().unwrap()), "{ip} не должен пройти");
        }
    }

    #[test]
    fn разбор_строки_tasklist() {
        assert_eq!(parse_tasklist_line(r#""cs2.exe","4242","Console","1","1 234 КБ""#), Some(4242));
        // Имя с пробелом — ради этого и CSV.
        assert_eq!(parse_tasklist_line(r#""Rocket League.exe","77","Console","1","10 КБ""#), Some(77));
        // Сообщение «нет задач» в любом переводе.
        assert_eq!(parse_tasklist_line("INFO: No tasks are running which match the specified criteria."), None);
        assert_eq!(parse_tasklist_line(""), None);
    }

    #[test]
    fn игру_узнаём_по_нестандартным_портам() {
        use std::collections::HashMap;
        let names: HashMap<u32, String> = [
            (1, "chrome.exe".to_string()),
            (2, "cs2.exe".to_string()),
            (3, "svchost.exe".to_string()),
        ]
        .into_iter()
        .collect();
        let c = |pid, ip: &str, port| Conn {
            pid,
            proto: Proto::Tcp,
            ip: ip.parse().unwrap(),
            port,
        };
        let conns = vec![
            // Браузер держит внешних соединений больше всех — и всё равно
            // не должен выигрывать.
            c(1, "104.16.0.1", 443),
            c(1, "104.16.0.2", 443),
            c(1, "104.16.0.3", 443),
            c(1, "104.16.0.4", 443),
            c(3, "20.1.1.1", 443),
            // А у игры свой порт.
            c(2, "162.159.135.232", 27018),
        ];
        assert_eq!(guess_game(&conns, &names).as_deref(), Some("cs2.exe"));
    }

    #[test]
    fn без_игровых_портов_берём_самого_активного_но_не_браузер() {
        use std::collections::HashMap;
        let names: HashMap<u32, String> = [
            (1, "chrome.exe".to_string()),
            (2, "RocketLeague.exe".to_string()),
        ]
        .into_iter()
        .collect();
        let c = |pid, ip: &str| Conn { pid, proto: Proto::Tcp, ip: ip.parse().unwrap(), port: 443 };
        let conns = vec![c(1, "1.1.1.1"), c(1, "1.1.1.2"), c(2, "8.8.8.8")];
        assert_eq!(guess_game(&conns, &names).as_deref(), Some("RocketLeague.exe"));
    }

    #[test]
    fn внутренние_адреса_в_догадку_не_идут() {
        use std::collections::HashMap;
        let names: HashMap<u32, String> = [(2, "game.exe".to_string())].into_iter().collect();
        let conns = vec![Conn {
            pid: 2,
            proto: Proto::Udp,
            ip: "192.168.1.1".parse().unwrap(),
            port: 27015,
        }];
        assert_eq!(guess_game(&conns, &names), None);
    }

    #[test]
    fn пояснение_не_выдаёт_пустой_скан_за_результат() {
        assert!(describe(false, 0, 5).contains("не найден"));
        assert!(describe(true, 0, 5).contains("наружу пока не ходила"));
        assert!(describe(true, 12, 5).contains("12"));
        // И честно говорит, что список неполон, если игру режут.
        assert!(describe(true, 12, 5).contains("ДОШЛА"));
        assert!(describe(false, 0, 0).contains("не запускалось"));
    }

    #[test]
    fn блок_выделяется_и_не_задевает_чужое() {
        let текст = [
            "1.1.1.1",
            "2.2.2.2",
            BLOCK_START,
            "104.16.0.1",
            "162.159.135.232",
            BLOCK_END,
            "3.3.3.3",
        ]
        .join("\r\n");
        assert_eq!(extract_block(&текст), vec!["104.16.0.1", "162.159.135.232"]);
        let без = without_block(&текст);
        assert!(без.contains("1.1.1.1") && без.contains("3.3.3.3"));
        assert!(!без.contains("104.16.0.1"), "{без}");
        assert!(!без.contains("klutz"), "метки тоже наши: {без}");
    }

    #[test]
    fn обновление_списка_не_стирает_собранное() {
        // Ровно тот случай, ради которого метки и появились: скачанный
        // список кладётся вместо чужого, а наш блок переносится.
        let старое = [BLOCK_START, "104.16.0.1", BLOCK_END].join("\r\n");
        let свои = extract_block(&старое);
        let скачанное = ["8.8.8.8", "9.9.9.9"].join("\r\n");
        let новое = merge_block(&скачанное, &свои);
        assert!(новое.contains("8.8.8.8") && новое.contains("9.9.9.9"), "{новое}");
        assert_eq!(extract_block(&новое), vec!["104.16.0.1"], "{новое}");
    }

    #[test]
    fn заглушка_пустого_списка_уступает_настоящим_адресам() {
        // 203.0.113.113/32 означает «список загружен, но пуст». Рядом с
        // настоящими адресами ей делать нечего.
        let было = "203.0.113.113/32";
        let стало = merge_block(было, &["104.16.0.1".to_string()]);
        assert!(!стало.contains("203.0.113"), "{стало}");
        assert!(стало.contains("104.16.0.1"), "{стало}");
    }

    #[test]
    fn пустой_набор_убирает_блок_целиком() {
        let текст = ["7.7.7.7", BLOCK_START, "1.2.3.4", BLOCK_END].join("\r\n");
        let стало = merge_block(&текст, &[]);
        assert!(стало.contains("7.7.7.7"), "{стало}");
        assert!(!стало.contains("1.2.3.4"), "{стало}");
        assert!(!стало.contains("klutz"), "{стало}");
        // И на совсем пустом входе не появляется мусора.
        assert_eq!(merge_block("", &[]), "");
    }

    /// Живая проверка: `cargo test -- --ignored живой_скан --nocapture`.
    #[test]
    #[ignore]
    fn живой_скан_таблицы_соединений() {
        let all = connections();
        println!("всего соединений: {}", all.len());
        let ext = all.iter().filter(|c| is_external(&c.ip)).count();
        println!("из них внешних: {ext}");
        assert!(!all.is_empty(), "таблица соединений пуста — netstat не отработал");
    }
}
