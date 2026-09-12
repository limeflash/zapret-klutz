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

/// Известные НЕ-игровые порты вне веба. Без этого списка любая фоновая
/// служба выглядит игрой: у неё тоже «не 80 и не 443».
///
/// 5228 — Google FCM, на нём сидят уведомления половины программ; именно он
/// однажды и выдал службу HP за игру. Остальное — почта, DNS, время, SMB.
fn служебный_порт(port: u16) -> bool {
    matches!(
        port,
        53 | 67 | 68 | 88 | 123 | 135 | 137..=139 | 389 | 445 | 465 | 500
            | 514 | 587 | 636 | 993 | 995 | 1194 | 1701 | 1723 | 1900
            | 3389 | 5222 | 5223 | 5228..=5230 | 5353 | 5938 | 8080 | 8443 | 8883 | 9443
    )
}

/// Порт, на котором обычно живут игры.
///
/// Диапазоны взяты из того, что игры действительно используют: Battle.net
/// на 1119, Xbox на 3074, Riot около 5000-5500 и 7000-8000, Steam и
/// источники на 27000-27100. Всё прочее выше 1024 считаем возможным, но
/// слабым признаком — вес у него меньше.
fn игровой_порт(port: u16) -> bool {
    matches!(port, 1119 | 3074 | 3478..=3480 | 5000..=5500 | 6112..=6119 | 7000..=8000 | 27000..=27200)
}

/// Насколько соединение похоже на игровое. Ноль — не похоже вовсе.
fn вес(proto: Proto, port: u16) -> u32 {
    // Известный служебный порт перекрывает всё: диапазоны игр широкие и
    // задевают чужое. 5228 (уведомления Google) попадает в «риотовские»
    // 5000-5500, и именно на этом эвристика однажды приняла службу HP за
    // игру. Сначала отсекаем известное, потом смотрим на игровое.
    if port < 1024 || служебный_порт(port) {
        return 0;
    }
    match (proto, игровой_порт(port)) {
        // UDP на игровом порту — самый сильный признак: так ходит сам матч,
        // а фоновые службы этого почти не делают.
        (Proto::Udp, true) => 8,
        (Proto::Tcp, true) => 4,
        // UDP на произвольном высоком порту — слабее, но тоже довод.
        (Proto::Udp, false) => 3,
        // А вот TCP на случайном высоком порту не значит ничего: так ходит
        // половина фоновых программ.
        (Proto::Tcp, false) => 0,
    }
}

/// Настоящий ли это процесс.
///
/// netstat вешает на PID 0 соединения, которые закрываются или чьи владельцы
/// уже вышли, а PID 4 — это ядро. Оба выглядят как обычные строки с живыми
/// портами: на этой машине «System Idle Process» так и вышел в кандидаты с
/// портами 1119 и 27018. Адреса там настоящие, а владелец — нет, и следить
/// за таким процессом бессмысленно: он никогда ничего не откроет.
///
/// Отсекаем по НОМЕРУ, а не по имени: имя псевдопроцесса переведено на
/// русской Windows, и привязка к тексту сломалась бы там же, где и всё
/// остальное.
fn настоящий_процесс(pid: u32) -> bool {
    pid > 4
}

/// Кандидат в игру: процесс и чем он себя выдал.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Candidate {
    pub name: String,
    /// Сумма весов соединений — по ней и сортируем.
    pub score: u32,
    /// Сколько разных внешних адресов.
    pub addrs: usize,
    /// Порты, по которым его посчитали похожим на игру.
    pub ports: Vec<u16>,
}

/// Кто из работающих процессов похож на игру, лучшие первыми.
///
/// Считаем по ПОЛОЖИТЕЛЬНЫМ признакам, а не по отсутствию в чёрном списке.
/// Прежняя версия брала всё, что ходит не по 80 и 443, и однажды уверенно
/// назвала игрой службу HP: та стучалась на 5228, порт уведомлений Google.
/// Чёрным списком это не лечится — фоновых процессов сотни, и перечислить
/// их нельзя. А вот признаки игры перечислить можно: UDP на высоком порту и
/// известные игровые диапазоны.
///
/// Пусто — значит не нашли. Это честный ответ: лучше сказать «запусти игру»,
/// чем собрать адреса постороннего процесса и положить их в обход.
///
/// Чистая функция: соединения и имена собирает вызывающий.
pub fn candidates(
    conns: &[Conn],
    names: &std::collections::HashMap<u32, String>,
) -> Vec<Candidate> {
    use std::collections::HashMap;
    let mut acc: HashMap<&str, (u32, BTreeSet<String>, BTreeSet<u16>)> = HashMap::new();
    for c in conns {
        if !is_external(&c.ip) || !настоящий_процесс(c.pid) {
            continue;
        }
        let w = вес(c.proto, c.port);
        if w == 0 {
            continue;
        }
        let Some(name) = names.get(&c.pid) else { continue };
        let e = acc.entry(name).or_default();
        e.0 += w;
        e.1.insert(c.ip.to_string());
        e.2.insert(c.port);
    }
    let mut out: Vec<Candidate> = acc
        .into_iter()
        .map(|(name, (score, addrs, ports))| Candidate {
            name: name.to_string(),
            score,
            addrs: addrs.len(),
            ports: ports.into_iter().collect(),
        })
        .collect();
    // По убыванию веса, а при равенстве — по имени, чтобы порядок не плясал
    // от запуска к запуску.
    out.sort_by(|a, b| b.score.cmp(&a.score).then(a.name.cmp(&b.name)));
    out
}

/// Самый вероятный кандидат, если он есть.
pub fn guess_game(
    conns: &[Conn],
    names: &std::collections::HashMap<u32, String>,
) -> Option<String> {
    candidates(conns, names).into_iter().next().map(|c| c.name)
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
/// отдаёт, а таблица снимается дёшево.
///
/// Чего опрос НЕ умеет, и это стоит знать: соединение, открывшееся и
/// закрывшееся между двумя тиками, он пропустит. Раньше здесь было написано
/// ровно наоборот — будто шаг в пару секунд такие соединения ловит. Не
/// ловит, и уменьшать шаг до бесконечности смысла нет.
/// Пустой `images` означает «найди сам»: на первом же тике берём процесс,
/// больше всего похожий на игру, и дальше следим только за ним.
pub fn scan(
    images: &[String],
    total: Duration,
    step: Duration,
    mut progress: impl FnMut(&str, usize),
) -> ScanResult {
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
    // Искать нечего — не занимать полминуты молчанием. Раньше цикл честно
    // отрабатывал всё время, ничего не делая, и человек ждал впустую.
    if images.is_empty() {
        return ScanResult {
            running: false,
            addrs: Vec::new(),
            tcp_ports: Vec::new(),
            udp_ports: Vec::new(),
            ticks: 0,
            note: "не нашлось ни одного процесса, похожего на игру. Запусти игру, \
                   зайди в меню и попробуй снова"
                .into(),
        };
    }
    progress(images.first().map(|s| s.as_str()).unwrap_or(""), 0);
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
        progress(images.first().map(|s| s.as_str()).unwrap_or(""), addrs.len());
        let left = total.saturating_sub(started.elapsed());
        if left.is_zero() {
            break;
        }
        std::thread::sleep(step.min(left));
    }

    let mut note = describe(running, addrs.len(), ticks);
    if let Some(g) = &угадан {
        note = format!("процесс: {g}. {note}");
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
        "поймано адресов: {found}. Это те, до которых игра ДОШЛА; если её режут на \
         подключении, часть серверов сюда не попадёт — сканируй при работающем обходе. \
         В список кладём их сети /24: игровые серверы обычно стоят в одном блоке, \
         так что соседи по пулу накроются заодно"
    )
}

// ─────────── сети оператора ───────────
//
// Пойманный адрес — один сервер из пула, и /24 вокруг него покрывает лишь
// соседей по стойке. У Riot объявлено 36 сетей, у Valve 45, и матч может
// уехать в любую: за два сбора подряд на Valorant поймались 162.249.72.0/24
// и 185.40.64.0/24 — разные сети одного оператора. Поэтому спрашиваем, чьи
// это адреса, и берём все его сети сразу.

/// Порог, выше которого оператор считается облаком, а не игровым.
///
/// Взято из замеров, а не с потолка: Riot объявляет 36 сетей, Valve — 45.
/// А Cloudflare 2395, Google 1233, Amazon 18020. Разница на два порядка,
/// и порог посередине разделяет их надёжнее любого списка имён — который
/// к тому же устарел бы на первом же операторе, о котором мы не слышали.
///
/// Зачем порог вообще: втащить в список тысячи сетей Cloudflare значило бы
/// направить обход на пол-интернета. Для игрового профиля это верный способ
/// сломать всё разом.
pub const MAX_OPERATOR_PREFIXES: usize = 256;

/// Стоит ли разворачивать адрес в сети оператора.
pub fn should_expand(prefix_count: usize) -> bool {
    prefix_count > 0 && prefix_count <= MAX_OPERATOR_PREFIXES
}

/// Номер оператора из ответа справочника о сети.
pub fn parse_asn(json: &str) -> Option<String> {
    let at = json.find("\"asns\"")?;
    let rest = &json[at..];
    let start = rest.find('[')?;
    let end = rest.find(']')?;
    rest[start + 1..end]
        .split(',')
        .next()?
        .trim()
        .trim_matches('"')
        .parse::<u32>()
        .ok()
        .map(|n| n.to_string())
}

/// Сети IPv4 из ответа справочника о префиксах оператора.
pub fn parse_prefixes(json: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in json.split("\"prefix\"").skip(1) {
        let Some(start) = part.find('"') else { continue };
        let rest = &part[start + 1..];
        let Some(end) = rest.find('"') else { continue };
        let p = &rest[..end];
        // Только IPv4 и только похожее на сеть.
        if !p.contains(':') && p.contains('/') && p.split('.').count() == 4 && !out.contains(&p.to_string()) {
            out.push(p.to_string());
        }
    }
    out
}

/// Сети оператора, которому принадлежит адрес. `None` — выяснить не вышло
/// или оператор оказался облаком.
///
/// Best-effort целиком: любая осечка возвращает `None`, и вызывающий просто
/// оставляет /24. Сеть тут не обязана быть — сбор работает и без неё.
pub fn operator_prefixes(ip: &str) -> Option<Vec<String>> {
    let info = crate::maintenance::http_get(&format!(
        "https://stat.ripe.net/data/network-info/data.json?resource={ip}"
    ))
    .ok()?;
    let asn = parse_asn(&info)?;
    let list = crate::maintenance::http_get(&format!(
        "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    ))
    .ok()?;
    let pfx = parse_prefixes(&list);
    should_expand(pfx.len()).then_some(pfx)
}

/// Адрес сервера — это один из пула, а не единственный.
///
/// Матч подключается к ОДНОМУ серверу: за полминуты сбора их и набирается
/// один-два. Следующий матч даст соседний, и в списке его уже не будет —
/// собирать заново перед каждой игрой никто не станет.
///
/// Поэтому храним не адрес, а его сеть /24. Провайдер держит игровые
/// серверы пачками в одном блоке: поймав 146.66.155.73 у Valve, мы
/// накрываем и остальные её relay в 146.66.155.0/24. Шире брать не
/// стоит — /24 это один узел присутствия, а не половина интернета.
///
/// IPv6 оставляем как есть: там адресов столько, что нарезать их по
/// подсетям наугад смысла нет, а игровой трафик по IPv6 пока редкость.
pub fn to_subnet(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => {
            let o = v.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        _ => ip.to_string(),
    }
}

/// Куда класть собранные адреса.
///
/// У одних и тех же адресов два противоположных применения, и выбирать
/// между ними должен человек, а не мы за него:
///
/// * `Bypass` — игра заблокирована, обход должен до неё дотянуться. Адреса
///   идут в `ipset-all.txt`, по которому игровой профиль и решает, к чему
///   применяться.
/// * `Skip` — игра работает, а обход ей мешает. Адреса идут в
///   `ipset-exclude-user.txt`, и winws оставляет этот трафик в покое. Это
///   и есть здешний аналог `--lua-desync=pass` из наборов zapret2, где
///   игровой UDP Riot помечен «не трогать».
///
/// Второй случай не теоретический: на живом Valorant добавление серверов
/// Riot в `ipset-all.txt` включило на них `fake` с двенадцатью повторами,
/// и игра показала «высокий пинг» и «проблема с сетью».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Bypass,
    Skip,
}

impl Target {
    fn file(self) -> &'static str {
        match self {
            Target::Bypass => "ipset-all.txt",
            Target::Skip => "ipset-exclude-user.txt",
        }
    }
}

/// Кладёт собранные адреса в список релиза, не тронув чужие строки.
pub fn save_ips_to(
    root: &std::path::Path,
    target: Target,
    addrs: &[String],
) -> Result<usize, String> {
    let list = root.join("lists").join(target.file());
    let existing = std::fs::read_to_string(&list).unwrap_or_default();
    // К уже собранному добавляем, а не заменяем: сканов бывает несколько —
    // отдельно меню, отдельно матч, отдельно голосовой чат.
    let mut all: BTreeSet<String> = extract_block(&existing).into_iter().collect();
    for a in addrs {
        // Сети оператора, если удалось выяснить; иначе /24 вокруг адреса.
        // Один адрес одного оператора спрашиваем один раз: у пойманных
        // адресов оператор обычно общий.
        match operator_prefixes(a) {
            Some(pfx) => all.extend(pfx),
            None => {
                all.insert(to_subnet(a));
            }
        }
    }
    let all: Vec<String> = all.into_iter().collect();
    let merged = merge_block(&existing, &all);
    std::fs::write(&list, merged).map_err(|e| e.to_string())?;
    Ok(all.len())
}

/// Совместимость с прежними вызовами: по умолчанию — в обход.
pub fn save_ips(root: &std::path::Path, addrs: &[String]) -> Result<usize, String> {
    save_ips_to(root, Target::Bypass, addrs)
}

/// Какие наши адреса сейчас в списке.
pub fn saved_ips_in(root: &std::path::Path, target: Target) -> Vec<String> {
    std::fs::read_to_string(root.join("lists").join(target.file()))
        .map(|c| extract_block(&c))
        .unwrap_or_default()
}

pub fn saved_ips(root: &std::path::Path) -> Vec<String> {
    saved_ips_in(root, Target::Bypass)
}

/// Убирает наш блок целиком, оставив чужое как было.
pub fn clear_ips_in(root: &std::path::Path, target: Target) -> Result<(), String> {
    let list = root.join("lists").join(target.file());
    let existing = std::fs::read_to_string(&list).unwrap_or_default();
    std::fs::write(&list, merge_block(&existing, &[])).map_err(|e| e.to_string())
}

pub fn clear_ips(root: &std::path::Path) -> Result<(), String> {
    clear_ips_in(root, Target::Bypass)
}

// ─────────── сбор из лога самого winws ───────────
//
// Зачем это отдельно от netstat. Таблица сокетов показывает удалённый адрес
// только у СОЕДИНЁННЫХ сокетов. Игровой матч так не ходит: он шлёт пакеты
// через sendto, и в таблице напротив такого сокета стоит «*:*». Замерено на
// живой машине: из 77 строк UDP удалённый адрес был у двух, и одна из них
// петля. То есть главный трафик игры этим способом не увидеть в принципе.
//
// А winws сидит на WinDivert и видит сами пакеты. С `--debug=1` он печатает
// каждый, который попал под `--wf-*`, — включая тот самый несоединённый UDP.
// Klutz его вывод и так перехватывает, остаётся разобрать строки.
//
// Оговорка, которой тут сперва не было: печатает он их в своём формате, и
// пока разбор его не понимал, всё это не имело значения. Сбор «работал» и
// находил единицы адресов из редких строк другого вида.

/// Адрес назначения из строки лога winws, если он там есть.
///
/// Две формы, обе встречаются в его выводе:
///   `TCP [1.2.3.4]:52000 => [5.6.7.8]:27015 : ...`
///   `dpi desync src=1.2.3.4:52000 dst=5.6.7.8:27015`
/// Разбираем обе и не привязываемся к остальному тексту: он меняется от
/// версии к версии, а адрес — нет.
pub fn parse_log_addr(line: &str) -> Option<LogAddr> {
    let proto = if line.to_ascii_lowercase().contains("proto=udp") || line.contains("UDP") {
        Proto::Udp
    } else {
        Proto::Tcp
    };

    // Форма «dpi desync»: адрес с портом прямо в поле.
    if let Some(rest) = line.split("dst=").nth(1) {
        if let Some(token) = rest.split_whitespace().next() {
            if let Some((ip, port)) = split_addr(token) {
                return Some(LogAddr { ip, port, proto, sport: поле(line, "sport=") });
            }
        }
    }

    // Основная форма пакета. Собрана у winws из отдельных кусков и
    // выглядит так:
    //   IP4: 192.168.1.16 => 104.21.43.64 proto=udp ttl=128 sport=50282 dport=443
    // Порт тут ОТДЕЛЬНЫМ полем, а не после адреса. Я этого сперва не
    // учёл: разбор ждал «=> адрес:порт», на этих строках возвращал пусто,
    // и сбор работал только на редких строках «dpi desync». Отсюда и
    // выходили единицы адресов вместо десятков.
    if let Some(rest) = line.split("=> ").nth(1) {
        if let Some(token) = rest.split_whitespace().next() {
            // Сначала форма, где порт рядом с адресом: [1.2.3.4]:27015.
            // Разбираем ИСХОДНЫЙ токен: обрезав скобки заранее, мы
            let bare = token.trim_matches(|c| c == '[' || c == ']');
            if let Ok(ip) = bare.parse::<IpAddr>() {
                if let Some(port) = поле(line, "dport=") {
                    return Some(LogAddr { ip, port, proto, sport: поле(line, "sport=") });
                }
            }
            // И старая форма conntrack, где порт всё-таки рядом с адресом.
            if let Some((ip, port)) = split_addr(token) {
                return Some(LogAddr { ip, port, proto, sport: поле(line, "sport=") });
            }
        }
    }
    None
}

/// Адрес из строки лога вместе с тем, что о нём известно.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogAddr {
    pub ip: IpAddr,
    pub port: u16,
    pub proto: Proto,
    /// Исходящий порт. По нему пакет можно привязать к процессу: локальные
    /// порты у процесса система показывает даже для несоединённого UDP.
    pub sport: Option<u16>,
}

/// Числовое поле вида `имя=1234` из строки лога.
fn поле(line: &str, name: &str) -> Option<u16> {
    line.split(name)
        .nth(1)?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// Копилка адресов, пока идёт сбор из лога. `None` — сбор не идёт, и тогда
/// строки лога через неё просто пролетают.
pub static HARVEST: std::sync::Mutex<Option<BTreeSet<String>>> = std::sync::Mutex::new(None);

pub fn harvest_start() {
    *HARVEST.lock().unwrap_or_else(|e| e.into_inner()) = Some(BTreeSet::new());
}

/// Останавливает сбор и отдаёт накопленное.
pub fn harvest_stop() -> Vec<String> {
    HARVEST
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .map(|s| s.into_iter().collect())
        .unwrap_or_default()
}

pub fn harvest_active() -> bool {
    HARVEST.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// Сколько адресов накопилось прямо сейчас.
pub fn harvest_len() -> usize {
    HARVEST
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|s| s.len())
        .unwrap_or(0)
}

/// Скармливает строку лога копилке. Зовётся на каждой строке winws, поэтому
/// сперва самая дешёвая проверка — идёт ли сбор вообще.
pub fn harvest_line(line: &str) {
    let mut g = HARVEST.lock().unwrap_or_else(|e| e.into_inner());
    let Some(set) = g.as_mut() else { return };
    if let Some(a) = parse_log_addr(line) {
        if is_external(&a.ip) && стоит_собирать(a.proto, a.port) {
            set.insert(a.ip.to_string());
        }
    }
}

/// Порты, по которым ходит веб помимо 80 и 443.
///
/// Это альтернативные HTTPS-порты Cloudflare, и они не выдуманы: ровно этот
/// список стоит в веб-фильтре конфигов релиза рядом с 80 и 443. По ним
/// ходит Discord, и на живом тесте оттуда в игровой список утёк
/// 104.29.153.0/24 — сеть Cloudflare, к играм отношения не имеющая.
///
/// Адресу сайта в игровом списке не место: свои профили к нему применяются
/// и так, а попав сюда, он получил бы вдобавок настройки игрового, которые
/// рассчитаны совсем на другой трафик.
fn веб_порт(port: u16) -> bool {
    // Полный набор альтернативных портов Cloudflare, а не только те, что
    // попались на тесте: HTTP — 8080, 8880, 2052, 2082, 2086, 2095;
    // HTTPS — 2053, 2083, 2087, 2096, 8443. Игровых среди них нет.
    matches!(
        port,
        80 | 443 | 2052 | 2053 | 2082 | 2083 | 2086 | 2087 | 2095 | 2096 | 8080 | 8443 | 8880
    )
}

/// Стоит ли класть в игровой список адрес с этого порта и протокола.
///
/// Правило разное для TCP и UDP, и вот почему. Снятый с Valorant трафик
/// показал: по TCP он ходит ТОЛЬКО в веб — Cloudflare на 443, чат на 5223,
/// античит на 8443. Ни одного игрового адреса по TCP там нет вовсе, зато
/// пролезала чужая сеть Cloudflare. А у CS2 по TCP есть настоящий игровой
/// адрес — менеджер соединений Steam на 27018.
///
/// Значит для TCP нужен известный игровой диапазон, а не «всё, кроме
/// веба»: слишком много веба ходит по нестандартным портам, и каждый раз
/// он оказывается в игровом списке. Для UDP наоборот — там почти не бывает
/// ничего, кроме игр и QUIC, и ограничивать диапазоном значило бы
/// пропустить игру на неизвестном порту.
fn стоит_собирать(proto: Proto, port: u16) -> bool {
    if port < 1024 || веб_порт(port) || служебный_порт(port) {
        return false;
    }
    match proto {
        Proto::Udp => true,
        Proto::Tcp => игровой_порт(port),
    }
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
/// Заглушка «список загружен, но пуст». Адрес из TEST-NET-3 (RFC 5737),
/// который не ответит никогда.
///
/// Она не косметика. У winws ПУСТОЙ ipset означает «без ограничения по
/// адресу»: профиль начинает применяться ко всему подряд на своих портах.
/// Для игрового профиля это худший из возможных исходов — обход лезет в
/// каждый матч. Поэтому, убрав свои адреса, мы обязаны вернуть заглушку, а
/// не оставить файл пустым.
pub const EMPTY_STUB: &str = "203.0.113.113/32";

pub fn merge_block(existing: &str, addrs: &[String]) -> String {
    // Заглушку выбрасываем, только когда есть чем её заменить: рядом с
    // настоящими адресами она бессмысленна, а вместо них — необходима.
    let base: Vec<String> = without_block(existing)
        .lines()
        .filter(|l| addrs.is_empty() || !l.trim().starts_with("203.0.113.113"))
        .map(|l| l.to_string())
        .collect();
    let mut out = base.join("\r\n").trim_end().to_string();
    if addrs.is_empty() {
        // Своих адресов нет и чужих строк не осталось — возвращаем заглушку.
        // Пустой файл тут значит «применяться ко всему», и кнопка «Убрать»
        // молча включала бы обход на весь игровой трафик.
        if out.is_empty() {
            return format!("{EMPTY_STUB}\r\n");
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
            (101, "chrome.exe".to_string()),
            (202, "cs2.exe".to_string()),
            (303, "svchost.exe".to_string()),
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
            c(101, "104.16.0.1", 443),
            c(101, "104.16.0.2", 443),
            c(101, "104.16.0.3", 443),
            c(101, "104.16.0.4", 443),
            c(303, "20.1.1.1", 443),
            // А у игры свой порт.
            c(202, "162.159.135.232", 27018),
        ];
        assert_eq!(guess_game(&conns, &names).as_deref(), Some("cs2.exe"));
    }

    #[test]
    fn без_признаков_игры_честно_отвечаем_что_не_нашли() {
        use std::collections::HashMap;
        // Никто не ходит по игровым портам: только веб. Прежняя версия
        // выбирала «самого активного», и это было выдумкой — теперь
        // ответ «не нашли», а интерфейс попросит запустить игру.
        let names: HashMap<u32, String> = [
            (101, "chrome.exe".to_string()),
            (202, "SomeApp.exe".to_string()),
        ]
        .into_iter()
        .collect();
        let c = |pid, ip: &str, port| Conn { pid, proto: Proto::Tcp, ip: ip.parse().unwrap(), port };
        let conns = vec![c(101, "1.1.1.1", 443), c(101, "1.1.1.2", 80), c(202, "8.8.8.8", 443)];
        assert_eq!(guess_game(&conns, &names), None);
        assert!(candidates(&conns, &names).is_empty());
    }

    #[test]
    fn псевдопроцессы_в_кандидаты_не_идут() {
        use std::collections::HashMap;
        // Ровно то, что вылезло на тесте: netstat отдал закрывающиеся
        // соединения на игровых портах, повесив их на PID 0, и он вышел
        // в кандидаты впереди Steam.
        let names: HashMap<u32, String> = [
            (0, "System Idle Process".to_string()),
            (4, "System".to_string()),
            (100, "steam.exe".to_string()),
        ]
        .into_iter()
        .collect();
        let c = |pid, ip: &str, port| Conn { pid, proto: Proto::Tcp, ip: ip.parse().unwrap(), port };
        let conns = vec![
            c(0, "104.16.0.1", 1119),
            c(0, "104.16.0.2", 27018),
            c(4, "104.16.0.3", 27015),
            c(100, "155.133.226.76", 27023),
        ];
        let got = candidates(&conns, &names);
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].name, "steam.exe");
    }

    #[test]
    fn служебный_порт_за_игру_не_сходит() {
        use std::collections::HashMap;
        // Ровно тот случай, на котором эвристика однажды и попалась:
        // служба HP стучалась на 5228 — это уведомления Google, не игра.
        let names: HashMap<u32, String> = [(404, "happd.exe".to_string())].into_iter().collect();
        let conns = vec![Conn {
            pid: 404,
            proto: Proto::Tcp,
            ip: "142.250.153.188".parse().unwrap(),
            port: 5228,
        }];
        assert_eq!(guess_game(&conns, &names), None);
    }

    #[test]
    fn udp_на_высоком_порту_весит_больше_веба() {
        use std::collections::HashMap;
        let names: HashMap<u32, String> = [
            (101, "launcher.exe".to_string()),
            (202, "VALORANT-Win64-Shipping.exe".to_string()),
        ]
        .into_iter()
        .collect();
        // Лаунчер держит кучу TCP на игровом порту, игра — один UDP.
        let mut conns: Vec<Conn> = (0..3)
            .map(|i| Conn {
                pid: 101,
                proto: Proto::Tcp,
                ip: format!("104.16.0.{i}").parse().unwrap(),
                port: 7000,
            })
            .collect();
        conns.push(Conn {
            pid: 202,
            proto: Proto::Udp,
            ip: "162.159.1.1".parse().unwrap(),
            port: 5060,
        });
        let c = candidates(&conns, &names);
        // Оба попали в кандидаты — выбор остаётся за человеком.
        assert_eq!(c.len(), 2, "{c:?}");
        assert!(c.iter().any(|x| x.name.contains("VALORANT")), "{c:?}");
        assert!(c.iter().any(|x| x.name == "launcher.exe"), "{c:?}");
    }

    #[test]
    fn внутренние_адреса_в_догадку_не_идут() {
        use std::collections::HashMap;
        let names: HashMap<u32, String> = [(202, "game.exe".to_string())].into_iter().collect();
        let conns = vec![Conn {
            pid: 202,
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
    fn убрав_адреса_возвращаем_заглушку_а_не_пустоту() {
        // Пустой ipset у winws значит «применяться ко всему». Если кнопка
        // «Убрать» оставит файл пустым, обход полезет в каждый матч — то
        // есть станет хуже, чем было до сбора.
        let было = [BLOCK_START, "146.66.155.0/24", BLOCK_END].join("\r\n");
        let стало = merge_block(&было, &[]);
        assert!(стало.contains(EMPTY_STUB), "{стало:?}");
        assert!(!стало.contains("146.66.155"), "{стало:?}");
        // А когда есть настоящие адреса, заглушка не нужна.
        let стало = merge_block(EMPTY_STUB, &["146.66.155.0/24".to_string()]);
        assert!(!стало.contains(EMPTY_STUB), "{стало:?}");
    }

    #[test]
    fn пустой_набор_убирает_блок_целиком() {
        let текст = ["7.7.7.7", BLOCK_START, "1.2.3.4", BLOCK_END].join("\r\n");
        let стало = merge_block(&текст, &[]);
        assert!(стало.contains("7.7.7.7"), "{стало}");
        assert!(!стало.contains("1.2.3.4"), "{стало}");
        assert!(!стало.contains("klutz"), "{стало}");
        // И на совсем пустом входе получаем заглушку, а не пустоту:
        // пустой список у winws означает «применяться ко всему».
        assert_eq!(merge_block("", &[]), format!("{EMPTY_STUB}\r\n"));
    }

    #[test]
    fn адрес_из_строки_лога_winws() {
        // Форма conntrack.
        let a = parse_log_addr("UDP [192.168.1.5]:52000 => [162.159.135.232]:27015 : t0=1").unwrap();
        let (ip, port) = (a.ip, a.port);
        assert_eq!(ip.to_string(), "162.159.135.232");
        assert_eq!(port, 27015);

        // Форма «dpi desync». Она важнее: у неё dst стоит явно, и её мы
        // проверяем первой.
        let a = parse_log_addr("dpi desync src=192.168.1.5:52000 dst=104.16.0.1:443").unwrap();
        let (ip, port) = (a.ip, a.port);
        assert_eq!(ip.to_string(), "104.16.0.1");
        assert_eq!(port, 443);

        // IPv6 в скобках.
        let a = parse_log_addr("TCP [fe80::1]:1 => [2606:4700::1]:443 : x").unwrap();
        let (ip, _) = (a.ip, a.port);
        assert_eq!(ip.to_string(), "2606:4700::1");
    }

    #[test]
    fn настоящая_строка_пакета_winws_разбирается() {
        // Ровно так winws собирает её из своих кусков: «IP4: %s», «%s => %s»,
        // «%s proto=%s ttl=%u», «sport=%u dport=%u». Порт стоит ОТДЕЛЬНЫМ
        // полем, и на этом разбор сперва и спотыкался — а это основная
        // форма, ради которой всё затевалось.
        let a = parse_log_addr(
            "IP4: 192.168.1.16 => 104.21.43.64 proto=udp ttl=128 sport=50282 dport=27015",
        )
        .unwrap();
        assert_eq!(a.ip.to_string(), "104.21.43.64");
        assert_eq!(a.port, 27015);
        assert_eq!(a.proto, Proto::Udp);
        assert_eq!(a.sport, Some(50282), "исходящий порт нужен для привязки к процессу");

        // TCP-вариант с флагами.
        let a = parse_log_addr(
            "IP4: 192.168.1.16 => 146.66.155.73 proto=tcp ttl=128 sport=51000 dport=27018 flags=S seq=1 ack_seq=0",
        )
        .unwrap();
        assert_eq!(a.port, 27018);
        assert_eq!(a.proto, Proto::Tcp);
    }

    #[test]
    fn посторонние_строки_лога_не_дают_адресов() {
        for line in [
            "",
            "packet contains TLS ClientHello",
            "Window size change 64240 => 512",
            "rewrite original packet ttl 128 => 64",
            "sending 6 dups with ttl rewrite 128 => 64",
            "hostname: discord.com",
        ] {
            assert_eq!(parse_log_addr(line), None, "{line:?}");
        }
    }

    /// Копилка одна на процесс, а тестов, которые её трогают, несколько.
    /// Cargo гоняет их параллельно, и без этого замка они отбирали бы
    /// накопленное друг у друга — тест мигал бы через раз.
    static ТЕСТ_КОПИЛКИ: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Живая проверка цепочки: адрес -> оператор -> все его сети.
    /// cargo test -- --ignored живой_оператор --nocapture
    #[test]
    #[ignore]
    fn живой_оператор_по_адресу() {
        // Пойманные на этой машине адреса Riot и Valve.
        for ip in ["185.40.64.5", "162.249.72.10", "146.66.155.73"] {
            let got = operator_prefixes(ip);
            println!("{ip}: {:?} сетей", got.as_ref().map(|v| v.len()));
            let pfx = got.unwrap_or_else(|| panic!("{ip}: оператор не определился"));
            assert!(!pfx.is_empty());
            assert!(pfx.iter().all(|p| p.contains('/')));
        }
        // А облако разворачивать нельзя — у него тысячи сетей.
        let cf = operator_prefixes("104.29.153.1");
        println!("Cloudflare: {:?}", cf.as_ref().map(|v| v.len()));
        assert!(cf.is_none(), "облако не должно разворачиваться");
    }

    #[test]
    fn облако_целиком_в_список_не_тащим() {
        // Замерено: Riot объявляет 36 сетей, Valve 45 — их берём целиком.
        assert!(should_expand(36), "Riot");
        assert!(should_expand(45), "Valve");
        // А Cloudflare 2395, Google 1233, Amazon 18020 — это облака, и
        // затащить их в игровой список значит направить обход на
        // пол-интернета.
        assert!(!should_expand(2395), "Cloudflare");
        assert!(!should_expand(1233), "Google");
        assert!(!should_expand(18020), "Amazon");
        // Пустой ответ — не повод ничего разворачивать.
        assert!(!should_expand(0));
    }

    #[test]
    fn разбор_ответов_справочника() {
        // Форма ответа про сеть.
        let j = r#"{"data":{"prefix":"185.40.64.0/24","asns":["6507"]}}"#;
        assert_eq!(parse_asn(j).as_deref(), Some("6507"));
        // Несколько операторов — берём первого.
        let j2 = r#"{"data":{"asns":["32590","1234"]}}"#;
        assert_eq!(parse_asn(j2).as_deref(), Some("32590"));
        // Мусор не должен ломать.
        assert_eq!(parse_asn("{}"), None);
        assert_eq!(parse_asn(""), None);
        assert_eq!(parse_asn(r#"{"asns":[]}"#), None);

        // Форма ответа про сети оператора.
        let p = r#"{"data":{"prefixes":[{"prefix":"162.249.72.0/21"},{"prefix":"2a04::/32"},{"prefix":"185.40.64.0/24"},{"prefix":"162.249.72.0/21"}]}}"#;
        let got = parse_prefixes(p);
        assert_eq!(got, vec!["162.249.72.0/21", "185.40.64.0/24"], "IPv6 и повторы отсеяны");
        assert!(parse_prefixes("{}").is_empty());
    }

    #[test]
    fn адрес_расширяется_до_подсети() {
        // Пойманный сервер — один из пула: следующий матч даст соседний.
        assert_eq!(to_subnet("146.66.155.73"), "146.66.155.0/24");
        assert_eq!(to_subnet("155.133.226.68"), "155.133.226.0/24");
        // Уже сеть или IPv6 — оставляем как есть.
        assert_eq!(to_subnet("2606:4700::1"), "2606:4700::1");
        assert_eq!(to_subnet("не адрес"), "не адрес");
    }

    #[test]
    fn по_tcp_берём_только_игровые_порты_а_по_udp_всё() {
        // Снято с живого Valorant: по TCP он ходит ТОЛЬКО в веб, и оттуда
        // в игровой список лезла чужая сеть Cloudflare. Игрового адреса по
        // TCP у него нет вовсе.
        assert!(!стоит_собирать(Proto::Tcp, 443));
        assert!(!стоит_собирать(Proto::Tcp, 5223), "чат Riot — это не игра");
        assert!(!стоит_собирать(Proto::Tcp, 8443), "античит по HTTPS");
        assert!(!стоит_собирать(Proto::Tcp, 49152), "случайный высокий порт");
        // А у CS2 по TCP игровой адрес есть — менеджер соединений Steam.
        assert!(стоит_собирать(Proto::Tcp, 27018));
        assert!(стоит_собирать(Proto::Tcp, 1119), "Battle.net");
        // По UDP берём широко: там почти не бывает ничего, кроме игр, и
        // ограничив диапазоном, мы пропустили бы игру на чужом порту.
        assert!(стоит_собирать(Proto::Udp, 27015));
        assert!(стоит_собирать(Proto::Udp, 7000));
        assert!(стоит_собирать(Proto::Udp, 61337), "неизвестный порт — всё равно берём");
        // Но и там веб со служебным не нужны.
        assert!(!стоит_собирать(Proto::Udp, 443), "QUIC — это веб");
        assert!(!стоит_собирать(Proto::Udp, 53), "DNS");
    }

    #[test]
    fn веб_в_игровой_список_не_попадает() {
        let _g = ТЕСТ_КОПИЛКИ.lock().unwrap_or_else(|e| e.into_inner());
        harvest_start();
        // Игровой порт — берём.
        harvest_line("UDP [1.1.1.1]:1 => [162.159.135.232]:27015 : x");
        // Веб — нет: у сайтов свои профили, и чужие настройки им не нужны.
        harvest_line("TCP [1.1.1.1]:1 => [104.16.0.1]:443 : x");
        harvest_line("TCP [1.1.1.1]:1 => [104.16.0.2]:80 : x");
        // И альтернативные HTTPS-порты Cloudflare — на живом тесте через
        // них в игровой список утёк Discord.
        for p in [2053, 2083, 2087, 2096, 8443] {
            harvest_line(&format!("TCP [1.1.1.1]:1 => [104.29.153.5]:{p} : x"));
        }
        // Служебное — тоже нет.
        harvest_line("TCP [1.1.1.1]:1 => [142.250.153.188]:5228 : x");
        let got = harvest_stop();
        assert_eq!(got, vec!["162.159.135.232"], "{got:?}");
    }

    #[test]
    fn копилка_берёт_только_внешние_и_только_когда_включена() {
        let _g = ТЕСТ_КОПИЛКИ.lock().unwrap_or_else(|e| e.into_inner());
        // Выключена — строки пролетают мимо.
        assert!(!harvest_active());
        harvest_line("UDP [1.1.1.1]:1 => [104.16.0.1]:27015 : x");
        assert_eq!(harvest_len(), 0);

        harvest_start();
        assert!(harvest_active());
        harvest_line("UDP [1.1.1.1]:1 => [104.16.0.1]:27015 : x");
        // Домашний роутер в обход попасть не должен.
        harvest_line("UDP [1.1.1.1]:1 => [192.168.1.1]:27015 : x");
        harvest_line("мусор");
        assert_eq!(harvest_len(), 1);

        let got = harvest_stop();
        assert_eq!(got, vec!["104.16.0.1"]);
        assert!(!harvest_active(), "после остановки сбор не идёт");
    }

    /// Живая проверка: `cargo test -- --ignored живой_скан --nocapture`.
    #[test]
    #[ignore]
    fn живой_скан_таблицы_соединений() {
        let all = connections();
        let ext = all.iter().filter(|c| is_external(&c.ip)).count();
        println!("соединений: {}, из них внешних: {ext}", all.len());
        let names = process_names();
        for c in candidates(&all, &names) {
            println!("кандидат: {} вес={} адресов={} порты={:?}", c.name, c.score, c.addrs, c.ports);
        }
        assert!(!all.is_empty(), "таблица соединений пуста — netstat не отработал");
    }
}
