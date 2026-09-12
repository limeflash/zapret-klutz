//! Предтест фрагментацией: «поможет ли обход здесь вообще».
//!
//! Оракул из `probe.rs` отвечает, ГДЕ режут — по имени или по адресу. Этот
//! отвечает на следующий вопрос: если режут по имени, лечится ли это тем
//! способом, которым лечит zapret.
//!
//! Приём тот же, что применяет сам zapret, и он публично описан: отправить
//! ClientHello, разрезанный по TCP-сегментам ВНУТРИ имени хоста. Коробка,
//! разбирающая каждый сегмент отдельно, имени целиком не увидит и пропустит.
//! Коробка, пересобирающая поток, увидит — и тогда весь класс стратегий с
//! разрезом бесполезен, сколько их ни перебирай.
//!
//! Зачем это Klutz. Сейчас единственный способ узнать, поможет ли
//! что-нибудь, — прогнать через PowerShell-скрипт все двадцать с лишним
//! конфигов, а это минуты. Здесь ответ за пару секунд и ДО прогона.
//!
//! ClientHello собираем свой, потому что curl такого не умеет: нужно
//! положить разрез в заранее известное место внутри имени. Рукопожатие мы
//! не доводим до конца — достаточно узнать, вернулось ли хоть что-то.

use serde::Serialize;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

/// Чем закончилась отправка одного ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChOutcome {
    /// Пришли байты в ответ. Что именно — ServerHello, alert, что угодно —
    /// неважно: путь до сервера живой.
    Answered,
    /// Соединение сброшено. Классическая подпись коробки, увидевшей имя.
    Reset,
    /// Тишина до таймаута или закрытие без единого байта.
    Silent,
    /// Не удалось даже подключиться — мерить нечего.
    NoConnect,
}

impl ChOutcome {
    fn passed(self) -> bool {
        self == ChOutcome::Answered
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FragVerdict {
    /// Целый ClientHello и так проходит — резать нечего.
    NotBlocked,
    /// Целый режут, разрезанный проходит. Стратегии со split применимы.
    Helps,
    /// Режут и разрезанный тоже: коробка пересобирает сегменты либо дело не
    /// в имени. Перебор split-стратегий ничего не даст.
    DoesNotHelp,
    /// Подключиться не вышло или результат не воспроизвёлся.
    Inconclusive,
}

#[derive(Debug, Clone, Serialize)]
pub struct FragProbe {
    pub whole: ChOutcome,
    pub split: ChOutcome,
    pub verdict: FragVerdict,
    /// Фраза для человека — её же кладём в лог прогона тестов.
    pub note: String,
}

// ───────────────────────── сборка ClientHello ─────────────────────────

fn u16b(v: usize) -> [u8; 2] {
    [(v >> 8) as u8, v as u8]
}

/// Дописывает блок, длина которого стоит впереди двумя байтами.
fn push_len16(out: &mut Vec<u8>, body: &[u8]) {
    out.extend_from_slice(&u16b(body.len()));
    out.extend_from_slice(body);
}

/// Расширение TLS: тип, длина, тело.
fn ext(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
    out.extend_from_slice(&u16b(kind as usize));
    push_len16(out, body);
}

/// Собранный ClientHello и позиция имени хоста внутри него.
pub struct ClientHello {
    pub bytes: Vec<u8>,
    /// Смещение первого байта имени хоста в `bytes`.
    pub sni_offset: usize,
    pub sni_len: usize,
}

impl ClientHello {
    /// Куда резать, чтобы разрыв пришёлся ВНУТРИ имени. Имя короче двух
    /// байт разрезать смысла нет — тогда режем сразу после его начала.
    pub fn split_at(&self) -> usize {
        self.sni_offset + (self.sni_len / 2).max(1)
    }
}

/// Собирает ClientHello с заданным именем.
///
/// Набор расширений подобран так, чтобы ответил и сервер TLS 1.2, и 1.3:
/// есть supported_versions и key_share, поэтому 1.3-сервер отвечает сразу
/// ServerHello, без HelloRetryRequest. Ключ в key_share — случайные 32
/// байта: любая такая строка годится как публичный ключ x25519, а
/// рукопожатие нам всё равно не доводить.
pub fn build_client_hello(sni: &str) -> ClientHello {
    let mut rnd = [0u8; 64];
    if !crate::sys::os_random(&mut rnd) {
        // ГСЧ недоступен — на результат пробы это не влияет, важна лишь
        // непохожесть байтов на константу.
        for (i, b) in rnd.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
    }

    let mut body: Vec<u8> = Vec::with_capacity(512);
    body.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
    body.extend_from_slice(&rnd[..32]); // random
    body.push(32); // session_id
    body.extend_from_slice(&rnd[32..64]);

    // Наборы шифров: три от TLS 1.3 плюс обычная современная выборка.
    let suites: [u16; 12] = [
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0x009c, 0x009d,
        0x002f,
    ];
    let mut s = Vec::with_capacity(suites.len() * 2);
    for c in suites {
        s.extend_from_slice(&u16b(c as usize));
    }
    push_len16(&mut body, &s);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null

    // ── расширения ──
    let mut exts: Vec<u8> = Vec::with_capacity(256);

    // server_name. Запоминаем, где внутри ЭТОГО буфера легло имя, чтобы
    // потом пересчитать смещение в готовой записи.
    let name = sni.as_bytes();
    let mut sni_body = Vec::with_capacity(name.len() + 5);
    sni_body.extend_from_slice(&u16b(name.len() + 3)); // длина списка имён
    sni_body.push(0x00); // тип: host_name
    sni_body.extend_from_slice(&u16b(name.len()));
    let sni_at_in_sni_body = sni_body.len();
    sni_body.extend_from_slice(name);
    // +4 — заголовок расширения (тип и длина), который допишет ext().
    let sni_at_in_exts = exts.len() + 4 + sni_at_in_sni_body;
    ext(&mut exts, 0x0000, &sni_body);

    ext(&mut exts, 0x0017, &[]); // extended_master_secret
    ext(&mut exts, 0x0023, &[]); // session_ticket
    ext(&mut exts, 0x000b, &[0x01, 0x00]); // ec_point_formats: uncompressed
    ext(&mut exts, 0x000a, &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18]); // groups
    ext(
        &mut exts,
        0x000d, // signature_algorithms
        &[
            0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01,
            0x08, 0x06, 0x06, 0x01,
        ],
    );
    ext(&mut exts, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]); // supported_versions: 1.3, 1.2
    ext(&mut exts, 0x002d, &[0x01, 0x01]); // psk_key_exchange_modes
    // ALPN: h2, http/1.1
    ext(
        &mut exts,
        0x0010,
        &[
            0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ],
    );
    // key_share: x25519 со случайным ключом
    let mut ks = Vec::with_capacity(40);
    ks.extend_from_slice(&u16b(36)); // длина списка
    ks.extend_from_slice(&u16b(0x001d)); // x25519
    ks.extend_from_slice(&u16b(32));
    ks.extend_from_slice(&rnd[..32]);
    ext(&mut exts, 0x0033, &ks);

    push_len16(&mut body, &exts);
    // Заголовок расширений — два байта длины, они уже перед exts.
    let sni_at_in_body = body.len() - exts.len() + sni_at_in_exts;

    // ── handshake ──
    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(0x01); // client_hello
    hs.extend_from_slice(&[(body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8]);
    hs.extend_from_slice(&body);
    let sni_at_in_hs = 4 + sni_at_in_body;

    // ── запись ──
    let mut rec = Vec::with_capacity(hs.len() + 5);
    rec.push(0x16); // handshake
    rec.extend_from_slice(&[0x03, 0x01]); // legacy record version
    rec.extend_from_slice(&u16b(hs.len()));
    rec.extend_from_slice(&hs);

    ClientHello { bytes: rec, sni_offset: 5 + sni_at_in_hs, sni_len: name.len() }
}

// ───────────────────────────── отправка ─────────────────────────────

/// Отправляет ClientHello и ждёт хоть какого-нибудь ответа.
///
/// При `fragment` запись уходит двумя порциями с разрывом внутри имени.
/// TCP_NODELAY обязателен: без него Nagle склеил бы обе записи в один
/// сегмент, и проверка потеряла бы смысл.
pub fn send_ch(ip: IpAddr, port: u16, sni: &str, fragment: bool, timeout: Duration) -> ChOutcome {
    let addr = SocketAddr::new(ip, port);
    let Ok(mut sock) = TcpStream::connect_timeout(&addr, timeout) else {
        return ChOutcome::NoConnect;
    };
    let _ = sock.set_nodelay(true);
    let _ = sock.set_write_timeout(Some(timeout));
    let _ = sock.set_read_timeout(Some(timeout));

    let ch = build_client_hello(sni);
    let write_res = if fragment {
        let at = ch.split_at().min(ch.bytes.len());
        match sock.write_all(&ch.bytes[..at]).and_then(|_| sock.flush()) {
            Ok(()) => {
                // Пауза, чтобы вторая часть точно уехала отдельным сегментом.
                std::thread::sleep(Duration::from_millis(40));
                sock.write_all(&ch.bytes[at..]).and_then(|_| sock.flush())
            }
            Err(e) => Err(e),
        }
    } else {
        sock.write_all(&ch.bytes).and_then(|_| sock.flush())
    };
    if let Err(e) = write_res {
        return outcome_from_err(&e);
    }

    let mut buf = [0u8; 64];
    match sock.read(&mut buf) {
        Ok(0) => ChOutcome::Silent,
        Ok(_) => ChOutcome::Answered,
        Err(e) => outcome_from_err(&e),
    }
}

fn outcome_from_err(e: &std::io::Error) -> ChOutcome {
    match e.kind() {
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
            ChOutcome::Reset
        }
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => ChOutcome::Silent,
        _ => ChOutcome::Silent,
    }
}

/// Чистое правило вердикта — сеть дёргает вызывающий.
pub fn classify_frag(whole: ChOutcome, split: ChOutcome) -> (FragVerdict, String) {
    if whole == ChOutcome::NoConnect || split == ChOutcome::NoConnect {
        return (
            FragVerdict::Inconclusive,
            "до адреса не достучались — про фрагментацию сказать нечего".into(),
        );
    }
    if whole.passed() {
        return (
            FragVerdict::NotBlocked,
            "целый ClientHello доходит — резать нечего, дело не в имени".into(),
        );
    }
    if split.passed() {
        (
            FragVerdict::Helps,
            "целый ClientHello режут, а разрезанный по сегментам проходит — \
             стратегии с разрезом здесь работают, подбор имеет смысл"
                .into(),
        )
    } else {
        (
            FragVerdict::DoesNotHelp,
            "режут и целый, и разрезанный: коробка пересобирает сегменты либо \
             дело не в имени — перебирать стратегии с разрезом бесполезно"
                .into(),
        )
    }
}

/// Полная проба: целый ClientHello, затем разрезанный.
pub fn probe_fragmentation(ip: IpAddr, port: u16, sni: &str, timeout: Duration) -> FragProbe {
    let whole = send_ch(ip, port, sni, false, timeout);
    // Разрезанный шлём, только если целый не прошёл: иначе платили бы вторым
    // соединением за вопрос, ответ на который уже известен.
    let split = if whole.passed() {
        ChOutcome::Answered
    } else {
        send_ch(ip, port, sni, true, timeout)
    };
    let (verdict, note) = classify_frag(whole, split);
    FragProbe { whole, split, verdict, note }
}


/// Сводит вердикты по нескольким целям в один.
///
/// Достаточно ОДНОЙ цели, где фрагментация помогает, чтобы подбор имел
/// смысл: стратегия применяется ко всем сразу, и вытащить хотя бы часть
/// уже выигрыш. А вот «бесполезно» говорим только когда ни одна цель
/// надежды не подала.
pub fn aggregate(verdicts: &[FragVerdict]) -> (FragVerdict, String) {
    use FragVerdict::*;
    if verdicts.contains(&Helps) {
        return (
            Helps,
            "разрез ClientHello пробивает — стратегии zapret здесь применимы, подбор имеет смысл"
                .into(),
        );
    }
    if verdicts.contains(&DoesNotHelp) {
        return (
            DoesNotHelp,
            "разрез ClientHello не пробивает ни одну цель: коробка пересобирает сегменты              либо режут не по имени. Перебор стратегий, скорее всего, ничего не даст"
                .into(),
        );
    }
    if !verdicts.is_empty() && verdicts.iter().all(|v| *v == NotBlocked) {
        return (NotBlocked, "цели и так открываются — подбирать нечего".into());
    }
    (Inconclusive, "проверить не удалось — до целей не достучались".into())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn проверить_рамки(ch: &ClientHello) {
        let b = &ch.bytes;
        assert_eq!(b[0], 0x16, "тип записи handshake");
        assert_eq!(&b[1..3], &[0x03, 0x01], "legacy-версия записи");
        let rec_len = u16::from_be_bytes([b[3], b[4]]) as usize;
        assert_eq!(rec_len, b.len() - 5, "длина записи должна совпадать с телом");

        assert_eq!(b[5], 0x01, "client_hello");
        let hs_len = ((b[6] as usize) << 16) | ((b[7] as usize) << 8) | b[8] as usize;
        assert_eq!(hs_len, b.len() - 9, "длина handshake должна совпадать");
    }

    #[test]
    fn длины_сходятся_на_любом_имени() {
        for sni in ["a", "discord.com", "redirector.googlevideo.com", "очень-длинное-имя.example"] {
            let ch = build_client_hello(sni);
            проверить_рамки(&ch);
        }
    }

    #[test]
    fn имя_лежит_там_где_обещано() {
        for sni in ["discord.com", "www.youtube.com", "a.b"] {
            let ch = build_client_hello(sni);
            let got = &ch.bytes[ch.sni_offset..ch.sni_offset + ch.sni_len];
            assert_eq!(got, sni.as_bytes(), "смещение имени неверно для {sni}");
        }
    }

    #[test]
    fn имя_встречается_в_записи_ровно_один_раз() {
        // Иначе разрез мог бы прийтись не на то вхождение.
        let sni = "discord.com";
        let ch = build_client_hello(sni);
        let n = ch.bytes.windows(sni.len()).filter(|w| *w == sni.as_bytes()).count();
        assert_eq!(n, 1, "имя должно быть в ClientHello один раз");
    }

    #[test]
    fn разрез_приходится_внутрь_имени() {
        for sni in ["discord.com", "www.youtube.com", "ab", "a"] {
            let ch = build_client_hello(sni);
            let at = ch.split_at();
            assert!(at > ch.sni_offset, "{sni}: разрез не должен быть до имени");
            assert!(
                at < ch.sni_offset + ch.sni_len || ch.sni_len <= 1,
                "{sni}: разрез не должен быть после имени"
            );
            assert!(at < ch.bytes.len(), "{sni}: разрез внутри буфера");
        }
    }

    #[test]
    fn вердикт_целый_прошёл() {
        let (v, _) = classify_frag(ChOutcome::Answered, ChOutcome::Answered);
        assert_eq!(v, FragVerdict::NotBlocked);
    }

    #[test]
    fn вердикт_фрагментация_помогает() {
        for whole in [ChOutcome::Reset, ChOutcome::Silent] {
            let (v, why) = classify_frag(whole, ChOutcome::Answered);
            assert_eq!(v, FragVerdict::Helps, "{whole:?}");
            assert!(why.contains("подбор имеет смысл"));
        }
    }

    #[test]
    fn вердикт_фрагментация_не_помогает() {
        for split in [ChOutcome::Reset, ChOutcome::Silent] {
            let (v, why) = classify_frag(ChOutcome::Reset, split);
            assert_eq!(v, FragVerdict::DoesNotHelp, "{split:?}");
            assert!(why.contains("бесполезно"));
        }
    }

    #[test]
    fn без_подключения_вывода_нет() {
        for (w, s) in [
            (ChOutcome::NoConnect, ChOutcome::NoConnect),
            (ChOutcome::Reset, ChOutcome::NoConnect),
        ] {
            let (v, _) = classify_frag(w, s);
            assert_eq!(v, FragVerdict::Inconclusive);
        }
    }

    #[test]
    fn сводный_вердикт_хватает_одной_надежды() {
        use FragVerdict::*;
        let (v, _) = aggregate(&[DoesNotHelp, NotBlocked, Helps]);
        assert_eq!(v, Helps, "одной пробившей цели достаточно");
    }

    #[test]
    fn сводный_вердикт_бесполезно_только_когда_надежды_нет() {
        use FragVerdict::*;
        assert_eq!(aggregate(&[DoesNotHelp, NotBlocked]).0, DoesNotHelp);
        assert_eq!(aggregate(&[NotBlocked, NotBlocked]).0, NotBlocked);
        assert_eq!(aggregate(&[Inconclusive, NotBlocked]).0, Inconclusive);
        assert_eq!(aggregate(&[]).0, Inconclusive);
    }

    #[test]
    fn два_вызова_дают_разные_random() {
        // Иначе ClientHello был бы константой и сам стал бы отпечатком.
        let a = build_client_hello("discord.com");
        let b = build_client_hello("discord.com");
        assert_ne!(a.bytes, b.bytes, "random должен отличаться");
        assert_eq!(a.sni_offset, b.sni_offset, "а смещение имени — нет");
    }

    #[test]
    fn расширение_имени_объявлено_первым() {
        // Порядок сам по себе не критичен, но имя ближе к началу означает,
        // что разрез попадёт в первые сегменты — туда, куда смотрит коробка.
        let ch = build_client_hello("discord.com");
        assert!(ch.sni_offset < 120, "имя слишком глубоко: {}", ch.sni_offset);
    }
}

