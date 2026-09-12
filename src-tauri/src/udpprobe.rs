//! Проходит ли UDP наружу.
//!
//! Зачем отдельная проба. Всё остальное, что мы меряем, — TCP: HTTPS-запрос,
//! рукопожатие TLS, разрез ClientHello. А голос Discord и QUIC у YouTube
//! ходят по UDP, и у конфигов zapret под это есть отдельные профили
//! (`--filter-udp=443`). Когда UDP не проходит вовсе — а так бывает и от
//! провайдера, и от домашнего роутера, и от антивируса, — ни одна стратегия
//! этого не изменит: резать нечего, пакеты просто не уходят. Человек при
//! этом видит «не подключается к голосовому каналу» и перебирает конфиги.
//!
//! Как меряем. STUN (RFC 5389) — самый дешёвый честный способ: запрос 20
//! байт, ответ приходит от самого сервера, и ни с чем другим его не спутать,
//! потому что в нём возвращается наш же идентификатор транзакции. Заодно
//! это ровно тот протокол, которым клиент Discord выясняет свой внешний
//! адрес перед голосовым соединением.

use serde::Serialize;
use std::net::{ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// Публичные STUN-серверы. Несколько, и у разных владельцев: один может
/// лежать сам по себе, и его молчание — не приговор всему UDP.
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun1.l.google.com:19302",
];

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UdpVerdict {
    /// Ответ пришёл — UDP наружу ходит.
    Ok,
    /// Ни один сервер не ответил. Похоже, UDP не выпускают.
    Blocked,
    /// Не удалось даже открыть сокет или разрешить имя — мерить нечего.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct UdpResult {
    pub verdict: UdpVerdict,
    pub note: String,
    /// Сколько серверов ответило из скольких опрошенных.
    pub answered: u32,
    pub asked: u32,
    /// Задержка до первого ответившего, мс.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ms: Option<u64>,
}

/// Запрос STUN Binding: заголовок из 20 байт и ничего больше.
///
/// Идентификатор транзакции возвращают в ответе неизменным — по нему и
/// отличаем настоящий ответ от случайного пакета, прилетевшего на порт.
pub fn build_binding_request(tx: &[u8; 12]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Длина тела — ноль: атрибутов не шлём.
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    buf[8..20].copy_from_slice(tx);
    buf
}

/// Наш ли это ответ. Проверяем всё, что можно проверить дёшево: тип, метку
/// и идентификатор транзакции.
pub fn is_our_response(buf: &[u8], tx: &[u8; 12]) -> bool {
    if buf.len() < 20 {
        return false;
    }
    let kind = u16::from_be_bytes([buf[0], buf[1]]);
    let magic = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    kind == BINDING_SUCCESS && magic == MAGIC && &buf[8..20] == tx
}

/// Чистое правило вердикта — сеть дёргает вызывающий.
pub fn classify_udp(asked: u32, answered: u32) -> (UdpVerdict, String) {
    if asked == 0 {
        return (
            UdpVerdict::Unknown,
            "ни один STUN-сервер не удалось даже спросить — про UDP вывода нет".into(),
        );
    }
    if answered > 0 {
        return (
            UdpVerdict::Ok,
            "UDP наружу проходит — голос Discord и QUIC не упираются в это".into(),
        );
    }
    (
        UdpVerdict::Blocked,
        format!(
            "ни один из {asked} STUN-серверов не ответил по UDP. Похоже, UDP наружу не \
             выпускают — провайдер, роутер или антивирус. Голосовые каналы Discord так \
             не заработают, и стратегия обхода тут ни при чём: резать нечего, пакеты не \
             уходят"
        ),
    )
}

/// Один запрос к одному серверу. `true` — ответил.
fn ask(server: &str, timeout: Duration) -> Option<bool> {
    let addr = server.to_socket_addrs().ok()?.next()?;
    // Порт 0 — пусть система выберет сама.
    let sock = UdpSocket::bind(if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).ok()?;
    sock.set_read_timeout(Some(timeout)).ok()?;

    let mut tx = [0u8; 12];
    crate::sys::os_random(&mut tx);
    let req = build_binding_request(&tx);
    sock.send_to(&req, addr).ok()?;

    // Читаем, пока не придёт НАШ ответ или не кончится время: на открытый
    // порт может прилететь что угодно, и чужой пакет не должен считаться
    // ответом. Но и крутиться вечно нельзя — ограничиваем попытки.
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 512];
    for _ in 0..4 {
        if Instant::now() >= deadline {
            break;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from == addr && is_our_response(&buf[..n], &tx) => return Some(true),
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    Some(false)
}

/// Опрашивает серверы по очереди и останавливается на первом ответившем:
/// вопрос «ходит ли UDP вообще», а не «сколько серверов живо».
pub fn probe_udp(timeout: Duration) -> UdpResult {
    let started = Instant::now();
    let (mut asked, mut answered) = (0u32, 0u32);
    for server in STUN_SERVERS {
        match ask(server, timeout) {
            Some(true) => {
                asked += 1;
                answered += 1;
                break;
            }
            Some(false) => asked += 1,
            // Имя не разрешилось или сокет не открылся — это не ответ и не
            // молчание, такой сервер просто не в счёт.
            None => continue,
        }
    }
    let (verdict, note) = classify_udp(asked, answered);
    UdpResult {
        verdict,
        note,
        answered,
        asked,
        ms: (answered > 0).then(|| started.elapsed().as_millis() as u64),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn запрос_собирается_по_стандарту() {
        let tx = [7u8; 12];
        let req = build_binding_request(&tx);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0, "тело пустое");
        assert_eq!(u32::from_be_bytes([req[4], req[5], req[6], req[7]]), MAGIC);
        assert_eq!(&req[8..20], &tx);
    }

    #[test]
    fn чужой_пакет_за_ответ_не_принимается() {
        let tx = [1u8; 12];
        let mut good = [0u8; 20];
        good[0..2].copy_from_slice(&BINDING_SUCCESS.to_be_bytes());
        good[4..8].copy_from_slice(&MAGIC.to_be_bytes());
        good[8..20].copy_from_slice(&tx);
        assert!(is_our_response(&good, &tx));

        // Тот же ответ, но на чужую транзакцию.
        assert!(!is_our_response(&good, &[2u8; 12]));
        // Правильная транзакция, но это запрос, а не ответ.
        let mut req = good;
        req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
        assert!(!is_our_response(&req, &tx));
        // Без метки STUN.
        let mut nomagic = good;
        nomagic[4] = 0;
        assert!(!is_our_response(&nomagic, &tx));
        // Обрезки и мусор не паникуют.
        assert!(!is_our_response(&[], &tx));
        assert!(!is_our_response(&good[..19], &tx));
        assert!(!is_our_response(&[0xABu8; 64], &tx));
    }

    #[test]
    fn вердикт_по_числу_ответов() {
        assert_eq!(classify_udp(3, 1).0, UdpVerdict::Ok);
        assert_eq!(classify_udp(3, 0).0, UdpVerdict::Blocked);
        // Ни одного спрошенного — это «не измерено», а не «заблокировано».
        let (v, why) = classify_udp(0, 0);
        assert_eq!(v, UdpVerdict::Unknown);
        assert!(why.contains("вывода нет"), "{why}");
    }

    /// Живая проверка: `cargo test -- --ignored живой_udp --nocapture`.
    #[test]
    #[ignore]
    fn живой_udp_через_stun() {
        let r = probe_udp(Duration::from_secs(3));
        println!("{:?} ({}/{}) {:?} мс — {}", r.verdict, r.answered, r.asked, r.ms, r.note);
        assert_ne!(r.verdict, UdpVerdict::Unknown, "ни один сервер не опрошен");
    }
}
