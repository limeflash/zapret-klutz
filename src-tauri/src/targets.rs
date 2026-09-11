use serde::{Deserialize, Serialize};

use crate::probe::{http_probe, tcp_probe, ProbeResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Target {
    pub name: String,
    pub host: String,
    pub port: u16,
}

pub fn default_targets() -> Vec<Target> {
    let raw: &[(&str, &str, u16)] = &[
        ("Discord Main", "discord.com", 443),
        ("Discord Gateway", "gateway.discord.gg", 443),
        ("Discord CDN", "cdn.discordapp.com", 443),
        ("Discord Updates", "updates.discord.com", 443),
        ("YouTube Web", "www.youtube.com", 443),
        // Не голый googlevideo.com: его сертификат выписан на *.googlevideo.com
        // и к самому домену не подходит, curl падает на проверке сертификата
        // при любом конфиге — YouTube всегда выглядел «не отвечающим». Этот
        // же хост проверяет и тест самого zapret.
        ("YouTube Video", "redirector.googlevideo.com", 443),
        ("YouTube Short", "youtu.be", 443),
        ("Rocket League", "api.rlpp.psynet.gg", 443),
        ("Epic Online", "api.epicgames.dev", 443),
        ("Steam", "api.steampowered.com", 443),
        ("Riot", "auth.riotgames.com", 443),
        ("Battle.net", "us.actual.battle.net", 1119),
        ("Xbox Live", "title.mgt.xboxlive.com", 443),
    ];
    raw.iter()
        .map(|(n, h, p)| Target {
            name: (*n).to_string(),
            host: (*h).to_string(),
            port: *p,
        })
        .collect()
}

/// Чинит сохранённые списки целей от старых версий: там «YouTube Video»
/// указывал на голый googlevideo.com (см. default_targets).
pub fn migrate_hosts(list: &mut [Target]) {
    for t in list.iter_mut() {
        if t.host.eq_ignore_ascii_case("googlevideo.com") {
            t.host = "redirector.googlevideo.com".into();
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TargetResult {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub ok: bool,
    pub ms: u64,
    pub reason: Option<String>,
    /// Каким способом проверяли — в интерфейсе видно, чему верить.
    pub probe: &'static str,
}

/// Сайты (80/443) проверяем настоящим HTTPS-запросом, всё остальное —
/// TCP-хендшейком: у игровых серверов на своих портах HTTP просто нет.
fn probe_target(t: &Target) -> (ProbeResult, &'static str) {
    if t.port == 443 || t.port == 80 {
        let scheme = if t.port == 443 { "https" } else { "http" };
        (http_probe(&format!("{scheme}://{}", t.host), 4), "http")
    } else {
        (tcp_probe(&t.host, t.port, 4000), "tcp")
    }
}

pub fn check_targets(targets: &[Target]) -> Vec<TargetResult> {
    let handles: Vec<_> = targets
        .iter()
        .cloned()
        .map(|t| std::thread::spawn(move || {
            let (r, probe) = probe_target(&t);
            TargetResult {
                name: t.name,
                host: t.host,
                port: t.port,
                ok: r.ok,
                ms: r.ms,
                reason: r.reason,
                probe,
            }
        }))
        .collect();
    handles.into_iter().filter_map(|h| h.join().ok()).collect()
}
