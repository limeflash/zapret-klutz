use serde::Serialize;
use std::path::Path;

use crate::sys;

#[derive(Debug, Serialize)]
pub struct DiagRow {
    pub label: String,
    pub ok: bool,
    #[serde(rename = "fixKey", skip_serializing_if = "Option::is_none")]
    pub fix_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warn: Option<String>,
}

fn row(label: &str, ok: bool) -> DiagRow {
    DiagRow { label: label.into(), ok, fix_key: None, warn: None }
}

/// Список служб целиком. `sc query` без аргументов перечисляет только
/// ЗАПУЩЕННЫЕ службы Win32, поэтому строки «…отсутствует» на самом деле
/// значили «сейчас не запущена». Забираем один раз на весь прогон: вызов
/// не мгновенный, а проверок по нему пять.
fn all_services() -> String {
    sys::run("sc", &["query", "state=", "all"]).to_lowercase()
}

fn svc_matches(services: &str, pattern: &str) -> bool {
    pattern.split('|').any(|p| {
        let p = p.trim().to_lowercase();
        !p.is_empty() && services.contains(&p)
    })
}

/// Подпись «timestamps» на неанглийской Windows переводится целиком, а вот
/// номер RFC и значение enabled/disabled остаются английскими — ищем их.
fn timestamps_enabled() -> bool {
    sys::run("netsh", &["interface", "tcp", "show", "global"])
        .lines()
        .find(|l| l.contains("1323"))
        .map(|l| l.to_lowercase().contains("enabled"))
        .unwrap_or(false)
}

pub fn run_diagnostics(root: Option<&Path>) -> Vec<DiagRow> {
    let mut out = Vec::new();
    let services = all_services();

    let bfe_ok = sys::svc_query("BFE").state.as_deref() == Some("RUNNING");
    out.push(DiagRow {
        label: "Base Filtering Engine запущен".into(),
        ok: bfe_ok,
        fix_key: if bfe_ok { None } else { Some("bfe".into()) },
        warn: None,
    });

    let proxy_on = sys::run(
        "reg",
        &[
            "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v",
            "ProxyEnable",
        ],
    )
    .contains("0x1");
    out.push(DiagRow {
        label: "Системный прокси выключен".into(),
        ok: !proxy_on,
        fix_key: None,
        warn: if proxy_on {
            Some("Прокси включён — убедись, что он рабочий, иначе может мешать".into())
        } else {
            None
        },
    });

    // Подпись «timestamps» на неанглийской Windows переводится целиком, а вот
    // номер RFC и значение enabled/disabled остаются английскими — ищем их.
    let ts_ok = timestamps_enabled();
    out.push(DiagRow {
        label: "TCP timestamps включены".into(),
        ok: ts_ok,
        fix_key: if ts_ok { None } else { Some("tcp-timestamps".into()) },
        warn: None,
    });

    out.push(row("Adguard не мешает", !sys::proc_running("AdguardSvc.exe")));
    out.push(row("Killer network service отсутствует", !svc_matches(&services, "killer")));
    // Не просто «intel»: под это попадала любая служба Intel — звук,
    // графика, Management Engine, — и строка краснела почти на каждом
    // ноутбуке с их чипом, обесценивая весь список.
    out.push(row(
        "Intel Connectivity Network Service отсутствует",
        !svc_matches(&services, "connectivity network service"),
    ));
    out.push(row("Check Point отсутствует", !svc_matches(&services, "tracsrvwrapper|epwd")));
    out.push(row("SmartByte отсутствует", !svc_matches(&services, "smartbyte")));

    let bin_ok = root
        .map(|r| r.join("bin").join("WinDivert64.sys").exists())
        .unwrap_or(false);
    out.push(row("WinDivert64.sys на месте", bin_ok));

    let vpn = svc_matches(&services, "vpn");
    out.push(DiagRow {
        label: "Конфликтующих VPN-служб нет".into(),
        ok: !vpn,
        fix_key: None,
        warn: if vpn { Some("Найдены VPN-службы — могут конфликтовать с zapret".into()) } else { None },
    });

    out.push(row(
        "Конфликтующие обходы (GoodbyeDPI и т.п.) отсутствуют",
        !svc_matches(&services, "goodbyedpi|discordfix_zapret|winws1|winws2"),
    ));

    // Всё остальное здесь — про машину, а это единственная строка про сеть.
    // Она тут потому, что ответ на неё ничего не говорит о стратегии: если
    // UDP наружу не выпускают, голос Discord не заработает ни с каким
    // конфигом, и перебирать их — время впустую.
    let udp = crate::udpprobe::probe_udp(std::time::Duration::from_secs(3));
    out.push(DiagRow {
        label: "UDP наружу проходит (голос Discord, QUIC)".into(),
        ok: udp.verdict != crate::udpprobe::UdpVerdict::Blocked,
        fix_key: None,
        // Неизмеренное не выдаём за исправное: строка зелёная, но с оговоркой.
        warn: match udp.verdict {
            crate::udpprobe::UdpVerdict::Ok => None,
            _ => Some(udp.note),
        },
    });

    out
}

/// Чиним только то, где исправление — один однозначный системный тумблер без
/// побочных эффектов. Всё остальное в списке означало бы остановку чужого
/// софта (Adguard, VPN, утилиты Killer) или отключение прокси, который может
/// быть нужен пользователю — это не решение приложения.
/// Результат проверяем перечитыванием состояния, а не по факту запуска
/// команды: раньше обе ветки возвращали Ok(()) безусловно, и интерфейс
/// рапортовал «исправлено» даже когда `net start` отказывал по правам.
pub fn fix(key: &str) -> Result<(), String> {
    match key {
        "bfe" => {
            let out = sys::run("net", &["start", "BFE"]);
            if sys::svc_query("BFE").state.as_deref() == Some("RUNNING") {
                Ok(())
            } else {
                Err(fail_text(out, "не удалось запустить Base Filtering Engine"))
            }
        }
        "tcp-timestamps" => {
            let out = sys::run("netsh", &["interface", "tcp", "set", "global", "timestamps=enabled"]);
            if timestamps_enabled() {
                Ok(())
            } else {
                Err(fail_text(out, "не удалось включить TCP timestamps"))
            }
        }
        _ => Err("Неизвестная проверка.".into()),
    }
}

fn fail_text(out: String, fallback: &str) -> String {
    let t = out.trim();
    if t.is_empty() { fallback.to_string() } else { t.to_string() }
}
