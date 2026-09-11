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

fn svc_matches(pattern: &str) -> bool {
    let out = sys::run("sc", &["query"]).to_lowercase();
    pattern.split('|').any(|p| out.contains(&p.to_lowercase()))
}

pub fn run_diagnostics(root: Option<&Path>) -> Vec<DiagRow> {
    let mut out = Vec::new();

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
    let ts_out = sys::run("netsh", &["interface", "tcp", "show", "global"]);
    let ts_ok = ts_out
        .lines()
        .find(|l| l.contains("1323"))
        .map(|l| l.to_lowercase().contains("enabled"))
        .unwrap_or(false);
    out.push(DiagRow {
        label: "TCP timestamps включены".into(),
        ok: ts_ok,
        fix_key: if ts_ok { None } else { Some("tcp-timestamps".into()) },
        warn: None,
    });

    out.push(row("Adguard не мешает", !sys::proc_running("AdguardSvc.exe")));
    out.push(row("Killer network service отсутствует", !svc_matches("Killer")));
    out.push(row("Intel Connectivity Network Service отсутствует", !svc_matches("Intel")));
    out.push(row("Check Point отсутствует", !svc_matches("TracSrvWrapper|EPWD")));
    out.push(row("SmartByte отсутствует", !svc_matches("SmartByte")));

    let bin_ok = root
        .map(|r| r.join("bin").join("WinDivert64.sys").exists())
        .unwrap_or(false);
    out.push(row("WinDivert64.sys на месте", bin_ok));

    let vpn = svc_matches("VPN");
    out.push(DiagRow {
        label: "Конфликтующих VPN-служб нет".into(),
        ok: !vpn,
        fix_key: None,
        warn: if vpn { Some("Найдены VPN-службы — могут конфликтовать с zapret".into()) } else { None },
    });

    out.push(row(
        "Конфликтующие обходы (GoodbyeDPI и т.п.) отсутствуют",
        !svc_matches("GoodbyeDPI|discordfix_zapret|winws1|winws2"),
    ));

    out
}

/// Чиним только то, где исправление — один однозначный системный тумблер без
/// побочных эффектов. Всё остальное в списке означало бы остановку чужого
/// софта (Adguard, VPN, утилиты Killer) или отключение прокси, который может
/// быть нужен пользователю — это не решение приложения.
pub fn fix(key: &str) -> Result<(), String> {
    match key {
        "bfe" => {
            sys::run("net", &["start", "BFE"]);
            Ok(())
        }
        "tcp-timestamps" => {
            sys::run("netsh", &["interface", "tcp", "set", "global", "timestamps=enabled"]);
            Ok(())
        }
        _ => Err("Неизвестная проверка.".into()),
    }
}
