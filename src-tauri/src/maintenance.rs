use serde::Serialize;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::sys;
use crate::toggles::ipset_mode_from;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

const RAW_BASE: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service";

/// Скачивание через curl.exe — он и так есть в Windows и уже используется
/// для проб связи, тащить ради этого целый HTTP-клиент с TLS незачем.
pub fn http_get(url: &str) -> Result<String, String> {
    #[allow(unused_mut)]
    let mut cmd = Command::new(sys::system_exe("curl.exe"));
    cmd.args(["-fsSL", "-m", "20", url]);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(sys::CREATE_NO_WINDOW);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("не удалось скачать {url}"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[derive(Debug, Serialize)]
pub struct IpsetUpdate {
    pub ok: bool,
    pub error: Option<String>,
    pub mode: String,
    pub applied: bool,
}

/// Бэкап всегда получает свежие данные, чтобы возврат в режим «loaded» их
/// подхватил. А живой файл трогаем только если фильтр сейчас и так в
/// «loaded»: режимы «any»/«none» выставлены осознанно, и эта кнопка не должна
/// молча их отменять.
pub fn update_ipset(root: &Path) -> IpsetUpdate {
    let text = match http_get(&format!("{RAW_BASE}/ipset-service.txt")) {
        Ok(t) => t,
        Err(e) => {
            return IpsetUpdate { ok: false, error: Some(e), mode: String::new(), applied: false }
        }
    };
    let list = root.join("lists").join("ipset-all.txt");
    let backup = root.join("lists").join("ipset-all.txt.backup");
    let mode = fs::read_to_string(&list)
        .map(|c| ipset_mode_from(&c))
        .unwrap_or_else(|_| "loaded".into());

    if let Err(e) = fs::write(&backup, &text) {
        return IpsetUpdate { ok: false, error: Some(e.to_string()), mode, applied: false };
    }
    let applied = mode == "loaded";
    if applied {
        if let Err(e) = fs::write(&list, &text) {
            return IpsetUpdate { ok: false, error: Some(e.to_string()), mode, applied: false };
        }
    }
    IpsetUpdate { ok: true, error: None, mode, applied }
}

#[derive(Debug, Serialize)]
pub struct HostsUpdate {
    pub ok: bool,
    pub error: Option<String>,
    #[serde(rename = "needsUpdate")]
    pub needs_update: bool,
}

/// Сам файл hosts не переписываем: открываем рекомендованный текст в блокноте
/// и подсвечиваем системный файл в проводнике. Правка hosts за спиной
/// пользователя — не то, что приложение должно делать молча.
pub fn update_hosts() -> HostsUpdate {
    let text = match http_get(&format!("{RAW_BASE}/hosts")) {
        Ok(t) => t,
        Err(e) => return HostsUpdate { ok: false, error: Some(e), needs_update: false },
    };
    let hosts_path = r"C:\Windows\System32\drivers\etc\hosts";
    let current = fs::read_to_string(hosts_path).unwrap_or_default();
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let needs_update = match (lines.first(), lines.last()) {
        (Some(f), Some(l)) => !(current.contains(f) && current.contains(l)),
        _ => false,
    };
    if needs_update {
        let tmp = std::env::temp_dir().join("zapret_hosts.txt");
        if fs::write(&tmp, &text).is_ok() {
            let _ = Command::new(sys::system_exe("notepad.exe")).arg(&tmp).spawn();
            // Именно одним аргументом: explorer разбирает командную строку
            // сам и на «/select,» с пробелом перед путём открывает папку по
            // умолчанию вместо того, чтобы подсветить файл.
            let _ = Command::new(sys::system_exe("explorer.exe")).arg(format!("/select,{hosts_path}")).spawn();
        }
    }
    HostsUpdate { ok: true, error: None, needs_update }
}

#[derive(Debug, Serialize)]
pub struct UpdateCheck {
    pub ok: bool,
    pub error: Option<String>,
    pub local: String,
    pub remote: String,
    #[serde(rename = "upToDate")]
    pub up_to_date: bool,
    #[serde(rename = "releaseUrl")]
    pub release_url: String,
}

/// Версия загруженного релиза zapret-discord-youtube — из самого релиза
/// (LOCAL_VERSION в service.bat), а не из имени папки: папку могут
/// переименовать.
pub fn local_version(root: &Path) -> Option<String> {
    let svc = fs::read_to_string(root.join("service.bat")).ok()?;
    let v: String = svc
        .split("LOCAL_VERSION=")
        .nth(1)?
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '.')
        .collect();
    if v.is_empty() { None } else { Some(v) }
}

pub fn check_updates(root: &Path) -> UpdateCheck {
    let local = local_version(root).unwrap_or_else(|| "unknown".into());

    let remote = match http_get(&format!("{RAW_BASE}/version.txt")) {
        Ok(t) => t.trim().to_string(),
        Err(e) => {
            return UpdateCheck {
                ok: false,
                error: Some(e),
                local,
                remote: String::new(),
                up_to_date: false,
                release_url: String::new(),
            }
        }
    };
    UpdateCheck {
        up_to_date: local == remote,
        release_url: format!(
            "https://github.com/Flowseal/zapret-discord-youtube/releases/tag/{remote}"
        ),
        ok: true,
        error: None,
        local,
        remote,
    }
}

#[derive(Debug, Serialize)]
pub struct CacheClear {
    pub ok: bool,
    pub cleared: Vec<String>,
}

const DISCORD_IMAGES: [&str; 3] = ["Discord.exe", "DiscordPTB.exe", "DiscordCanary.exe"];

pub fn clear_discord_cache() -> CacheClear {
    // Все каналы, а не только стабильный: PTB и Canary лежат отдельно.
    for image in DISCORD_IMAGES {
        sys::run("taskkill", &["/IM", image, "/F"]);
    }
    // taskkill возвращается раньше, чем процесс действительно исчезает, и
    // удаление падало на «файл занят», молча отдавая пустой список.
    for _ in 0..20 {
        if !DISCORD_IMAGES.iter().any(|i| sys::proc_running(i)) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }

    // Без APPDATA путь получался относительным, и remove_dir_all ушёл бы
    // чистить каталог «discord» рядом с текущим рабочим каталогом.
    let base = match std::env::var("APPDATA") {
        Ok(b) if !b.trim().is_empty() => b,
        _ => return CacheClear { ok: false, cleared: Vec::new() },
    };
    let mut cleared = Vec::new();
    for channel in ["discord", "discordptb", "discordcanary"] {
        for dir in ["Cache", "Code Cache", "GPUCache"] {
            let p = Path::new(&base).join(channel).join(dir);
            if p.exists() && fs::remove_dir_all(&p).is_ok() {
                cleared.push(format!("{channel}/{dir}"));
            }
        }
    }
    CacheClear { ok: true, cleared }
}

// ─────────── Свои списки доменов ───────────

fn list_paths(root: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        root.join("lists").join("list-general-user.txt"),
        root.join("lists").join("list-exclude-user.txt"),
    )
}

fn read_list(p: &Path) -> String {
    fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Serialize)]
pub struct CustomLists {
    pub ok: bool,
    pub include: String,
    pub exclude: String,
}

pub fn get_custom_lists(root: &Path) -> CustomLists {
    let (inc, exc) = list_paths(root);
    CustomLists { ok: true, include: read_list(&inc), exclude: read_list(&exc) }
}

pub fn save_custom_lists(root: &Path, include: &str, exclude: &str) -> Result<(), String> {
    let (inc_path, exc_path) = list_paths(root);
    let clean = |t: &str| {
        let body = t
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        if body.is_empty() { String::new() } else { format!("{body}\n") }
    };
    let inc = clean(include);
    let exc = clean(exclude);
    // Пустой файл ломает winws — оставляем заглушку, как это делает сам zapret.
    fs::write(
        &inc_path,
        if inc.is_empty() { "# Never leave this file empty\ndomain.example.abc\n".to_string() } else { inc },
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        &exc_path,
        if exc.is_empty() { "domain.example.abc\n".to_string() } else { exc },
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}
