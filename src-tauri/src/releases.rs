//! Скачивание релизов zapret с GitHub и распаковка .zip.

use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tauri::{AppHandle, Emitter, Manager};

use crate::sys;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

const REPO: &str = "Flowseal/zapret-discord-youtube";

fn curl_text(url: &str) -> Result<String, String> {
    #[allow(unused_mut)]
    let mut cmd = Command::new(sys::system_exe("curl.exe"));
    cmd.args(["-fsSL", "-m", "20", "-H", "User-Agent: klutz", url]);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(sys::CREATE_NO_WINDOW);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err("не удалось связаться с GitHub".into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

#[derive(Debug, Serialize)]
pub struct LatestRelease {
    pub ok: bool,
    pub error: Option<String>,
    pub version: String,
    pub name: String,
    pub size: u64,
    pub url: String,
    #[serde(rename = "notesUrl")]
    pub notes_url: String,
}

pub fn latest_release() -> LatestRelease {
    let fail = |e: String| LatestRelease {
        ok: false,
        error: Some(e),
        version: String::new(),
        name: String::new(),
        size: 0,
        url: String::new(),
        notes_url: String::new(),
    };
    let text = match curl_text(&format!("https://api.github.com/repos/{REPO}/releases/latest")) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return fail("GitHub ответил неожиданным форматом.".into());
    };
    let asset = v
        .get("assets")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|a| a.get("name").and_then(|n| n.as_str()).map(|n| n.to_lowercase().ends_with(".zip")).unwrap_or(false))
        });
    let Some(asset) = asset else {
        return fail("В последнем релизе нет .zip файла.".into());
    };
    LatestRelease {
        ok: true,
        error: None,
        version: v.get("tag_name").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        name: asset.get("name").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        size: asset.get("size").and_then(|t| t.as_u64()).unwrap_or(0),
        url: asset.get("browser_download_url").and_then(|t| t.as_str()).unwrap_or("").to_string(),
        notes_url: v.get("html_url").and_then(|t| t.as_str()).unwrap_or("").to_string(),
    }
}

/// Куда складываем скачанные релизы — рядом с настройками приложения.
pub fn releases_dir(app: &AppHandle) -> PathBuf {
    let dir = app.path().app_data_dir().expect("no app data dir").join("releases");
    let _ = fs::create_dir_all(&dir);
    dir
}

/// Скачиваем через curl с `--progress-bar`: он пишет проценты в stderr, что
/// даёт живой прогресс без своего HTTP-клиента с редиректами (GitHub отдаёт
/// 302 на S3, curl идёт по ним сам с -L).
pub fn download_latest(app: &AppHandle) -> Result<PathBuf, String> {
    let info = latest_release();
    if !info.ok {
        return Err(info.error.unwrap_or_else(|| "не удалось получить релиз".into()));
    }
    let dest = releases_dir(app).join(&info.name);

    #[allow(unused_mut)]
    let mut cmd = Command::new(sys::system_exe("curl.exe"));
    cmd.args([
        "-L",
        "--fail",
        "--progress-bar",
        // Иначе зависшее после установки соединение держит нас вечно:
        // общего таймаута на закачку ставить нельзя (файл большой), а вот
        // «меньше килобайта в секунду полминуты» — верный признак смерти.
        "--connect-timeout",
        "20",
        "--speed-limit",
        "1024",
        "--speed-time",
        "30",
        "-H",
        "User-Agent: klutz",
        "-o",
        &dest.to_string_lossy(),
        &info.url,
    ])
    .stderr(std::process::Stdio::piped());
    #[cfg(target_os = "windows")]
    cmd.creation_flags(sys::CREATE_NO_WINDOW);

    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    if let Some(stderr) = child.stderr.take() {
        use std::io::Read;
        let app2 = app.clone();
        std::thread::spawn(move || {
            let mut reader = stderr;
            let mut buf = [0u8; 256];
            let mut acc = String::new();
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                // curl рисует прогресс через возврат каретки, а не перевод строки.
                if let Some(pct) = acc.rsplit(['\r', '\n']).find_map(parse_percent) {
                    let _ = app2.emit("download-progress", pct);
                }
                if acc.len() > 4096 {
                    acc.clear();
                }
            }
        });
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        let _ = fs::remove_file(&dest);
        return Err("Скачивание не удалось.".into());
    }
    let _ = app.emit("download-progress", 100u8);
    Ok(dest)
}

fn parse_percent(chunk: &str) -> Option<u8> {
    let t = chunk.trim();
    if t.is_empty() {
        return None;
    }
    // Полоса curl выглядит как "######   45.2%"
    let num: String = t
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if !t.ends_with('%') || num.is_empty() {
        return None;
    }
    num.parse::<f64>().ok().map(|v| v.clamp(0.0, 100.0) as u8)
}

/// Распаковка .zip. Внутри архивы zapret обычно лежат одной верхней папкой —
/// если так, корнем релиза считаем её, а не временную обёртку.
pub fn extract_zip(zip_path: &Path, target_dir: &Path) -> Result<PathBuf, String> {
    let file = fs::File::open(zip_path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    fs::create_dir_all(target_dir).map_err(|e| e.to_string())?;

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        // enclosed_name отбрасывает пути с ".." — защита от zip slip.
        let Some(rel) = entry.enclosed_name() else { continue };
        let out = target_dir.join(rel);
        if entry.is_dir() {
            fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut dst = fs::File::create(&out).map_err(|e| e.to_string())?;
        std::io::copy(&mut entry, &mut dst).map_err(|e| e.to_string())?;
    }

    let entries: Vec<_> = fs::read_dir(target_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .collect();
    if entries.len() == 1 && entries[0].path().is_dir() {
        return Ok(entries[0].path());
    }
    Ok(target_dir.to_path_buf())
}

#[derive(Debug, Serialize)]
pub struct ReleaseEntry {
    pub name: String,
    pub path: String,
    pub current: bool,
    /// Когда папку распаковали — мс от эпохи, как ждёт `new Date(...)`.
    /// None, если файловая система не отдала время.
    #[serde(rename = "extractedAt")]
    pub extracted_at: Option<u64>,
}

fn dir_created_ms(entry: &fs::DirEntry) -> Option<u64> {
    let meta = entry.metadata().ok()?;
    let t = meta.created().or_else(|_| meta.modified()).ok()?;
    Some(t.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as u64)
}

pub fn list_releases(app: &AppHandle, current_root: Option<&str>) -> Vec<ReleaseEntry> {
    let dir = releases_dir(app);
    fs::read_dir(dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| e.path().is_dir())
                .map(|e| {
                    let path = e.path();
                    let p = path.to_string_lossy().to_string();
                    ReleaseEntry {
                        name: e.file_name().to_string_lossy().to_string(),
                        current: current_root == Some(p.as_str()),
                        extracted_at: dir_created_ms(&e),
                        path: p,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn delete_release(app: &AppHandle, folder: &str) -> Result<(), String> {
    // Двоеточие тоже: `Path::join("C:Users")` в Windows отбрасывает базовый
    // путь, и remove_dir_all ушёл бы гулять за пределы каталога релизов.
    // «.» тоже: оно проходило все прежние проверки, а join(".") оставляет
    // путь на самом каталоге релизов — remove_dir_all снёс бы их все разом.
    if !crate::commands::safe_name(folder) {
        return Err("Недопустимое имя папки.".into());
    }
    let p = releases_dir(app).join(folder);
    if !p.exists() {
        return Err("Папка не найдена.".into());
    }
    fs::remove_dir_all(p).map_err(|e| e.to_string())
}
