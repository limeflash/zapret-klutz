use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tauri::{AppHandle, Emitter};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

#[derive(Debug, Clone, Serialize)]
pub struct ResultRow {
    pub config: String,
    pub ok: u32,
    pub err: u32,
    pub unsup: u32,
    #[serde(rename = "pingOk")]
    pub ping_ok: u32,
    #[serde(rename = "pingFail")]
    pub ping_fail: u32,
    pub blocked: u32,
}

impl ResultRow {
    /// Доля целей, которые реально ответили. В DPI-режиме «заблокировано»
    /// считается неудачей наравне с ошибкой.
    pub fn score(&self, dpi: bool) -> f64 {
        let total = if dpi {
            self.ok + self.err + self.unsup + self.blocked
        } else {
            self.ok + self.err + self.unsup
        };
        if total == 0 {
            0.0
        } else {
            self.ok as f64 / total as f64
        }
    }
}

static STD_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^(.+?)\s*:\s*HTTP OK:\s*(\d+),\s*ERR:\s*(\d+),\s*UNSUP:\s*(\d+),\s*Ping OK:\s*(\d+),\s*Fail:\s*(\d+)\s*$").unwrap()
});
static DPI_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^(.+?)\s*:\s*OK:\s*(\d+),\s*ERR:\s*(\d+),\s*UNSUP:\s*(\d+),\s*BLOCK(?:ED)?:\s*(\d+)\s*$").unwrap()
});

/// Разбор блока ANALYTICS из файла результатов — формат зависит от режима.
pub fn parse_results(text: &str) -> (Vec<ResultRow>, bool) {
    let block = match text.find("=== ANALYTICS ===") {
        Some(i) => &text[i..],
        None => text,
    };

    let mut rows: Vec<ResultRow> = STD_RE
        .captures_iter(block)
        .map(|c| ResultRow {
            config: c[1].trim().to_string(),
            ok: c[2].parse().unwrap_or(0),
            err: c[3].parse().unwrap_or(0),
            unsup: c[4].parse().unwrap_or(0),
            ping_ok: c[5].parse().unwrap_or(0),
            ping_fail: c[6].parse().unwrap_or(0),
            blocked: 0,
        })
        .collect();

    if !rows.is_empty() {
        return (rows, false);
    }

    rows = DPI_RE
        .captures_iter(block)
        .map(|c| ResultRow {
            config: c[1].trim().to_string(),
            ok: c[2].parse().unwrap_or(0),
            err: c[3].parse().unwrap_or(0),
            unsup: c[4].parse().unwrap_or(0),
            ping_ok: 0,
            ping_fail: 0,
            blocked: c[5].parse().unwrap_or(0),
        })
        .collect();
    (rows, true)
}

fn results_dir(root: &Path) -> PathBuf {
    root.join("utils").join("test results")
}

fn snapshot_results(root: &Path) -> HashSet<String> {
    fs::read_dir(results_dir(root))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn newest_new_result(root: &Path, before: &HashSet<String>) -> Option<PathBuf> {
    let dir = results_dir(root);
    let mut fresh: Vec<String> = fs::read_dir(&dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !before.contains(n))
        .collect();
    fresh.sort();
    fresh.pop().map(|n| dir.join(n))
}

/// Один прогон `test zapret.ps1`.
///
/// Скрипт спрашивает две вещи: тип теста (1 = HTTP/Ping, 2 = DPI-checker) и
/// режим (1 = все конфиги, 2 = выбранные). Если передан `subset`, отвечаем
/// «2» и следом шлём номера конфигов — нумерация у скрипта совпадает с нашей,
/// потому что он сортирует тем же способом (natural sort, service* отброшен).
pub fn run_test_script(
    app: &AppHandle,
    root: &Path,
    dpi: bool,
    subset: Option<&[usize]>,
) -> Result<String, String> {
    let script = root.join("utils").join("test zapret.ps1");
    if !script.exists() {
        return Err("В этом релизе нет utils\\test zapret.ps1.".into());
    }

    let before = snapshot_results(root);

    #[allow(unused_mut)]
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        &script.to_string_lossy(),
    ])
    .current_dir(root.join("utils"))
    .env("NO_UPDATE_CHECK", "1")
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);

    let mut child = cmd.spawn().map_err(|e| e.to_string())?;

    // PID нужен, чтобы «Остановить» гасило именно этот прогон, а не все
    // powershell.exe в системе — включая чужие окна пользователя.
    {
        use tauri::Manager;
        *app.state::<crate::state::AppState>().test_pid.lock().unwrap() = Some(child.id());
    }

    {
        // take(), а не as_mut(): по выходу из блока stdin закрывается. Иначе
        // труба остаётся открытой, и если скрипт спросит что-то сверх этих
        // двух ответов, он будет ждать ввода вечно — а вместе с ним и мы.
        let mut stdin = child.stdin.take().ok_or("нет stdin у процесса тестов")?;
        let test_type = if dpi { "2" } else { "1" };
        match subset {
            Some(nums) if !nums.is_empty() => {
                let list = nums.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(",");
                write!(stdin, "{test_type}\n2\n{list}\n").map_err(|e| e.to_string())?;
            }
            _ => write!(stdin, "{test_type}\n1\n").map_err(|e| e.to_string())?,
        }
        stdin.flush().ok();
    }

    if let Some(stdout) = child.stdout.take() {
        let app2 = app.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().flatten() {
                if !line.trim().is_empty() {
                    let _ = app2.emit("test-log", line);
                }
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let app2 = app.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().flatten() {
                if !line.trim().is_empty() {
                    let _ = app2.emit("test-log", line);
                }
            }
        });
    }

    let status = child.wait().map_err(|e| e.to_string())?;
    let _ = status;
    {
        use tauri::Manager;
        *app.state::<crate::state::AppState>().test_pid.lock().unwrap() = None;
    }

    let file = newest_new_result(root, &before)
        .ok_or("Тесты завершились, но файл результатов не найден.")?;
    fs::read_to_string(file).map_err(|e| e.to_string())
}
