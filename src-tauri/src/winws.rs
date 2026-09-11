use once_cell::sync::Lazy;
use regex::Regex;
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use tauri::{AppHandle, Emitter, Manager};

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
const CREATE_NO_WINDOW: u32 = 0x08000000;

use crate::state::AppState;

struct GameFilterValues {
    game_filter: &'static str,
    game_filter_tcp: &'static str,
    game_filter_udp: &'static str,
}

/// Port of `getGameFilterValues()` — reads the same utils\game_filter.enabled
/// marker file the .bat scripts themselves read.
fn game_filter_values(root: &Path) -> GameFilterValues {
    let marker = root.join("utils").join("game_filter.enabled");
    let mode = fs::read_to_string(marker)
        .unwrap_or_default()
        .trim()
        .to_lowercase();
    match mode.as_str() {
        "tcp" => GameFilterValues {
            game_filter: "1024-65535",
            game_filter_tcp: "1024-65535",
            game_filter_udp: "12",
        },
        "udp" => GameFilterValues {
            game_filter: "1024-65535",
            game_filter_tcp: "12",
            game_filter_udp: "1024-65535",
        },
        "" => GameFilterValues {
            game_filter: "12",
            game_filter_tcp: "12",
            game_filter_udp: "12",
        },
        _ => GameFilterValues {
            game_filter: "1024-65535",
            game_filter_tcp: "1024-65535",
            game_filter_udp: "1024-65535",
        },
    }
}

static LINE_CONTINUATION: Lazy<Regex> = Lazy::new(|| Regex::new(r"[ \t]*\^\r?\n[ \t]*").unwrap());
static EXE_MARKER: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?i)winws\.exe""#).unwrap());
static TOKEN_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r#"(?:[^\s"]+|"[^"]*")+"#).unwrap());

/// Port of `extractWinwsArgs()` — reads a general*.bat and pulls out the
/// literal argv winws.exe gets launched with, so we can spawn it directly
/// (piped stdio) instead of via `start /min`, which would detach it into an
/// untracked console we can't read logs from. Returns None if the file
/// doesn't look like the expected shape.
pub fn extract_winws_args(root: &Path, file_name: &str) -> Option<Vec<String>> {
    let file_path = root.join(file_name);
    let raw = fs::read_to_string(&file_path).ok()?;
    let text = LINE_CONTINUATION.replace_all(&raw, " ");

    let line_with_exe = text.lines().find(|l| EXE_MARKER.is_match(l))?;
    let mat = EXE_MARKER.find(line_with_exe)?;
    let after_exe = &line_with_exe[mat.end()..];
    if after_exe.trim().is_empty() {
        return None;
    }

    let bin_path = format!("{}\\", root.join("bin").display());
    let lists_path = format!("{}\\", root.join("lists").display());
    let gf = game_filter_values(root);

    let args: Vec<String> = TOKEN_RE
        .find_iter(after_exe)
        .map(|m| m.as_str().replace('"', ""))
        .map(|t| {
            t.replace("%BIN%", &bin_path)
                .replace("%LISTS%", &lists_path)
                .replace("%GameFilterTCP%", gf.game_filter_tcp)
                .replace("%GameFilterUDP%", gf.game_filter_udp)
                .replace("%GameFilter%", gf.game_filter)
        })
        .filter(|t| !t.is_empty() && t != "^")
        .collect();

    if args.is_empty() || !args.iter().any(|a| a.starts_with("--")) {
        return None;
    }
    Some(args)
}

/// `taskkill /IM winws.exe /F` — same as `stopWinws()`. Best-effort: a
/// missing process is not an error here, same as the JS version ignoring it.
pub fn stop_winws() {
    #[allow(unused_mut)]
    let mut cmd = Command::new(crate::sys::system_exe("taskkill.exe"));
    cmd.args(["/IM", "winws.exe", "/F"]);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);
    let _ = cmd.output();
}

pub fn is_winws_running() -> bool {
    #[allow(unused_mut)]
    let mut cmd = Command::new(crate::sys::system_exe("tasklist.exe"));
    cmd.args(["/FI", "IMAGENAME eq winws.exe"]);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);
    match cmd.output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).to_lowercase().contains("winws.exe"),
        Err(_) => false,
    }
}

const LOG_CAP: usize = 500;

fn push_log_lines(app: &AppHandle, state: &AppState, chunk: &str) {
    let lines: Vec<String> = chunk
        .lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();
    if lines.is_empty() {
        return;
    }
    {
        let mut buf = state.winws_log.lock().unwrap();
        for line in &lines {
            buf.push(line.clone());
        }
        let overflow = buf.len().saturating_sub(LOG_CAP);
        if overflow > 0 {
            buf.drain(0..overflow);
        }
    }
    let _ = app.emit("winws-log", &lines);
}

/// Port of `applyDirect()`'s spawn half — parses the config's real args and
/// spawns winws.exe directly with piped stdio so live logs work, same as the
/// Electron version. Falls back to nothing (caller decides what "no live
/// logs" means) when the args can't be extracted, matching the "returns
/// null, caller falls back to the .bat" contract upstream.
pub fn spawn_winws(app: &AppHandle, root: &Path, file_name: &str) -> Result<bool, String> {
    let state = app.state::<AppState>();

    // Kill whatever's running first — same "stop before start" as applyDirect().
    {
        let mut child_guard = state.winws_child.lock().unwrap();
        if let Some(mut child) = child_guard.take() {
            *state.winws_intentional_stop.lock().unwrap() = true;
            let _ = child.kill();
        }
    }
    stop_winws();
    std::thread::sleep(std::time::Duration::from_millis(400));

    state.winws_log.lock().unwrap().clear();

    let args = extract_winws_args(root, file_name);
    let winws_exe = root.join("bin").join("winws.exe");
    let live_logs = args.is_some() && winws_exe.exists();

    if let Some(args) = args.filter(|_| winws_exe.exists()) {
        *state.winws_intentional_stop.lock().unwrap() = false;
        #[allow(unused_mut)]
        let mut cmd = Command::new(&winws_exe);
        cmd.args(&args)
            .current_dir(root.join("bin"))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(target_os = "windows")]
        cmd.creation_flags(CREATE_NO_WINDOW);

        let mut child = cmd.spawn().map_err(|e| e.to_string())?;
        let pid = child.id();

        if let Some(stdout) = child.stdout.take() {
            let app2 = app.clone();
            std::thread::spawn(move || {
                let state = app2.state::<AppState>();
                crate::sys::for_each_line(stdout, |line| push_log_lines(&app2, &state, &line));
            });
        }
        if let Some(stderr) = child.stderr.take() {
            let app2 = app.clone();
            std::thread::spawn(move || {
                let state = app2.state::<AppState>();
                crate::sys::for_each_line(stderr, |line| push_log_lines(&app2, &state, &line));
            });
        }

        *state.winws_child.lock().unwrap() = Some(child);
        watch_child(app, pid);
    } else {
        // Fallback: run the .bat itself via cmd — no live logs, but works
        // for any release shape, same tradeoff as the Electron fallback.
        #[allow(unused_mut)]
        let mut cmd = Command::new(crate::sys::system_exe("cmd.exe"));
        cmd.args(["/c", file_name])
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(target_os = "windows")]
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.spawn().map_err(|e| e.to_string())?;
        watch_by_poll(app);
    }

    Ok(live_logs)
}

/// Обход упал сам. Чистим состояние и говорим об этом всем, кто слушает.
fn report_crash(app: &AppHandle) {
    let state = app.state::<AppState>();
    let crashed = state.persisted.lock().unwrap().active_config.clone();
    let Some(crashed) = crashed else { return };
    {
        let mut p = state.persisted.lock().unwrap();
        p.active_config = None;
        p.installed_as_service = false;
        p.started_at = None;
    }
    crate::state::save_state(app, &state);
    crate::notify::send_critical_from(
        app,
        "Обход упал",
        &format!("{} неожиданно остановилась.", crashed.trim_end_matches(".bat")),
    );
    let _ = app.emit("winws-crashed", crashed);
    crate::tray::refresh(app);
}

/// Следит за КОНКРЕТНЫМ процессом. Раньше поток смотрел просто на ячейку
/// `winws_child`: если он просыпался уже после того, как её занял следующий
/// запуск, то оставался жить и стерёг чужого ребёнка — по одному лишнему
/// потоку на каждое переключение самолечения.
fn watch_child(app: &AppHandle, pid: u32) {
    let app = app.clone();
    std::thread::spawn(move || {
        let state = app.state::<AppState>();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let mut guard = state.winws_child.lock().unwrap();
            let Some(child) = guard.as_mut() else { break };
            if child.id() != pid {
                break;
            }
            match child.try_wait() {
                Ok(Some(_status)) => {
                    // Пожинаем процесс и освобождаем ячейку.
                    *guard = None;
                    drop(guard);
                    let intentional = {
                        let mut f = state.winws_intentional_stop.lock().unwrap();
                        let was = *f;
                        *f = false;
                        was
                    };
                    if !intentional {
                        report_crash(&app);
                    }
                    break;
                }
                Ok(None) => continue,
                // Состояние процесса прочитать не вышло — держать в ячейке
                // handle, про который мы больше ничего не знаем, хуже, чем
                // честно её освободить.
                Err(_) => {
                    *guard = None;
                    break;
                }
            }
        }
    });
}

/// Резервный режим: winws поднимает сам .bat, своего `Child` у нас нет, и
/// падение обхода тут не замечал вообще никто — ни уведомления, ни события
/// `winws-crashed`. Следим опросом.
fn watch_by_poll(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        // Даём процессу подняться, иначе «ещё не стартовал» примем за падение.
        std::thread::sleep(std::time::Duration::from_secs(3));
        let state = app.state::<AppState>();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            // Появился свой Child — значит запустили заново обычным путём,
            // и за ним следит watch_child.
            if state.winws_child.lock().unwrap().is_some() {
                break;
            }
            if is_winws_running() {
                continue;
            }
            let intentional = {
                let mut f = state.winws_intentional_stop.lock().unwrap();
                let was = *f;
                *f = false;
                was
            };
            if !intentional {
                report_crash(&app);
            }
            break;
        }
    });
}

pub fn kill_winws(app: &AppHandle) {
    let state = app.state::<AppState>();
    *state.winws_intentional_stop.lock().unwrap() = true;
    {
        let mut child_guard = state.winws_child.lock().unwrap();
        if let Some(mut child) = child_guard.take() {
            let _ = child.kill();
            // Ждём выхода: иначе процесс остаётся незажатым, а наблюдатель
            // уже ушёл по ветке «ячейка пуста».
            let _ = child.wait();
        }
    }
    stop_winws();
}
