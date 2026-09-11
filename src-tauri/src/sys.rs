//! Тонкие обёртки над системными утилитами Windows (sc/net/tasklist/reg/schtasks).
//! Абсолютных путей намеренно не берём — но и окон не показываем.

use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
pub const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Запускает команду, отдаёт stdout. Ошибку не считаем фатальной — многие
/// из этих утилит возвращают ненулевой код на «ничего не найдено».
pub fn run(program: &str, args: &[&str]) -> String {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);
    match cmd.output() {
        Ok(out) => {
            let mut s = String::from_utf8_lossy(&out.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&out.stderr));
            s
        }
        Err(_) => String::new(),
    }
}

pub fn run_ok(program: &str, args: &[&str]) -> bool {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    cmd.args(args);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);
    cmd.output().map(|o| o.status.success()).unwrap_or(false)
}

pub struct SvcState {
    pub exists: bool,
    pub state: Option<String>,
}

/// sc.exe локализует названия полей (STATE/TYPE), но само значение состояния
/// остаётся английским — поэтому ищем именно значение, а не подпись.
pub fn svc_query(name: &str) -> SvcState {
    let out = run("sc", &["query", name]);
    for token in [
        "RUNNING",
        "STOP_PENDING",
        "START_PENDING",
        "CONTINUE_PENDING",
        "PAUSE_PENDING",
        "PAUSED",
        "STOPPED",
    ] {
        if out.contains(token) {
            return SvcState { exists: true, state: Some(token.to_string()) };
        }
    }
    SvcState { exists: false, state: None }
}

pub fn proc_running(image: &str) -> bool {
    run("tasklist", &["/FI", &format!("IMAGENAME eq {image}")])
        .to_lowercase()
        .contains(&image.to_lowercase())
}

/// Какая стратегия прописана у установленной службы zapret.
pub fn installed_service_strategy() -> Option<String> {
    let out = run(
        "reg",
        &[
            "query",
            r"HKLM\System\CurrentControlSet\Services\zapret",
            "/v",
            "zapret-discord-youtube",
        ],
    );
    let idx = out.find("REG_SZ")?;
    let tail = out[idx + "REG_SZ".len()..].trim_start();
    let line = tail.lines().next()?.trim();
    if line.is_empty() {
        None
    } else {
        Some(line.to_string())
    }
}
