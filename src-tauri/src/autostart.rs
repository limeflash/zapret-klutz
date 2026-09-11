//! Автозапуск через Планировщик заданий, а не через обычный автозапуск
//! Windows: приложению нужны права администратора (WinDivert), а обычный
//! автозапуск их не даёт и спрашивал бы UAC при каждом входе в систему.

use crate::sys;

pub const TASK_NAME: &str = "Klutz-Autostart";

pub fn is_enabled() -> bool {
    sys::run_ok("schtasks", &["/Query", "/TN", TASK_NAME])
}

pub fn set_enabled(enabled: bool) -> Result<(), String> {
    if !enabled {
        sys::run("schtasks", &["/Delete", "/TN", TASK_NAME, "/F"]);
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let tr = format!("\"{}\" --autostart", exe.display());
    let out = sys::run(
        "schtasks",
        &["/Create", "/TN", TASK_NAME, "/TR", &tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"],
    );
    if is_enabled() {
        Ok(())
    } else {
        Err(if out.trim().is_empty() { "не удалось создать задачу".into() } else { out })
    }
}
