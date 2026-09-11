//! Уведомления Windows. Приложение часто стартует свёрнутым в трей, так что
//! это единственный способ сообщить о падении стратегии или итоге тестов.
//!
//! Тост уходит беззвучным: у системного звука Windows нельзя выставить
//! громкость, поэтому сигнал с настоящей громкостью играет окно (оно живо и
//! скрытым в трее) — как в Electron-версии.

use tauri::{AppHandle, Emitter, Manager};

use crate::state::AppState;

/// AppUserModelID ставим только установленному приложению: у exe из
/// target/ нет ярлыка с этим ID, и Windows такой тост просто не покажет.
#[cfg(target_os = "windows")]
fn installed_app_id(app: &AppHandle) -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?.to_string_lossy().to_lowercase();
    if dir.ends_with("target\\debug") || dir.ends_with("target\\release") {
        return None;
    }
    Some(app.config().identifier.clone())
}

fn show(app: &AppHandle, state: &AppState, title: &str, body: &str, critical: bool) {
    let (enabled, volume, long) = {
        let p = state.persisted.lock().unwrap();
        (
            p.notifications.unwrap_or(true),
            p.notify_volume.unwrap_or(70),
            p.notify_duration.as_deref() == Some("long"),
        )
    };
    if !enabled {
        return;
    }
    let _ = app.emit("play-notify-sound", serde_json::json!({ "volume": volume, "critical": critical }));

    let mut n = notify_rust::Notification::new();
    n.summary(title).body(body).auto_icon().timeout(if long {
        notify_rust::Timeout::Never
    } else {
        notify_rust::Timeout::Default
    });
    #[cfg(target_os = "windows")]
    if let Some(id) = installed_app_id(app) {
        n.app_id(&id);
    }
    // Показ тоста ходит в WinRT и может подвиснуть — не держим вызывающий поток.
    std::thread::spawn(move || {
        let _ = n.show();
    });
}

pub fn send(app: &AppHandle, state: &tauri::State<AppState>, title: &str, body: &str) {
    show(app, state, title, body, false);
}

/// Тот же вызов, но когда `State` под рукой нет (фоновые потоки).
pub fn send_from(app: &AppHandle, title: &str, body: &str) {
    show(app, &app.state::<AppState>(), title, body, false);
}

/// Падение обхода или прокси — сигнал с дополнительной нотой, чтобы его
/// можно было отличить на слух от «тесты закончились».
pub fn send_critical_from(app: &AppHandle, title: &str, body: &str) {
    show(app, &app.state::<AppState>(), title, body, true);
}
