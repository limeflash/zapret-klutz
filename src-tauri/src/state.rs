use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

/// Всё, что переживает перезапуск — аналог state.json из Electron-версии.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PersistedState {
    #[serde(rename = "rootPath")]
    pub root_path: Option<String>,
    #[serde(rename = "activeConfig")]
    pub active_config: Option<String>,
    #[serde(rename = "installedAsService")]
    pub installed_as_service: bool,
    #[serde(rename = "canInstallService")]
    pub can_install_service: bool,
    #[serde(rename = "startedAt")]
    pub started_at: Option<u64>,
    /// None — пользователь список не трогал, берём стандартный.
    #[serde(rename = "gameTargets")]
    pub game_targets: Option<Vec<crate::targets::Target>>,
    pub tgws: Option<crate::tgws::TgSettings>,
    #[serde(rename = "autoSwitch")]
    pub auto_switch: Option<AutoSwitch>,
    pub notifications: Option<bool>,
    #[serde(rename = "onboardingDone")]
    pub onboarding_done: Option<bool>,
    #[serde(rename = "healLog")]
    pub heal_log: Option<Vec<HealEntry>>,
    #[serde(rename = "notifyVolume")]
    pub notify_volume: Option<u8>,
    #[serde(rename = "notifyDuration")]
    pub notify_duration: Option<String>,
    #[serde(rename = "autotestEnabled")]
    pub autotest_enabled: Option<bool>,
    #[serde(rename = "autotestDays")]
    pub autotest_days: Option<u32>,
    #[serde(rename = "autotestLastRun")]
    pub autotest_last_run: Option<u64>,
    #[serde(rename = "autotestMode")]
    pub autotest_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoSwitch {
    pub enabled: bool,
    pub threshold: u32,
    #[serde(rename = "intervalSec")]
    pub interval_sec: u64,
}

impl Default for AutoSwitch {
    fn default() -> Self {
        Self { enabled: false, threshold: 3, interval_sec: 30 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealEntry {
    pub at: u64,
    #[serde(rename = "type")]
    pub kind: String,
    pub from: Option<String>,
    pub to: Option<String>,
    pub ok: bool,
}

pub struct AppState {
    pub persisted: Mutex<PersistedState>,
    pub winws_child: Mutex<Option<std::process::Child>>,
    pub winws_log: Mutex<Vec<String>>,
    pub winws_intentional_stop: Mutex<bool>,
    pub tgws_pid: Mutex<Option<u32>>,
    pub tgws_log: Mutex<Vec<String>>,
    /// (сколько ключевых целей ответило, сколько проверяли) — от этого зависит
    /// цвет иконки в трее и решение автопереключения.
    pub last_check: Mutex<Option<(usize, usize)>>,
    pub degraded_ticks: Mutex<u32>,
    pub healing_attempts: Mutex<Vec<String>>,
    pub testing: Mutex<bool>,
    /// PID запущенного прогона тестов — чтобы «Остановить» гасило именно его.
    pub test_pid: Mutex<Option<u32>>,
    /// Последняя фоновая проверка по целям (имя, ответила, мс) — меню трея
    /// показывает её построчно, как в Electron-версии.
    pub last_targets: Mutex<Vec<(String, bool, u64)>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            persisted: Mutex::new(PersistedState::default()),
            winws_child: Mutex::new(None),
            winws_log: Mutex::new(Vec::new()),
            winws_intentional_stop: Mutex::new(false),
            tgws_pid: Mutex::new(None),
            tgws_log: Mutex::new(Vec::new()),
            last_check: Mutex::new(None),
            degraded_ticks: Mutex::new(0),
            healing_attempts: Mutex::new(Vec::new()),
            testing: Mutex::new(false),
            test_pid: Mutex::new(None),
            last_targets: Mutex::new(Vec::new()),
        }
    }
}

fn state_path(app: &AppHandle) -> PathBuf {
    app.path().app_data_dir().expect("no app data dir").join("state.json")
}

pub fn load_state(app: &AppHandle, state: &AppState) {
    if let Ok(text) = fs::read_to_string(state_path(app)) {
        if let Ok(mut parsed) = serde_json::from_str::<PersistedState>(&text) {
            if let Some(targets) = parsed.game_targets.as_mut() {
                crate::targets::migrate_hosts(targets);
            }
            *state.persisted.lock().unwrap() = parsed;
        }
    }
}

pub fn save_state(app: &AppHandle, state: &AppState) {
    let dir = app.path().app_data_dir().expect("no app data dir");
    let _ = fs::create_dir_all(&dir);
    let snapshot = state.persisted.lock().unwrap().clone();
    if let Ok(json) = serde_json::to_string_pretty(&snapshot) {
        let _ = fs::write(state_path(app), json);
    }
}
