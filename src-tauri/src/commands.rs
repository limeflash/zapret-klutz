use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, Manager, State};

use crate::release::{validate_release, ReleaseCheck};
use crate::state::{save_state, AppState};
use crate::winws;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[derive(Debug, Serialize)]
pub struct GetStateResult {
    #[serde(rename = "rootPath")]
    root_path: Option<String>,
    configs: Vec<String>,
    #[serde(rename = "activeConfig")]
    active_config: Option<String>,
    running: bool,
    #[serde(rename = "installedAsService")]
    installed_as_service: bool,
    #[serde(rename = "hasTestScript")]
    has_test_script: bool,
    #[serde(rename = "canInstallService")]
    can_install_service: bool,
    monitor: Option<serde_json::Value>,
    #[serde(rename = "startedAt")]
    started_at: Option<u64>,
}

/// Port of the `get-state` IPC handler.
#[tauri::command(async)]
pub fn get_state(state: State<AppState>) -> GetStateResult {
    let persisted = state.persisted.lock().unwrap().clone();
    let root_path = persisted.root_path.clone().filter(|p| Path::new(p).exists());

    let check = root_path
        .as_ref()
        .map(|p| validate_release(Path::new(p)));

    let running = winws::is_winws_running();

    GetStateResult {
        root_path: root_path.clone(),
        configs: check.as_ref().filter(|c| c.ok).map(|c| c.configs.clone()).unwrap_or_default(),
        active_config: if root_path.is_some() { persisted.active_config } else { None },
        running,
        installed_as_service: persisted.installed_as_service,
        has_test_script: check.as_ref().map(|c| c.has_test_script).unwrap_or(false),
        can_install_service: check.as_ref().map(|c| c.can_install_service).unwrap_or(false),
        // TODO: port the connectivity monitor (runMonitorTick in main.js) —
        // this slice doesn't have it yet, so "Здоровье связи" stays blank.
        monitor: None,
        started_at: if running { persisted.started_at } else { None },
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LoadPathResult {
    Ok {
        ok: bool,
        root: String,
        configs: Vec<String>,
        #[serde(rename = "hasTestScript")]
        has_test_script: bool,
        #[serde(rename = "canInstallService")]
        can_install_service: bool,
    },
    Err {
        ok: bool,
        error: String,
    },
}

/// Port of `load-path` — folder case only for this first slice (the .zip
/// extraction path from `extractZipRelease()` isn't ported yet).
#[tauri::command(async)]
pub fn load_path(app: AppHandle, state: State<AppState>, input_path: String) -> LoadPathResult {
    let path = PathBuf::from(&input_path);
    if !path.is_dir() {
        return LoadPathResult::Err {
            ok: false,
            error: "Нужна папка релиза (поддержка .zip будет позже).".into(),
        };
    }

    let check: ReleaseCheck = validate_release(&path);
    if !check.ok {
        return LoadPathResult::Err {
            ok: false,
            error: check.error.unwrap_or_else(|| "Не удалось загрузить релиз.".into()),
        };
    }

    {
        let mut p = state.persisted.lock().unwrap();
        p.root_path = Some(path.to_string_lossy().to_string());
        p.active_config = None;
        p.installed_as_service = false;
        p.started_at = None;
        p.can_install_service = check.can_install_service;
    }
    save_state(&app, &state);

    LoadPathResult::Ok {
        ok: true,
        root: path.to_string_lossy().to_string(),
        configs: check.configs,
        has_test_script: check.has_test_script,
        can_install_service: check.can_install_service,
    }
}

#[derive(Debug, Serialize)]
pub struct RunConfigResult {
    ok: bool,
    error: Option<String>,
    #[serde(rename = "liveLogs")]
    live_logs: bool,
}

/// Port of `run-config` → `applyDirect()`. Service install (asService) isn't
/// ported in this slice — Стратегии's "запустить разово" path only.
#[tauri::command(async)]
pub fn run_config(app: AppHandle, state: State<AppState>, file_name: String) -> RunConfigResult {
    let root = match state.persisted.lock().unwrap().root_path.clone() {
        Some(r) => PathBuf::from(r),
        None => {
            return RunConfigResult {
                ok: false,
                error: Some("Сначала загрузи релиз zapret.".into()),
                live_logs: false,
            }
        }
    };

    // Установленная служба zapret держит свой winws.exe — прямой запуск
    // поверх неё конфликтует, поэтому просим сначала снять службу.
    if crate::service::service_conflict() {
        return RunConfigResult {
            ok: false,
            error: Some("Установлена служба Windows «zapret» — сначала сними её.".into()),
            live_logs: false,
        };
    }

    let live_logs = match winws::spawn_winws(&app, &root, &file_name) {
        Ok(v) => v,
        Err(e) => {
            return RunConfigResult {
                ok: false,
                error: Some(e),
                live_logs: false,
            }
        }
    };

    {
        let mut p = state.persisted.lock().unwrap();
        p.active_config = Some(file_name);
        p.installed_as_service = false;
        p.started_at = Some(now_ms());
    }
    save_state(&app, &state);

    // Same 1.5s settle-then-verify as applyDirect() before reporting success.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let running = winws::is_winws_running();

    RunConfigResult {
        ok: running,
        error: if running { None } else { Some("winws.exe не запустился, проверь конфиг вручную.".into()) },
        live_logs: live_logs && running,
    }
}

#[tauri::command(async)]
pub fn stop_config(app: AppHandle, state: State<AppState>) -> Result<(), ()> {
    winws::kill_winws(&app);
    {
        let mut p = state.persisted.lock().unwrap();
        p.active_config = None;
        p.started_at = None;
    }
    save_state(&app, &state);
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct WinwsLogResult {
    lines: Vec<String>,
    live: bool,
}

#[tauri::command(async)]
pub fn get_winws_log(state: State<AppState>) -> WinwsLogResult {
    WinwsLogResult {
        lines: state.winws_log.lock().unwrap().clone(),
        live: state.winws_child.lock().unwrap().is_some(),
    }
}

// ─────────── Проверка связи ───────────

#[derive(Debug, Serialize)]
pub struct CheckGamesResult {
    ok: bool,
    targets: Vec<crate::targets::TargetResult>,
    pending: bool,
    #[serde(rename = "checkedAt")]
    checked_at: u64,
    running: bool,
    strategy: Option<String>,
}

#[tauri::command(async)]
pub fn check_games(state: State<AppState>) -> CheckGamesResult {
    let targets = {
        let p = state.persisted.lock().unwrap();
        p.game_targets.clone().unwrap_or_else(crate::targets::default_targets)
    };
    let results = crate::targets::check_targets(&targets);
    CheckGamesResult {
        ok: true,
        targets: results,
        pending: false,
        checked_at: now_ms(),
        running: winws::is_winws_running(),
        strategy: state.persisted.lock().unwrap().active_config.clone(),
    }
}

#[derive(Debug, Serialize)]
pub struct TargetsPayload {
    targets: Vec<crate::targets::Target>,
}

#[tauri::command(async)]
pub fn get_game_targets(state: State<AppState>) -> TargetsPayload {
    let p = state.persisted.lock().unwrap();
    TargetsPayload {
        targets: p.game_targets.clone().unwrap_or_else(crate::targets::default_targets),
    }
}

#[tauri::command(async)]
pub fn get_default_game_targets() -> TargetsPayload {
    TargetsPayload { targets: crate::targets::default_targets() }
}

#[derive(Debug, Serialize)]
pub struct SaveTargetsResult {
    ok: bool,
    targets: Vec<crate::targets::Target>,
}

#[tauri::command(async)]
pub fn save_game_targets(
    app: AppHandle,
    state: State<AppState>,
    targets: Vec<crate::targets::Target>,
) -> SaveTargetsResult {
    let clean: Vec<_> = targets
        .into_iter()
        .filter(|t| !t.name.trim().is_empty() && !t.host.trim().is_empty() && t.port > 0)
        .collect();
    {
        let mut p = state.persisted.lock().unwrap();
        p.game_targets = if clean.is_empty() { None } else { Some(clean) };
    }
    save_state(&app, &state);
    let p = state.persisted.lock().unwrap();
    SaveTargetsResult {
        ok: true,
        targets: p.game_targets.clone().unwrap_or_else(crate::targets::default_targets),
    }
}

#[tauri::command(async)]
pub fn reset_game_targets(app: AppHandle, state: State<AppState>) -> SaveTargetsResult {
    state.persisted.lock().unwrap().game_targets = None;
    save_state(&app, &state);
    SaveTargetsResult { ok: true, targets: crate::targets::default_targets() }
}

// ─────────── Тесты стратегий ───────────

#[derive(Debug, Serialize)]
pub struct RunTestsResult {
    ok: bool,
    error: Option<String>,
    text: String,
}

/// mode: "standard" | "dpi" | "funnel".
///
/// «funnel» — то, ради чего всё затевалось: сначала полный прогон DPI, потом
/// HTTP/Ping, но только по тем конфигам, что прошли DPI на 100%. Экономит
/// половину времени и не тратит его на заведомо пробитые блокировкой варианты.
#[tauri::command(async)]
pub fn run_tests(app: AppHandle, state: State<AppState>, mode: String) -> RunTestsResult {
    let root = match state.persisted.lock().unwrap().root_path.clone() {
        Some(r) => PathBuf::from(r),
        None => {
            return RunTestsResult { ok: false, error: Some("Сначала загрузи релиз zapret.".into()), text: String::new() }
        }
    };

    // Команды выполняются параллельно, поэтому второй запуск надо отсечь
    // здесь: два прогона одновременно перетирали бы конфиг друг другу.
    {
        let mut testing = state.testing.lock().unwrap();
        if *testing {
            return RunTestsResult { ok: false, error: Some("Тесты уже идут.".into()), text: String::new() };
        }
        *testing = true;
    }
    let result = run_tests_inner(&app, &state, &root, &mode);
    *state.testing.lock().unwrap() = false;
    *state.test_pid.lock().unwrap() = None;
    result
}

fn run_tests_inner(
    app: &AppHandle,
    state: &State<AppState>,
    root: &Path,
    mode: &str,
) -> RunTestsResult {
    let _ = state;
    if mode != "funnel" {
        return match crate::tests::run_test_script(app, root, mode == "dpi", None) {
            Ok(text) => RunTestsResult { ok: true, error: None, text },
            Err(e) => RunTestsResult { ok: false, error: Some(e), text: String::new() },
        };
    }

    // Этап 1 — DPI по всем конфигам.
    let _ = app.emit("test-log", "── Этап 1: DPI-checker по всем конфигам ──".to_string());
    let dpi_text = match crate::tests::run_test_script(app, root, true, None) {
        Ok(t) => t,
        Err(e) => return RunTestsResult { ok: false, error: Some(e), text: String::new() },
    };

    let (dpi_rows, _) = crate::tests::parse_results(&dpi_text);
    let configs = crate::release::list_configs(root);

    // Номера для скрипта — позиция в его же списке (сортировка совпадает).
    let passed: Vec<usize> = dpi_rows
        .iter()
        .filter(|r| r.score(true) >= 1.0)
        .filter_map(|r| {
            configs
                .iter()
                .position(|c| c.trim_end_matches(".bat") == r.config.trim_end_matches(".bat"))
                .map(|i| i + 1)
        })
        .collect();

    if passed.is_empty() {
        let _ = app.emit(
            "test-log",
            "Ни один конфиг не прошёл DPI полностью — второй этап пропущен.".to_string(),
        );
        return RunTestsResult { ok: true, error: None, text: dpi_text };
    }

    let _ = app.emit(
        "test-log",
        format!("── Этап 2: HTTP/Ping по {} конфигам, прошедшим DPI ──", passed.len()),
    );
    match crate::tests::run_test_script(app, root, false, Some(&passed)) {
        Ok(text) => RunTestsResult { ok: true, error: None, text },
        Err(e) => RunTestsResult { ok: false, error: Some(e), text: dpi_text },
    }
}

#[derive(Debug, Serialize)]
pub struct LastResults {
    ok: bool,
    text: String,
}

#[tauri::command(async)]
pub fn get_last_test_results(state: State<AppState>) -> LastResults {
    let root = match state.persisted.lock().unwrap().root_path.clone() {
        Some(r) => PathBuf::from(r),
        None => return LastResults { ok: false, text: String::new() },
    };
    let dir = root.join("utils").join("test results");
    let mut files: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(d) => d
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.to_lowercase().ends_with(".txt"))
            .collect(),
        Err(_) => return LastResults { ok: false, text: String::new() },
    };
    files.sort();
    match files.pop().and_then(|n| std::fs::read_to_string(dir.join(n)).ok()) {
        Some(text) => LastResults { ok: true, text },
        None => LastResults { ok: false, text: String::new() },
    }
}

#[tauri::command(async)]
pub fn stop_tests(state: State<AppState>) {
    // Гасим ровно то дерево, которое сами и запустили: убивать все
    // powershell.exe нельзя — у пользователя могут быть свои открытые окна.
    let pid = state.test_pid.lock().unwrap().take();
    if let Some(pid) = pid {
        crate::sys::run("taskkill", &["/PID", &pid.to_string(), "/T", "/F"]);
    }
    // Скрипт поднимает winws.exe сам, отдельным процессом — он переживёт
    // смерть powershell, если его не тронуть.
    winws::stop_winws();
    *state.testing.lock().unwrap() = false;
}

// ─────────── Служба Windows ───────────

#[derive(Debug, Serialize)]
pub struct SimpleResult {
    ok: bool,
    error: Option<String>,
}

fn ok() -> SimpleResult {
    SimpleResult { ok: true, error: None }
}
fn err(e: impl Into<String>) -> SimpleResult {
    SimpleResult { ok: false, error: Some(e.into()) }
}

fn root_of(state: &State<AppState>) -> Option<PathBuf> {
    state.persisted.lock().unwrap().root_path.clone().map(PathBuf::from)
}

#[tauri::command(async)]
pub fn install_service(app: AppHandle, state: State<AppState>, file_name: String) -> SimpleResult {
    let root = match root_of(&state) {
        Some(r) => r,
        None => return err("Сначала загрузи релиз zapret."),
    };
    winws::kill_winws(&app);
    std::thread::sleep(std::time::Duration::from_millis(300));
    match crate::service::install_service(&root, &file_name) {
        Ok(()) => {
            {
                let mut p = state.persisted.lock().unwrap();
                p.active_config = Some(file_name);
                p.installed_as_service = true;
                p.started_at = Some(now_ms());
            }
            save_state(&app, &state);
            crate::tray::refresh(&app);
            ok()
        }
        Err(e) => err(e),
    }
}

#[tauri::command(async)]
pub fn remove_service(app: AppHandle, state: State<AppState>) -> SimpleResult {
    winws::kill_winws(&app);
    crate::service::remove_service();
    {
        let mut p = state.persisted.lock().unwrap();
        p.installed_as_service = false;
        p.active_config = None;
        p.started_at = None;
    }
    save_state(&app, &state);
    crate::tray::refresh(&app);
    ok()
}

#[derive(Debug, Serialize)]
pub struct ServiceStatus {
    #[serde(rename = "serviceExists")]
    service_exists: bool,
    #[serde(rename = "serviceState")]
    service_state: Option<String>,
    #[serde(rename = "windivertState")]
    windivert_state: Option<String>,
    strategy: Option<String>,
    #[serde(rename = "winwsRunning")]
    winws_running: bool,
}

#[tauri::command(async)]
pub fn get_service_status() -> ServiceStatus {
    let svc = crate::sys::svc_query("zapret");
    let wd = crate::sys::svc_query("WinDivert");
    ServiceStatus {
        service_exists: svc.exists,
        service_state: svc.state,
        windivert_state: wd.state,
        strategy: crate::sys::installed_service_strategy(),
        winws_running: winws::is_winws_running(),
    }
}

// ─────────── Тумблеры релиза ───────────

#[tauri::command(async)]
pub fn get_toggles(state: State<AppState>) -> serde_json::Value {
    match root_of(&state) {
        Some(root) => serde_json::to_value(crate::toggles::read_toggles(&root)).unwrap_or(serde_json::json!({})),
        None => serde_json::json!({}),
    }
}

#[tauri::command(async)]
pub fn set_game_filter(state: State<AppState>, mode: String) -> SimpleResult {
    match root_of(&state) {
        Some(root) => match crate::toggles::set_game_filter(&root, &mode) {
            Ok(()) => ok(),
            Err(e) => err(e),
        },
        None => err("Сначала загрузи релиз zapret."),
    }
}

#[tauri::command(async)]
pub fn cycle_ipset_mode(state: State<AppState>) -> SimpleResult {
    match root_of(&state) {
        Some(root) => match crate::toggles::cycle_ipset(&root) {
            Ok(()) => ok(),
            Err(e) => err(e),
        },
        None => err("Сначала загрузи релиз zapret."),
    }
}

#[tauri::command(async)]
pub fn set_auto_update(state: State<AppState>, enabled: bool) -> SimpleResult {
    match root_of(&state) {
        Some(root) => match crate::toggles::set_auto_update(&root, enabled) {
            Ok(()) => ok(),
            Err(e) => err(e),
        },
        None => err("Сначала загрузи релиз zapret."),
    }
}

// ─────────── Автозапуск ───────────

#[derive(Debug, Serialize)]
pub struct AutostartState {
    enabled: bool,
}

#[tauri::command(async)]
pub fn get_autostart() -> AutostartState {
    AutostartState { enabled: crate::autostart::is_enabled() }
}

#[tauri::command(async)]
pub fn set_autostart(enabled: bool) -> SimpleResult {
    match crate::autostart::set_enabled(enabled) {
        Ok(()) => ok(),
        Err(e) => err(e),
    }
}

// ─────────── Диагностика системы ───────────

#[derive(Debug, Serialize)]
pub struct DiagResult {
    ok: bool,
    results: Vec<crate::diag::DiagRow>,
}

#[tauri::command(async)]
pub fn run_diagnostics(state: State<AppState>) -> DiagResult {
    let root = root_of(&state);
    DiagResult { ok: true, results: crate::diag::run_diagnostics(root.as_deref()) }
}

#[tauri::command(async)]
pub fn fix_diagnostic(key: String) -> SimpleResult {
    match crate::diag::fix(&key) {
        Ok(()) => ok(),
        Err(e) => err(e),
    }
}

// ─────────── Самолечение / автопереключение ───────────

#[derive(Debug, Serialize)]
pub struct AutoSwitchState {
    enabled: bool,
    threshold: u32,
    #[serde(rename = "intervalSec")]
    interval_sec: u64,
    #[serde(rename = "hasRanking")]
    has_ranking: bool,
}

#[tauri::command(async)]
pub fn get_auto_switch(state: State<AppState>) -> AutoSwitchState {
    let p = state.persisted.lock().unwrap();
    let a = p.auto_switch.clone().unwrap_or_default();
    let has_ranking = p
        .root_path
        .as_ref()
        .map(|r| Path::new(r).join("utils").join("test results").exists())
        .unwrap_or(false);
    AutoSwitchState {
        enabled: a.enabled,
        threshold: a.threshold,
        interval_sec: a.interval_sec,
        has_ranking,
    }
}

#[tauri::command(async)]
pub fn set_auto_switch(
    app: AppHandle,
    state: State<AppState>,
    enabled: bool,
    threshold: Option<u32>,
    interval_sec: Option<u64>,
) -> SimpleResult {
    {
        let mut p = state.persisted.lock().unwrap();
        let mut a = p.auto_switch.clone().unwrap_or_default();
        a.enabled = enabled;
        if let Some(t) = threshold {
            a.threshold = t.clamp(2, 10);
        }
        if let Some(i) = interval_sec {
            a.interval_sec = if [30, 60, 300].contains(&i) { i } else { a.interval_sec };
        }
        p.auto_switch = Some(a);
    }
    *state.degraded_ticks.lock().unwrap() = 0;
    state.healing_attempts.lock().unwrap().clear();
    save_state(&app, &state);
    ok()
}

#[derive(Debug, Serialize)]
pub struct HealLog {
    ok: bool,
    entries: Vec<crate::state::HealEntry>,
}

#[tauri::command(async)]
pub fn get_heal_log(state: State<AppState>) -> HealLog {
    HealLog {
        ok: true,
        entries: state.persisted.lock().unwrap().heal_log.clone().unwrap_or_default(),
    }
}

// ─────────── Мелкие настройки ───────────

#[tauri::command(async)]
pub fn get_onboarding_done(state: State<AppState>) -> bool {
    state.persisted.lock().unwrap().onboarding_done.unwrap_or(false)
}

#[tauri::command(async)]
pub fn set_onboarding_done(app: AppHandle, state: State<AppState>, done: bool) -> SimpleResult {
    state.persisted.lock().unwrap().onboarding_done = Some(done);
    save_state(&app, &state);
    ok()
}

#[derive(Debug, Serialize)]
pub struct NotifyState {
    enabled: bool,
    /// Тосты есть в любой поддерживаемой Windows (10+); поле ждёт renderer.
    supported: bool,
}

#[tauri::command(async)]
pub fn get_notifications(state: State<AppState>) -> NotifyState {
    NotifyState { enabled: state.persisted.lock().unwrap().notifications.unwrap_or(true), supported: true }
}

#[tauri::command(async)]
pub fn set_notifications(app: AppHandle, state: State<AppState>, enabled: bool) -> SimpleResult {
    state.persisted.lock().unwrap().notifications = Some(enabled);
    save_state(&app, &state);
    ok()
}

// ─────────── Telegram-прокси ───────────

#[tauri::command(async)]
pub fn start_tgwsproxy(app: AppHandle) -> SimpleResult {
    match crate::tgws::start(&app) {
        Ok(()) => ok(),
        Err(e) => err(e),
    }
}

#[tauri::command(async)]
pub fn stop_tgwsproxy(app: AppHandle) -> SimpleResult {
    crate::tgws::stop(&app);
    ok()
}

#[tauri::command(async)]
pub fn restart_tgwsproxy(app: AppHandle) -> SimpleResult {
    crate::tgws::stop(&app);
    std::thread::sleep(std::time::Duration::from_millis(400));
    match crate::tgws::start(&app) {
        Ok(()) => ok(),
        Err(e) => err(e),
    }
}

#[derive(Debug, Serialize)]
pub struct TgStatus {
    running: bool,
    healthy: bool,
    available: bool,
    host: String,
    port: u16,
    autostart: bool,
    /// Готовая ссылка для Telegram — кнопка «Скопировать» берёт её отсюда.
    #[serde(rename = "tgProxyUrl")]
    tg_proxy_url: String,
}

#[tauri::command(async)]
pub fn get_tgwsproxy_status(app: AppHandle, state: State<AppState>) -> TgStatus {
    crate::tgws::ensure_settings(&app);
    let s = state.persisted.lock().unwrap().tgws.clone().unwrap_or_default();
    let running = state.tgws_pid.lock().unwrap().is_some();
    let healthy = running && crate::tgws::probe_health(&s);
    let available = app
        .path()
        .resource_dir()
        .map(|d| d.join("TgWsProxyHeadless.exe").exists())
        .unwrap_or(false)
        || std::path::Path::new("bin/TgWsProxyHeadless.exe").exists();
    let tg_proxy_url = crate::tgws::proxy_url(&s);
    TgStatus { running, healthy, available, host: s.host, port: s.port, autostart: s.auto_start, tg_proxy_url }
}

#[derive(Debug, Serialize)]
pub struct TgLog {
    lines: Vec<String>,
}

#[tauri::command(async)]
pub fn get_tgwsproxy_log(state: State<AppState>) -> TgLog {
    TgLog { lines: state.tgws_log.lock().unwrap().clone() }
}

/// Отдаём TgSettings как есть — renderer ждёт именно эти поля
/// (dcIps массивом, cfproxy, autoStart), как было в Electron-версии.
#[tauri::command(async)]
pub fn get_tgwsproxy_settings(app: AppHandle, state: State<AppState>) -> crate::tgws::TgSettings {
    crate::tgws::ensure_settings(&app);
    state.persisted.lock().unwrap().tgws.clone().unwrap_or_default()
}

#[tauri::command(async)]
pub fn set_tgwsproxy_settings(
    app: AppHandle,
    state: State<AppState>,
    host: Option<String>,
    port: Option<u16>,
    secret: Option<String>,
    dc_ips: Option<String>,
    cfproxy: Option<bool>,
) -> SimpleResult {
    // Telegram принимает только 16 байт hex после «dd» — любой другой секрет
    // даёт «неправильную ссылку», поэтому не сохраняем его вовсе.
    let secret = match secret.map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()) {
        None => None,
        Some(sec) => {
            let sec = if sec.len() == 34 && sec.starts_with("dd") { sec[2..].to_string() } else { sec };
            if sec.len() != 32 || !sec.chars().all(|c| c.is_ascii_hexdigit()) {
                return err("Секрет должен состоять из 32 шестнадцатеричных символов (0-9, a-f).");
            }
            Some(sec)
        }
    };
    {
        let mut p = state.persisted.lock().unwrap();
        let mut s = p.tgws.clone().unwrap_or_default();
        if let Some(h) = host.filter(|h| !h.trim().is_empty()) {
            s.host = h.trim().to_string();
        }
        if let Some(pt) = port.filter(|p| *p > 0) {
            s.port = pt;
        }
        if let Some(sec) = secret {
            s.secret = sec;
        }
        if let Some(d) = dc_ips {
            let list: Vec<String> = d
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();
            if !list.is_empty() {
                s.dc_ips = list;
            }
        }
        if let Some(cf) = cfproxy {
            s.cfproxy = cf;
        }
        p.tgws = Some(s);
    }
    save_state(&app, &state);
    ok()
}

#[tauri::command(async)]
pub fn set_tgwsproxy_autostart(app: AppHandle, state: State<AppState>, enabled: bool) -> SimpleResult {
    {
        let mut p = state.persisted.lock().unwrap();
        let mut s = p.tgws.clone().unwrap_or_default();
        s.auto_start = enabled;
        p.tgws = Some(s);
    }
    save_state(&app, &state);
    ok()
}

#[derive(Debug, Serialize)]
pub struct SecretResult {
    ok: bool,
    secret: String,
}

#[tauri::command(async)]
pub fn regenerate_tgwsproxy_secret(app: AppHandle, state: State<AppState>) -> SecretResult {
    let secret = crate::tgws::random_secret();
    {
        let mut p = state.persisted.lock().unwrap();
        let mut s = p.tgws.clone().unwrap_or_default();
        s.secret = secret.clone();
        p.tgws = Some(s);
    }
    save_state(&app, &state);
    SecretResult { ok: true, secret }
}

#[tauri::command(async)]
pub fn open_tg_proxy_link(app: AppHandle, state: State<AppState>) -> SimpleResult {
    crate::tgws::ensure_settings(&app);
    let s = state.persisted.lock().unwrap().tgws.clone().unwrap_or_default();
    open_url(&crate::tgws::proxy_url(&s))
}

// ─────────── Ссылки и файлы ───────────

/// Напрямую через ShellExecuteW, а не `cmd /c start`: cmd разбирает строку
/// заново и режет её по `&`, так что tg://proxy?server=…&port=…&secret=…
/// доезжал до Telegram без порта и секрета — отсюда «неправильная ссылка».
#[cfg(target_os = "windows")]
fn open_url(target: &str) -> SimpleResult {
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let verb = wide("open");
    let file = wide(target);
    let res = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute сигналит успех значением больше 32.
    if res as isize > 32 {
        ok()
    } else {
        err("Не удалось открыть ссылку — нет приложения, которое её обрабатывает.")
    }
}

#[cfg(not(target_os = "windows"))]
fn open_url(_target: &str) -> SimpleResult {
    err("Открытие ссылок поддерживается только в Windows.")
}

/// Через плагин буфера обмена на стороне Rust: navigator.clipboard в WebView2
/// отказывает в записи, из-за чего копирование молча не срабатывало.
#[tauri::command(async)]
pub fn copy_text(app: AppHandle, text: String) -> SimpleResult {
    use tauri_plugin_clipboard_manager::ClipboardExt;
    match app.clipboard().write_text(text) {
        Ok(()) => ok(),
        Err(e) => err(e.to_string()),
    }
}

#[tauri::command(async)]
pub fn open_external_url(url: String) -> SimpleResult {
    if !url.starts_with("https://") && !url.starts_with("http://") && !url.starts_with("tg://") {
        return err("Недопустимая ссылка.");
    }
    open_url(&url)
}

#[tauri::command(async)]
pub fn open_release_folder(state: State<AppState>) -> SimpleResult {
    match root_of(&state) {
        Some(root) => {
            crate::sys::run("explorer", &[&root.to_string_lossy()]);
            ok()
        }
        None => err("Релиз не загружен."),
    }
}

#[tauri::command(async)]
pub fn open_result_file(state: State<AppState>, file_name: String) -> SimpleResult {
    // Только внутри папки результатов — имя приходит из интерфейса, но
    // проверить дешевле, чем доверять.
    if file_name.contains("..") || file_name.contains('/') || file_name.contains('\\') {
        return err("Недопустимое имя файла.");
    }
    match root_of(&state) {
        Some(root) => {
            let p = root.join("utils").join("test results").join(&file_name);
            if !p.exists() {
                return err("Файл не найден.");
            }
            crate::sys::run("explorer", &[&p.to_string_lossy()]);
            ok()
        }
        None => err("Релиз не загружен."),
    }
}

// ─────────── История прогонов ───────────

#[derive(Debug, Serialize)]
pub struct HistoryRun {
    date: String,
    file: String,
    best: Option<String>,
    mode: String,
    #[serde(rename = "maxScore")]
    max_score: u32,
}

#[derive(Debug, Serialize)]
pub struct HistoryConfig {
    name: String,
    #[serde(rename = "latestShare")]
    latest_share: Option<f64>,
    #[serde(rename = "shareSeries")]
    share_series: Vec<f64>,
    wins: u32,
}

#[derive(Debug, Serialize)]
pub struct HistoryResult {
    ok: bool,
    runs: Vec<HistoryRun>,
    configs: Vec<HistoryConfig>,
}

#[tauri::command(async)]
pub fn get_test_history(state: State<AppState>) -> HistoryResult {
    let Some(root) = root_of(&state) else {
        return HistoryResult { ok: true, runs: vec![], configs: vec![] };
    };
    let dir = root.join("utils").join("test results");
    let mut files: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(d) => d
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.to_lowercase().ends_with(".txt"))
            .collect(),
        Err(_) => return HistoryResult { ok: true, runs: vec![], configs: vec![] },
    };
    files.sort();

    let mut runs = Vec::new();
    // config -> доли по прогонам, в порядке от старого к новому
    let mut series: std::collections::BTreeMap<String, Vec<f64>> = Default::default();
    let mut wins: std::collections::BTreeMap<String, u32> = Default::default();

    for f in &files {
        let Ok(text) = std::fs::read_to_string(dir.join(f)) else { continue };
        let (rows, dpi) = crate::tests::parse_results(&text);
        if rows.is_empty() {
            continue;
        }
        let best_score = rows.iter().map(|r| r.score(dpi)).fold(0.0_f64, f64::max);
        let best = rows
            .iter()
            .max_by(|a, b| a.score(dpi).partial_cmp(&b.score(dpi)).unwrap_or(std::cmp::Ordering::Equal))
            .map(|r| r.config.clone());
        if let Some(b) = &best {
            *wins.entry(b.clone()).or_insert(0) += 1;
        }
        for r in &rows {
            // Доля от лучшего в прогоне: иначе HTTP и DPI с разными
            // максимумами между собой не сравнить.
            let share = if best_score > 0.0 { r.score(dpi) / best_score } else { 0.0 };
            series.entry(r.config.clone()).or_default().push(share);
        }
        runs.push(HistoryRun {
            date: f.trim_end_matches(".txt").to_string(),
            file: f.clone(),
            best,
            mode: if dpi { "dpi".into() } else { "standard".into() },
            max_score: (best_score * 7.0).round() as u32,
        });
    }

    let configs = series
        .into_iter()
        .map(|(name, s)| HistoryConfig {
            latest_share: s.last().copied(),
            share_series: s,
            wins: *wins.get(&name).unwrap_or(&0),
            name,
        })
        .collect();

    HistoryResult { ok: true, runs, configs }
}

// ─────────── Обслуживание ───────────

#[tauri::command(async)]
pub fn update_ipset_list(state: State<AppState>) -> serde_json::Value {
    match root_of(&state) {
        Some(root) => serde_json::to_value(crate::maintenance::update_ipset(&root)).unwrap_or_default(),
        None => serde_json::json!({ "ok": false, "error": "Сначала загрузи релиз zapret." }),
    }
}

#[tauri::command(async)]
pub fn update_hosts_file() -> serde_json::Value {
    serde_json::to_value(crate::maintenance::update_hosts()).unwrap_or_default()
}

#[tauri::command(async)]
pub fn check_updates(state: State<AppState>) -> serde_json::Value {
    match root_of(&state) {
        Some(root) => serde_json::to_value(crate::maintenance::check_updates(&root)).unwrap_or_default(),
        None => serde_json::json!({ "ok": false, "error": "Сначала загрузи релиз zapret." }),
    }
}

// ─────────── Версии компонентов ───────────

#[derive(Debug, Serialize)]
pub struct Versions {
    /// Версия Klutz — единственный источник: tauri.conf.json / Cargo.toml.
    app: String,
    zapret: Option<String>,
    tgws: &'static str,
}

#[tauri::command(async)]
pub fn get_versions(app: AppHandle, state: State<AppState>) -> Versions {
    Versions {
        app: app.package_info().version.to_string(),
        zapret: root_of(&state).and_then(|r| crate::maintenance::local_version(&r)),
        tgws: crate::tgws::BUNDLED_VERSION,
    }
}

#[derive(Debug, Serialize)]
pub struct ComponentUpdate {
    current: Option<String>,
    latest: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ComponentUpdates {
    zapret: ComponentUpdate,
    tgws: ComponentUpdate,
}

/// Сверяет обе встроенные части с последними версиями у Flowseal.
#[tauri::command(async)]
pub fn check_component_updates(state: State<AppState>) -> ComponentUpdates {
    let zapret = match root_of(&state) {
        Some(root) => {
            let u = crate::maintenance::check_updates(&root);
            ComponentUpdate {
                current: Some(u.local),
                latest: if u.ok { Some(u.remote) } else { None },
                error: u.error,
            }
        }
        None => ComponentUpdate { current: None, latest: None, error: Some("Релиз zapret не загружен.".into()) },
    };
    let current = Some(crate::tgws::BUNDLED_VERSION.to_string());
    let tgws = match crate::tgws::latest_upstream() {
        Ok(latest) => ComponentUpdate { current, latest: Some(latest), error: None },
        Err(e) => ComponentUpdate { current, latest: None, error: Some(e) },
    };
    ComponentUpdates { zapret, tgws }
}

#[tauri::command(async)]
pub fn clear_discord_cache() -> serde_json::Value {
    serde_json::to_value(crate::maintenance::clear_discord_cache()).unwrap_or_default()
}

#[tauri::command(async)]
pub fn get_custom_lists(state: State<AppState>) -> serde_json::Value {
    match root_of(&state) {
        Some(root) => serde_json::to_value(crate::maintenance::get_custom_lists(&root)).unwrap_or_default(),
        None => serde_json::json!({ "ok": false, "include": "", "exclude": "" }),
    }
}

#[tauri::command(async)]
pub fn save_custom_lists(state: State<AppState>, include: String, exclude: String) -> SimpleResult {
    match root_of(&state) {
        Some(root) => match crate::maintenance::save_custom_lists(&root, &include, &exclude) {
            Ok(()) => ok(),
            Err(e) => err(e),
        },
        None => err("Сначала загрузи релиз zapret."),
    }
}

// ─────────── Экспорт / импорт настроек ───────────
//
// Намеренно узко: только то, что переносимо между машинами и релизами.
// gameFilter, ipsetMode и свои списки доменов живут файлами внутри папки
// релиза, а не здесь, — они вне области.

#[tauri::command(async)]
pub fn export_settings(app: AppHandle, state: State<AppState>, path: String) -> SimpleResult {
    let p = state.persisted.lock().unwrap();
    let payload = serde_json::json!({
        "gameTargets": p.game_targets,
        "autoSwitch": p.auto_switch,
        "notifications": p.notifications,
        "tgws": p.tgws,
    });
    drop(p);
    let _ = &app;
    match std::fs::write(&path, serde_json::to_string_pretty(&payload).unwrap_or_default()) {
        Ok(()) => ok(),
        Err(e) => err(e.to_string()),
    }
}

#[tauri::command(async)]
pub fn import_settings(app: AppHandle, state: State<AppState>, path: String) -> SimpleResult {
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => return err(e.to_string()),
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return err("Файл настроек повреждён.");
    };
    {
        let mut p = state.persisted.lock().unwrap();
        if let Some(t) = v.get("gameTargets") {
            p.game_targets = serde_json::from_value(t.clone()).ok();
        }
        if let Some(a) = v.get("autoSwitch") {
            if let Ok(a) = serde_json::from_value(a.clone()) {
                p.auto_switch = Some(a);
            }
        }
        if let Some(n) = v.get("notifications").and_then(|n| n.as_bool()) {
            p.notifications = Some(n);
        }
        if let Some(t) = v.get("tgws") {
            if let Ok(t) = serde_json::from_value(t.clone()) {
                p.tgws = Some(t);
            }
        }
    }
    save_state(&app, &state);
    ok()
}

// ─────────── Релизы zapret ───────────

#[tauri::command(async)]
pub fn get_latest_release_info() -> crate::releases::LatestRelease {
    crate::releases::latest_release()
}

#[derive(Debug, Serialize)]
pub struct DownloadResult {
    ok: bool,
    error: Option<String>,
    root: Option<String>,
}

/// Скачивает свежий релиз и сразу распаковывает — интерфейсу нужен готовый
/// корень, а не путь к архиву.
#[tauri::command(async)]
pub fn download_latest_release(app: AppHandle, state: State<AppState>) -> DownloadResult {
    let zip = match crate::releases::download_latest(&app) {
        Ok(p) => p,
        Err(e) => return DownloadResult { ok: false, error: Some(e), root: None },
    };
    let name = zip.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "release".into());
    let target = crate::releases::releases_dir(&app).join(&name);
    let root = match crate::releases::extract_zip(&zip, &target) {
        Ok(r) => r,
        Err(e) => return DownloadResult { ok: false, error: Some(e), root: None },
    };
    let _ = std::fs::remove_file(&zip);

    let check = validate_release(&root);
    if !check.ok {
        return DownloadResult {
            ok: false,
            error: check.error.or_else(|| Some("Скачанный архив не похож на релиз zapret.".into())),
            root: None,
        };
    }
    {
        let mut p = state.persisted.lock().unwrap();
        p.root_path = Some(root.to_string_lossy().to_string());
        p.active_config = None;
        p.installed_as_service = false;
        p.started_at = None;
        p.can_install_service = check.can_install_service;
    }
    save_state(&app, &state);
    DownloadResult { ok: true, error: None, root: Some(root.to_string_lossy().to_string()) }
}

#[derive(Debug, Serialize)]
pub struct ReleasesList {
    ok: bool,
    releases: Vec<crate::releases::ReleaseEntry>,
}

#[tauri::command(async)]
pub fn list_releases(app: AppHandle, state: State<AppState>) -> ReleasesList {
    let current = state.persisted.lock().unwrap().root_path.clone();
    ReleasesList { ok: true, releases: crate::releases::list_releases(&app, current.as_deref()) }
}

#[tauri::command(async)]
pub fn delete_release(app: AppHandle, folder_name: String) -> SimpleResult {
    match crate::releases::delete_release(&app, &folder_name) {
        Ok(()) => ok(),
        Err(e) => err(e),
    }
}

/// Распаковка вручную выбранного .zip — второй путь загрузки релиза,
/// помимо скачивания с GitHub.
#[tauri::command(async)]
pub fn load_archive(app: AppHandle, state: State<AppState>, zip_path: String) -> LoadPathResult {
    let zip = PathBuf::from(&zip_path);
    let name = zip.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "release".into());
    let target = crate::releases::releases_dir(&app).join(&name);
    let root = match crate::releases::extract_zip(&zip, &target) {
        Ok(r) => r,
        Err(e) => return LoadPathResult::Err { ok: false, error: e },
    };
    load_path(app, state, root.to_string_lossy().to_string())
}

// ─────────── Уведомления ───────────

#[derive(Debug, Serialize)]
pub struct NotifySound {
    volume: u8,
    duration: String,
}

#[tauri::command(async)]
pub fn get_notify_sound(state: State<AppState>) -> NotifySound {
    let p = state.persisted.lock().unwrap();
    NotifySound {
        volume: p.notify_volume.unwrap_or(70),
        duration: p.notify_duration.clone().unwrap_or_else(|| "short".into()),
    }
}

#[tauri::command(async)]
pub fn set_notify_sound(
    app: AppHandle,
    state: State<AppState>,
    volume: Option<u8>,
    duration: Option<String>,
) -> SimpleResult {
    {
        let mut p = state.persisted.lock().unwrap();
        if let Some(v) = volume {
            p.notify_volume = Some(v.min(100));
        }
        if let Some(d) = duration {
            p.notify_duration = Some(if d == "long" { d } else { "short".into() });
        }
    }
    save_state(&app, &state);
    ok()
}

#[tauri::command(async)]
pub fn test_notification(app: AppHandle, state: State<AppState>) -> SimpleResult {
    // send() молча ничего не делает при выключенных уведомлениях — без этой
    // проверки кнопка «Проверить» обещала бы тост, которого не будет.
    if !state.persisted.lock().unwrap().notifications.unwrap_or(true) {
        return err("Уведомления выключены — включи переключатель выше.");
    }
    crate::notify::send(&app, &state, "Klutz: тестовое уведомление", "Так будут выглядеть сообщения о сбоях и итогах тестов.");
    ok()
}

// ─────────── Расписание автопрогона тестов ───────────

#[derive(Debug, Serialize)]
pub struct AutoTestSchedule {
    enabled: bool,
    days: u32,
    mode: String,
    #[serde(rename = "lastRunAt")]
    last_run_at: Option<u64>,
}

#[tauri::command(async)]
pub fn get_auto_test_schedule(state: State<AppState>) -> AutoTestSchedule {
    let p = state.persisted.lock().unwrap();
    AutoTestSchedule {
        enabled: p.autotest_enabled.unwrap_or(false),
        days: p.autotest_days.unwrap_or(7),
        mode: p.autotest_mode.clone().unwrap_or_else(|| "standard".into()),
        last_run_at: p.autotest_last_run,
    }
}

#[tauri::command(async)]
pub fn set_auto_test_schedule(
    app: AppHandle,
    state: State<AppState>,
    enabled: Option<bool>,
    days: Option<u32>,
    mode: Option<String>,
) -> SimpleResult {
    {
        let mut p = state.persisted.lock().unwrap();
        if let Some(e) = enabled {
            p.autotest_enabled = Some(e);
        }
        if let Some(d) = days {
            p.autotest_days = Some(d.clamp(1, 30));
        }
        if let Some(m) = mode {
            p.autotest_mode = Some(if m == "dpi" { m } else { "standard".into() });
        }
    }
    save_state(&app, &state);
    ok()
}

#[tauri::command]
pub fn window_minimize(window: tauri::Window) {
    let _ = window.minimize();
}

#[tauri::command]
pub fn window_toggle_maximize(window: tauri::Window) {
    if window.is_maximized().unwrap_or(false) {
        let _ = window.unmaximize();
    } else {
        let _ = window.maximize();
    }
}

// TODO: once the tray icon is ported, this should hide-to-tray like the
// Electron build did (closing the window ≠ quitting — winws.exe keeps
// running). For this first slice it just quits, so there's no way to get a
// hidden window back yet.
#[tauri::command]
pub fn window_close(window: tauri::Window) {
    let _ = window.close();
}

#[tauri::command]
pub fn window_is_maximized(window: tauri::Window) -> bool {
    window.is_maximized().unwrap_or(false)
}
