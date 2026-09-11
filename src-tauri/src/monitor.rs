//! Фоновая проверка связи и самолечение.
//!
//! Стратегия считается «просевшей», когда большинство ключевых целей перестало
//! отвечать. Одна неудачная проверка — обычно просто сетевая икота, поэтому
//! требуем несколько подряд, прежде чем что-то делать.

use tauri::{AppHandle, Emitter, Manager};

use crate::state::{save_state, AppState, HealEntry};
use crate::targets;
use crate::winws;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn is_core(name: &str) -> bool {
    let n = name.to_lowercase();
    n.starts_with("discord") || n.starts_with("youtube")
}

pub fn start(app: AppHandle) {
    std::thread::spawn(move || loop {
        let interval = {
            let state = app.state::<AppState>();
            let p = state.persisted.lock().unwrap();
            p.auto_switch.as_ref().map(|a| a.interval_sec).unwrap_or(30)
        };
        std::thread::sleep(std::time::Duration::from_secs(interval.clamp(10, 600)));
        tick(&app);
    });
}

fn tick(app: &AppHandle) {
    let state = app.state::<AppState>();

    // Во время прогона тестов стратегия меняется каждые несколько секунд —
    // мерить в этот момент бессмысленно и вредно.
    if *state.testing.lock().unwrap() {
        return;
    }
    if !winws::is_winws_running() {
        *state.last_check.lock().unwrap() = None;
        state.last_targets.lock().unwrap().clear();
        *state.degraded_ticks.lock().unwrap() = 0;
        crate::tray::refresh(app);
        return;
    }

    let list = {
        let p = state.persisted.lock().unwrap();
        p.game_targets.clone().unwrap_or_else(targets::default_targets)
    };
    let core: Vec<_> = list.into_iter().filter(|t| is_core(&t.name)).collect();
    if core.is_empty() {
        return;
    }
    let results = targets::check_targets(&core);
    let ok = results.iter().filter(|r| r.ok).count();
    let total = results.len();
    *state.last_check.lock().unwrap() = Some((ok, total));
    *state.last_targets.lock().unwrap() = results.iter().map(|r| (r.name.clone(), r.ok, r.ms)).collect();
    crate::tray::refresh(app);
    let _ = app.emit("monitor-tick", serde_json::json!({ "ok": ok, "total": total }));

    let degraded = total > 0 && ok * 2 < total;
    if !degraded {
        *state.degraded_ticks.lock().unwrap() = 0;
        state.healing_attempts.lock().unwrap().clear();
        return;
    }

    let (enabled, threshold) = {
        let p = state.persisted.lock().unwrap();
        let a = p.auto_switch.clone().unwrap_or_default();
        (a.enabled, a.threshold)
    };
    let ticks = {
        let mut t = state.degraded_ticks.lock().unwrap();
        *t += 1;
        *t
    };
    if ticks < threshold || !enabled {
        return;
    }
    attempt_switch(app);
}

/// Переключается на следующую стратегию из рейтинга последнего прогона,
/// пропуская те, что уже пробовали в этой серии.
fn attempt_switch(app: &AppHandle) {
    let state = app.state::<AppState>();
    let root = match state.persisted.lock().unwrap().root_path.clone() {
        Some(r) => std::path::PathBuf::from(r),
        None => return,
    };

    let ranked = latest_ranking(&root);
    if ranked.is_empty() {
        return;
    }
    let current = state.persisted.lock().unwrap().active_config.clone();
    let tried = state.healing_attempts.lock().unwrap().clone();
    let next = ranked
        .into_iter()
        .find(|c| Some(c) != current.as_ref() && !tried.contains(c) && root.join(c).exists());

    let Some(next) = next else {
        // Перепробовали всё — дальше молотить бессмысленно, выключаем
        // самолечение, чтобы не крутиться вхолостую.
        if !tried.is_empty() {
            let mut p = state.persisted.lock().unwrap();
            if let Some(a) = p.auto_switch.as_mut() {
                a.enabled = false;
            }
            drop(p);
            save_state(app, &state);
            state.healing_attempts.lock().unwrap().clear();
        }
        return;
    };

    state.healing_attempts.lock().unwrap().push(next.clone());
    *state.degraded_ticks.lock().unwrap() = 0;

    if apply_config(app, &next).is_ok() {
        let mut p = state.persisted.lock().unwrap();
        let log = p.heal_log.get_or_insert_with(Vec::new);
        log.push(HealEntry {
            at: now_ms(),
            kind: "switch".into(),
            from: current.clone(),
            to: Some(next.clone()),
            ok: true,
        });
        if log.len() > 50 {
            let cut = log.len() - 50;
            log.drain(0..cut);
        }
        drop(p);
        save_state(app, &state);
        crate::notify::send_from(
            app,
            "Переключился на другую стратегию",
            &format!(
                "{}Включена {}.",
                current
                    .as_ref()
                    .map(|c| format!("{} перестала работать. ", c.trim_end_matches(".bat")))
                    .unwrap_or_default(),
                next.trim_end_matches(".bat")
            ),
        );
        let _ = app.emit(
            "auto-switched",
            serde_json::json!({ "from": current, "to": next }),
        );
    }
}

/// Включает конфиг тем же способом, каким сейчас работает обход: службой,
/// если стоит служба, иначе прямым запуском winws. Общий путь для
/// самолечения и меню «Переключить на» в трее.
pub fn apply_config(app: &AppHandle, name: &str) -> Result<(), String> {
    let state = app.state::<AppState>();
    let (root, as_service) = {
        let p = state.persisted.lock().unwrap();
        (p.root_path.clone(), p.installed_as_service)
    };
    let root = std::path::PathBuf::from(root.ok_or("Сначала загрузи релиз zapret.")?);
    if !root.join(name).exists() {
        return Err(format!("Нет файла {name} в папке релиза."));
    }
    if as_service {
        crate::service::install_service(&root, name).map_err(|e| e.to_string())?;
    } else {
        if crate::service::service_conflict() {
            return Err("Установлена служба Windows «zapret» — сначала сними её.".into());
        }
        winws::spawn_winws(app, &root, name).map_err(|e| e.to_string())?;
    }
    {
        let mut p = state.persisted.lock().unwrap();
        p.active_config = Some(name.to_string());
        p.started_at = Some(now_ms());
    }
    save_state(app, &state);
    crate::tray::refresh(app);
    Ok(())
}

/// Рейтинг из свежайшего файла результатов тестов.
pub fn latest_ranking(root: &std::path::Path) -> Vec<String> {
    let dir = root.join("utils").join("test results");
    let mut files: Vec<String> = match std::fs::read_dir(&dir) {
        Ok(d) => d
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.to_lowercase().ends_with(".txt"))
            .collect(),
        Err(_) => return vec![],
    };
    files.sort();
    let Some(name) = files.pop() else { return vec![] };
    let Ok(text) = std::fs::read_to_string(dir.join(name)) else {
        return vec![];
    };
    let (mut rows, dpi) = crate::tests::parse_results(&text);
    rows.sort_by(|a, b| b.score(dpi).partial_cmp(&a.score(dpi)).unwrap_or(std::cmp::Ordering::Equal));
    rows.into_iter()
        .map(|r| {
            if r.config.to_lowercase().ends_with(".bat") {
                r.config
            } else {
                format!("{}.bat", r.config)
            }
        })
        .collect()
}
