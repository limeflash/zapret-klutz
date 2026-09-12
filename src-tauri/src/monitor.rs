//! Фоновая проверка связи и самолечение.
//!
//! Стратегия считается «просевшей», когда какой-нибудь ключевой сервис
//! (Discord, YouTube) перестал отвечать целиком. Одна неудачная проверка —
//! обычно просто сетевая икота, поэтому требуем несколько подряд, прежде чем
//! что-то делать.

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

/// К какому сервису относится цель. Признак — имя, а его пользователь может
/// переименовать, поэтому ниже есть запасной путь.
fn service_of(name: &str) -> Option<&'static str> {
    let n = name.to_lowercase();
    if n.starts_with("discord") {
        Some("discord")
    } else if n.starts_with("youtube") {
        Some("youtube")
    } else {
        None
    }
}

/// Просадка — когда хоть один ключевой сервис перестал отвечать целиком.
///
/// Считать долей от общего числа хостов нельзя: у Discord их четыре, у
/// YouTube три, и условие «ответило меньше половины» пропускало «Discord
/// лёг весь» (3 из 7), но никогда не срабатывало на «YouTube лёг весь»
/// (4 из 7) — переключение было асимметричным.
fn is_degraded(results: &[targets::TargetResult]) -> bool {
    let mut groups: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    for r in results {
        let e = groups.entry(service_of(&r.name).unwrap_or("прочие")).or_insert((0, 0));
        e.1 += 1;
        if r.ok {
            e.0 += 1;
        }
    }
    groups.values().any(|(ok, total)| *total > 0 && *ok == 0)
}

pub fn start(app: AppHandle) {
    std::thread::spawn(move || loop {
        // Проверяем сразу, а не после первого сна: иначе полминуты после
        // запуска приложение вообще не знает состояния связи.
        tick(&app);
        let interval = {
            let state = app.state::<AppState>();
            let p = state.persisted.lock().unwrap();
            p.auto_switch.as_ref().map(|a| a.interval_sec).unwrap_or(30)
        };
        std::thread::sleep(std::time::Duration::from_secs(interval.clamp(10, 600)));
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
        *state.last_check_at.lock().unwrap() = 0;
        *state.degraded_ticks.lock().unwrap() = 0;
        crate::tray::refresh(app);
        return;
    }

    let list = {
        let p = state.persisted.lock().unwrap();
        p.game_targets.clone().unwrap_or_else(targets::default_targets)
    };
    // Если пользователь переименовал все цели, признака «ключевая» не
    // остаётся. Раньше на этом месте был ранний return — и мониторинг тихо
    // умирал навсегда: трей застывал на старых данных, самолечение не
    // срабатывало, сообщения об этом не было. Берём тогда весь список.
    let mut core: Vec<_> = list.iter().filter(|t| service_of(&t.name).is_some()).cloned().collect();
    if core.is_empty() {
        core = list;
    }
    if core.is_empty() {
        return;
    }
    let results = targets::check_targets(&core);
    let ok = results.iter().filter(|r| r.ok).count();
    let total = results.len();
    *state.last_check.lock().unwrap() = Some((ok, total));
    *state.last_targets.lock().unwrap() = results.iter().map(|r| (r.name.clone(), r.ok, r.ms)).collect();
    *state.last_check_at.lock().unwrap() = now_ms();
    crate::tray::refresh(app);

    let degraded = is_degraded(&results);
    if !degraded {
        *state.degraded_ticks.lock().unwrap() = 0;
        state.healing_attempts.lock().unwrap().clear();
        *state.heal_exhausted.lock().unwrap() = false;
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
    // Имена приходят из файла результатов, который пишет чужой скрипт.
    // Без проверки строка вида «..\\other.bat» увела бы apply_config за
    // пределы папки релиза.
    let configs = crate::release::list_configs(&root);
    let next = ranked
        .into_iter()
        .find(|c| Some(c) != current.as_ref() && !tried.contains(c) && configs.contains(c));

    let Some(next) = next else {
        // Перепробовали всё — молотить дальше бессмысленно, но и выключать
        // самолечение нельзя: раньше здесь стояло `a.enabled = false` с
        // записью на диск, и получасовой обрыв связи навсегда гасил чужую
        // настройку. Список испробованного и так держит нас в покое: пока
        // связь не вернётся, следующей стратегии не найдётся. Как только
        // цели снова ответят, tick() очистит его сам.
        if !tried.is_empty() && !*state.heal_exhausted.lock().unwrap() {
            *state.heal_exhausted.lock().unwrap() = true;
            crate::notify::send_from(
                app,
                "Самолечение перебрало все стратегии",
                "Ни одна из последнего прогона не вернула связь. Похоже, дело не в стратегии — проверь интернет или прогони тесты заново.",
            );
        }
        return;
    };

    state.healing_attempts.lock().unwrap().push(next.clone());
    *state.degraded_ticks.lock().unwrap() = 0;

    let applied = apply_config(app, &next);
    // В журнал попадает и неудача: раньше запись делалась только в ветке
    // успеха и всегда с ok: true, поэтому серия провалившихся переключений
    // выглядела для пользователя полной тишиной.
    {
        let mut p = state.persisted.lock().unwrap();
        let log = p.heal_log.get_or_insert_with(Vec::new);
        log.push(HealEntry {
            at: now_ms(),
            kind: "switch".into(),
            from: current.clone(),
            to: Some(next.clone()),
            ok: applied.is_ok(),
        });
        if log.len() > 50 {
            let cut = log.len() - 50;
            log.drain(0..cut);
        }
        drop(p);
        save_state(app, &state);
    }

    if applied.is_ok() {
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
    // Ровно один из показанных конфигов, а не любой существующий путь:
    // дальше имя уезжает в cmd /c, который разбирает строку заново.
    if !crate::release::list_configs(&root).iter().any(|c| c == name) {
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
    // Свежайший — по времени изменения. Здесь ошибиться дороже всего:
    // по этому рейтингу самолечение выбирает, на что переключаться.
    let Some(path) = crate::tests::newest_result_file(root) else {
        return vec![];
    };
    let Ok(text) = std::fs::read_to_string(path) else {
        return vec![];
    };
    let (mut rows, dpi) = crate::tests::parse_results(&text);
    rows.sort_by(|a, b| crate::tests::rank_desc(a, b, dpi));
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

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::targets::TargetResult;

    fn t(name: &str, ok: bool) -> TargetResult {
        TargetResult { name: name.into(), host: "h".into(), port: 443, ok, ms: 1, reason: None, probe: "http" }
    }

    /// Стандартные ключевые цели: четыре Discord и три YouTube.
    fn целиком(discord_ok: bool, youtube_ok: bool) -> Vec<TargetResult> {
        let mut v: Vec<_> = (1..=4).map(|i| t(&format!("Discord {i}"), discord_ok)).collect();
        v.extend((1..=3).map(|i| t(&format!("YouTube {i}"), youtube_ok)));
        v
    }

    #[test]
    fn просадка_симметрична_по_сервисам() {
        assert!(is_degraded(&целиком(false, true)), "Discord лёг целиком — это просадка");
        // Ровно этот случай старое условие ok*2 < total не ловило никогда:
        // 4 живых из 7, 8 < 7 ложно.
        assert!(is_degraded(&целиком(true, false)), "YouTube лёг целиком — тоже просадка");
        assert!(!is_degraded(&целиком(true, true)), "всё отвечает — не просадка");
        assert!(is_degraded(&целиком(false, false)));
    }

    #[test]
    fn старое_условие_действительно_пропускало_youtube() {
        let r = целиком(true, false);
        let ok = r.iter().filter(|x| x.ok).count();
        assert_eq!(ok, 4);
        assert!(!(ok * 2 < r.len()), "старое условие тут молчало");
    }

    #[test]
    fn одна_упавшая_цель_из_сервиса_не_считается_просадкой() {
        let mut r = целиком(true, true);
        r[0].ok = false;
        assert!(!is_degraded(&r), "одна икота из четырёх — не повод переключаться");
    }

    #[test]
    fn сервис_определяется_без_учёта_регистра() {
        assert_eq!(service_of("Discord Main"), Some("discord"));
        assert_eq!(service_of("YOUTUBE Web"), Some("youtube"));
        assert_eq!(service_of("Steam"), None);
    }

    #[test]
    fn переименованные_цели_попадают_в_одну_группу() {
        // Пользователь переименовал всё — раньше tick() уходил в ранний
        // return и мониторинг умирал молча.
        let r = vec![t("Дискорд", false), t("Ютуб", false)];
        assert!(is_degraded(&r));
        let r = vec![t("Дискорд", true), t("Ютуб", true)];
        assert!(!is_degraded(&r));
    }
}
