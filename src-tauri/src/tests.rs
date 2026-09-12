use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::Write;
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
    /// Сколько целей всего проверяли — знаменатель `score`. Он зависит от
    /// релиза и режима, поэтому восстанавливать его из доли по памяти
    /// («было же семь целей») нельзя: число целей задаёт чужой скрипт.
    pub fn total(&self, dpi: bool) -> u32 {
        // saturating: числа приходят из чужого файла результатов, и сумма
        // u32 у самой границы в release-сборке тихо переполнилась бы.
        let base = self.ok.saturating_add(self.err).saturating_add(self.unsup);
        if dpi {
            base.saturating_add(self.blocked)
        } else {
            base
        }
    }

    /// Доля целей, которые реально ответили. В DPI-режиме «заблокировано»
    /// считается неудачей наравне с ошибкой.
    pub fn score(&self, dpi: bool) -> f64 {
        let total = self.total(dpi);
        if total == 0 {
            0.0
        } else {
            self.ok as f64 / total as f64
        }
    }

    /// Доля успешных пингов. В DPI-режиме скрипт пингов не гоняет — там ноль.
    pub fn ping_share(&self) -> f64 {
        let total = self.ping_ok.saturating_add(self.ping_fail);
        if total == 0 {
            0.0
        } else {
            self.ping_ok as f64 / total as f64
        }
    }
}

/// Порядок «лучше → хуже» внутри одного прогона.
///
/// Живёт в одном месте, потому что по нему выбирают трое: самолечение,
/// меню трея и автопрогон. Разойдись они — окно предложило бы одну
/// стратегию, а переключилось бы на другую.
///
/// Ping участвует только как разрешение ничьей. Он меряет доступность узла
/// по ICMP, а режут нас на TLS ClientHello: дай пингу вес в самой оценке, и
/// конфиг с отличным пингом и посредственным HTTP обойдёт тот, который
/// реально работает. При равном HTTP предпочесть меньше потерь — честно.
pub fn rank_desc(a: &ResultRow, b: &ResultRow, dpi: bool) -> std::cmp::Ordering {
    b.score(dpi)
        .partial_cmp(&a.score(dpi))
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| {
            b.ping_share()
                .partial_cmp(&a.ping_share())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
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

/// stdout и stderr — разные типы, а обрабатываем их одинаково.
enum Either {
    Out(std::process::ChildStdout),
    Err(std::process::ChildStderr),
}

fn results_dir(root: &Path) -> PathBuf {
    root.join("utils").join("test results")
}

fn is_result_file(name: &str) -> bool {
    name.to_lowercase().ends_with(".txt")
}

fn snapshot_results(root: &Path) -> HashSet<String> {
    fs::read_dir(results_dir(root))
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| is_result_file(n))
                .collect()
        })
        .unwrap_or_default()
}

/// Самый свежий файл результатов из тех, что прошли `keep`.
///
/// По времени изменения, а не по алфавиту: имена файлов результатов задаёт
/// чужой скрипт, и их порядок не обязан совпадать с временем. Фильтр по
/// расширению — чтобы «результатом» не стал случайный файл или подкаталог,
/// созданный скриптом позже.
fn newest_matching(root: &Path, keep: impl Fn(&str) -> bool) -> Option<PathBuf> {
    fs::read_dir(results_dir(root))
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .into_string()
                .map(|n| is_result_file(&n) && keep(&n))
                .unwrap_or(false)
        })
        .filter_map(|e| {
            let t = e.metadata().and_then(|m| m.modified()).ok()?;
            Some((t, e.path()))
        })
        .max_by_key(|(t, _)| *t)
        .map(|(_, p)| p)
}

fn newest_new_result(root: &Path, before: &HashSet<String>) -> Option<PathBuf> {
    newest_matching(root, |n| !before.contains(n))
}

/// Последний прогон вообще — им пользуются окно, трей и самолечение.
/// Раньше каждый из них брал файл по алфавиту и мог взять не тот.
pub fn newest_result_file(root: &Path) -> Option<PathBuf> {
    newest_matching(root, |_| true)
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
    let mut cmd = Command::new(crate::sys::system_exe("powershell.exe"));
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
    let pid = child.id();
    {
        use tauri::Manager;
        *app.state::<crate::state::AppState>().test_pid.lock().unwrap() = Some(pid);
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

    for stream in [child.stdout.take().map(Either::Out), child.stderr.take().map(Either::Err)]
        .into_iter()
        .flatten()
    {
        let app2 = app.clone();
        std::thread::spawn(move || {
            let emit = |line: String| {
                if !line.trim().is_empty() {
                    let _ = app2.emit("test-log", line);
                }
            };
            match stream {
                Either::Out(s) => crate::sys::for_each_line(s, emit),
                Either::Err(s) => crate::sys::for_each_line(s, emit),
            }
        });
    }

    let status = child.wait().map_err(|e| e.to_string())?;
    let _ = status;
    {
        use tauri::Manager;
        // Только если это всё ещё наш PID: в воронке скрипт запускается
        // дважды, и безусловное обнуление стирало бы номер чужого этапа.
        let state = app.state::<crate::state::AppState>();
        let mut guard = state.test_pid.lock().unwrap();
        if *guard == Some(pid) {
            *guard = None;
        }
    }

    let file = newest_new_result(root, &before)
        .ok_or("Тесты завершились, но файл результатов не найден.")?;
    fs::read_to_string(file).map_err(|e| e.to_string())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn row(ok: u32, err: u32, unsup: u32, blocked: u32) -> ResultRow {
        ResultRow { config: "c".into(), ok, err, unsup, ping_ok: 0, ping_fail: 0, blocked }
    }

    #[test]
    fn score_не_переполняется_на_значениях_из_чужого_файла() {
        let r = row(u32::MAX, u32::MAX, u32::MAX, u32::MAX);
        let s = r.score(true);
        assert!(s.is_finite() && (0.0..=1.0).contains(&s), "получили {s}");
        let s = r.score(false);
        assert!(s.is_finite() && (0.0..=1.0).contains(&s));
    }

    #[test]
    fn score_в_dpi_считает_заблокированные_неудачей() {
        let r = row(5, 0, 0, 5);
        assert_eq!(r.score(true), 0.5);
        assert_eq!(r.score(false), 1.0);
    }

    #[test]
    fn score_пустой_строки_ноль_а_не_паника() {
        assert_eq!(row(0, 0, 0, 0).score(true), 0.0);
    }

    fn row_p(ok: u32, err: u32, ping_ok: u32, ping_fail: u32) -> ResultRow {
        ResultRow { config: "c".into(), ok, err, unsup: 0, ping_ok, ping_fail, blocked: 0 }
    }

    #[test]
    fn total_это_настоящее_число_целей_а_не_семь() {
        // Раньше знаменатель восстанавливали как «доля × 7» — число целей
        // из Electron-версии. Оно зависит от релиза и от режима.
        assert_eq!(row(6, 1, 0, 0).total(false), 7);
        assert_eq!(row(6, 1, 2, 0).total(false), 9);
        // В DPI «заблокировано» тоже проверенная цель.
        assert_eq!(row(5, 0, 0, 5).total(true), 10);
        assert_eq!(row(5, 0, 0, 5).total(false), 5);
        assert_eq!(row(0, 0, 0, 0).total(true), 0);
    }

    #[test]
    fn ping_решает_только_ничью_и_не_перебивает_http() {
        let лучше_по_http = row_p(7, 0, 0, 5); // HTTP идеален, пинг ужасен
        let хуже_по_http = row_p(5, 2, 5, 0); // HTTP хуже, пинг идеален
        assert_eq!(
            rank_desc(&лучше_по_http, &хуже_по_http, false),
            std::cmp::Ordering::Less,
            "конфиг с лучшим HTTP должен идти первым, каким бы ни был пинг"
        );
    }

    #[test]
    fn при_равном_http_вперёд_идёт_меньше_потерь_по_пингу() {
        let целый_пинг = row_p(6, 1, 7, 0);
        let рваный_пинг = row_p(6, 1, 3, 4);
        assert_eq!(rank_desc(&целый_пинг, &рваный_пинг, false), std::cmp::Ordering::Less);
        assert_eq!(rank_desc(&рваный_пинг, &целый_пинг, false), std::cmp::Ordering::Greater);
    }

    #[test]
    fn порядок_устойчив_когда_равно_всё() {
        let a = row_p(6, 1, 7, 0);
        let b = row_p(6, 1, 7, 0);
        assert_eq!(rank_desc(&a, &b, false), std::cmp::Ordering::Equal);
    }

    #[test]
    fn сортировка_по_rank_desc_ставит_лучшее_первым() {
        let mut rows = vec![row_p(3, 4, 7, 0), row_p(7, 0, 0, 7), row_p(5, 2, 7, 0)];
        rows.sort_by(|a, b| rank_desc(a, b, false));
        assert_eq!(rows.iter().map(|r| r.ok).collect::<Vec<_>>(), vec![7, 5, 3]);
        // min_by по тому же порядку обязан дать ту же голову: им пользуются
        // автопрогон и история, а сортировкой — трей и самолечение.
        let best = rows.iter().min_by(|a, b| rank_desc(a, b, false)).unwrap();
        assert_eq!(best.ok, 7);
    }

    #[test]
    fn разбор_обоих_форматов_analytics() {
        let std_text = "шум\n=== ANALYTICS ===\ngeneral (ALT).bat: HTTP OK: 6, ERR: 1, UNSUP: 0, Ping OK: 5, Fail: 2\n";
        let (rows, dpi) = parse_results(std_text);
        assert!(!dpi);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].config, "general (ALT).bat");
        assert_eq!((rows[0].ok, rows[0].err, rows[0].ping_ok, rows[0].ping_fail), (6, 1, 5, 2));

        let dpi_text = "=== ANALYTICS ===\ngeneral.bat: OK: 3, ERR: 1, UNSUP: 0, BLOCKED: 3\n";
        let (rows, dpi) = parse_results(dpi_text);
        assert!(dpi);
        assert_eq!((rows[0].ok, rows[0].blocked), (3, 3));
    }

    #[test]
    fn файлом_результата_считается_только_txt() {
        assert!(is_result_file("2026-09-12 14-05.txt"));
        assert!(is_result_file("A.TXT"));
        assert!(!is_result_file("лог.log"));
        assert!(!is_result_file("подкаталог"));
    }
}
