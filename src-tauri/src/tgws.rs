//! TgWsProxy — мост MTProto↔WebSocket для Telegram (headless-сборка из
//! proxy/tg_ws_proxy.py, без трея и окон, управляется только флагами).

use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};

use crate::state::AppState;
use crate::sys;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

pub const DEFAULT_DC_IPS: [&str; 2] = ["2:149.154.167.220", "4:149.154.167.220"];

/// Версия tg-ws-proxy (Flowseal), из которой собран встроенный
/// TgWsProxyHeadless.exe — `__version__` в proxy/__init__.py снимка из
/// tools/tgwsproxy-build. Меняется только вместе с пересборкой exe.
pub const BUNDLED_VERSION: &str = "1.10.2";

/// Последний релиз tg-ws-proxy у Flowseal — чтобы видеть, что встроенный
/// прокси отстал и Klutz пора пересобрать.
pub fn latest_upstream() -> Result<String, String> {
    let text = crate::maintenance::http_get("https://api.github.com/repos/Flowseal/tg-ws-proxy/releases/latest")?;
    let v: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| "GitHub ответил неожиданным форматом.".to_string())?;
    v.get("tag_name")
        .and_then(|t| t.as_str())
        .map(|t| t.trim_start_matches('v').to_string())
        .ok_or_else(|| "В ответе GitHub нет версии.".into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TgSettings {
    pub host: String,
    pub port: u16,
    pub secret: String,
    #[serde(rename = "dcIps")]
    pub dc_ips: Vec<String>,
    pub cfproxy: bool,
    #[serde(rename = "autoStart")]
    pub auto_start: bool,
}

impl Default for TgSettings {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 1443,
            secret: random_secret(),
            dc_ips: DEFAULT_DC_IPS.iter().map(|s| s.to_string()).collect(),
            cfproxy: true,
            auto_start: false,
        }
    }
}

/// Системный ГСЧ. `RandomState` для этого не годился: std засевает ключи
/// SipHash из ОС ОДИН раз на поток, а дальше просто инкрементирует счётчик —
/// два блока подряд получали связанные ключи, и вся энтропия сводилась к
/// одному посеву плюс метке времени, а не к 128 битам, как выглядело.
#[cfg(target_os = "windows")]
fn os_random(buf: &mut [u8]) -> bool {
    use windows_sys::Win32::Security::Cryptography::ProcessPrng;
    unsafe { ProcessPrng(buf.as_mut_ptr(), buf.len()) != 0 }
}

#[cfg(not(target_os = "windows"))]
fn os_random(buf: &mut [u8]) -> bool {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .is_ok()
}

/// 16 байт hex — формат, который ждёт клиент Telegram.
pub fn random_secret() -> String {
    let mut bytes = [0u8; 16];
    if !os_random(&mut bytes) {
        // ГСЧ ОС не отвечает — случай почти невозможный, но пустой секрет
        // хуже слабого: добираем тем, что есть, и не роняем приложение.
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, chunk) in bytes.chunks_mut(8).enumerate() {
            let mut h = RandomState::new().build_hasher();
            h.write_u64(i as u64);
            h.write_u128(nanos);
            chunk.copy_from_slice(&h.finish().to_le_bytes()[..chunk.len()]);
        }
    }
    bytes.iter().fold(String::with_capacity(32), |mut s, b| {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub fn is_valid_secret(s: &str) -> bool {
    s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Создаёт и сохраняет настройки прокси один раз. Без этого каждое обращение
/// к ещё не сохранённым настройкам давало бы НОВЫЙ случайный секрет — и секрет
/// в ссылке tg://proxy не совпадал бы с секретом запущенного прокси.
pub fn ensure_settings(app: &AppHandle) {
    let state = app.state::<AppState>();
    let changed = {
        let mut p = state.persisted.lock().unwrap();
        match p.tgws.as_mut() {
            None => {
                p.tgws = Some(TgSettings::default());
                true
            }
            // Секрет из старой версии или импорта в неверном формате —
            // Telegram такую ссылку не примет, выдаём новый.
            Some(s) if !is_valid_secret(&s.secret) => {
                s.secret = random_secret();
                true
            }
            Some(_) => false,
        }
    };
    if changed {
        crate::state::save_state(app, &state);
    }
}

fn exe_path(app: &AppHandle) -> PathBuf {
    // В собранном приложении лежит рядом как ресурс, в dev — в bin/.
    if let Ok(dir) = app.path().resource_dir() {
        let p = dir.join("TgWsProxyHeadless.exe");
        if p.exists() {
            return p;
        }
    }
    PathBuf::from("bin/TgWsProxyHeadless.exe")
}

/// «dd» перед секретом помечает padded-intermediate («fake TLS») режим —
/// без него ссылка tg://proxy у клиента не заработает.
pub fn proxy_url(s: &TgSettings) -> String {
    // 0.0.0.0 — адрес «слушать на всех», а не куда подключаться: клиент
    // Telegram к нему не пойдёт, поэтому в ссылку отдаём локальный адрес.
    let server = match s.host.trim() {
        "" | "0.0.0.0" | "::" => "127.0.0.1",
        h => h,
    };
    format!("tg://proxy?server={}&port={}&secret=dd{}", server, s.port, s.secret)
}

/// Живость проверяем реальным TCP-подключением: живой процесс ещё не значит,
/// что он действительно принимает соединения.
pub fn probe_health(s: &TgSettings) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(mut addrs) = (s.host.as_str(), s.port).to_socket_addrs() else {
        return false;
    };
    addrs.any(|a| TcpStream::connect_timeout(&a, Duration::from_millis(2500)).is_ok())
}

/// Имя образа процесса по PID — чтобы не принять за свой прокси чужую
/// программу, занявшую тот же порт.
fn image_name(pid: u32) -> Option<String> {
    let out = sys::run("tasklist", &["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"]);
    // Формат CSV: "имя.exe","PID","сессия",…
    out.lines()
        .find(|l| l.starts_with('"'))
        .and_then(|l| l.split('"').nth(1))
        .map(|s| s.to_lowercase())
}

/// PID того, кто реально слушает порт. Нужен, чтобы подобрать процесс,
/// переживший наш прошлый запуск (падение, убийство приложения) — иначе он
/// продолжит обслуживать трафик, пока интерфейс показывает «выключено».
pub fn pid_listening_on(port: u16) -> Option<u32> {
    for line in sys::run("netstat", &["-ano"]).lines() {
        let l = line.trim();
        if !l.starts_with("TCP") || !l.to_uppercase().contains("LISTENING") {
            continue;
        }
        let parts: Vec<&str> = l.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let local = parts[1];
        let listening_port = local.rsplit(':').next().and_then(|p| p.parse::<u16>().ok());
        if listening_port == Some(port) {
            if let Ok(pid) = parts[4].parse::<u32>() {
                return Some(pid);
            }
        }
    }
    None
}

/// Бутлоадер PyInstaller --onefile выполняет реальную работу в дочернем
/// процессе, а не в том, который мы породили: убийство порождённого PID
/// оставляет настоящий прокси живым и всё так же занятым портом. taskkill /T
/// гасит всё дерево.
pub fn kill_tree(pid: u32) {
    sys::run("taskkill", &["/PID", &pid.to_string(), "/T", "/F"]);
}

pub fn start(app: &AppHandle) -> Result<(), String> {
    let state = app.state::<AppState>();
    {
        let mut guard = state.tgws_pid.lock().unwrap();
        match *guard {
            Some(pid) if pid_alive(pid) => return Ok(()),
            // Записанный процесс уже мёртв (усыновлённый прокси упал, и
            // некому было это заметить) — забываем его и поднимаем заново.
            Some(_) => *guard = None,
            None => {}
        }
    }
    ensure_settings(app);
    let settings = state.persisted.lock().unwrap().tgws.clone().unwrap_or_default();

    let exe = exe_path(app);
    if !exe.exists() {
        return Err("TgWsProxyHeadless.exe не найден рядом с приложением.".into());
    }

    let mut args: Vec<String> = vec![
        "--host".into(), settings.host.clone(),
        "--port".into(), settings.port.to_string(),
        "--secret".into(), settings.secret.clone(),
    ];
    for dc in &settings.dc_ips {
        args.push("--dc-ip".into());
        args.push(dc.clone());
    }
    if !settings.cfproxy {
        args.push("--no-cfproxy".into());
    }

    state.tgws_log.lock().unwrap().clear();

    #[allow(unused_mut)]
    let mut cmd = Command::new(&exe);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "windows")]
    cmd.creation_flags(sys::CREATE_NO_WINDOW);

    let mut child = cmd.spawn().map_err(|e| e.to_string())?;
    let pid = child.id();
    // Занимаем ячейку сразу: между проверкой в начале функции и этой
    // строкой второй вызов start() видел None и поднимал второй прокси на
    // том же порту, а один из PID терялся.
    {
        let mut guard = state.tgws_pid.lock().unwrap();
        if let Some(existing) = *guard {
            if pid_alive(existing) {
                kill_tree(pid);
                return Ok(());
            }
        }
        *guard = Some(pid);
    }

    if let Some(out) = child.stdout.take() {
        pipe_log(app.clone(), out);
    }
    if let Some(errs) = child.stderr.take() {
        pipe_log_err(app.clone(), errs);
    }

    std::thread::spawn({
        let app = app.clone();
        move || {
            let _ = child.wait();
            let state = app.state::<AppState>();
            let mut guard = state.tgws_pid.lock().unwrap();
            // Если это всё ещё текущий процесс — значит stop() никто не
            // звал, и он упал сам. Как и у winws, различаем ожидаемое
            // завершение и неожиданное.
            if *guard == Some(pid) {
                *guard = None;
                drop(guard);
                crate::notify::send_critical_from(
                    &app,
                    "Telegram-прокси упал",
                    "Обход блокировки Telegram неожиданно остановился.",
                );
                let _ = app.emit("tgwsproxy-state-changed", serde_json::json!({ "running": false }));
                crate::tray::refresh(&app);
            }
        }
    });

    let _ = app.emit("tgwsproxy-state-changed", serde_json::json!({ "running": true }));
    crate::tray::refresh(app);
    Ok(())
}

fn pipe_log(app: AppHandle, out: std::process::ChildStdout) {
    std::thread::spawn(move || sys::for_each_line(out, |line| push_line(&app, line)));
}
fn pipe_log_err(app: AppHandle, out: std::process::ChildStderr) {
    std::thread::spawn(move || sys::for_each_line(out, |line| push_line(&app, line)));
}

fn push_line(app: &AppHandle, line: String) {
    if line.trim().is_empty() {
        return;
    }
    let state = app.state::<AppState>();
    {
        let mut buf = state.tgws_log.lock().unwrap();
        buf.push(line.clone());
        let over = buf.len().saturating_sub(500);
        if over > 0 {
            buf.drain(0..over);
        }
    }
    let _ = app.emit("tgwsproxy-log", vec![line]);
}

pub fn stop(app: &AppHandle) {
    let state = app.state::<AppState>();
    let pid = state.tgws_pid.lock().unwrap().take();
    if let Some(pid) = pid {
        kill_tree(pid);
    }
    let _ = app.emit("tgwsproxy-state-changed", serde_json::json!({ "running": false }));
    crate::tray::refresh(app);
}

/// Подбирает процесс, оставшийся от прошлого запуска приложения.
///
/// Одного совпадения по порту мало: на нём может сидеть что угодно чужое, а
/// «Остановить» потом валит дерево процессов через taskkill /T /F из-под
/// администратора. Поэтому сверяем имя образа.
pub fn adopt_existing(app: &AppHandle) {
    let state = app.state::<AppState>();
    if state.tgws_pid.lock().unwrap().is_some() {
        return;
    }
    ensure_settings(app);
    let settings = state.persisted.lock().unwrap().tgws.clone().unwrap_or_default();
    let Some(pid) = pid_listening_on(settings.port) else { return };
    if image_name(pid).as_deref() != Some("tgwsproxyheadless.exe") {
        return;
    }
    *state.tgws_pid.lock().unwrap() = Some(pid);
    let _ = app.emit("tgwsproxy-state-changed", serde_json::json!({ "running": true }));
    crate::tray::refresh(app);
}

/// Жив ли процесс, который мы считаем своим прокси. Усыновлённый PID своего
/// наблюдателя не имеет, поэтому без этой проверки «работает» залипало бы
/// навсегда, а «Запустить» молча ничего не делала.
pub fn pid_alive(pid: u32) -> bool {
    image_name(pid).is_some()
}
