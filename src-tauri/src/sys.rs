//! Тонкие обёртки над системными утилитами Windows (sc/net/tasklist/reg/schtasks).
//! Абсолютных путей намеренно не берём — но и окон не показываем.

use std::process::Command;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;
#[cfg(target_os = "windows")]
pub const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Абсолютный путь к системной утилите.
///
/// `Command::new("cmd.exe")` ищет файл в том числе в ТЕКУЩЕМ каталоге, а
/// часть команд мы запускаем с `current_dir` в папке релиза — то есть в
/// каталоге, который пользователь мог распаковать из чужого архива.
/// Подложенный туда `cmd.exe` исполнился бы с правами администратора.
pub fn system_exe(name: &str) -> std::path::PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    let root = std::path::Path::new(&root);
    // powershell лежит не в корне System32, explorer — не в System32 вовсе.
    for candidate in [
        root.join("System32").join(name),
        root.join("System32").join("WindowsPowerShell").join("v1.0").join(name),
        root.join(name),
    ] {
        if candidate.exists() {
            return candidate;
        }
    }
    std::path::PathBuf::from(name)
}

/// Декодирует вывод консольной утилиты. Сначала UTF-8, а если не вышло —
/// кодовая страница OEM: на русской Windows sc, net и netsh пишут в CP866, и
/// `from_utf8_lossy` превращал их сообщения в ромбики — включая текст ошибки,
/// который потом показывали пользователю.
pub fn decode_console(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    #[cfg(target_os = "windows")]
    if let Some(s) = decode_oem(bytes) {
        return s;
    }
    String::from_utf8_lossy(bytes).to_string()
}

#[cfg(target_os = "windows")]
fn decode_oem(bytes: &[u8]) -> Option<String> {
    use windows_sys::Win32::Globalization::MultiByteToWideChar;
    const CP_OEMCP: u32 = 1;
    if bytes.is_empty() {
        return Some(String::new());
    }
    unsafe {
        let need = MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32, std::ptr::null_mut(), 0);
        if need <= 0 {
            return None;
        }
        let mut buf = vec![0u16; need as usize];
        let got = MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), bytes.len() as i32, buf.as_mut_ptr(), need);
        if got <= 0 {
            return None;
        }
        String::from_utf16(&buf[..got as usize]).ok()
    }
}

/// Читает поток построчно и отдаёт уже декодированные строки.
///
/// `lines()` здесь не годится: он строгий UTF-8, а `.flatten()` МОЛЧА
/// выбрасывает каждую строку, которую не удалось разобрать, — на русской
/// Windows это все строки с кириллицей, и они просто исчезали из живого лога.
pub fn for_each_line<R: std::io::Read>(r: R, mut f: impl FnMut(String)) {
    use std::io::BufRead;
    let mut reader = std::io::BufReader::new(r);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let line = decode_console(&buf);
        f(line.trim_end_matches(['\r', '\n']).to_string());
    }
}

/// Запускает команду, отдаёт stdout. Ошибку не считаем фатальной — многие
/// из этих утилит возвращают ненулевой код на «ничего не найдено».
pub fn run(program: &str, args: &[&str]) -> String {
    #[allow(unused_mut)]
    let mut cmd = Command::new(system_exe(program));
    cmd.args(args);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(CREATE_NO_WINDOW);
    match cmd.output() {
        Ok(out) => {
            let mut s = decode_console(&out.stdout);
            s.push_str(&decode_console(&out.stderr));
            s
        }
        Err(_) => String::new(),
    }
}

pub fn run_ok(program: &str, args: &[&str]) -> bool {
    #[allow(unused_mut)]
    let mut cmd = Command::new(system_exe(program));
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
