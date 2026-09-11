use std::fs;
use std::path::Path;
use std::process::Command;

use crate::sys;

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

const ADMIN_ANCHOR: &str = r#"if "%1"=="admin" ("#;

/// Дописывает в service.bat релиза тихую точку входа `install_auto <файл>`,
/// переиспользуя его же логику создания службы. Идемпотентно и привязано к
/// якорям, чтобы переживать смену версий zapret без ручной правки под каждую.
pub fn patch_service_bat(root: &Path) -> Result<(), String> {
    let svc_path = root.join("service.bat");
    if !svc_path.exists() {
        return Err("в релизе нет service.bat".into());
    }
    let mut text = fs::read_to_string(&svc_path).map_err(|e| e.to_string())?;
    if text.contains("install_auto") {
        return Ok(());
    }
    if !text.contains(ADMIN_ANCHOR) {
        return Err("не найден якорь admin в service.bat".into());
    }

    let install_auto_block = format!(
        r#"if /i "%~1"=="install_auto" (
    setlocal EnableDelayedExpansion
    set "BIN_PATH=%~dp0bin\"
    set "LISTS_PATH=%~dp0lists\"
    set "selectedFile=%~2"
    call :game_switch_status
    if not exist "%~dp0!selectedFile!" (
        echo [ERROR] Config file not found: !selectedFile!
        endlocal
        exit /b 1
    )
    call :install_selected_file
    endlocal
    exit /b 0
)

{ADMIN_ANCHOR}"#
    );
    text = text.replacen(ADMIN_ANCHOR, &install_auto_block, 1);

    let choose_anchor = "set \"selectedFile=!file%choice%!\"\r\nif not defined selectedFile (\r\n    echo Invalid choice, exiting...\r\n    pause\r\n    goto menu\r\n)\r\n\r\n:: Args that should be followed by value";
    let choose_anchor_lf = choose_anchor.replace("\r\n", "\n");
    let (anchor2, nl) = if text.contains(choose_anchor) {
        (choose_anchor.to_string(), "\r\n")
    } else if text.contains(&choose_anchor_lf) {
        (choose_anchor_lf.clone(), "\n")
    } else {
        return Err("не найден якорь выбора конфига в service.bat".into());
    };

    let replacement2 = format!(
        "set \"selectedFile=!file%choice%!\"{nl}if not defined selectedFile ({nl}    echo Invalid choice, exiting...{nl}    pause{nl}    goto menu{nl}){nl}{nl}call :install_selected_file{nl}{nl}pause{nl}goto menu{nl}{nl}{nl}:: INSTALL SELECTED FILE (shared by interactive menu and install_auto) ===={nl}:install_selected_file{nl}:: Args that should be followed by value"
    );
    text = text.replacen(&anchor2, &replacement2, 1);

    let end_anchor = format!(
        "sc start %SRVCNAME%{nl}for %%F in (\"!file%choice%!\") do ({nl}    set \"filename=%%~nF\"{nl}){nl}reg add \"HKLM\\System\\CurrentControlSet\\Services\\zapret\" /v zapret-discord-youtube /t REG_SZ /d \"!filename!\" /f{nl}{nl}pause{nl}goto menu"
    );
    if !text.contains(&end_anchor) {
        return Err("не найден финальный якорь в service.bat".into());
    }
    let end_replacement = format!(
        "sc start %SRVCNAME%{nl}for %%F in (\"!selectedFile!\") do ({nl}    set \"filename=%%~nF\"{nl}){nl}reg add \"HKLM\\System\\CurrentControlSet\\Services\\zapret\" /v zapret-discord-youtube /t REG_SZ /d \"!filename!\" /f{nl}{nl}exit /b"
    );
    text = text.replacen(&end_anchor, &end_replacement, 1);

    fs::write(&svc_path, text).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn can_install_service(root: &Path) -> bool {
    // Патч идемпотентный, так что «получится ли» проверяем попыткой.
    patch_service_bat(root).is_ok()
}

pub fn install_service(root: &Path, file_name: &str) -> Result<(), String> {
    patch_service_bat(root)
        .map_err(|e| format!("Автоустановка недоступна для этой версии service.bat: {e}"))?;

    #[allow(unused_mut)]
    let mut cmd = Command::new("cmd.exe");
    cmd.args(["/c", "service.bat", "install_auto", file_name])
        .current_dir(root);
    #[cfg(target_os = "windows")]
    cmd.creation_flags(sys::CREATE_NO_WINDOW);

    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let msg = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        Err(if msg.trim().is_empty() { "не удалось установить службу".into() } else { msg })
    }
}

/// Снимает и службу zapret, и драйвер WinDivert — иначе он остаётся
/// загруженным и мешает следующему запуску.
pub fn remove_service() {
    sys::run("net", &["stop", "zapret"]);
    sys::run("sc", &["delete", "zapret"]);
    crate::winws::stop_winws();
    for name in ["WinDivert", "WinDivert14"] {
        sys::run("net", &["stop", name]);
        sys::run("sc", &["delete", name]);
    }
}

/// Служба уже стоит — значит прямой запуск winws.exe конфликтовал бы с ней.
pub fn service_conflict() -> bool {
    sys::svc_query("zapret").exists
}
