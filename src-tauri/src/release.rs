use serde::Serialize;
use std::fs;
use std::path::Path;

/// Same key `main.js`'s `naturalSortKey()` built: zero-pad every run of
/// digits so "general (ALT2).bat" sorts before "general (ALT10).bat"
/// instead of after it lexicographically.
fn natural_sort_key(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 8);
    let mut digits = String::new();
    let flush = |digits: &mut String, out: &mut String| {
        if !digits.is_empty() {
            out.push_str(&format!("{:0>8}", digits));
            digits.clear();
        }
    };
    for c in name.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
        } else {
            flush(&mut digits, &mut out);
            out.push(c.to_ascii_lowercase());
        }
    }
    flush(&mut digits, &mut out);
    out
}

pub fn list_configs(root: &Path) -> Vec<String> {
    let mut configs: Vec<String> = fs::read_dir(root)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|f| {
                    let lower = f.to_lowercase();
                    lower.ends_with(".bat") && !lower.starts_with("service")
                })
                .collect()
        })
        .unwrap_or_default();
    configs.sort_by(|a, b| natural_sort_key(a).cmp(&natural_sort_key(b)));
    configs
}

#[derive(Debug, Serialize)]
pub struct ReleaseCheck {
    pub ok: bool,
    pub error: Option<String>,
    pub configs: Vec<String>,
    #[serde(rename = "hasTestScript")]
    pub has_test_script: bool,
    #[serde(rename = "canInstallService")]
    pub can_install_service: bool,
}

/// Порт `validateRelease()` — убеждается, что это действительно релиз zapret
/// (есть bin\winws.exe и хотя бы один *.bat), прежде чем остальное
/// приложение начнёт считать его таковым.
pub fn validate_release(root: &Path) -> ReleaseCheck {
    let winws = root.join("bin").join("winws.exe");
    if !winws.exists() {
        return ReleaseCheck {
            ok: false,
            error: Some("В папке нет bin\\winws.exe — это не похоже на релиз zapret.".into()),
            configs: vec![],
            has_test_script: false,
            can_install_service: false,
        };
    }
    let configs = list_configs(root);
    if configs.is_empty() {
        return ReleaseCheck {
            ok: false,
            error: Some("Не найдено ни одного *.bat конфига (кроме service.bat).".into()),
            configs: vec![],
            has_test_script: false,
            can_install_service: false,
        };
    }
    let has_test_script = root.join("utils").join("test zapret.ps1").exists();
    ReleaseCheck {
        ok: true,
        error: None,
        configs,
        has_test_script,
        // Патч service.bat идемпотентный, так что «получится ли поставить
        // службой» проверяется самой попыткой пропатчить.
        can_install_service: crate::service::can_install_service(root),
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn натуральная_сортировка_ставит_alt2_перед_alt10() {
        let mut v = vec![
            "general (ALT10).bat".to_string(),
            "general (ALT2).bat".to_string(),
            "general.bat".to_string(),
        ];
        v.sort_by_key(|a| natural_sort_key(a));
        assert_eq!(v, vec!["general (ALT2).bat", "general (ALT10).bat", "general.bat"]);
    }

    #[test]
    fn ключ_не_зависит_от_регистра() {
        assert_eq!(natural_sort_key("General (ALT).BAT"), natural_sort_key("general (alt).bat"));
    }
}
