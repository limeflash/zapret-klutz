//! Дополнительные стратегии: варианты шипованного конфига с другими
//! позициями разреза.
//!
//! Зачем это вообще. Релиз Flowseal привозит два десятка конфигов, и когда
//! ни один не пробивает, подбирать больше не из чего. Соседний проект
//! [necronicle/z2k](https://github.com/necronicle/z2k) (MIT) гоняет на
//! роутерах свои пулы, и часть их параметров у Flowseal не встречается.
//!
//! Что взято и что НЕ взято. Движки разные: у z2k это `nfqws2` с флагами
//! `--lua-desync=...`, у нас `winws.exe` первого поколения с
//! `--dpi-desync-...`. Стратегии как единое целое не переносятся: самый
//! частый приём z2k (`tls_client_hello_clone`, 71 директива из 254) во
//! флагах winws не выражается вовсе. Зато НАБОРЫ ПОЗИЦИЙ РАЗРЕЗА — обычные
//! значения `--dpi-desync-split-pos=`, и они переносятся один в один.
//!
//! Сверено с zapret-discord-youtube 1.10.2: там встречаются только `1`,
//! `1,midsld`, `2` и `2,sniext+1`. Всё, что ниже, — из боевых пулов z2k и
//! у Flowseal отсутствует.
//!
//! Файлы генерируются ИЗ РЕЛИЗА ПОЛЬЗОВАТЕЛЯ и остаются в его папке. Мы
//! ничего не перераспространяем: у релиза Flowseal нет лицензии, которая
//! это позволяла бы.
//!
//! ВАЖНО: проверить, что из этого действительно пробивает, можно только
//! прогоном на живой сети. Здесь гарантируется лишь синтаксическая форма —
//! меняется одно значение в остальном нетронутого рабочего конфига.

use once_cell::sync::Lazy;
use regex::Regex;
use std::fs;
use std::path::Path;

/// Префикс имени сгенерированных файлов. По нему же их и удаляем, так что
/// конфиги Flowseal задеть невозможно.
pub const MARK: &str = "general (Z2K ";

/// (суффикс имени, значение --dpi-desync-split-pos).
const EXTRA_SPLIT_POS: &[(&str, &str)] = &[
    ("midsld10", "10,midsld"),
    ("sld1", "sld+1"),
    ("7sld1", "7,sld+1"),
    ("2sld", "2,sld"),
    ("sniext1", "1,sniext+1"),
    ("endsld", "1,sld+1,endsld-2"),
    ("multi7", "2,5,105,host+5,sld-1,endsld-5,endsld"),
    ("multi8", "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1"),
];

static SPLIT_POS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"--dpi-desync-split-pos=[^\s\^]+").unwrap());

fn variant_name(suffix: &str) -> String {
    format!("{MARK}{suffix}).bat")
}

pub fn is_variant(name: &str) -> bool {
    name.starts_with(MARK) && name.to_lowercase().ends_with(".bat")
}

/// Сколько вариантов уже лежит в папке релиза.
pub fn count(root: &Path) -> usize {
    crate::release::list_configs(root).iter().filter(|c| is_variant(c)).count()
}

/// Какой конфиг брать за образец, если пользователь не выбрал сам: активный,
/// иначе первый не-вариант из списка. Вариант образцом не берём — иначе
/// получится вариант варианта.
pub fn default_template(root: &Path, active: Option<&str>) -> Option<String> {
    let configs = crate::release::list_configs(root);
    if let Some(a) = active {
        if !is_variant(a) && configs.iter().any(|c| c == a) {
            return Some(a.to_string());
        }
    }
    configs.into_iter().find(|c| !is_variant(c))
}

/// Создаёт варианты образца с другими позициями разреза.
///
/// Заменяются только УЖЕ ЕСТЬ в конфиге вхождения `--dpi-desync-split-pos=`.
/// Новых не добавляем: позиция разреза осмысленна лишь для split-приёмов, и
/// приписывать её профилю, который работает одним `fake`, — значит сочинять
/// за автора конфига.
pub fn generate(root: &Path, template: &str) -> Result<Vec<String>, String> {
    if is_variant(template) {
        return Err("Образцом нужен конфиг из релиза, а не другой вариант.".into());
    }
    if !crate::release::list_configs(root).iter().any(|c| c == template) {
        return Err(format!("Нет такого конфига в релизе: {template}"));
    }
    let text = fs::read_to_string(root.join(template)).map_err(|e| e.to_string())?;
    if !SPLIT_POS.is_match(&text) {
        return Err(format!(
            "В «{template}» нет ни одной позиции разреза — менять нечего. \
             Возьми образцом конфиг со split или multisplit."
        ));
    }

    let mut made = Vec::new();
    for (suffix, pos) in EXTRA_SPLIT_POS {
        let body = SPLIT_POS.replace_all(&text, format!("--dpi-desync-split-pos={pos}").as_str());
        let name = variant_name(suffix);
        fs::write(root.join(&name), body.as_ref()).map_err(|e| format!("{name}: {e}"))?;
        made.push(name);
    }
    Ok(made)
}

/// Удаляет всё, что сгенерировали. Чужие конфиги не трогает: фильтр по
/// нашему же префиксу.
pub fn remove_all(root: &Path) -> Result<usize, String> {
    let mut n = 0;
    for name in crate::release::list_configs(root) {
        if !is_variant(&name) {
            continue;
        }
        fs::remove_file(root.join(&name)).map_err(|e| format!("{name}: {e}"))?;
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn релиз() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "klutz-strat-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::write(dir.join("bin").join("winws.exe"), "").unwrap();
        dir
    }

    fn образец() -> String {
        [
            "@echo off",
            "start \"zapret\" /min \"%BIN%winws.exe\" --wf-tcp=80,443 ^",
            "--filter-tcp=443 --dpi-desync=fake --dpi-desync-repeats=6 --new ^",
            "--filter-tcp=80 --dpi-desync=fake,multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=ts ^",
            "--filter-udp=443 --dpi-desync=multisplit --dpi-desync-split-pos=2 --dpi-desync-repeats=6",
        ]
        .join("\r\n")
    }

    #[test]
    fn создаёт_вариант_на_каждый_набор_позиций() {
        let dir = релиз();
        fs::write(dir.join("general.bat"), образец()).unwrap();

        let made = generate(&dir, "general.bat").unwrap();
        assert_eq!(made.len(), EXTRA_SPLIT_POS.len());
        assert_eq!(count(&dir), EXTRA_SPLIT_POS.len());

        let v = fs::read_to_string(dir.join(variant_name("sld1"))).unwrap();
        assert!(v.contains("--dpi-desync-split-pos=sld+1"), "{v}");
        // Заменены ОБА вхождения, а не первое.
        assert_eq!(v.matches("--dpi-desync-split-pos=sld+1").count(), 2, "{v}");
        assert!(!v.contains("split-pos=1,midsld"), "старое значение осталось");
        // Всё остальное — нетронутый конфиг.
        assert!(v.contains("--dpi-desync-fooling=ts") && v.contains("--new"), "{v}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn новых_позиций_не_приписывает() {
        let dir = релиз();
        fs::write(dir.join("general.bat"), образец()).unwrap();
        generate(&dir, "general.bat").unwrap();

        let v = fs::read_to_string(dir.join(variant_name("2sld"))).unwrap();
        // В образце два split-pos — ровно столько же должно остаться.
        assert_eq!(v.matches("--dpi-desync-split-pos=").count(), 2, "{v}");
        // Профиль на одном fake позиции разреза не получил.
        let fake_line = v.lines().find(|l| l.contains("--dpi-desync=fake ")).unwrap();
        assert!(!fake_line.contains("split-pos"), "{fake_line}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn без_позиций_в_образце_понятная_ошибка() {
        let dir = релиз();
        fs::write(
            dir.join("general.bat"),
            "start \"z\" \"%BIN%winws.exe\" --filter-tcp=443 --dpi-desync=fake",
        )
        .unwrap();
        let e = generate(&dir, "general.bat").unwrap_err();
        assert!(e.contains("нет ни одной позиции разреза"), "{e}");
        assert_eq!(count(&dir), 0, "при ошибке файлы создаваться не должны");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn вариант_нельзя_взять_образцом() {
        let dir = релиз();
        fs::write(dir.join("general.bat"), образец()).unwrap();
        generate(&dir, "general.bat").unwrap();
        let e = generate(&dir, &variant_name("sld1")).unwrap_err();
        assert!(e.contains("не другой вариант"), "{e}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn удаляет_только_своё() {
        let dir = релиз();
        fs::write(dir.join("general.bat"), образец()).unwrap();
        fs::write(dir.join("general (ALT).bat"), образец()).unwrap();
        generate(&dir, "general.bat").unwrap();

        let n = remove_all(&dir).unwrap();
        assert_eq!(n, EXTRA_SPLIT_POS.len());
        assert!(dir.join("general.bat").exists(), "чужой конфиг удалять нельзя");
        assert!(dir.join("general (ALT).bat").exists(), "чужой конфиг удалять нельзя");
        assert_eq!(count(&dir), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn образец_по_умолчанию_не_вариант() {
        let dir = релиз();
        fs::write(dir.join("general.bat"), образец()).unwrap();
        generate(&dir, "general.bat").unwrap();

        // Активен вариант — образцом всё равно берём настоящий конфиг.
        let t = default_template(&dir, Some(&variant_name("sld1"))).unwrap();
        assert!(!is_variant(&t), "{t}");
        // Активен настоящий — берём именно его.
        assert_eq!(default_template(&dir, Some("general.bat")).as_deref(), Some("general.bat"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn имена_вариантов_узнаются() {
        assert!(is_variant("general (Z2K sld1).bat"));
        assert!(!is_variant("general (ALT).bat"));
        assert!(!is_variant("general.bat"));
        assert!(!is_variant("general (Z2K sld1).txt"));
    }
}
