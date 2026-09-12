# Klutz

Графическая оболочка для обхода блокировок Discord, YouTube и игровых
сервисов на Windows. Управляет [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)
и встроенным [tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy) для Telegram.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/main-dark.png">
  <img alt="Главная: обход работает, Discord и YouTube отвечают" src="docs/main-light.png">
</picture>

Одна кнопка. Klutz сам подбирает рабочую стратегию, следит за связью и
переключается, если она пропала.

<img alt="Подбор стратегии: перебор конфигов по целям обхода" src="docs/autopick.png">

Телеметрии нет: Klutz не собирает о вас ничего и никуда не отправляет. Наружу
ходит только за обновлениями — к `api.github.com` и `raw.githubusercontent.com`
за версиями Klutz, zapret и TgWsProxy, за списком ipset и за рекомендованным
`hosts`. Как и у любого запроса, GitHub при этом видит ваш IP.

Интерфейс при этом полностью офлайновый: шрифт лежит внутри приложения
(`src/assets/fonts`), а не подгружается со стороны, и никаких внешних адресов
окно не открывает — это запрещено политикой CSP в `tauri.conf.json`.

## Что умеет

- **Подбор стратегии.** Прогоняет конфиги zapret тестами HTTP/Ping, DPI-checker
  или воронкой DPI → HTTP и включает лучший.
- **Следит за связью.** Фоновая проверка Discord и YouTube; если стратегия
  перестала работать — сам переключается на следующую из последнего прогона.
  Раз в несколько дней может прогнать тесты заново, пока никого нет за компьютером.
- **Telegram.** Запускает TgWsProxy и даёт ссылку `tg://proxy` для подключения.
- **Трей.** Статус и цели, переключение стратегии и тумблер Telegram — без окна.
- Служба Windows, автозапуск при входе, уведомления, диагностика системы,
  обслуживание (ipset, hosts, кэш Discord), экспорт и импорт настроек.

## Установка

Скачайте `Klutz_X.Y.Z_x64-setup.exe` со [страницы последнего релиза](https://github.com/vbu00/zapret-klutz/releases/latest) и установите.
Нужны Windows 10/11 и права администратора (их требует драйвер WinDivert,
на котором работает zapret). Сам zapret-discord-youtube Klutz скачает или
возьмёт из указанной папки при первом запуске.

Установщик не подписан — SmartScreen может предупредить: «Подробнее» →
«Выполнить в любом случае». Klutz раз в сутки сам проверяет, не вышла ли новая
версия, и подсказывает, где её скачать; новая ставится поверх, настройки сохраняются.

## Сборка из исходников

Нужны [Rust](https://rustup.rs) (MSVC), Visual Studio Build Tools (C++), Node.js.

```
npm install
npx tauri build
```

Установщик появится в `src-tauri/target/release/bundle/nsis/`.

Если сборка падает на линковке из Git Bash: `link.exe` из Git for Windows
перекрывает линкер MSVC. Укажите настоящий в `src-tauri/.cargo/config.toml`
(файл не хранится в репозитории — путь у каждого свой):

```toml
[target.x86_64-pc-windows-msvc]
linker = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Tools\\MSVC\\<версия>\\bin\\Hostx64\\x64\\link.exe"
```

`src-tauri/bin/TgWsProxyHeadless.exe` собирается из зафиксированного снимка
tg-ws-proxy скриптом `tools/tgwsproxy-build/build.ps1`.

## Версии

Semver, история — в [CHANGELOG.md](CHANGELOG.md). Каждый выпуск помечен тегом `vX.Y.Z`.

## Команда Klutz

- **[limeflash](https://github.com/limeflash)**
- **[aleuuu](https://github.com/aleuuu)**
- **[vbu00](https://github.com/vbu00)**

## Благодарности

Огромное спасибо **[Flowseal](https://github.com/Flowseal)** за zapret-discord-youtube
и tg-ws-proxy — Klutz только управляет ими. И [bol-van](https://github.com/bol-van/zapret)
за сам zapret.

## Лицензия

[MIT](LICENSE). tg-ws-proxy распространяется под своей лицензией —
`tools/tgwsproxy-build/LICENSE.tg-ws-proxy`.
