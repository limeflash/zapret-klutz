// Стаб window.zapret для проверки интерфейса без Tauri.
// НЕ используется в продакшене — подключается только preview-server.js по /mock.
//
// ВАЖНО: формы ответов должны совпадать с тем, что реально отдают команды
// Rust (src-tauri/src/commands.rs и структуры с serde rename). Стенд, который
// врёт про контракт, хуже, чем его отсутствие: именно так здесь незаметно
// разъехались getToggles, checkUpdates и getNotifySound.
(function () {
  const CONFIGS = [
    'general.bat', 'general (ALT).bat', 'general (ALT2).bat', 'general (ALT3).bat',
    'general (FAKE TLS AUTO).bat', 'general (FAKE TLS AUTO ALT).bat',
    'general (SIMPLE FAKE).bat', 'general (SIMPLE FAKE ALT).bat',
    'general (MGTS).bat', 'general (MGTS2).bat',
  ];

  const DEFAULT_TARGETS = [
    { name: 'Discord Main', host: 'discord.com', port: 443 },
    { name: 'Discord Gateway', host: 'gateway.discord.gg', port: 443 },
    { name: 'Discord CDN', host: 'cdn.discordapp.com', port: 443 },
    { name: 'Discord Updates', host: 'updates.discord.com', port: 443 },
    { name: 'YouTube Web', host: 'www.youtube.com', port: 443 },
    { name: 'YouTube Video', host: 'redirector.googlevideo.com', port: 443 },
    { name: 'YouTube Short', host: 'youtu.be', port: 443 },
    { name: 'Rocket League', host: 'api.rlpp.psynet.gg', port: 443 },
    { name: 'Epic Online', host: 'api.epicgames.dev', port: 443 },
    { name: 'Steam', host: 'api.steampowered.com', port: 443 },
    { name: 'Riot', host: 'auth.riotgames.com', port: 443 },
    { name: 'Battle.net', host: 'us.actual.battle.net', port: 1119 },
    { name: 'Xbox Live', host: 'title.mgt.xboxlive.com', port: 443 },
  ];

  let customTargets = [
    { name: 'PlayStation Network', host: 'auth.api.sonyentertainmentnetwork.com', port: 443 },
  ];

  function allTargets() {
    return [...DEFAULT_TARGETS, ...customTargets];
  }

  function pingResult(t, i) {
    const ok = i % 5 !== 4;
    return { name: t.name, host: t.host, port: t.port, ok, ms: ok ? 30 + (i * 7) % 120 : null, pending: false };
  }

  const state = {
    rootPath: 'C:\\Users\\vbu00\\Desktop\\zapret-discord-youtube-1.9.9c',
    configs: CONFIGS,
    activeConfig: 'general (ALT).bat',
    running: true,
    installedAsService: false,
    // Служба zapret, поставленная не из Klutz (см. get_state в commands.rs).
    serviceExists: false,
    canInstallService: true,
    startedAt: Date.now() - 12 * 60 * 1000,
    monitor: { checkedAt: Date.now(), targets: allTargets().map(pingResult) },
  };

  const noop = async () => ({ ok: true });

  window.zapret = {
    // Перетаскивание идёт событием Tauri, а не через DOM. Метод обязан
    // существовать: renderer подписывается на него при загрузке, и без
    // заглушки весь скрипт падал бы на TypeError.
    onFileDrop: () => () => {},
    getVersions: async () => ({ app: '1.1.0', zapret: '1.9.9c', tgws: '1.10.2' }),
    checkKlutzUpdate: async () => ({ current: '1.1.0', latest: '1.2.0', error: null, url: 'https://github.com/vbu00/zapret-klutz/releases/latest' }),
    checkComponentUpdates: async () => ({
      klutz: { current: '1.1.0', latest: '1.1.0', error: null, url: 'https://github.com/vbu00/zapret-klutz/releases/latest' },
      zapret: { current: '1.9.9c', latest: '1.9.9c', error: null },
      tgws: { current: '1.10.2', latest: '1.10.2', error: null },
    }),
    copyText: async () => ({ ok: true }),

    pickFolder: noop,
    pickArchive: noop,
    loadPath: noop,
    getState: async () => state,

    listReleases: async () => ({
      ok: true,
      releases: [
        { name: 'zapret-discord-youtube-1.9.9c', path: 'C:\\Users\\vbu00\\AppData\\Roaming\\com.vbu00.klutz\\releases\\zapret-discord-youtube-1.9.9c', current: true, extractedAt: Date.now() - 3 * 86400000 },
        { name: 'zapret-discord-youtube-1.9.8', path: 'C:\\Users\\vbu00\\AppData\\Roaming\\com.vbu00.klutz\\releases\\zapret-discord-youtube-1.9.8', current: false, extractedAt: Date.now() - 40 * 86400000 },
      ],
    }),
    deleteRelease: noop,

    getLatestReleaseInfo: async () => ({
      ok: true,
      error: null,
      version: '1.9.9c',
      name: 'zapret-discord-youtube-1.9.9c.zip',
      size: 12_400_000,
      url: 'https://example.invalid/zapret.zip',
      notesUrl: 'https://github.com/Flowseal/zapret-discord-youtube/releases/tag/1.9.9c',
    }),
    downloadLatestRelease: noop,
    onDownloadProgress: () => () => {},

    getOnboardingDone: async () => true,
    setOnboardingDone: noop,

    runConfig: noop,
    stopConfig: noop,
    getWinwsLog: async () => ({ live: true, lines: ['[winws] запущен', '[winws] general (ALT).bat активен'] }),
    onWinwsLog: () => () => {},
    onWinwsCrashed: () => () => {},
    installService: noop,
    removeService: noop,
    getServiceStatus: async () => ({ serviceExists: false, serviceState: 'STOPPED', windivertState: 'RUNNING', winwsRunning: true, strategy: state.activeConfig }),

    runTests: async () => ({
      ok: true,
      text:
        '=== ANALYTICS ===\n' +
        CONFIGS.map((c, i) => `${c}: HTTP OK: ${7 - (i % 5)}, ERR: ${i % 5}, UNSUP: 0, Ping OK: ${7 - (i % 4)}, Fail: ${i % 4}`).join('\n'),
    }),
    stopTests: noop,
    getLastTestResults: async () => ({
      ok: true,
      text:
        '=== ANALYTICS ===\n' +
        CONFIGS.map((c, i) => `${c}: HTTP OK: ${7 - (i % 5)}, ERR: ${i % 5}, UNSUP: 0, Ping OK: ${7 - (i % 4)}, Fail: ${i % 4}`).join('\n'),
    }),
    onTestLog: () => () => {},

    getToggles: async () => ({ gameMode: 'off', ipsetMode: 'loaded', autoUpdate: false }),
    setGameFilter: noop,
    cycleIpsetMode: noop,
    setAutoUpdate: noop,

    updateIpsetList: noop,
    updateHostsFile: noop,
    checkUpdates: async () => ({
      ok: true,
      error: null,
      local: '1.9.9c',
      remote: '1.9.10',
      upToDate: false,
      releaseUrl: 'https://github.com/Flowseal/zapret-discord-youtube/releases/tag/1.9.10',
    }),
    clearDiscordCache: noop,
    runDiagnostics: async () => ({
      ok: true,
      results: [
        { label: 'Служба фильтрации Windows (BFE)', ok: true },
        { label: 'Драйвер WinDivert', ok: true },
        { label: 'winws.exe', ok: true },
        { label: 'Файл hosts', ok: false, fixKey: 'hosts', warn: 'найдены посторонние записи' },
      ],
    }),
    fixDiagnostic: noop,

    getCustomLists: async () => ({ ok: true, include: '', exclude: '' }),
    saveCustomLists: noop,

    checkGames: async () => ({ ok: true, targets: allTargets().map(pingResult), pending: false, checkedAt: Date.now(), running: true, strategy: state.activeConfig }),
    getGameTargets: async () => ({ targets: allTargets() }),
    getDefaultGameTargets: async () => ({ targets: DEFAULT_TARGETS }),
    saveGameTargets: async (targets) => {
      customTargets = targets.filter((t) => !DEFAULT_TARGETS.some((d) => d.host === t.host && d.port === t.port));
      return { ok: true, targets: allTargets() };
    },
    resetGameTargets: async () => {
      customTargets = [];
      return { ok: true, targets: allTargets() };
    },
    getAutostart: async () => ({ enabled: true }),
    setAutostart: noop,

    exportSettings: async () => ({ ok: false, cancelled: true }),
    importSettings: async () => ({ ok: true }),

    getNotifications: async () => ({ enabled: true, supported: true }),
    setNotifications: noop,
    testNotification: noop,

    getNotifySound: async () => ({ volume: 70, duration: 'short' }),
    setNotifySound: noop,
    onPlayNotifySound: () => () => {},

    getAutoSwitch: async () => ({ enabled: true, threshold: 3, intervalSec: 30, hasRanking: true }),
    setAutoSwitch: async () => ({ ok: true }),
    getHealLog: async () => ({
      ok: true,
      entries: [
        { at: Date.now() - 40 * 60000, type: 'switch', from: 'general.bat', to: 'general (ALT).bat', ok: true },
        { at: Date.now() - 90 * 60000, type: 'switch', from: 'general (MGTS).bat', to: 'general.bat', ok: false },
      ],
    }),

    getAutoTestSchedule: async () => ({ enabled: false, days: 14, mode: 'dpi', lastRunAt: null }),
    setAutoTestSchedule: noop,
    onAutoSwitched: () => () => {},

    // Не пустой список: ровно на пустом списке в своё время и не заметили,
    // что карточка релизов рендерит «undefined». Поля — те же, что у Rust.
    getTestHistory: async () => ({
      ok: true,
      runs: [
        { date: '2026-09-10_19-20', file: '2026-09-10_19-20.txt', best: 'general (ALT).bat', mode: 'standard', bestOk: 6, bestTotal: 7 },
        { date: '2026-09-12_08-05', file: '2026-09-12_08-05.txt', best: 'general (ALT2).bat', mode: 'dpi', bestOk: 7, bestTotal: 7 },
      ],
      configs: [
        { name: 'general (ALT).bat', latestShare: 0.86, shareSeries: [1, 0.86], wins: 1 },
        { name: 'general (ALT2).bat', latestShare: 1, shareSeries: [0.71, 1], wins: 1 },
      ],
    }),
    openResultFile: noop,
    openExternalUrl: noop,
    openReleaseFolder: noop,

    startTgwsproxy: noop,
    stopTgwsproxy: noop,
    restartTgwsproxy: noop,
    getTgwsproxyStatus: async () => ({ running: true, healthy: true, available: true, host: '127.0.0.1', port: 8443, autostart: false, tgProxyUrl: 'tg://proxy?server=127.0.0.1&port=8443&secret=dda1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4' }),
    openTgProxyLink: noop,
    getTgwsproxyLog: async () => ({ lines: ['[tgws] прокси запущен', '[tgws] клиент подключился 127.0.0.1:51422', '[tgws] handshake ok'] }),
    onTgwsproxyLog: () => () => {},
    onTgwsproxyStateChanged: () => () => {},
    getTgwsproxySettings: async () => ({ host: '127.0.0.1', port: 8443, secret: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', dcIps: ['2:149.154.167.220', '4:149.154.167.220'], cfproxy: true, autoStart: false }),
    setTgwsproxySettings: noop,
    regenerateTgwsproxySecret: async () => ({ ok: true, secret: 'ee' + 'ffffffffffffffffffffffffffffffff' }),
    setTgwsproxyAutostart: noop,

    windowMinimize: noop,
    windowToggleMaximize: noop,
    windowClose: noop,
    windowIsMaximized: async () => false,
    onWindowMaximized: () => () => {},
  };
})();
