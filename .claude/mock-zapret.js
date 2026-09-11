// Стаб window.zapret для визуальной проверки вёрстки без реального Electron.
// НЕ используется в продакшене — подключается только preview-server.js по /mock.
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
    canInstallService: true,
    startedAt: Date.now() - 12 * 60 * 1000,
    monitor: { checkedAt: Date.now(), targets: allTargets().map(pingResult) },
  };

  const noop = async () => ({ ok: true });

  window.zapret = {
    getPathForFile: (f) => f.name,
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

    listReleases: async () => ({ ok: true, releases: [] }),
    deleteRelease: noop,

    getLatestReleaseInfo: async () => ({ ok: true, version: '1.9.9c', notes: 'Тестовые данные — без реального релиза.' }),
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

    getToggles: async () => ({ gameFilter: 'tcp+udp', ipsetMode: 'auto', autoUpdate: false }),
    setGameFilter: noop,
    cycleIpsetMode: noop,
    setAutoUpdate: noop,

    updateIpsetList: noop,
    updateHostsFile: noop,
    checkUpdates: async () => ({ ok: true, hasUpdate: false, version: '1.9.9c' }),
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

    getCustomLists: async () => ({ include: '', exclude: '' }),
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
    runGameStrategyTest: async () => {
      const rows = CONFIGS.slice(0, 6).map((c, i) => ({
        config: c,
        gameFilterMode: i % 2 ? 'tcp+udp' : 'off',
        successRate: [1, 0.6, 0, 1, 0.4, 1][i],
        udp: { ok: i % 2 === 0 },
        avgMs: 30 + i * 12,
      }));
      if (window.__gameProgressCb) window.__gameProgressCb(rows);
      return { ok: true };
    },
    stopGameStrategyTest: noop,
    onGameTestLog: () => () => {},
    onGameTestProgress: (cb) => {
      window.__gameProgressCb = cb;
      return () => {
        window.__gameProgressCb = null;
      };
    },

    getAutostart: async () => ({ enabled: true }),
    setAutostart: noop,

    exportSettings: noop,
    importSettings: noop,

    getNotifications: async () => ({ enabled: true, supported: true }),
    setNotifications: noop,
    testNotification: noop,

    getNotifySound: async () => ({ volume: 70, duration: 5 }),
    setNotifySound: noop,
    onPlayNotifySound: () => () => {},

    getAutoSwitch: async () => ({ enabled: true, threshold: 3, intervalSec: 30, hasRanking: true }),
    setAutoSwitch: async () => ({ ok: true }),
    getHealLog: async () => ({ ok: true, entries: [] }),

    getAutoTestSchedule: async () => ({ enabled: false, days: 7 }),
    setAutoTestSchedule: noop,
    onAutoSwitched: () => () => {},

    getTestHistory: async () => ({ ok: true, runs: [], configs: [] }),
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
