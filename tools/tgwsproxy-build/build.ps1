# Rebuilds bin/TgWsProxyHeadless.exe from the pinned proxy/ snapshot in this
# folder. Run from anywhere; paths below are relative to this script.
#
# To pull in upstream changes: re-download proxy/*.py from
# https://github.com/Flowseal/tg-ws-proxy at a newer commit, update
# PINNED_COMMIT.txt, then run this again.

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

python -m venv "$here\venv"
& "$here\venv\Scripts\python.exe" -m pip install --disable-pip-version-check -q cryptography certifi pyinstaller

Push-Location $here
try {
    Remove-Item -Recurse -Force build, dist, *.spec -ErrorAction SilentlyContinue
    & "$here\venv\Scripts\python.exe" -m PyInstaller --onefile --name TgWsProxyHeadless --console `
        --distpath dist --workpath build --specpath . headless_entry.py
} finally {
    Pop-Location
}

Copy-Item "$here\dist\TgWsProxyHeadless.exe" "$here\..\..\src-tauri\bin\TgWsProxyHeadless.exe" -Force
Write-Output "Copied to src-tauri\bin\TgWsProxyHeadless.exe"
