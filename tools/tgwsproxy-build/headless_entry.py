"""Thin entry point for the headless PyInstaller build.

Deliberately outside the `proxy` package (same layout Flowseal's own
windows.py/linux.py/macos.py use) so `proxy` is imported as a normal
top-level package rather than triggering the package-relative-import shim
at the top of proxy/tg_ws_proxy.py, which does not survive being frozen.
"""
from proxy.tg_ws_proxy import main

if __name__ == '__main__':
    main()
