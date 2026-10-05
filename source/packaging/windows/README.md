# ZeroTrust Demo Windows Installer

This packaging path builds a single Windows self-extracting installer:

```bat
python packaging\windows\build_installer.py
```

The installer deploys to `%LOCALAPPDATA%\ZeroTrustDemo`, creates Desktop and
Start Menu shortcuts, and runs PostgreSQL from the install directory as a user
process on `127.0.0.1:55432`.
The web server binds to local IPv4. If port 8000 is unavailable, the launcher
selects another local port and uses it for the browser and token devices.

It does not install or use SQLite. The application still uses PostgreSQL only.
The payload includes only the application runtime scripts. Local `.env`, database
files, generated token launchers, tests, and developer scripts are excluded.

Created shortcuts:

- `ZeroTrust` starts PostgreSQL/server in the background and opens the web UI.
- `ZeroTrust 제어` opens a GUI reset/stop control app.
- `ZeroTrust 토큰 기기` opens the token-device launcher folder.
