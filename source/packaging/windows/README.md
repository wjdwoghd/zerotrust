# ZeroTrust Demo Windows Installer

This packaging path builds a single Windows self-extracting installer:

```bat
python packaging\windows\build_installer.py
```

The installer deploys to `%LOCALAPPDATA%\ZeroTrustDemo`, creates Desktop and
Start Menu shortcuts, and runs PostgreSQL from the install directory as a user
process on `127.0.0.1:55432`.

It does not install or use SQLite. The application still uses PostgreSQL only.

Created shortcuts:

- `ZeroTrust` starts PostgreSQL/server in the background and opens the web UI.
- `ZeroTrust 제어` opens a GUI reset/stop control app.
- `ZeroTrust 토큰 기기` opens the token-device launcher folder.
