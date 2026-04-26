# Docker

This directory contains the container deployment surfaces for ASRFacet-Rb.

Use one of these entrypoints:

- `docker/run-docker.sh` on Linux or macOS
- `docker/run-docker.ps1` on PowerShell
- `docker/run-docker.bat` on Windows CMD

The wrapper scripts support:

- flag-driven automation
- interactive prompt mode when no action is provided
- deploy stack startup and shutdown
- logs, shell access, image builds, and one-off ASRFacet-Rb CLI commands

Examples:

```bash
./docker/run-docker.sh --action up --rebuild --detach
./docker/run-docker.sh --action cli --command "scan example.com --passive-only"
```

```powershell
.\docker\run-docker.ps1 -Action up -Rebuild -Detach
.\docker\run-docker.ps1 -Action cli -Command "scan example.com --passive-only"
```
