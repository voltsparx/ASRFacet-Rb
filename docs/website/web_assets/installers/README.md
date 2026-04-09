# Part of ASRFacet-Rb - authorized testing only

# Website Installers

This folder contains standalone installer launchers for website users.

They download the latest ASRFacet-Rb source into a temporary directory and
delegate to the maintained lifecycle scripts under `install/`:

- `install/linux.sh`
- `install/macos.sh`
- `install/windows.ps1`

To reduce bloat, website installers use sparse checkout and download only
required runtime paths for the selected mode. `README.md` and `LICENSE` are
included with the installed framework bundle, and only `docs/images` is kept
from the docs tree. During installation, nested `README.md` files are removed
from subdirectories so only the root `README.md` remains.

## Files

- `asrfacet-rb-installer-linux.sh`
- `asrfacet-rb-installer-macos.sh`
- `asrfacet-rb-installer-windows.ps1`
- `asrfacet-rb-installer-windows.cmd`

## Modes

All installers support:

- `install`
- `test`
- `update`
- `uninstall`

If no mode is passed, an interactive mode chooser is shown.

## Prompt Theme

Installer prompts follow a shared subtle theme so terminal output feels consistent with docs and website language:

- `[ASRFacet-Rb][INFO]` progress updates
- `[ASRFacet-Rb][ OK ]` completed actions
- `[ASRFacet-Rb][WARN]` recoverable warnings
- `[ASRFacet-Rb][FAIL]` stopping errors

## Optional flags

- `--yes` or `--no-prompt`: skip prompts where possible
- `--keep-temp`: keep downloaded temporary files for troubleshooting
- `--verbose`: print command-level progress

## Examples

Linux/macOS:

```bash
bash asrfacet-rb-installer-linux.sh install --yes
bash asrfacet-rb-installer-linux.sh test --keep-temp
bash asrfacet-rb-installer-macos.sh update --verbose
```

Windows:

```powershell
.\asrfacet-rb-installer-windows.ps1 install --yes
.\asrfacet-rb-installer-windows.cmd install --yes
.\asrfacet-rb-installer-windows.cmd uninstall
```
