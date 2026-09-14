AgentMeter-Gov 2.0.0 Windows Setup package
================================================

Requirements
------------
1. Windows 10/11 x64.
2. OpenClaw is already installed and the `openclaw` command is available.
3. Python is not required on the target computer.

Install
-------
1. Extract the complete ZIP. Do not run the installer inside a ZIP preview window.
2. Double-click AgentMeter-Gov-Setup-2.0.0.exe (recommended).
3. install.cmd is retained only as a diagnostic fallback inside the ZIP package.
4. The installer starts one AgentMeter-Gov desktop pet after installation.
5. The pet starts automatically after every Windows sign-in. No desktop shortcut is created; use the Start menu entry to reopen it.
6. Double-click the floating desktop pet to open the security audit workspace.
7. If an older release created a shortcut, the installer removes that obsolete shortcut.
8. The pet docks as a compact head at the screen edge when idle. Fully exiting it does not stop the OpenClaw guard or monitoring backend.
9. Direct monitoring address: http://127.0.0.1:8765/security-layer.html

Install location
----------------
%LOCALAPPDATA%\AgentMeter-Gov\current

Installing a newer build upgrades this directory in place. Audit, approval and profile state is
migrated from 1.0.0/1.1.0 before the old program directory is removed. Failed upgrades roll back.

Uninstall
---------
Use Windows Settings > Apps > Installed apps > AgentMeter-Gov > Uninstall. The ZIP fallback also
contains uninstall.cmd. Program files, plugin files, and the desktop-pet auto-start entry are removed. Audit data is
preserved by default under:
%LOCALAPPDATA%\AgentMeter-Gov-Archive\<timestamp>

Notes
-----
- The installer only updates the AgentMeter-Gov plugin section of OpenClaw's
  configuration. It does not replace the complete OpenClaw configuration.
- Supported OpenClaw floor: 2026.6.5. Existing enabled plugins are checked before changes.
  Existing plugin warnings do not block setup while the Gateway remains usable, and unrelated
  plugins are never disabled automatically.
- A missing OpenClaw Gateway service is installed and verified automatically.
- Keep the error text in the installer window if installation fails.
- This is the CPU/fallback semantic build. The BGE model is not embedded;
  core rules, closed-loop enforcement, and audit do not depend on BGE.
