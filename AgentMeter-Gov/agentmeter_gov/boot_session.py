from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path


@lru_cache(maxsize=1)
def monitoring_boot_started_at() -> datetime:
    """Read an OS boot boundary, stable across application restarts.

    Windows Kernel-Boot event 27 also marks Fast Startup boots. Never substitute
    the web server's start time: restarting the service must preserve this boot.
    This lookup is lazy so ordinary plugin liveness probes stay inexpensive.
    """
    if os.name == "nt":
        script = (
            "$ErrorActionPreference='Stop'; $times=@(); "
            "try {$times += (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()} catch {}; "
            "try {$event=Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Kernel-Boot';Id=27} -MaxEvents 1; "
            "$times += $event.TimeCreated.ToUniversalTime()} catch {}; "
            "if (!$times.Count) {exit 2}; "
            "($times | Sort-Object -Descending | Select-Object -First 1).ToString('o')"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=6, check=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        boot = datetime.fromisoformat(result.stdout.strip().replace("Z", "+00:00"))
    elif sys.platform.startswith("linux"):
        match = re.search(r"^btime (\d+)$", Path("/proc/stat").read_text(), re.MULTILINE)
        if not match:
            raise RuntimeError("OS boot timestamp is unavailable")
        boot = datetime.fromtimestamp(int(match.group(1)), timezone.utc)
    elif sys.platform == "darwin":
        result = subprocess.run(["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=3, check=True)
        match = re.search(r"sec\s*=\s*(\d+)", result.stdout)
        if not match:
            raise RuntimeError("OS boot timestamp is unavailable")
        boot = datetime.fromtimestamp(int(match.group(1)), timezone.utc)
    else:
        raise RuntimeError("OS boot detection is unsupported on this platform")
    if boot.tzinfo is None or boot > datetime.now(timezone.utc):
        raise RuntimeError("OS boot timestamp is invalid")
    return boot.astimezone(timezone.utc)
