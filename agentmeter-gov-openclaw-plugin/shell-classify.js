// Pure, dependency-free classification of shell/text surfaced through exec.
// These helpers are kept separate from index.js so unit tests can exercise them
// without loading the OpenClaw plugin SDK.

export function isFileWriteShellText(text) {
  return /copy-item|set-content|add-content|out-file|new-item|move-item|rename-item/i.test(text)
    && !/remove-item|clear-content|\brm\b|\bdel\b/i.test(text);
}

export function isDestructiveShellText(text) {
  return /remove-item|clear-content|\bdeletefile\s*\(|sendtorecyclebin|\bunlink\s*\(|(?:^|[\s"'`;])(?:rm|del|erase)(?:\s|$)/i.test(text);
}

export function extractShellDestination(command) {
  const text = String(command ?? "");
  const destination = text.match(/(?:-Destination|-Path)\s+["']?([^"';\r\n]+)["']?/i);
  if (/copy-item/i.test(text)) {
    const explicit = text.match(/-Destination\s+["']?([^"';\r\n]+)["']?/i);
    if (explicit) {
      return explicit[1];
    }
    const positional = text.match(/copy-item\s+["'][^"']+["']\s+["']([^"']+)["']/i);
    if (positional) {
      return positional[1];
    }
    const unquoted = text.match(/copy-item\s+\S+\s+([^\s;|]+)(?:\s|;|\||$)/i);
    if (unquoted) {
      return unquoted[1];
    }
  }
  return destination?.[1] ?? "";
}

export function isSensitiveWorkspaceEnumeration(text) {
  const normalized = String(text ?? "").toLowerCase();
  const scansWorkspace = /\.openclaw[\\/]+workspace/.test(normalized);
  const scansJson = /\*\.json|-filter\s+["']?\*\.json/.test(normalized);
  const readsContents = /get-content|convertfrom-json|foreach-object/.test(normalized);
  return scansWorkspace && scansJson && readsContents;
}

export function isReadOnlyShellText(text) {
  const normalized = String(text ?? "")
    .toLowerCase()
    .replace(/\b[12]\s*>\s*(?:nul|\/dev\/null|\$null)\b/g, "")
    .replace(/\b2\s*>\s*&\s*1\b/g, "");
  // mapToolEvent serializes the whole params object, so the text may look like
  // {"command":"bash -c \"find . -name '*.txt'\"",...}. Extract the command by
  // walking past the first `"command":"` prefix and its JSON-escaped quotes.
  let command = normalized;
  const cmdPrefix = normalized.match(/"command"\s*:\s*"/);
  if (cmdPrefix) {
    const rest = normalized.slice(cmdPrefix.index + cmdPrefix[0].length);
    // Walk to the first UNESCAPED quote, which closes the command string.
    let end = rest.length;
    for (let i = 0; i < rest.length; i += 1) {
      if (rest[i] === "\\") {
        i += 1;
        continue;
      }
      if (rest[i] === '"') {
        end = i;
        break;
      }
    }
    command = rest.slice(0, end).replace(/\\(["\\])/g, "$1").trim();
  }
  const readMarkers = [
    "get-content",
    "get-childitem",
    "get-item",
    "select-object",
    "format-table",
    "type ",
    " type ",
    " dir",
    " dir ",
    "pwd",
    "ls ",
  ];
  const writeMarkers = [
    "remove-item",
    "clear-content",
    "copy-item",
    "set-content",
    "add-content",
    "move-item",
    "rename-item",
    "new-item",
    "out-file",
    "curl ",
    "iwr ",
    "wget ",
    "invoke-webrequest",
    "deletefile(",
    "sendtorecyclebin",
    "unlink(",
  ];
  const redirectsOutput = /(?<!-)>/.test(normalized);
  if (
    readMarkers.some((marker) => normalized.includes(marker))
    && !writeMarkers.some((marker) => normalized.includes(marker))
    && !redirectsOutput
  ) {
    return true;
  }
  // Strip a leading shell wrapper before classifying: `bash -c "..."`,
  // `wsl bash -c "..."`, a full-path `D:\git\Git\bin\bash.exe -c "..."`, the
  // PowerShell call operator `& 'path' -c "..."`, or
  // `powershell -NoProfile -Command "..."`.
  let unwrapped = command
    .replace(/^(?:bash|sh|zsh|cmd|pwsh|powershell)(?:\.exe)?\s+-c\s*["']([\s\S]+)["']$/i, "$1")
    .replace(/^&\s*["'][a-z]:\\[\s\S]*?(?:bash|sh|zsh|cmd|pwsh|powershell)(?:\.exe)?["']\s+-c\s*["']([\s\S]+)["']$/i, "$1")
    .replace(/^[a-z]:\\[\s\S]*?(?:bash|sh|zsh|cmd|pwsh|powershell)(?:\.exe)?\s+-c\s*["']([\s\S]+)["']$/i, "$1")
    .replace(/^wsl(?:\s+--?\w+)*\s+(?:bash|sh)\s+-c\s*["']([\s\S]+)["']$/i, "$1")
    .replace(/^powershell(?:\.exe)?(?:\s+-noprofile)?\s+-command\s+["']([\s\S]+)["']$/i, "$1")
    .trim();
  // A PowerShell wrapper whose inner command is a harmless read-only probe.
  const psReadOnly = /^(?:get-date|get-location|get-command|get-process|get-service|get-childitem|get-item|get-content|get-ciminstance|get-wmiobject|select-object|format-(?:table|list)|test-path)\b/i;
  if (psReadOnly.test(unwrapped)) {
    return true;
  }
  // PowerShell read-only scripts: an assignment block that only invokes Get-* /
  // Test-* / Select-* / Write-Output cmdlets (no Set-*/Remove-*/Out-*/Copy-*).
  const psScriptReadOnly =
    /^(?:get-date|get-location|get-command|get-process|get-service|get-childitem|get-item|get-content|get-ciminstance|get-wmiobject|select-object|format-(?:table|list)|test-path|write-output|\$[a-z_]\w*\s*=)/i.test(unwrapped)
    && !/(?:set-|remove-|clear-|copy-|move-|rename-|new-|add-|out-|start-|stop-|restart-|invoke-|curl|iwr|wget|delete|mkdir|rmdir)/i.test(unwrapped)
    && !/[<>|&]/.test(unwrapped);
  if (psScriptReadOnly) {
    return true;
  }
  // Read-only git operations (status/log/diff/ls-remote/show) carry no side effect.
  const gitReadOnly = /^(?:git\s+)?(?:status|log|diff|ls-remote|show|rev-parse|branch|remote\s+-v|config\s+--get)\b/i;
  if (gitReadOnly.test(unwrapped) && !/git\s+(?:push|commit|add|rm|mv|checkout|reset|clean|rebase|merge|tag)\b/i.test(unwrapped)) {
    return true;
  }
  // `find` with a destructive or mutating predicate is a side effect.
  if (/^(?:sudo\s+)?find\b/i.test(unwrapped) && /-(?:delete|exec|execdir)\b/.test(unwrapped)) {
    return false;
  }
  const unixReadOnly = /^(?:(?:sudo\s+)?(?:find|free|cat|less|more|head|tail|grep|wc|ps|du|df|uname|whoami|hostname|echo|printenv|env|date|uptime|ls|dir|pwd|stat|file|which|where|whereis|type|tree)\b)(?:\s+[^\r\n;&|`<>]*)?$/i;
  if (unixReadOnly.test(unwrapped) && !redirectsOutput) {
    return true;
  }
  // Windows read-only inspection: `dir ... | findstr ...`, `findstr ...` and
  // `where ...` are greps over the filesystem/text; they carry no side effect.
  const winReadOnly = /^(?:dir\b[\s\S]*\|?\s*findstr\b[\s\S]*|findstr\b[\s\S]*|where\b[\s\S]*)$/i;
  if (winReadOnly.test(unwrapped) && !/remove-item|clear-content|copy-item|set-content|add-content|move-item|rename-item|new-item|out-file|>|\bdel\b|\berase\b|\brm\b/i.test(unwrapped)) {
    return true;
  }
  return false;
}

export function isHarmlessShellProbeText(text) {
  const normalized = String(text ?? "")
    .toLowerCase()
    .replace(/\b[12]\s*>\s*(?:nul|\/dev\/null|\$null)\b/g, "")
    .replace(/\b2\s*>\s*&\s*1\b/g, "")
    .trim();
  const command = normalized.match(/"command"\s*:\s*"([^"]+)"/)?.[1]?.trim() ?? normalized;
  const dangerous = /[>|&;`]|\$\w+|\$env:|%\w+%|token|api[_-]?key|secret|password|db_pass|curl|iwr|wget|invoke-webrequest|set-content|add-content|out-file|remove-item|del |rm /.test(command);
  if (dangerous) {
    return false;
  }
  return /^(echo\s+[\w .:_-]{1,80}|whoami|hostname|ver)$/.test(command);
}

export function isAuditDeleteText(text) {
  return /(audit\.log|error\.log|access\.log|审计日志|操作日志|系统日志|日志)/i.test(text)
    && /(remove-item|(?:^|[\s"'`;])del(?:\s|$)|(?:^|[\s"'`;])erase(?:\s|$)|(?:^|[\s"'`;])rm(?:\s|$)|clear-content|set-content|删除|清空|覆盖)/i.test(text);
}
