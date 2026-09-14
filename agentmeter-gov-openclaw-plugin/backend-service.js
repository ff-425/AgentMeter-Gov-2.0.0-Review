import { spawn as spawnProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_GATE_URL = "http://127.0.0.1:8765/api/v1/evaluate";
const DEFAULT_STARTUP_TIMEOUT_MS = 15000;
const DEFAULT_PROBE_INTERVAL_MS = 250;
const DEFAULT_RESTART_DELAY_MS = 1000;
const DEFAULT_RESTART_MAX_DELAY_MS = 30000;
const PLUGIN_DIR = dirname(fileURLToPath(import.meta.url));

export function createBackendService(api, overrides = {}) {
  const probe = overrides.probe ?? probeBackend;
  const spawn = overrides.spawn ?? spawnProcess;
  const waitForReady = overrides.waitForReady ?? waitForBackend;
  const pathExists = overrides.pathExists ?? existsSync;
  const platform = overrides.platform ?? process.platform;
  const onStatus = overrides.onStatus ?? (async () => {});
  const schedule = overrides.schedule ?? setTimeout;
  const cancelSchedule = overrides.cancelSchedule ?? clearTimeout;
  let child = null;
  let ownsChild = false;
  let spawnError = "";
  let serviceActive = false;
  let stopping = false;
  let restartTimer = null;
  let restartAttempts = 0;
  let lastContext = null;
  let recoveryPromise = null;
  const plannedStops = new WeakSet();

  async function emitStatus(ctx, status, details = {}) {
    const event = {
      status,
      timestamp: new Date().toISOString(),
      ...details,
    };
    const logger = ctx?.logger;
    const message = `AgentMeter-Gov backend ${status}${details.message ? `: ${details.message}` : ""}`;
    if (status === "failed") logger?.error?.(message);
    else if (status === "disabled" || status === "external") logger?.warn?.(message);
    else logger?.info?.(message);
    try {
      await onStatus(event);
    } catch (error) {
      logger?.warn?.(`AgentMeter-Gov backend lifecycle audit failed: ${String(error?.message ?? error)}`);
    }
  }

  function scheduleRestart(ctx, details = {}) {
    if (!serviceActive || stopping || restartTimer) return;
    const config = api.pluginConfig ?? {};
    if (config.autoStartBackend === false || config.restartBackendOnUnexpectedExit === false) return;
    restartAttempts += 1;
    const baseDelay = Math.max(100, Number(config.backendRestartDelayMs ?? DEFAULT_RESTART_DELAY_MS));
    const maxDelay = Math.max(baseDelay, Number(config.backendRestartMaxDelayMs ?? DEFAULT_RESTART_MAX_DELAY_MS));
    const delayMs = Math.min(maxDelay, baseDelay * (2 ** Math.min(restartAttempts - 1, 10)));
    void emitStatus(ctx ?? lastContext, "restarting", {
      attempt: restartAttempts,
      delay_ms: delayMs,
      exit_code: details.exitCode ?? null,
      signal: details.signal ?? null,
      message: `owned backend exited unexpectedly; restart attempt ${restartAttempts} is scheduled`,
    });
    restartTimer = schedule(async () => {
      restartTimer = null;
      if (!serviceActive || stopping) return;
      await service.start(ctx ?? lastContext, { restart: true });
    }, delayMs);
    restartTimer?.unref?.();
  }

  // Emit the terminal startup status for a launch whose readiness was confirmed
  // off the gateway's startup path. Mirrors the synchronous branch in start().
  async function finishStartup(ctx, ready, { healthUrl, launch, startedAt }) {
    if (!serviceActive || stopping) return;
    const elapsedMs = Date.now() - startedAt;
    if (!ready) {
      const exitCode = child?.exitCode;
      if (ownsChild && child && !child.killed) child.kill();
      child = null;
      ownsChild = false;
      await emitStatus(ctx, "failed", {
        health_url: healthUrl,
        command: launch.command,
        entrypoint: launch.entrypoint,
        launch_mode: launch.mode,
        exit_code: exitCode,
        elapsed_ms: elapsedMs,
        message: spawnError || "health check did not become ready before the startup timeout",
      });
      return;
    }
    if (child?.exitCode !== null && child?.exitCode !== undefined) {
      const exitCode = child.exitCode;
      child = null;
      ownsChild = false;
      await emitStatus(ctx, "reused", {
        health_url: healthUrl,
        exit_code: exitCode,
        elapsed_ms: elapsedMs,
        message: "another local backend became healthy while this launcher was starting",
      });
      return;
    }
    await emitStatus(ctx, "started", {
      health_url: healthUrl,
      monitor_url: new URL("/", healthUrl).toString(),
      pid: child?.pid ?? null,
      command: launch.command,
      entrypoint: launch.entrypoint,
      launch_mode: launch.mode,
      elapsed_ms: elapsedMs,
      message: "backend is healthy and the monitoring page is available",
    });
    restartAttempts = 0;
  }

  const service = {
    id: "agentmeter-gov-backend",

    async start(ctx, options = {}) {
      lastContext = ctx ?? lastContext;
      serviceActive = true;
      stopping = false;
      const config = api.pluginConfig ?? {};
      if (config.autoStartBackend === false) {
        await emitStatus(ctx, "disabled", { message: "automatic startup is disabled by configuration" });
        return;
      }

      const gateUrl = String(config.gateUrl ?? DEFAULT_GATE_URL);
      const healthUrl = String(config.backendHealthUrl ?? deriveHealthUrl(gateUrl));
      if (!isLocalHttpUrl(healthUrl)) {
        await emitStatus(ctx, "external", {
          health_url: healthUrl,
          message: "remote or HTTPS backend is operator-managed and will not be spawned locally",
        });
        return;
      }

      if (await probe(healthUrl, Number(config.backendProbeTimeoutMs ?? 1000))) {
        await emitStatus(ctx, "reused", {
          health_url: healthUrl,
          message: "an existing healthy backend is already listening",
        });
        return;
      }

      const launch = resolveBackendLaunch(config, { platform });
      if (!launch.runtimeRoot || !pathExists(launch.entrypoint)) {
        await emitStatus(ctx, "failed", {
          health_url: healthUrl,
          runtime_root: launch.runtimeRoot,
          entrypoint: launch.entrypoint,
          message: launch.mode === "executable"
            ? "the packaged backend executable was not found; reinstall AgentMeter-Gov"
            : "server.py was not found; set runtimeDir or backendRoot to the AgentMeter-Gov runtime directory",
        });
        return;
      }

      const health = new URL(healthUrl);
      const env = {
        ...process.env,
        AGENTMETER_GOV_HOME: launch.runtimeRoot,
        AGENTMETER_HOST: normalizeBindHost(health.hostname),
        AGENTMETER_PORT: health.port || "8765",
      };
      if (config.apiToken) env.AGENTMETER_API_TOKEN = String(config.apiToken);

      try {
        spawnError = "";
        const launchedChild = spawn(launch.command, launch.args, {
          cwd: launch.runtimeRoot,
          env,
          windowsHide: true,
          stdio: "ignore",
        });
        child = launchedChild;
        ownsChild = true;
        launchedChild.once?.("error", (error) => {
          spawnError = String(error?.message ?? error);
        });
        launchedChild.once?.("exit", (exitCode, signal) => {
          if (child === launchedChild) {
            child = null;
            ownsChild = false;
          }
          if (serviceActive && !stopping && !plannedStops.has(launchedChild)) {
            scheduleRestart(ctx, { exitCode, signal });
          }
        });
      } catch (error) {
        child = null;
        ownsChild = false;
        await emitStatus(ctx, "failed", {
          health_url: healthUrl,
          message: `could not launch ${launch.command}: ${String(error?.message ?? error)}`,
        });
        return;
      }

      // Do not hold the gateway's startup path while the backend becomes
      // healthy. A cold boot loads the packaged backend from a cold disk cache
      // and can take far longer than a warm restart, and the gateway does not
      // report "ready" until every service start() resolves. Blocking here made
      // the OpenClaw control UI unreachable after sign-in until someone
      // restarted the gateway, which warmed the cache and hid the real cause.
      // Report readiness asynchronously instead; the gate calls ensureReady()
      // before every tool decision, and failClosed keeps tool calls safe while
      // the backend is still coming up.
      const startedAt = Date.now();
      const readyPromise = waitForReady(healthUrl, {
        probe,
        child,
        timeoutMs: Number(config.backendStartupTimeoutMs ?? DEFAULT_STARTUP_TIMEOUT_MS),
        intervalMs: Number(config.backendProbeIntervalMs ?? DEFAULT_PROBE_INTERVAL_MS),
        probeTimeoutMs: Number(config.backendProbeTimeoutMs ?? 1000),
      });
      if (options.awaitReady === false) {
        void readyPromise.then(
          (ok) => finishStartup(ctx, ok, { healthUrl, launch, startedAt }),
          () => finishStartup(ctx, false, { healthUrl, launch, startedAt }),
        );
        await emitStatus(ctx, "starting", {
          health_url: healthUrl,
          command: launch.command,
          entrypoint: launch.entrypoint,
          launch_mode: launch.mode,
          pid: child?.pid ?? null,
          message: "backend launch started; readiness is being confirmed in the background",
        });
        return;
      }
      const ready = await readyPromise;
      if (!ready) {
        const exitCode = child?.exitCode;
        if (ownsChild && child && !child.killed) child.kill();
        child = null;
        ownsChild = false;
        await emitStatus(ctx, "failed", {
          health_url: healthUrl,
          command: launch.command,
          entrypoint: launch.entrypoint,
          launch_mode: launch.mode,
          exit_code: exitCode,
          message: spawnError || "health check did not become ready before the startup timeout",
        });
        return;
      }

      if (child?.exitCode !== null && child?.exitCode !== undefined) {
        const exitCode = child.exitCode;
        child = null;
        ownsChild = false;
        await emitStatus(ctx, "reused", {
          health_url: healthUrl,
          exit_code: exitCode,
          message: "another local backend became healthy while this launcher was starting",
        });
        return;
      }

      await emitStatus(ctx, "started", {
        health_url: healthUrl,
        monitor_url: new URL("/", healthUrl).toString(),
        pid: child?.pid ?? null,
        command: launch.command,
        entrypoint: launch.entrypoint,
        launch_mode: launch.mode,
        message: "backend is healthy and the monitoring page is available",
      });
      restartAttempts = 0;
    },

    async ensureReady(ctx) {
      const config = api.pluginConfig ?? {};
      const gateUrl = String(config.gateUrl ?? DEFAULT_GATE_URL);
      const healthUrl = String(config.backendHealthUrl ?? deriveHealthUrl(gateUrl));
      if (!isLocalHttpUrl(healthUrl) || config.autoStartBackend === false) return false;
      if (await probe(healthUrl, Number(config.backendProbeTimeoutMs ?? 1000))) return true;
      if (recoveryPromise) return recoveryPromise;
      recoveryPromise = (async () => {
        if (ownsChild && child) {
          const staleChild = child;
          plannedStops.add(staleChild);
          child = null;
          ownsChild = false;
          if (!staleChild.killed) staleChild.kill();
        }
        await emitStatus(ctx ?? lastContext, "recovering", {
          health_url: healthUrl,
          message: "an unavailable local backend was detected during a protected request",
        });
        await service.start(ctx ?? lastContext, { restart: true });
        return probe(healthUrl, Number(config.backendProbeTimeoutMs ?? 1000));
      })().finally(() => {
        recoveryPromise = null;
      });
      return recoveryPromise;
    },

    async stop(ctx) {
      const config = api.pluginConfig ?? {};
      serviceActive = false;
      stopping = true;
      if (restartTimer) {
        cancelSchedule(restartTimer);
        restartTimer = null;
      }
      if (!ownsChild || !child || config.stopBackendOnGatewayExit === false) return;
      const pid = child.pid ?? null;
      plannedStops.add(child);
      if (!child.killed) child.kill();
      child = null;
      ownsChild = false;
      await emitStatus(ctx, "stopped", {
        pid,
        message: "backend process owned by this Gateway was stopped",
      });
    },
  };
  return service;
}

export function deriveHealthUrl(gateUrl) {
  const parsed = new URL(String(gateUrl ?? DEFAULT_GATE_URL));
  return new URL("/health", parsed).toString();
}

export function isLocalHttpUrl(url) {
  try {
    const parsed = new URL(String(url));
    const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    return parsed.protocol === "http:" && ["127.0.0.1", "localhost", "::1"].includes(host);
  } catch {
    return false;
  }
}

export function resolveBackendLaunch(config = {}, options = {}) {
  const platform = options.platform ?? process.platform;
  const configuredRoot = config.backendRoot ?? config.runtimeDir ?? process.env.AGENTMETER_GOV_HOME;
  const fallbackRoot = resolve(join(PLUGIN_DIR, "..", "AgentMeter-Gov"));
  const runtimeRoot = configuredRoot ? resolve(String(configuredRoot)) : fallbackRoot;
  if (config.backendExecutable) {
    const configuredExecutable = String(config.backendExecutable);
    const executablePath = isAbsolute(configuredExecutable)
      ? configuredExecutable
      : resolve(join(runtimeRoot, configuredExecutable));
    return {
      runtimeRoot,
      mode: "executable",
      entrypoint: executablePath,
      command: executablePath,
      args: [],
      executablePath,
      serverPath: null,
      pythonExecutable: null,
    };
  }
  const configuredServer = String(config.backendServerPath ?? "server.py");
  const serverPath = isAbsolute(configuredServer)
    ? configuredServer
    : resolve(join(runtimeRoot, configuredServer));
  const pythonExecutable = String(
    config.backendPython
      ?? process.env.AGENTMETER_PYTHON
      ?? (platform === "win32" ? "python" : "python3"),
  );
  return {
    runtimeRoot,
    mode: "python",
    entrypoint: serverPath,
    command: pythonExecutable,
    args: ["-u", serverPath],
    executablePath: null,
    serverPath,
    pythonExecutable,
  };
}

export async function probeBackend(healthUrl, timeoutMs = 1000) {
  try {
    const response = await fetch(healthUrl, {
      method: "GET",
      signal: AbortSignal.timeout(Math.max(100, timeoutMs)),
    });
    if (!response.ok) return false;
    const payload = await response.json().catch(() => ({}));
    return payload.status === "ok" || payload.ok === true;
  } catch {
    return false;
  }
}

export async function waitForBackend(healthUrl, options = {}) {
  const probe = options.probe ?? probeBackend;
  const timeoutMs = Math.max(100, Number(options.timeoutMs ?? DEFAULT_STARTUP_TIMEOUT_MS));
  const intervalMs = Math.max(20, Number(options.intervalMs ?? DEFAULT_PROBE_INTERVAL_MS));
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await probe(healthUrl, Number(options.probeTimeoutMs ?? 1000))) return true;
    if (options.child && options.child.exitCode !== null && options.child.exitCode !== undefined) return false;
    await new Promise((resolveDelay) => setTimeout(resolveDelay, intervalMs));
  }
  return false;
}

function normalizeBindHost(hostname) {
  const host = String(hostname).toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost") return "127.0.0.1";
  return host;
}
