import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { resolve } from "node:path";
import {
  createBackendService,
  deriveHealthUrl,
  isLocalHttpUrl,
  resolveBackendLaunch,
} from "./backend-service.js";

const logger = {
  info() {},
  warn() {},
  error() {},
};
const TEST_RUNTIME = resolve("agentmeter-test-runtime");
const TEST_BACKEND_RUNTIME = resolve("agentmeter-test-backend", "_internal");
const TEST_BACKEND_EXECUTABLE = process.platform === "win32"
  ? "AgentMeterGovBackend.exe"
  : "AgentMeterGovBackend";

function fakeChild() {
  const child = new EventEmitter();
  child.pid = 4242;
  child.exitCode = null;
  child.killed = false;
  child.kill = () => {
    child.killed = true;
    child.exitCode = 0;
    return true;
  };
  return child;
}

assert.equal(
  deriveHealthUrl("http://127.0.0.1:8765/api/v1/evaluate"),
  "http://127.0.0.1:8765/health",
);
assert.equal(isLocalHttpUrl("http://localhost:8765/health"), true);
assert.equal(isLocalHttpUrl("https://127.0.0.1:8765/health"), false);
assert.equal(isLocalHttpUrl("http://10.0.0.8:8765/health"), false);

const launch = resolveBackendLaunch(
  { runtimeDir: TEST_RUNTIME, backendPython: "python-test" },
  { platform: "win32" },
);
assert.equal(launch.serverPath, resolve(TEST_RUNTIME, "server.py"));
assert.equal(launch.pythonExecutable, "python-test");
assert.equal(launch.mode, "python");

const packagedLaunch = resolveBackendLaunch(
  {
    runtimeDir: TEST_BACKEND_RUNTIME,
    backendExecutable: `../${TEST_BACKEND_EXECUTABLE}`,
  },
  { platform: "win32" },
);
assert.equal(packagedLaunch.mode, "executable");
assert.equal(
  packagedLaunch.command,
  resolve(TEST_BACKEND_RUNTIME, "..", TEST_BACKEND_EXECUTABLE),
);
assert.deepEqual(packagedLaunch.args, []);

{
  const statuses = [];
  const probeResults = [true, false, false, true];
  let spawnCount = 0;
  const api = {
    pluginConfig: {
      gateUrl: "http://127.0.0.1:9876/api/v1/evaluate",
      runtimeDir: TEST_RUNTIME,
    },
  };
  const service = createBackendService(api, {
    probe: async () => probeResults.shift() ?? true,
    pathExists: () => true,
    spawn: () => {
      spawnCount += 1;
      return fakeChild();
    },
    waitForReady: async () => true,
    onStatus: async (status) => statuses.push(status),
  });
  await service.start({ logger });
  assert.equal(statuses[0].status, "reused");
  assert.equal(await service.ensureReady({ logger }), true);
  assert.equal(spawnCount, 1);
  assert.ok(statuses.some((item) => item.status === "recovering"));
  await service.stop({ logger });
}

{
  const statuses = [];
  const children = [fakeChild(), fakeChild()];
  let spawnCount = 0;
  const api = {
    pluginConfig: {
      gateUrl: "http://127.0.0.1:9876/api/v1/evaluate",
      runtimeDir: TEST_RUNTIME,
      backendRestartDelayMs: 20,
    },
  };
  const service = createBackendService(api, {
    probe: async () => false,
    pathExists: () => true,
    spawn: () => children[spawnCount++],
    waitForReady: async () => true,
    onStatus: async (status) => statuses.push(status),
  });
  await service.start({ logger });
  children[0].exitCode = 9;
  children[0].emit("exit", 9, null);
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 150));
  assert.equal(spawnCount, 2);
  assert.ok(statuses.some((item) => item.status === "restarting" && item.exit_code === 9));
  assert.equal(statuses.at(-1).status, "started");
  await service.stop({ logger });
}

{
  const statuses = [];
  const children = [fakeChild(), fakeChild()];
  let spawnCount = 0;
  const api = {
    pluginConfig: {
      gateUrl: "http://127.0.0.1:9876/api/v1/evaluate",
      runtimeDir: TEST_RUNTIME,
      backendRestartDelayMs: 20,
    },
  };
  const service = createBackendService(api, {
    probe: async () => false,
    pathExists: () => true,
    spawn: () => children[spawnCount++],
    waitForReady: async () => true,
    onStatus: async (status) => statuses.push(status),
  });
  await service.start({ logger });
  await service.stop({ logger });
  children[0].emit("exit", 0, null);
  await new Promise((resolveDelay) => setTimeout(resolveDelay, 80));
  assert.equal(spawnCount, 1);
  assert.equal(statuses.some((item) => item.status === "restarting"), false);
}

{
  const statuses = [];
  let spawnCount = 0;
  const api = {
    pluginConfig: {
      gateUrl: "http://127.0.0.1:8765/api/v1/evaluate",
      runtimeDir: TEST_RUNTIME,
    },
  };
  const service = createBackendService(api, {
    probe: async () => true,
    spawn: () => {
      spawnCount += 1;
      return fakeChild();
    },
    onStatus: async (status) => statuses.push(status),
  });
  await service.start({ logger });
  await service.stop({ logger });
  assert.equal(spawnCount, 0);
  assert.deepEqual(statuses.map((item) => item.status), ["reused"]);
}

{
  const statuses = [];
  const spawned = [];
  const child = fakeChild();
  const api = {
    pluginConfig: {
      gateUrl: "http://127.0.0.1:9876/api/v1/evaluate",
      runtimeDir: TEST_BACKEND_RUNTIME,
      backendExecutable: `../${TEST_BACKEND_EXECUTABLE}`,
    },
  };
  const service = createBackendService(api, {
    probe: async () => false,
    pathExists: () => true,
    spawn: (...args) => {
      spawned.push(args);
      return child;
    },
    waitForReady: async () => true,
    onStatus: async (status) => statuses.push(status),
  });
  await service.start({ logger });
  assert.equal(spawned[0][0], resolve(TEST_BACKEND_RUNTIME, "..", TEST_BACKEND_EXECUTABLE));
  assert.deepEqual(spawned[0][1], []);
  assert.equal(spawned[0][2].cwd, TEST_BACKEND_RUNTIME);
  assert.equal(statuses[0].launch_mode, "executable");
  await service.stop({ logger });
}

{
  const statuses = [];
  const spawned = [];
  const child = fakeChild();
  const api = {
    pluginConfig: {
      gateUrl: "http://127.0.0.1:9876/api/v1/evaluate",
      runtimeDir: TEST_RUNTIME,
      backendPython: "python-test",
    },
  };
  const service = createBackendService(api, {
    probe: async () => false,
    pathExists: () => true,
    spawn: (...args) => {
      spawned.push(args);
      return child;
    },
    waitForReady: async () => true,
    onStatus: async (status) => statuses.push(status),
  });
  await service.start({ logger });
  assert.equal(spawned.length, 1);
  assert.equal(spawned[0][0], "python-test");
  assert.deepEqual(spawned[0][1].slice(0, 1), ["-u"]);
  assert.equal(spawned[0][2].windowsHide, true);
  assert.equal(spawned[0][2].env.AGENTMETER_PORT, "9876");
  assert.equal(statuses[0].status, "started");
  await service.stop({ logger });
  assert.equal(child.killed, true);
  assert.equal(statuses.at(-1).status, "stopped");
}

{
  const statuses = [];
  const service = createBackendService(
    { pluginConfig: { autoStartBackend: false } },
    {
      probe: async () => {
        throw new Error("disabled service must not probe");
      },
      onStatus: async (status) => statuses.push(status),
    },
  );
  await service.start({ logger });
  assert.equal(statuses[0].status, "disabled");
}

{
  const statuses = [];
  const service = createBackendService(
    { pluginConfig: { gateUrl: "http://10.0.0.8:8765/api/v1/evaluate" } },
    { onStatus: async (status) => statuses.push(status) },
  );
  await service.start({ logger });
  assert.equal(statuses[0].status, "external");
}

{
  const statuses = [];
  const service = createBackendService(
    {
      pluginConfig: {
        gateUrl: "http://127.0.0.1:8765/api/v1/evaluate",
        runtimeDir: "C:/missing-agentmeter-runtime",
      },
    },
    {
      probe: async () => false,
      pathExists: () => false,
      onStatus: async (status) => statuses.push(status),
    },
  );
  await service.start({ logger });
  assert.equal(statuses[0].status, "failed");
  assert.match(statuses[0].message, /server\.py was not found/);
}

{
  const statuses = [];
  const exitedChild = fakeChild();
  exitedChild.exitCode = 1;
  const service = createBackendService(
    {
      pluginConfig: {
        gateUrl: "http://127.0.0.1:8765/api/v1/evaluate",
        runtimeDir: TEST_RUNTIME,
      },
    },
    {
      probe: async () => false,
      pathExists: () => true,
      spawn: () => exitedChild,
      waitForReady: async () => true,
      onStatus: async (status) => statuses.push(status),
    },
  );
  await service.start({ logger });
  await service.stop({ logger });
  assert.equal(statuses[0].status, "reused");
  assert.equal(statuses.length, 1);
}

{
  // A cold boot can leave the packaged backend seconds away from healthy. The
  // gateway does not report "ready" until every service start() resolves, so
  // waiting inline made the OpenClaw control UI unreachable after sign-in.
  // With awaitReady:false, start() must return before readiness is confirmed
  // and still emit "started" once the background probe succeeds.
  const statuses = [];
  let released = null;
  const readyGate = new Promise((resolveGate) => { released = resolveGate; });
  const service = createBackendService(
    {
      pluginConfig: {
        gateUrl: "http://127.0.0.1:8765/api/v1/evaluate",
        runtimeDir: TEST_RUNTIME,
      },
    },
    {
      probe: async () => false,
      pathExists: () => true,
      spawn: () => fakeChild(),
      waitForReady: () => readyGate,
      onStatus: async (status) => statuses.push(status),
    },
  );

  await service.start({ logger }, { awaitReady: false });
  assert.equal(statuses.at(-1).status, "starting", "start() must not block the gateway on backend readiness");
  assert.equal(statuses.some((item) => item.status === "started"), false);

  released(true);
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(statuses.at(-1).status, "started", "readiness must still be reported once confirmed");
  await service.stop({ logger });
}

console.log({ total: 11, passed: 11 });
