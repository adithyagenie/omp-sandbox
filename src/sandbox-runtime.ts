import type { AgentToolResult } from "@oh-my-pi/pi-coding-agent";
import { SandboxManager, type SandboxAskCallback, type SandboxRuntimeConfig } from "@carderne/sandbox-runtime";
import { spawn } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import type { SandboxConfig, SessionAllowances } from "./config.ts";
import { unionListsForTool } from "./config.ts";
import { buildRuntimeNetwork, domainIsAllowed, shellQuoteArg } from "./policy.ts";

export interface ShellRunResult {
  exitCode: number | null;
  output: string;
}

export interface RuntimeSharedState {
  managerInitialized: boolean;
  initPromise: Promise<void> | null;
  session: SessionAllowances;
  launchGeneration: number;
  launchTemplates: Map<string, { generation: number; wrapped: string }>;
  launchTemplatePromises: Map<string, Promise<string>>;
  runtimeRawConfig: { globalSection: SandboxConfig; projectSection: SandboxConfig };
  runtimeRawConfigSignature: string;
}

export const RUNNER_EXTENSION_HANDLER_TIMEOUT_MS = 30_000;
export const SANDBOX_APPROVAL_TIMEOUT_MS = 24 * 60 * 60 * 1000;
const SET_TIMEOUT_BRIDGE_KEY = Symbol.for("pi-sandbox-omp.extensionHandlerTimeoutBridge");
const LAUNCH_CMD_VAR = "OMP_SANDBOX_LAUNCH_CMD";

export interface SetTimeoutBridge {
  armRunnerTimeout(): void;
}

interface GlobalWithTimeoutBridge {
  [SET_TIMEOUT_BRIDGE_KEY]?: SetTimeoutBridge;
}

export function getExtensionHandlerTimeoutBridge(): SetTimeoutBridge {
  const global = globalThis as typeof globalThis & GlobalWithTimeoutBridge;
  const existing = global[SET_TIMEOUT_BRIDGE_KEY];
  if (existing) return existing;
  const originalSetTimeout = globalThis.setTimeout.bind(globalThis) as typeof globalThis.setTimeout;
  let armedHandlerCount = 0;
  const bridge: SetTimeoutBridge = {
    armRunnerTimeout() {
      armedHandlerCount += 1;
      originalSetTimeout(() => {
        armedHandlerCount = Math.max(0, armedHandlerCount - 1);
      }, 0);
    },
  };
  globalThis.setTimeout = ((
    handler: Parameters<typeof globalThis.setTimeout>[0],
    timeout?: Parameters<typeof globalThis.setTimeout>[1],
    ...args: unknown[]
  ) => {
    const extend = armedHandlerCount > 0 && timeout === RUNNER_EXTENSION_HANDLER_TIMEOUT_MS;
    if (extend) armedHandlerCount -= 1;
    return originalSetTimeout(handler, extend ? SANDBOX_APPROVAL_TIMEOUT_MS : timeout, ...args);
  }) as typeof globalThis.setTimeout;
  global[SET_TIMEOUT_BRIDGE_KEY] = bridge;
  return bridge;
}

export function withExtensionHandlerTimeoutBridge<TArgs extends unknown[], TResult>(
  bridge: SetTimeoutBridge,
  handler: (...args: TArgs) => TResult,
): (...args: TArgs) => TResult {
  return (...args) => {
    try {
      return handler(...args);
    } finally {
      bridge.armRunnerTimeout();
    }
  };
}

let cachedBashPath: string | undefined;
export function bashShellPath(): string {
  if (cachedBashPath === undefined) {
    cachedBashPath = ["/bin/bash", "/usr/bin/bash", "/bin/sh"].find((path) => existsSync(path)) ?? "/bin/sh";
  }
  return cachedBashPath;
}

export function ensureSandboxTmpdir(): void {
  const tmpdir = process.env.OMP_TMPDIR ?? "/tmp/omp";
  process.env.OMP_TMPDIR = tmpdir;
  process.env.CLAUDE_CODE_TMPDIR ??= tmpdir;
  process.env.CLAUDE_TMPDIR ??= tmpdir;
  mkdirSync(tmpdir, { recursive: true });
}

export function enableNodeEnvProxy(): void {
  const [major, minor] = process.versions.node.split(".").map(Number);
  if ((major === 22 && minor >= 21) || major >= 24) process.env.NODE_USE_ENV_PROXY ??= "1";
}

export function createNetworkAskCallback(allowedDomains: string[]): SandboxAskCallback {
  return async ({ host }) => domainIsAllowed(host, allowedDomains);
}

function managerConfig(config: SandboxConfig, session: SessionAllowances): SandboxRuntimeConfig {
  const {
    enabled: _enabled,
    sandboxedDevices: _sandboxedDevices,
    ssh: _ssh,
    tools: _tools,
    ...runtime
  } = config;
  return {
    ...runtime,
    network: buildRuntimeNetwork(config.network, session.domains),
    filesystem: {
      ...config.filesystem,
      denyRead: config.filesystem?.denyRead ?? [],
      allowRead: [...(config.filesystem?.allowRead ?? []), ...session.read],
      allowWrite: [...(config.filesystem?.allowWrite ?? []), ...session.write],
      denyWrite: config.filesystem?.denyWrite ?? [],
    },
    enableWeakerNetworkIsolation: true,
  } as SandboxRuntimeConfig;
}

export async function initializeSandboxOnce(
  shared: RuntimeSharedState,
  config: SandboxConfig,
  session: SessionAllowances,
): Promise<void> {
  if (shared.managerInitialized) return;
  if (!shared.initPromise) {
    shared.initPromise = SandboxManager.initialize(
      managerConfig(config, session),
      createNetworkAskCallback(config.network?.allowedDomains ?? []),
    ).then(() => {
      shared.managerInitialized = true;
      enableNodeEnvProxy();
    }).catch((error: unknown) => {
      shared.initPromise = null;
      throw error;
    });
  }
  await shared.initPromise;
}

export async function updateSandboxConfig(config: SandboxConfig, session: SessionAllowances): Promise<void> {
  SandboxManager.updateConfig(managerConfig(config, session));
}

export async function resetSandbox(): Promise<void> {
  try {
    await SandboxManager.reset();
  } catch {
    // Session shutdown must not fail on best-effort runtime cleanup.
  }
}

export function cleanupAfterCommand(): void {
  try {
    SandboxManager.cleanupAfterCommand();
  } catch {
    // reset() and process-exit hooks are safety nets.
  }
}

export async function runSandboxedShell(
  command: string,
  cwd: string,
  shellPath: string,
  opts: {
    signal?: AbortSignal;
    timeout?: number;
    env?: Record<string, string>;
    wrap?: boolean;
    customConfig?: SandboxRuntimeConfig;
  },
): Promise<ShellRunResult> {
  if (!existsSync(cwd)) throw new Error(`Working directory does not exist: ${cwd}`);
  const wrapped = opts.wrap ?? true
    ? await SandboxManager.wrapWithSandbox(command, shellPath, opts.customConfig)
    : command;
  const { promise, resolve: resolvePromise, reject } = Promise.withResolvers<ShellRunResult>();
  const child = spawn(shellPath, ["-c", wrapped], {
    cwd,
    env: opts.env ?? process.env,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  let timedOut = false;
  let timeoutHandle: NodeJS.Timeout | undefined;
  let settled = false;
  const killChildGroup = () => {
    if (!child.pid) return;
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      child.kill("SIGKILL");
    }
  };
  if (opts.timeout !== undefined && opts.timeout > 0) {
    timeoutHandle = setTimeout(() => {
      timedOut = true;
      killChildGroup();
    }, opts.timeout * 1000);
  }
  child.stdout?.on("data", (chunk: Buffer) => { output += chunk.toString(); });
  child.stderr?.on("data", (chunk: Buffer) => { output += chunk.toString(); });
  const cleanup = () => {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    opts.signal?.removeEventListener("abort", onAbort);
  };
  const onAbort = () => { killChildGroup(); };
  opts.signal?.addEventListener("abort", onAbort, { once: true });
  if (opts.signal?.aborted) onAbort();
  child.on("error", (error) => {
    if (settled) return;
    settled = true;
    cleanup();
    reject(error);
  });
  child.on("close", (code) => {
    if (settled) return;
    settled = true;
    cleanup();
    if (opts.signal?.aborted) reject(new Error("aborted"));
    else if (timedOut) reject(new Error(`timeout:${opts.timeout}`));
    else resolvePromise({ exitCode: code, output });
  });
  return promise;
}

export function toToolResult(run: ShellRunResult): AgentToolResult<unknown> {
  const text = run.output || "(no output)";
  const exit = run.exitCode ?? 0;
  return {
    content: [{ type: "text", text: exit === 0 ? text : `${text}\n[exit code: ${exit}]` }],
    details: { exitCode: exit },
  } satisfies AgentToolResult<unknown>;
}

export function outputStats(output: string): {
  totalLines: number; totalBytes: number; outputLines: number; outputBytes: number;
} {
  const lines = output.split("\n").length;
  const bytes = Buffer.byteLength(output);
  return { totalLines: lines, totalBytes: bytes, outputLines: lines, outputBytes: bytes };
}

function filesystemOverride(
  shared: RuntimeSharedState,
  raw: { globalSection: SandboxConfig; projectSection: SandboxConfig },
  scope: "device" | "eval",
): SandboxRuntimeConfig {
  const lists = unionListsForTool(raw, scope === "eval" ? "eval" : null, shared.session);
  return {
    filesystem: {
      allowRead: lists.allowRead,
      denyRead: lists.denyRead,
      allowWrite: lists.allowWrite,
      denyWrite: lists.denyWrite,
    },
  } as SandboxRuntimeConfig;
}

export async function ensureLaunchTemplate(
  shared: RuntimeSharedState,
  scope: "device" | "eval",
  raw = shared.runtimeRawConfig,
): Promise<string> {
  const cacheKey = `${scope}:${JSON.stringify(raw)}`;
  const cached = shared.launchTemplates.get(cacheKey);
  if (cached?.generation === shared.launchGeneration) return cached.wrapped;
  const existing = shared.launchTemplatePromises.get(cacheKey);
  if (existing) return existing;
  const generation = shared.launchGeneration;
  const promise = SandboxManager.wrapWithSandbox(
    `exec ${shellQuoteArg(bashShellPath())} -c "$${LAUNCH_CMD_VAR}"`,
    bashShellPath(),
    filesystemOverride(shared, raw, scope),
  ).then((wrapped) => {
    shared.launchTemplates.set(cacheKey, { generation, wrapped });
    shared.launchTemplatePromises.delete(cacheKey);
    return wrapped;
  }).catch((error: unknown) => {
    shared.launchTemplatePromises.delete(cacheKey);
    throw error;
  });
  shared.launchTemplatePromises.set(cacheKey, promise);
  return promise;
}
