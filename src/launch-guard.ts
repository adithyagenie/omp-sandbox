import { AsyncLocalStorage } from "node:async_hooks";
import { basename } from "node:path";
import { shellQuoteJoin } from "./policy.ts";

export const LAUNCH_CMD_VAR = "OMP_SANDBOX_LAUNCH_CMD";
export const LAUNCH_WINDOW_TTL_MS = 10 * 60 * 1000;

export const INFRA_SPAWN_BASENAMES: Record<string, true> = {
  bwrap: true,
  socat: true,
  "apply-seccomp": true,
  "xdg-open": true,
  xclip: true,
  "wl-copy": true,
  "wl-paste": true,
  pbcopy: true,
  pbpaste: true,
  osascript: true,
  "termux-clipboard-set": true,
  getconf: true,
  wslpath: true,
  "powershell.exe": true,
};

type SpawnFn = (this: unknown, cmdOrOpts: unknown, maybeOpts?: unknown) => unknown;
type NodeSpawnFn = (this: unknown, file: string, args?: string[], opts?: unknown) => unknown;
export type LaunchScope = "device" | "eval";

export interface LaunchWindow {
  openedAt: number;
  scope: LaunchScope;
  template: string;
  closed: boolean;
}

export interface LaunchGuardState {
  installed: boolean;
  storage: AsyncLocalStorage<LaunchWindow>;
  bashPath: string;
  isEnabled: () => boolean;
  note: (message: string) => void;
  originalBunSpawn?: SpawnFn;
  originalNodeSpawn?: NodeSpawnFn;
}

const LAUNCH_GUARD_KEY = Symbol.for("pi-sandbox-omp.launchGuard");
interface GlobalWithLaunchGuard {
  [LAUNCH_GUARD_KEY]?: LaunchGuardState;
}

export function getLaunchGuardState(): LaunchGuardState {
  const global = globalThis as typeof globalThis & GlobalWithLaunchGuard;
  const existing = global[LAUNCH_GUARD_KEY];
  if (existing) {
    existing.storage ??= new AsyncLocalStorage<LaunchWindow>();
    return existing;
  }
  const state: LaunchGuardState = {
    installed: false,
    storage: new AsyncLocalStorage<LaunchWindow>(),
    bashPath: "/bin/bash",
    isEnabled: () => false,
    note: () => {},
  };
  global[LAUNCH_GUARD_KEY] = state;
  return state;
}

export async function withLaunchWindow<TResult>(
  state: LaunchGuardState,
  scope: LaunchScope,
  template: string,
  run: () => Promise<TResult>,
): Promise<TResult> {
  const window: LaunchWindow = {
    openedAt: Date.now(),
    scope,
    template,
    closed: false,
  };
  return state.storage.run(window, async () => {
    try {
      return await run();
    } finally {
      window.closed = true;
    }
  });
}

export function launchWindowActive(state: LaunchGuardState): LaunchWindow | null {
  const window = state.storage.getStore();
  if (!window || window.closed) return null;
  if (Date.now() - window.openedAt <= LAUNCH_WINDOW_TTL_MS) return window;
  window.closed = true;
  state.note(`[pi-sandbox-omp] expired stale ${window.scope} sandbox launch context`);
  return null;
}

export function isInfraSpawn(executable: string, argv: string[]): boolean {
  if (executable === process.execPath) return true;
  if (argv.some((arg) => arg === "__omp_worker_js_eval" || arg === "__omp_worker_daemon_broker")) return true;
  return INFRA_SPAWN_BASENAMES[basename(executable)] === true;
}

export function transformGuardedLaunch(
  state: LaunchGuardState,
  command: string | string[],
  opts: Record<string, unknown> | undefined,
): { cmd: string[]; opts: Record<string, unknown> } | null {
  if (!state.isEnabled()) return null;
  const window = launchWindowActive(state);
  if (!window) return null;
  if (opts && "ipc" in opts && opts.ipc !== undefined && opts.ipc !== null) return null;
  const commandText = typeof command === "string" ? command : shellQuoteJoin(command);
  if (commandText.length === 0) return null;
  const argv = typeof command === "string" ? command.split(/\s+/) : command;
  const executable = argv[0] ?? "";
  if (!executable || isInfraSpawn(executable, argv)) return null;
  if (!window.template) {
    throw new Error("[pi-sandbox-omp] active launch window has no sandbox template; retry the tool call");
  }
  const optionsEnvironment = opts?.env;
  const baseEnvironment: Record<string, string | undefined> =
    typeof optionsEnvironment === "object" && optionsEnvironment !== null
      ? optionsEnvironment as Record<string, string | undefined>
      : process.env;
  return {
    cmd: [state.bashPath, "-c", window.template],
    opts: { ...opts, env: { ...baseEnvironment, [LAUNCH_CMD_VAR]: commandText } },
  };
}

export function installLaunchSandboxGuard(state: LaunchGuardState): void {
  if (state.installed) return;
  state.installed = true;
  const bunGlobal = globalThis as typeof globalThis & { Bun?: { spawn?: unknown } };
  const bun = bunGlobal.Bun;
  if (bun && typeof bun.spawn === "function") {
    state.originalBunSpawn = bun.spawn as SpawnFn;
    const original = state.originalBunSpawn;
    bun.spawn = function (this: unknown, cmdOrOpts: unknown, maybeOpts?: unknown) {
      if (cmdOrOpts !== null && typeof cmdOrOpts === "object" && !Array.isArray(cmdOrOpts)) {
        const options = cmdOrOpts as Record<string, unknown>;
        const command = options.cmd;
        if (typeof command !== "string" && !Array.isArray(command)) return original.call(bun, cmdOrOpts, maybeOpts);
        const transformed = transformGuardedLaunch(state, command as string | string[], options);
        if (!transformed) return original.call(bun, cmdOrOpts, maybeOpts);
        return original.call(bun, { ...options, cmd: transformed.cmd, env: transformed.opts.env });
      }
      if (typeof cmdOrOpts !== "string" && !Array.isArray(cmdOrOpts)) return original.call(bun, cmdOrOpts, maybeOpts);
      const options = maybeOpts !== null && typeof maybeOpts === "object"
        ? maybeOpts as Record<string, unknown>
        : undefined;
      const transformed = transformGuardedLaunch(state, cmdOrOpts as string | string[], options);
      if (!transformed) return original.call(bun, cmdOrOpts, maybeOpts);
      return original.call(bun, transformed.cmd, transformed.opts);
    };
  }

  type NodeCpModule = { spawn: NodeSpawnFn };
  const childProcess = require("node:child_process") as NodeCpModule;
  state.originalNodeSpawn = childProcess.spawn.bind(childProcess);
  const originalNodeSpawn = state.originalNodeSpawn;
  childProcess.spawn = function (this: unknown, file: string, args?: string[], opts?: unknown) {
    if (typeof file !== "string" || file.length === 0) return originalNodeSpawn(file, args, opts);
    const argv = args === undefined ? [file] : [file, ...args];
    const options = opts !== null && typeof opts === "object" ? opts as Record<string, unknown> : undefined;
    const transformed = transformGuardedLaunch(state, argv, options);
    if (!transformed) return originalNodeSpawn(file, args, opts);
    return originalNodeSpawn(transformed.cmd[0], transformed.cmd.slice(1), transformed.opts);
  };
}
