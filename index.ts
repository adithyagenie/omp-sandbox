/**
 * Based on https://github.com/badlogic/pi-mono/blob/main/packages/coding-agent/examples/extensions/sandbox/index.ts
 * by Mario Zechner, used under the MIT License.
 *
 * Sandbox Extension - OS-level sandboxing for bash commands, hub process
 * launches, xd:// tool-device subprocesses, plus path policy enforcement for
 * omp's read/write/edit tools, with interactive permission prompts.
 *
 * Uses @carderne/sandbox-runtime to enforce filesystem and network
 * restrictions at the OS level (sandbox-exec on macOS, bubblewrap on Linux).
 * Three launch surfaces are covered:
 *   1. bash tool + !bang commands - wrapped via SandboxManager directly.
 *   2. hub tool op:"start" - the launch spec is rewritten in the tool_call
 *      handler (application -> shell, args -> ["-c", bwrap-wrapped command]),
 *      so the broker itself spawns the daemon inside the sandbox.
 *   3. xd:// device executions (github -> gh, browser -> Chromium) - omp
 *      spawns those subprocesses in-process via Bun.spawn / child_process.spawn;
 *      a guarded launch template re-routes them through bwrap while the device
 *      call is executing. Configured via `sandboxedDevices` (default
 *      ["github", "browser"]).
 * Also intercepts the read, write, and edit tools to apply the same
 * denyRead/denyWrite/allowWrite filesystem rules, which OS-level sandboxing
 * cannot cover (those tools run directly in Node.js, not in a subprocess).
 *
 * When a block is triggered, the user is prompted to:
 *   (a) Abort (keep blocked)
 *   (b) Allow for this session only  -- stored in memory, agent cannot access
 *   (c) Allow for this project       -- written to .omp/sandbox.json
 *   (d) Allow for all projects       -- written to <agent-dir>/sandbox.json
 *
 * What gets prompted vs. hard-blocked:
 *   - domains: prompted if not whitelisted nor explicitly denied
 *   - write: prompted if not whitelisted nor explicitly denied
 *   - read: always prompted (because denyRead is used for broad block, may want to punch holes)
 *
 * IMPORTANT -- precedence for read:
 *   Read:  allowRead OVERRIDES denyRead (prompt grant adds to allowRead)
 *   Write: denyWrite OVERRIDES allowWrite (most-specific deny wins)
 *
 * Config files (merged, project takes precedence):
 * - <agent-dir>/sandbox.json (global)
 * - <cwd>/.omp/sandbox.json  (project-local)
 *
 * Example .omp/sandbox.json:
 * ```json
 * {
 *   "enabled": true,
 *   "network": {
 *     "allowedDomains": ["github.com", "*.github.com"],
 *     "deniedDomains": []
 *   },
 *   "filesystem": {
 *     "denyRead": ["/Users", "/home"],
 *     "allowRead": [".", "~/.config", "~/.local", "Library"],
 *     "allowWrite": [".", "/tmp"],
 *     "denyWrite": [".env"]
 *   }
 * }
 * ```
 *
 * Usage (installed as an omp plugin; auto-loaded in interactive sessions):
 * - omp interactive            - sandbox enabled with default/config settings
 * - omp --no-sandbox           - disable sandboxing for the session
 * - /sandbox                   - show current sandbox configuration
 * - /sandbox-disable | /sandbox-enable - toggle the sandbox for the session
 *
 * Linux also requires: bubblewrap, socat, ripgrep
 */

import type { AgentToolResult, ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { getAgentDir, isToolCallEventType } from "@oh-my-pi/pi-coding-agent";
import { Key, matchesKey, truncateToWidth } from "@oh-my-pi/pi-tui";
import {
  SandboxManager,
  type SandboxAskCallback,
  type SandboxRuntimeConfig,
} from "@carderne/sandbox-runtime";

interface SandboxConfig extends SandboxRuntimeConfig {
  enabled?: boolean;
  /** xd:// device names whose subprocess launches run inside the OS sandbox. */
  sandboxedDevices?: string[];
}

interface ShellRunResult {
  exitCode: number | null;
  output: string;
}

/**
 * xd:// devices whose host subprocesses (spawned in-process by omp while the
 * device executes) are wrapped in the OS sandbox: github -> gh CLI,
 * browser -> Chromium via puppeteer. Devices that run their work in separate
 * worker processes (lsp, eval) or in-process against native code cannot be
 * covered from an extension.
 */
const DEFAULT_SANDBOXED_DEVICES = ["github", "browser"];

const DEFAULT_CONFIG: SandboxConfig = {
  enabled: true,
  network: {
    allowedDomains: [
      "npmjs.org",
      "*.npmjs.org",
      "registry.npmjs.org",
      "registry.yarnpkg.com",
      "pypi.org",
      "*.pypi.org",
      "github.com",
      "*.github.com",
      "api.github.com",
      "raw.githubusercontent.com",
    ],
    deniedDomains: [],
  },
  filesystem: {
    denyRead: ["/Users", "/home"],
    allowRead: [".", "~/.config", "~/.local", "Library"],
    allowWrite: [".", "/tmp"],
    denyWrite: [".env", ".env.*", "*.pem", "*.key"],
  },
  sandboxedDevices: [...DEFAULT_SANDBOXED_DEVICES],
};

function loadConfig(cwd: string): SandboxConfig {
  const projectConfigPath = join(cwd, ".omp", "sandbox.json");
  const globalConfigPath = join(getAgentDir(), "sandbox.json");

  let globalConfig: Partial<SandboxConfig> = {};
  let projectConfig: Partial<SandboxConfig> = {};

  if (existsSync(globalConfigPath)) {
    try {
      globalConfig = JSON.parse(readFileSync(globalConfigPath, "utf-8"));
    } catch (e) {
      console.error(`Warning: Could not parse ${globalConfigPath}: ${e}`);
    }
  }

  if (existsSync(projectConfigPath)) {
    try {
      projectConfig = JSON.parse(readFileSync(projectConfigPath, "utf-8"));
    } catch (e) {
      console.error(`Warning: Could not parse ${projectConfigPath}: ${e}`);
    }
  }

  return deepMerge(deepMerge(DEFAULT_CONFIG, globalConfig), projectConfig, true);
}

/** Union two path/domain lists, preserving order and dropping duplicates. */
function unionPaths(a?: string[], b?: string[]): string[] {
  return [...new Set([...(a ?? []), ...(b ?? [])])];
}

function deepMerge(
  base: SandboxConfig,
  overrides: Partial<SandboxConfig>,
  additive = false,
): SandboxConfig {
  const result: SandboxConfig = { ...base };

  if (overrides.enabled !== undefined) result.enabled = overrides.enabled;
  if (overrides.network) {
    // Allow-lists accumulate across layers (a later scope grants more); deny
    // lists and scalars still replace so a tighter scope can override defaults.
    result.network = {
      ...base.network,
      ...overrides.network,
      ...(additive
        ? {
            allowedDomains: unionPaths(
              base.network?.allowedDomains,
              overrides.network.allowedDomains,
            ),
          }
        : {}),
    };
  }
  if (overrides.filesystem) {
    result.filesystem = {
      ...base.filesystem,
      ...overrides.filesystem,
      ...(additive
        ? {
            allowRead: unionPaths(base.filesystem?.allowRead, overrides.filesystem.allowRead),
            allowWrite: unionPaths(base.filesystem?.allowWrite, overrides.filesystem.allowWrite),
          }
        : {}),
    };
  }
  if (overrides.sandboxedDevices !== undefined) {
    result.sandboxedDevices = additive
      ? unionPaths(base.sandboxedDevices, overrides.sandboxedDevices)
      : overrides.sandboxedDevices;
  }

  const extOverrides = overrides as {
    ignoreViolations?: Record<string, string[]>;
    enableWeakerNestedSandbox?: boolean;
    allowBrowserProcess?: boolean;
  };
  const extResult = result as {
    ignoreViolations?: Record<string, string[]>;
    enableWeakerNestedSandbox?: boolean;
    allowBrowserProcess?: boolean;
  };

  if (extOverrides.ignoreViolations) {
    extResult.ignoreViolations = extOverrides.ignoreViolations;
  }
  if (extOverrides.enableWeakerNestedSandbox !== undefined) {
    extResult.enableWeakerNestedSandbox = extOverrides.enableWeakerNestedSandbox;
  }
  if (extOverrides.allowBrowserProcess !== undefined) {
    extResult.allowBrowserProcess = extOverrides.allowBrowserProcess;
  }

  return result;
}

// ── Domain helpers ────────────────────────────────────────────────────────────

export function shouldPromptForWrite(
  path: string,
  allowWrite: string[],
  matchesPattern: (path: string, patterns: string[]) => boolean,
): boolean {
  // Secure default: empty allowWrite means deny-all writes (prompt every path).
  return allowWrite.length === 0 || !matchesPattern(path, allowWrite);
}

function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  const domains = new Set<string>();
  let match;
  while ((match = urlRegex.exec(command)) !== null) {
    domains.add(match[1]);
  }
  return [...domains];
}

// ── SSH target extraction ─────────────────────────────────────────────────────

/**
 * Binaries that can open an interactive remote channel over ssh. ssh/scp/sftp
 * are the OpenSSH clients; rsync is included only when its args contain an
 * ssh-transport remote (user@host: / host:); git only for `clone` with an
 * ssh-style remote. Purely-local rsync/git produce no targets and are ungated.
 */
const SSH_BINARIES: Record<string, true> = {
  ssh: true, scp: true, sftp: true, rsync: true, git: true,
};

/** Short options whose following token is an argument (not a host), per binary. */
const SSH_OPT_TAKES_ARG: Record<string, Record<string, true>> = {
  ssh: { b: true, c: true, F: true, i: true, J: true, L: true, l: true, m: true, o: true, O: true, p: true, R: true, w: true, D: true, W: true, S: true, I: true, E: true, B: true, Q: true },
  scp: { i: true, l: true, o: true, P: true, F: true, c: true, J: true, S: true },
  sftp: { i: true, b: true, c: true, F: true, J: true, l: true, o: true, P: true, S: true },
  rsync: { e: true },
};

/** Command wrappers to skip when locating the real binary in a token stream. */
const SHELL_WRAPPERS: Record<string, true> = {
  sudo: true, doas: true, nice: true, time: true, nohup: true, env: true, command: true, exec: true, xargs: true, strace: true, ltrace: true,
};

/**
 * Split a shell segment into tokens, honouring single/double quotes (the quote
 * chars are dropped, inner content kept as one token). This prevents quoted
 * option values like `ProxyCommand="nc host 22"` from leaking their inner
 * whitespace as spurious host/alias tokens. Not a full shell parser — no escape
 * or expansion handling — but sufficient for ssh host extraction.
 */
function shellTokens(s: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (let k = 0; k < s.length; k++) {
    const ch = s[k];
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (/\s/.test(ch)) {
      if (cur) { out.push(cur); cur = ""; }
    } else {
      cur += ch;
    }
  }
  if (cur) out.push(cur);
  return out;
}

function isHostLike(h: string): boolean {
  return (
    /^[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}$/.test(h) || // FQDN
    /^(\d{1,3}\.){3}\d{1,3}$/.test(h) // IPv4
  );
}

/**
 * Pull a host out of a remote-style token: `user@host:path`, `host:path`,
 * `host::module` (rsync daemon), `user@host`, or a bare FQDN/IP. Returns null
 * for local paths (incl. Windows `C:\`) and bare filenames with no `:`/`@` —
 * so `file.tgz` in an scp/rsync stream is not mistaken for a host. ssh:// is
 * handled separately by the caller's regex.
 */
function hostFromRemoteToken(token: string): string | null {
  if (/^[A-Za-z]:[\\/]/.test(token) || token.startsWith("/")) return null;
  const hadAt = token.includes("@");
  const at = token.lastIndexOf("@");
  const tok = at >= 0 ? token.slice(at + 1) : token;
  const daemon = tok.match(/^([A-Za-z0-9][A-Za-z0-9.\-]*)::/);
  if (daemon) return daemon[1];
  const colon = tok.indexOf(":");
  if (colon > 0) {
    const host = tok.slice(0, colon);
    if (/^[A-Za-z0-9][A-Za-z0-9.\-]*$/.test(host)) return host;
    return null;
  }
  if (hadAt && isHostLike(tok)) return tok;
  return null;
}

/**
 * Extract ssh target hosts from a command string. Splits on shell separators
 * (; | & \n) so `echo hi; ssh host` is caught. For ssh/sftp the target is the
 * first non-option token (option values skipped via SSH_OPT_TAKES_ARG; a bare
 * alias like `ssh prod` with no dot/IP is still captured). For scp/rsync every
 * remote-style token is collected. For git only `clone` with an ssh remote
 * (git@host: or ssh://) yields a target. Returns best-effort host labels used
 * for the confirmation prompt and persistence.
 */
function extractSshTargets(command: string): string[] {
  const targets = new Set<string>();

  const sshUrlRe = /ssh:\/\/(?:[^@\s/]+@)?([A-Za-z0-9][A-Za-z0-9.\-]+)/g;
  let m: RegExpExecArray | null;
  while ((m = sshUrlRe.exec(command)) !== null) targets.add(m[1]);

  for (const seg of command.split(/[\n;|&]+/)) {
    const tokens = shellTokens(seg);
    if (tokens.length === 0) continue;

    let i = 0;
    while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i++;
    while (i < tokens.length && SHELL_WRAPPERS[tokens[i]]) {
      i++;
      while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i++;
    }
    if (i >= tokens.length) continue;
    const bin = tokens[i].replace(/^.*\//, "");
    if (!SSH_BINARIES[bin]) continue;

    if (bin === "git") {
      if (tokens[i + 1] !== "clone") continue;
      for (let j = i + 2; j < tokens.length; j++) {
        const t = tokens[j];
        if (t.startsWith("-")) continue;
        if (t.includes("://")) break; // ssh:// handled by regex above; http(s)/git/file:// are not ssh
        const h = hostFromRemoteToken(t);
        if (h) targets.add(h);
        break; // first non-option token is the remote URL
      }
      continue;
    }

    const argOpts = SSH_OPT_TAKES_ARG[bin];
    const scanAll = bin === "scp" || bin === "rsync";
    for (let j = i + 1; j < tokens.length; j++) {
      const t = tokens[j];
      if (t.startsWith("--")) continue;
      if (/^-[A-Za-z]/.test(t)) {
        const last = t[t.length - 1];
        if (argOpts?.[last] && !t.includes("=") && j + 1 < tokens.length) j++;
        continue;
      }
      const h = hostFromRemoteToken(t);
      if (h) {
        targets.add(h);
        if (!scanAll) break;
      } else if (!scanAll) {
        const at = t.lastIndexOf("@");
        targets.add(at >= 0 ? t.slice(at + 1) : t); // bare alias: `ssh prod`
        break;
      }
    }
  }
  return [...targets];
}

function domainMatchesPattern(domain: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith("." + base);
  }
  return domain === pattern;
}

function allowsAllDomains(allowedDomains: string[] | undefined): boolean {
  return allowedDomains?.includes("*") ?? false;
}

function domainIsAllowed(domain: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((p) => domainMatchesPattern(domain, p));
}

function createNetworkAskCallback(allowedDomains: string[]): SandboxAskCallback {
  return async ({ host }) => domainIsAllowed(host, allowedDomains);
}

/**
 * "Allow all egress" (allowedDomains contains "*") with nothing denied means
 * there is no allowlist left to enforce. On Linux the proxy path still forces
 * bwrap --unshare-net, which strips every network interface and tunnels only
 * HTTP(S) through a socat/Unix-socket bridge — so dig/nslookup (raw UDP:53),
 * nc, ping, and every non-HTTP protocol fail with "network unreachable" even
 * though egress is supposedly unrestricted. sandbox-runtime treats an UNDEFINED
 * allowedDomains as "no network restriction" (needsNetworkRestriction =
 * allowedDomains !== undefined), skipping --unshare-net so the bash namespace
 * shares the host network. We only take this path when nothing is denied: a
 * denylist still needs the proxy to enforce it.
 */
function isUnrestrictedNetwork(network: SandboxConfig["network"]): boolean {
  return allowsAllDomains(network?.allowedDomains) && (network?.deniedDomains?.length ?? 0) === 0;
}

/**
 * Build the network config handed to sandbox-runtime. Under allow-all-with-no-
 * denies we omit allowedDomains so the runtime disables network isolation and
 * shares the host network (DNS, UDP, raw sockets all work); filesystem
 * isolation is untouched. Otherwise we merge session grants into the allowlist
 * and the filtering proxy enforces it as before.
 */
function buildRuntimeNetwork(
  network: SandboxConfig["network"],
  sessionDomains: string[],
): SandboxRuntimeConfig["network"] {
  if (isUnrestrictedNetwork(network)) {
    // allowedDomains: undefined -> sandbox-runtime skips --unshare-net. network
    // must stay an object: initialize()/updateConfig() read network.parentProxy.
    return { ...network, allowedDomains: undefined, deniedDomains: [] } as unknown as SandboxRuntimeConfig["network"];
  }
  return {
    ...network,
    allowedDomains: [...(network?.allowedDomains ?? []), ...sessionDomains],
    deniedDomains: network?.deniedDomains ?? [],
  };
}

/** Human-readable network mode for the status line. */
function formatNetworkLabel(network: SandboxConfig["network"]): string {
  if (isUnrestrictedNetwork(network)) return "unrestricted (host network)";
  if (allowsAllDomains(network?.allowedDomains)) return "all domains";
  return `${network?.allowedDomains?.length ?? 0} domains`;
}

// ── Output analysis ───────────────────────────────────────────────────────────

/**
 * Extract a path from a bash OS-sandbox write-denial error. Matches macOS
 * sandbox-exec ("Operation not permitted") and Linux bubblewrap denials
 * ("Read-only file system" / "Permission denied"), so the write-block
 * prompt-and-retry flow fires on both platforms.
 */
function extractBlockedWritePath(output: string): string | null {
  const match = output.match(
    /(?:\/bin\/bash|bash|sh): (?:line \d+: )?(\/[^\s:]+): (?:Operation not permitted|Read-only file system|Permission denied)/,
  );
  return match ? match[1] : null;
}

/**
 * Collect the filesystem write targets a tool call declares in its input, so
 * the write path policy (denyWrite hard-block / allowWrite prompt) covers not
 * just write/edit but every tool that names the paths it mutates:
 *   - write:    input.path
 *   - edit:     hashline patch section headers  [<path>#<tag>]
 *   - ast_edit: input.paths[]  (structural rewrite targets)
 *   - lsp:      action "rename_file" -> input.file (source) + input.new_name (dest)
 *
 * Tools that execute opaque in-process code (eval, browser) never declare the
 * paths they touch and cannot be covered here; gate those via tools.approval.
 */
function collectWriteTargets(toolName: string, input: Record<string, unknown>): string[] {
  const targets: string[] = [];
  const push = (v: unknown) => {
    if (typeof v === "string" && v.length > 0) targets.push(v);
  };

  switch (toolName) {
    case "write":
      // xd:// paths are the tool-device transport, not filesystem writes;
      // they are gated by the launch-sandbox device policy instead.
      if (typeof input.path === "string" && !input.path.startsWith("xd://")) push(input.path);
      break;
    case "edit":
      for (const value of Object.values(input)) {
        if (typeof value !== "string") continue;
        for (const m of value.matchAll(/^\[([^\]\n]+?)#[0-9A-Za-z]{2,}\]/gm)) {
          targets.push(m[1]);
        }
      }
      break;
    case "ast_edit":
      if (Array.isArray(input.paths)) {
        for (const p of input.paths) push(p);
      }
      break;
    case "lsp":
      if (input.action === "rename_file") {
        push(input.file);
        push(input.new_name);
      }
      break;
  }
  return targets;
}

// ── Path pattern matching ─────────────────────────────────────────────────────

function expandPath(filePath: string): string {
  const expanded = filePath.replace(/^~(?=$|\/)/, homedir());
  return resolve(expanded);
}

function canonicalizePath(filePath: string): string {
  const abs = expandPath(filePath);
  try {
    return realpathSync.native(abs);
  } catch {
    // For writes to paths that do not exist yet, resolve symlinks in the nearest
    // existing parent directory, then append the non-existent tail.
    const tail: string[] = [];
    let probe = abs;
    while (!existsSync(probe)) {
      const parent = dirname(probe);
      if (parent === probe) return abs;
      tail.unshift(basename(probe));
      probe = parent;
    }
    try {
      return resolve(realpathSync.native(probe), ...tail);
    } catch {
      return abs;
    }
  }
}

function matchesPattern(filePath: string, patterns: string[]): boolean {
  const abs = canonicalizePath(filePath);
  return patterns.some((p) => {
    const absP = p.includes("*") ? expandPath(p) : canonicalizePath(p);
    if (p.includes("*")) {
      const escaped = absP.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
      return new RegExp(`^${escaped}$`).test(abs);
    }
    const sep = absP.endsWith("/") ? "" : "/";
    return abs === absP || abs.startsWith(absP + sep);
  });
}

// ── Config file updaters (Node.js process — not OS-sandboxed) ─────────────────

function getConfigPaths(cwd: string): {
  globalPath: string;
  projectPath: string;
} {
  return {
    globalPath: join(getAgentDir(), "sandbox.json"),
    projectPath: join(cwd, ".omp", "sandbox.json"),
  };
}

function readOrEmptyConfig(configPath: string): Partial<SandboxConfig> {
  if (!existsSync(configPath)) return {};
  try {
    return JSON.parse(readFileSync(configPath, "utf-8"));
  } catch {
    return {};
  }
}

function writeConfigFile(configPath: string, config: Partial<SandboxConfig>): void {
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
}

function addDomainToConfig(configPath: string, domain: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.network?.allowedDomains ?? [];
  if (!existing.includes(domain)) {
    config.network = { ...config.network, allowedDomains: [...existing, domain] };
    writeConfigFile(configPath, config);
  }
}

function addReadPathToConfig(configPath: string, pathToAdd: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.filesystem?.allowRead ?? [];
  if (!existing.includes(pathToAdd)) {
    config.filesystem = { ...config.filesystem, allowRead: [...existing, pathToAdd] };
    writeConfigFile(configPath, config);
  }
}

function addWritePathToConfig(configPath: string, pathToAdd: string): void {
  const config = readOrEmptyConfig(configPath);
  const existing = config.filesystem?.allowWrite ?? [];
  if (!existing.includes(pathToAdd)) {
    config.filesystem = { ...config.filesystem, allowWrite: [...existing, pathToAdd] };
    writeConfigFile(configPath, config);
  }
}

// ── Launch sandbox guard (hub + xd:// device subprocesses) ───────────────────

/**
 * Environment variable that carries the payload command for the guarded
 * launch template. The template (produced by SandboxManager.wrapWithSandbox)
 * is a fixed bwrap/sandbox-exec wrapper whose innermost command is
 * `exec <shell> -c "$OMP_SANDBOX_LAUNCH_CMD"`, so arbitrary argv can be
 * launched synchronously (Bun.spawn / child_process.spawn cannot await an
 * async wrap) by passing the shell-quoted command through the environment —
 * no string surgery on the wrapped command, no quoting hazards.
 */
const LAUNCH_CMD_VAR = "OMP_SANDBOX_LAUNCH_CMD";

/** Windows older than this are dropped (guards against lost tool_result events). */
const LAUNCH_WINDOW_TTL_MS = 10 * 60 * 1000;

/**
 * Host utilities omp may spawn incidentally while a device call is executing
 * (clipboard helpers, URL opening, sandbox plumbing). Wrapping these would
 * break unrelated session features for no containment gain.
 */
const INFRA_SPAWN_BASENAMES: Record<string, true> = {
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
/** Quote one shell word (POSIX single-quote convention). */
function shellQuoteArg(arg: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

/** Quote an argv into a single shell command string. */
function shellQuoteJoin(argv: string[]): string {
  return argv.map(shellQuoteArg).join(" ");
}

interface LaunchTemplate {
  generation: number;
  wrapped: string;
}

/**
 * Process-global state for the launch guard. omp core and the extension share
 * one process, and subagent sessions re-bind the same prepared extension, so
 * module state suffices; the Symbol.for key survives plugin reloads. The
 * patched spawn functions close over this object; the extension updates the
 * accessors as the sandbox is initialized, reconfigured, or disabled.
 */
interface LaunchGuardState {
  installed: boolean;
  nesting: number;
  activeCalls: Map<string, number>;
  template: LaunchTemplate | null;
  bashPath: string;
  isEnabled: () => boolean;
  note: (message: string) => void;
}

const LAUNCH_GUARD_KEY = Symbol.for("pi-sandbox-omp.launchGuard");

interface GlobalWithLaunchGuard {
  [LAUNCH_GUARD_KEY]?: LaunchGuardState;
}

function getLaunchGuardState(): LaunchGuardState {
  const global = globalThis as typeof globalThis & GlobalWithLaunchGuard;
  const existing = global[LAUNCH_GUARD_KEY];
  if (existing) return existing;
  const state: LaunchGuardState = {
    installed: false,
    nesting: 0,
    activeCalls: new Map(),
    template: null,
    bashPath: "/bin/bash",
    isEnabled: () => false,
    note: () => {},
  };
  global[LAUNCH_GUARD_KEY] = state;
  return state;
}

function launchWindowActive(state: LaunchGuardState): boolean {
  const now = Date.now();
  for (const [id, openedAt] of state.activeCalls) {
    if (now - openedAt > LAUNCH_WINDOW_TTL_MS) state.activeCalls.delete(id);
  }
  return state.activeCalls.size > 0;
}

function isInfraSpawn(exe: string): boolean {
  // omp worker processes (daemon broker, LSP mux, ...) communicate over IPC or
  // shared sockets; wrapping them would break session infrastructure. The
  // guarded launcher itself calls the original spawn directly, so shell
  // binaries must NOT be skipped here — a device spawning a shell is a
  // workload, and skipping it would open an escape hatch.
  if (exe === process.execPath) return true;
  return INFRA_SPAWN_BASENAMES[basename(exe)] === true;
}

/**
 * Decide whether a spawn should be re-routed through the sandbox template.
 * Returns the replacement [bash, -c, template] spawn, or null to leave the
 * spawn untouched. Throws when a sandboxed-context spawn arrives with no
 * usable template (fail closed — the error surfaces in the tool result).
 */
function transformGuardedLaunch(
  state: LaunchGuardState,
  cmd: string | string[],
  opts: Record<string, unknown> | undefined,
): { cmd: string[]; opts: Record<string, unknown> } | null {
  if (state.nesting > 0 || !state.isEnabled() || !launchWindowActive(state)) return null;
  // IPC workers (omp infrastructure) communicate over a dedicated channel;
  // a shell intermediary would sever it.
  if (opts && ("ipc" in opts) && opts.ipc !== undefined && opts.ipc !== null) return null;

  const commandText = typeof cmd === "string" ? cmd : shellQuoteJoin(cmd);
  if (commandText.length === 0) return null;
  const exe = typeof cmd === "string" ? cmd.split(/\s+/)[0] ?? "" : cmd[0];
  if (!exe || isInfraSpawn(exe)) return null;

  const template = state.template;
  if (!template) {
    throw new Error(
      `[pi-sandbox-omp] sandboxed launch requested but the bwrap template is not ready; retry the tool call`,
    );
  }

  const optsEnv = opts?.env;
  const baseEnv: Record<string, string | undefined> =
    typeof optsEnv === "object" && optsEnv !== null ? optsEnv : process.env;
  const env = {
    ...baseEnv,
    [LAUNCH_CMD_VAR]: commandText,
  };
  return {
    cmd: [state.bashPath, "-c", template.wrapped],
    opts: { ...opts, env },
  };
}

/**
 * Patch the two in-process spawn surfaces omp uses for tool-device
 * subprocesses:
 *   - Bun.spawn            — global lookup at call time (xd://github gh CLI, MCP, ...)
 *   - child_process.spawn  — default-import surface (puppeteer/Chromium for xd://browser)
 * Named-import bindings (sandbox-runtime's socat bridges, this plugin's own
 * runner) resolved at module link time and are unaffected — no recursion.
 */
function installLaunchSandboxGuard(state: LaunchGuardState): void {
  type SpawnFn = (this: unknown, cmdOrOpts: unknown, maybeOpts?: unknown) => unknown;
  const bunGlobal = globalThis as typeof globalThis & { Bun?: { spawn?: unknown } };
  const bun = bunGlobal.Bun;
  if (bun && typeof bun.spawn === "function") {
    const original = bun.spawn as SpawnFn;
    const guarded = function (this: unknown, cmdOrOpts: unknown, maybeOpts?: unknown) {
      // Bun.spawn accepts (cmd, opts) or a single options object with .cmd.
      if (cmdOrOpts !== null && typeof cmdOrOpts === "object" && !Array.isArray(cmdOrOpts)) {
        const opts = cmdOrOpts as Record<string, unknown>;
        const cmd = opts.cmd;
        if (typeof cmd !== "string" && !Array.isArray(cmd)) {
          return original.call(bun, cmdOrOpts, maybeOpts);
        }
        const transformed = transformGuardedLaunch(state, cmd, opts);
        if (!transformed) return original.call(bun, cmdOrOpts, maybeOpts);
        return original.call(bun, { ...opts, cmd: transformed.cmd, env: transformed.opts.env });
      }
      if (typeof cmdOrOpts !== "string" && !Array.isArray(cmdOrOpts)) {
        return original.call(bun, cmdOrOpts, maybeOpts);
      }
      const opts =
        maybeOpts !== null && typeof maybeOpts === "object"
          ? (maybeOpts as Record<string, unknown>)
          : undefined;
      const transformed = transformGuardedLaunch(state, cmdOrOpts, opts);
      if (!transformed) return original.call(bun, cmdOrOpts, maybeOpts);
      return original.call(bun, transformed.cmd, transformed.opts);
    };
    bun.spawn = guarded;
  }

  type NodeCpModule = {
    spawn: (this: unknown, file: string, args?: string[], opts?: unknown) => unknown;
  };
  const nodeCp = require("node:child_process") as NodeCpModule;
  const originalSpawn = nodeCp.spawn.bind(nodeCp);
  nodeCp.spawn = function (this: unknown, file: string, args?: string[], opts?: unknown) {
    if (typeof file !== "string" || file.length === 0) {
      return originalSpawn(file, args, opts);
    }
    const argv = args === undefined ? [file] : [file, ...args];
    const optsRecord =
      opts !== null && typeof opts === "object" ? (opts as Record<string, unknown>) : undefined;
    const transformed = transformGuardedLaunch(state, argv, optsRecord);
    if (!transformed) return originalSpawn(file, args, opts);
    return originalSpawn(transformed.cmd[0], transformed.cmd.slice(1), transformed.opts);
  };
}

// ── Shell runner ──────────────────────────────────────────────────────────────

async function runSandboxedShell(
  command: string,
  cwd: string,
  shellPath: string,
  opts: {
    signal?: AbortSignal;
    timeout?: number;
    env?: Record<string, string>;
    wrap?: boolean;
  },
): Promise<ShellRunResult> {
  if (!existsSync(cwd)) {
    throw new Error(`Working directory does not exist: ${cwd}`);
  }

  const wrapped = opts.wrap ?? true ? await SandboxManager.wrapWithSandbox(command, shellPath) : command;
  const { promise, resolve, reject } = Promise.withResolvers<ShellRunResult>();
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
    if (child.pid) {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }
  };

  if (opts.timeout !== undefined && opts.timeout > 0) {
    timeoutHandle = setTimeout(() => {
      timedOut = true;
      killChildGroup();
    }, opts.timeout * 1000);
  }

  child.stdout?.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    output += chunk.toString();
  });

  const cleanup = () => {
    if (timeoutHandle) clearTimeout(timeoutHandle);
    opts.signal?.removeEventListener("abort", onAbort);
  };

  const onAbort = () => {
    killChildGroup();
  };

  opts.signal?.addEventListener("abort", onAbort, { once: true });
  if (opts.signal?.aborted) onAbort();

  child.on("error", (err) => {
    if (settled) return;
    settled = true;
    cleanup();
    reject(err);
  });

  child.on("close", (code) => {
    if (settled) return;
    settled = true;
    cleanup();

    if (opts.signal?.aborted) {
      reject(new Error("aborted"));
    } else if (timedOut) {
      reject(new Error(`timeout:${opts.timeout}`));
    } else {
      resolve({ exitCode: code, output });
    }
  });

  return promise;
}

function toToolResult(run: ShellRunResult): AgentToolResult<unknown> {
  const text = run.output || "(no output)";
  const exit = run.exitCode ?? 0;
  return {
    content: [{ type: "text", text: exit === 0 ? text : text + "\n[exit code: " + exit + "]" }],
    details: { exitCode: exit },
  } satisfies AgentToolResult<unknown>;
}

function outputStats(output: string): {
  totalLines: number;
  totalBytes: number;
  outputLines: number;
  outputBytes: number;
} {
  const lines = output.split("\n").length;
  const bytes = Buffer.byteLength(output);
  return {
    totalLines: lines,
    totalBytes: bytes,
    outputLines: lines,
    outputBytes: bytes,
  };
}

const RUNNER_EXTENSION_HANDLER_TIMEOUT_MS = 30_000;
const SANDBOX_APPROVAL_TIMEOUT_MS = 24 * 60 * 60 * 1000;
const SET_TIMEOUT_BRIDGE_KEY = Symbol.for("pi-sandbox-omp.extensionHandlerTimeoutBridge");

interface SetTimeoutBridge {
  armRunnerTimeout(): void;
}

interface GlobalWithTimeoutBridge {
  [SET_TIMEOUT_BRIDGE_KEY]?: SetTimeoutBridge;
}

function getExtensionHandlerTimeoutBridge(): SetTimeoutBridge {
  const global = globalThis as typeof globalThis & GlobalWithTimeoutBridge;
  const existing = global[SET_TIMEOUT_BRIDGE_KEY];
  if (existing) return existing;

  const originalSetTimeout = globalThis.setTimeout.bind(globalThis) as typeof globalThis.setTimeout;
  let armedHandlerCount = 0;

  const bridge: SetTimeoutBridge = {
    armRunnerTimeout() {
      armedHandlerCount += 1;
      // OMP normally creates the handler timer synchronously, but a deferred
      // dispatch can create it in a later microtask. Keep this scoped marker
      // alive through the turn so that timer is still extended.
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
    const shouldExtendTimeout = armedHandlerCount > 0 && timeout === RUNNER_EXTENSION_HANDLER_TIMEOUT_MS;
    if (shouldExtendTimeout) armedHandlerCount -= 1;
    const scopedTimeout = shouldExtendTimeout ? SANDBOX_APPROVAL_TIMEOUT_MS : timeout;
    return originalSetTimeout(handler, scopedTimeout, ...args);
  }) as typeof globalThis.setTimeout;

  global[SET_TIMEOUT_BRIDGE_KEY] = bridge;
  return bridge;
}

function withExtensionHandlerTimeoutBridge<TArgs extends unknown[], TResult>(
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

// ── Extension ─────────────────────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
  const ompTmpDir = process.env.OMP_TMPDIR ?? "/tmp/omp";
  process.env.OMP_TMPDIR = ompTmpDir;
  mkdirSync(ompTmpDir, { recursive: true });
  const timeoutBridge = getExtensionHandlerTimeoutBridge();

  pi.registerFlag("no-sandbox", {
    description: "Disable OS-level sandboxing for bash commands",
    type: "boolean",
    default: false,
  });

  // The sandboxed bash tool and user_bash always run POSIX bash, never the
  // user's interactive shell: the agent emits bash syntax, and an interactive
  // shell (e.g. fish) both mangles it and noisily fails to write its RC files
  // under the read-only home. Resolved once, lazily.
  let cachedBashPath: string | undefined;
  const bashShellPath = (): string => {
    if (cachedBashPath === undefined) {
      cachedBashPath = ["/bin/bash", "/usr/bin/bash", "/bin/sh"].find((p) => existsSync(p)) ?? "/bin/sh";
    }
    return cachedBashPath;
  };

  let sandboxEnabled = false;
  let sandboxInitialized = false;

  // Session-temporary allowances — held in JS memory, not accessible by the agent.
  // These are added on top of whatever is in the config files.
  const sessionAllowedDomains: string[] = [];
  const sessionAllowedReadPaths: string[] = [];
  const sessionAllowedWritePaths: string[] = [];

  // ── Launch sandbox (hub + xd:// device subprocesses) ──────────────────────

  const launchGuard = getLaunchGuardState();
  // Bumped whenever the sandbox config changes so the guarded-launch template
  // (bwrap argv baked once, reused synchronously at spawn time) is rebuilt.
  let launchTemplateGeneration = 0;
  let launchTemplatePromise: Promise<string> | null = null;

  function getEffectiveSandboxedDevices(cwd: string): Set<string> {
    return new Set(loadConfig(cwd).sandboxedDevices ?? DEFAULT_SANDBOXED_DEVICES);
  }

  /**
   * Build (or reuse) the guarded-launch template: a fixed wrapped command
   * whose payload rides in $OMP_SANDBOX_LAUNCH_CMD. Computed async here, then
   * available synchronously to the patched Bun.spawn / child_process.spawn.
   */
  function ensureLaunchTemplate(): Promise<string> {
    if (launchGuard.template && launchGuard.template.generation === launchTemplateGeneration) {
      return Promise.resolve(launchGuard.template.wrapped);
    }
    if (!launchTemplatePromise) {
      const generation = launchTemplateGeneration;
      launchTemplatePromise = SandboxManager.wrapWithSandbox(
        `exec ${shellQuoteArg(bashShellPath())} -c "$${LAUNCH_CMD_VAR}"`,
        bashShellPath(),
      )
        .then((wrapped) => {
          launchGuard.template = { generation, wrapped };
          return wrapped;
        })
        .catch((err: unknown) => {
          launchTemplatePromise = null;
          throw err;
        });
    }
    return launchTemplatePromise;
  }

  function configureLaunchGuard(note: (message: string) => void): void {
    launchGuard.bashPath = bashShellPath();
    launchGuard.isEnabled = () => sandboxEnabled && sandboxInitialized;
    launchGuard.note = note;
    installLaunchSandboxGuard(launchGuard);
    // Warm the template in the background so the first sandboxed device call
    // does not pay the wrap cost (rg deny-path scans, proxy check) up front.
    ensureLaunchTemplate().catch((err: unknown) => {
      note(`Warning: failed to build launch sandbox template: ${err instanceof Error ? err.message : err}`);
    });
  }

  // ── Effective config helpers ────────────────────────────────────────────────

  function getEffectiveAllowedDomains(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...(config.network?.allowedDomains ?? []), ...sessionAllowedDomains];
  }

  function getEffectiveAllowRead(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...(config.filesystem?.allowRead ?? []), ...sessionAllowedReadPaths];
  }

  function getEffectiveAllowWrite(cwd: string): string[] {
    const config = loadConfig(cwd);
    return [...(config.filesystem?.allowWrite ?? []), ...sessionAllowedWritePaths];
  }

  // ── Sandbox reinitialize ────────────────────────────────────────────────────
  // Called after granting a session/permanent allowance so the OS-level sandbox
  // picks up the new rules before the next bash subprocess starts.

  async function reinitializeSandbox(cwd: string): Promise<void> {
    if (!sandboxInitialized) return;
    const config = loadConfig(cwd);
    const configExt = config as unknown as { allowBrowserProcess?: boolean };
    try {
      const network = buildRuntimeNetwork(config.network, sessionAllowedDomains);
      // Hot-reload the allow-lists into the live sandbox config WITHOUT
      // reset()+initialize(). Tearing the proxy servers down mid-session calls
      // server.close(), which blocks until every in-flight proxied connection
      // drains. omp routes its own traffic (MCP, model API, websockets) through
      // this proxy via HTTP_PROXY/NODE_USE_ENV_PROXY, so a live keep-alive
      // connection makes close() — and thus this reinit, awaited inside the
      // tool_call handler — hang forever and freeze the session. updateConfig()
      // swaps the module config in place: wrapWithSandbox reads the new
      // filesystem rules on the next bash command and the proxy filter reads
      // config.network live, so approvals take effect with no restart, no hang.
      SandboxManager.updateConfig({
        network,
        filesystem: {
          ...config.filesystem,
          denyRead: config.filesystem?.denyRead ?? [],
          allowRead: [...(config.filesystem?.allowRead ?? []), ...sessionAllowedReadPaths],
          allowWrite: [...(config.filesystem?.allowWrite ?? []), ...sessionAllowedWritePaths],
          denyWrite: config.filesystem?.denyWrite ?? [],
        },
        allowBrowserProcess: configExt.allowBrowserProcess,
        enableWeakerNetworkIsolation: true,
      });
      // Filesystem/network rules changed — the baked launch template must be
      // rebuilt on next use.
      launchTemplateGeneration++;
      launchTemplatePromise = null;
    } catch (e) {
      console.error(`Warning: Failed to reinitialize sandbox: ${e}`);
    }
  }

  // ── UI prompts ──────────────────────────────────────────────────────────────

  interface PromptOption {
    label: string;
    key: string;
    action: "abort" | "session" | "project" | "global";
    confirm?: boolean;
    hint?: string;
  }

  const PERMISSION_OPTIONS: PromptOption[] = [
    { label: "Allow for this session only", key: "s", action: "session" },
    { label: "Abort (keep blocked)", key: "esc", action: "abort" },
    {
      label: "Allow for this project",
      key: "P",
      action: "project",
      confirm: true,
      hint: "→ .omp/sandbox.json",
    },
    {
      label: "Allow for all projects",
      key: "A",
      action: "global",
      confirm: true,
      hint: "→ <agent-dir>/sandbox.json",
    },
  ];

  async function showPermissionPrompt(
    ctx: ExtensionContext,
    title: string,
    options: PromptOption[],
  ): Promise<"abort" | "session" | "project" | "global"> {
    if (!ctx.hasUI) return "abort";

    const result = await ctx.ui.custom<"abort" | "session" | "project" | "global">(
      (tui, theme, _kb, done) => {
        let selectedIndex = 0;
        let pendingAction: "abort" | "session" | "project" | "global" | null = null;

        function resolve(action: "abort" | "session" | "project" | "global") {
          done(action);
        }

        return {
          render(width: number): string[] {
            const lines: string[] = [];
            lines.push(truncateToWidth(theme.fg("warning", title), width));
            lines.push("");

            for (let i = 0; i < options.length; i++) {
              const opt = options[i];
              const isSelected = i === selectedIndex;
              const isPending = pendingAction === opt.action;

              const prefix = isSelected ? " → " : "   ";
              const keyHint = theme.fg("accent", `[${opt.key}]`);
              let label = opt.label;

              if (opt.hint) {
                label += `  ${theme.fg("dim", opt.hint)}`;
              }

              if (isPending) {
                label += `  ${theme.fg("warning", "→ press Enter to confirm")}`;
              }

              const line = `${prefix}${keyHint} ${label}`;
              lines.push(truncateToWidth(line, width));
            }

            lines.push("");
            const footer = pendingAction
              ? "↑↓ navigate  enter confirm  esc cancel"
              : "↑↓ navigate  enter select  esc/ctrl+c cancel";
            lines.push(truncateToWidth(theme.fg("dim", footer), width));

            return lines;
          },

          handleInput(data: string): void {
            if (matchesKey(data, Key.escape) || matchesKey(data, Key.ctrl("c"))) {
              resolve("abort");
              return;
            }

            if (matchesKey(data, Key.enter)) {
              if (pendingAction) {
                resolve(pendingAction);
              } else {
                resolve(options[selectedIndex]?.action ?? "abort");
              }
              return;
            }

            if (matchesKey(data, Key.up)) {
              selectedIndex = Math.max(0, selectedIndex - 1);
              pendingAction = null;
              tui.requestRender();
              return;
            }
            if (matchesKey(data, Key.down)) {
              selectedIndex = Math.min(options.length - 1, selectedIndex + 1);
              pendingAction = null;
              tui.requestRender();
              return;
            }

            for (let i = 0; i < options.length; i++) {
              const opt = options[i];
              if (data === opt.key) {
                // Exact case match (uppercase P/A) → immediate
                resolve(opt.action);
                return;
              }
              if (data.toLowerCase() === opt.key.toLowerCase()) {
                // Lowercase match → confirmation required for P/A
                if (opt.confirm) {
                  pendingAction = opt.action;
                  selectedIndex = i;
                } else {
                  resolve(opt.action);
                }
                tui.requestRender();
                return;
              }
            }
          },

          invalidate(): void {
            // no-op
          },
        };
      },
    );

    return result ?? "abort";
  }

  async function promptDomainBlock(
    ctx: ExtensionContext,
    domain: string,
  ): Promise<"abort" | "session" | "project" | "global"> {
    return showPermissionPrompt(
      ctx,
      `🌐 Network blocked: "${domain}" is not in allowedDomains`,
      PERMISSION_OPTIONS,
    );
  }

  async function promptReadBlock(
    ctx: ExtensionContext,
    filePath: string,
  ): Promise<"abort" | "session" | "project" | "global"> {
    return showPermissionPrompt(
      ctx,
      `📖 Read blocked: "${filePath}" is not in allowRead`,
      PERMISSION_OPTIONS,
    );
  }

  async function promptWriteBlock(
    ctx: ExtensionContext,
    filePath: string,
  ): Promise<"abort" | "session" | "project" | "global"> {
    return showPermissionPrompt(
      ctx,
      `📝 Write blocked: "${filePath}" is not in allowWrite`,
      PERMISSION_OPTIONS,
    );
  }

  /**
   * SSH confirmation gate. ssh/scp/sftp/rsync-over-ssh are interactive remote
   * channels: they require explicit per-host confirmation even when the network
   * is otherwise unrestricted (allowedDomains "*"). A bare "*" does NOT
   * auto-approve ssh — every ssh host prompts the first time, mirroring
   * read/write path confirmation. Approval persists per host via allowedDomains,
   * so a host approved once (session/project/global) is silent thereafter.
   * Returns the host string if the user aborted (block), else null.
   */
  async function enforceSshGate(
    command: string,
    ctx: ExtensionContext,
  ): Promise<string | null> {
    for (const host of extractSshTargets(command)) {
      const approved = getEffectiveAllowedDomains(ctx.cwd).some(
        (p) => p !== "*" && domainMatchesPattern(host, p),
      );
      if (approved) continue;
      const choice = await showPermissionPrompt(
        ctx,
        `🔐 SSH blocked: ssh to "${host}" requires confirmation`,
        PERMISSION_OPTIONS,
      );
      if (choice === "abort") return host;
      await applyDomainChoice(choice, host, ctx.cwd);
    }
    return null;
  }

  function warnIfAllDomainsAllowed(ctx: ExtensionContext, config: SandboxConfig): void {
    if (!allowsAllDomains(config.network?.allowedDomains)) return;
    const msg = isUnrestrictedNetwork(config.network)
      ? '⚠️ Network isolation is DISABLED: allowedDomains is "*" with no deniedDomains, so ' +
        "sandboxed commands share the host network (raw sockets, DNS, and host loopback are " +
        'reachable). Add a deniedDomains entry or remove "*" to re-enable the filtering proxy.'
      : '⚠️ Network sandbox allows all domains because network.allowedDomains contains "*". ' +
        'Only use this intentionally; remove "*" to restore per-domain prompts.';
    ctx.ui.notify(msg, "warning");
  }

  // ── Apply allowance choices ─────────────────────────────────────────────────

  async function applyDomainChoice(
    choice: "session" | "project" | "global",
    domain: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedDomains.includes(domain)) sessionAllowedDomains.push(domain);
    if (choice === "project") addDomainToConfig(projectPath, domain);
    if (choice === "global") addDomainToConfig(globalPath, domain);
    await reinitializeSandbox(cwd);
  }

  async function applyReadChoice(
    choice: "session" | "project" | "global",
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedReadPaths.includes(filePath)) sessionAllowedReadPaths.push(filePath);
    if (choice === "project") addReadPathToConfig(projectPath, filePath);
    if (choice === "global") addReadPathToConfig(globalPath, filePath);
    await reinitializeSandbox(cwd);
  }

  async function applyWriteChoice(
    choice: "session" | "project" | "global",
    filePath: string,
    cwd: string,
  ): Promise<void> {
    const { globalPath, projectPath } = getConfigPaths(cwd);
    if (!sessionAllowedWritePaths.includes(filePath)) sessionAllowedWritePaths.push(filePath);
    if (choice === "project") addWritePathToConfig(projectPath, filePath);
    if (choice === "global") addWritePathToConfig(globalPath, filePath);
    await reinitializeSandbox(cwd);
  }

  // ── Bash tool — with write-block detection and retry ───────────────────────

  const z = pi.zod;
  pi.registerTool({
    name: "bash",
    label: "bash (sandboxed)",
    description:
      "Run a shell command. When the sandbox is enabled the command runs inside an OS-level sandbox (bubblewrap) restricting filesystem writes and network per the sandbox config.",
    parameters: z.object({
      command: z.string().describe("The shell command to run"),
      timeout: z.number().optional().describe("Timeout in seconds"),
      cwd: z.string().optional().describe("Working directory (defaults to session cwd)"),
    }),
    async execute(_id, params, signal, onUpdate, ctx) {
      const cwd = params.cwd ?? ctx.cwd;
      const runBash = async () => {
        const run = await runSandboxedShell(params.command, cwd, bashShellPath(), {
          signal,
          timeout: params.timeout,
          wrap: sandboxEnabled && sandboxInitialized,
        });
        return toToolResult(run);
      };

      let result: AgentToolResult<unknown>;
      try {
        result = await runBash();
      } catch (e) {
        if (!(e instanceof Error)) throw e;
        if (!/Operation not permitted|Read-only file system|Permission denied/.test(e.message)) throw e;

        result = {
          content: [
            {
              type: "text",
              text: `Error: Command failed with OS-level sandbox restriction: ${e.message}`,
            },
          ],
          details: {},
        } satisfies AgentToolResult<unknown>;
      }

      // Post-execution: detect OS-level write block and offer to allow.
      if (sandboxEnabled && sandboxInitialized && ctx?.hasUI) {
        const outputText = result.content
          .filter((c) => c.type === "text")
          .map((c) => c.text)
          .join("\n");

        const blockedPath = extractBlockedWritePath(outputText);
        if (blockedPath) {
          const choice = await promptWriteBlock(ctx, blockedPath);
          if (choice !== "abort") {
            await applyWriteChoice(choice, blockedPath, ctx.cwd);

            // Check if denyWrite would still block it even after allowing.
            const config = loadConfig(ctx.cwd);
            const { projectPath, globalPath } = getConfigPaths(ctx.cwd);
            if (matchesPattern(blockedPath, config.filesystem?.denyWrite ?? [])) {
              ctx.ui.notify(
                `⚠️ "${blockedPath}" was added to allowWrite, but it is also in denyWrite and will remain blocked.\n` +
                  `Check denyWrite in:\n  ${projectPath}\n  ${globalPath}`,
                "warning",
              );
              return result;
            }

            onUpdate?.({
              content: [
                {
                  type: "text",
                  text: `\n--- Write access granted for "${blockedPath}", retrying ---\n`,
                },
              ],
              details: {},
            });
            return runBash();
          }
        }
      }

      return result;
    },
  });

  // ── user_bash — network pre-check ──────────────────────────────────────────

  pi.on("user_bash", withExtensionHandlerTimeoutBridge(timeoutBridge, async (event, ctx) => {
    if (!sandboxEnabled || !sandboxInitialized) return;

    const domains = extractDomainsFromCommand(event.command);
    const effectiveDomains = getEffectiveAllowedDomains(ctx.cwd);

    for (const domain of domains) {
      if (!domainIsAllowed(domain, effectiveDomains)) {
        const choice = await promptDomainBlock(ctx, domain);
        if (choice === "abort") {
          const output = `Blocked: "${domain}" is not in allowedDomains. Use /sandbox to review your config.`;
          return {
            result: {
              output,
              exitCode: 1,
              cancelled: false,
              truncated: false,
              ...outputStats(output),
            },
          };
        }
        await applyDomainChoice(choice, domain, ctx.cwd);
      }
    }

    const sshBlockedHost = await enforceSshGate(event.command, ctx);
    if (sshBlockedHost) {
      const output = `Blocked: SSH to "${sshBlockedHost}" was not confirmed. Use /sandbox to review.`;
      return {
        result: {
          output,
          exitCode: 1,
          cancelled: false,
          truncated: false,
          ...outputStats(output),
        },
      };
    }

    const run = await runSandboxedShell(event.command, ctx.cwd, bashShellPath(), { wrap: true });
    return {
      result: {
        output: run.output,
        exitCode: run.exitCode ?? 0,
        cancelled: false,
        truncated: false,
        ...outputStats(run.output),
      },
    };
  }));

  // ── tool_call — network pre-check for bash/hub, launch wrapping, path policy

  /**
   * Domain + ssh pre-check shared by the bash tool and hub launches: prompts
   * for domains outside allowedDomains and confirms ssh-family targets.
   * Returns a block result, or undefined when the command may proceed.
   */
  async function enforceNetworkAndSshGate(
    command: string,
    ctx: ExtensionContext,
  ): Promise<{ block: true; reason: string } | undefined> {
    const effectiveDomains = getEffectiveAllowedDomains(ctx.cwd);
    for (const domain of extractDomainsFromCommand(command)) {
      if (domainIsAllowed(domain, effectiveDomains)) continue;
      const choice = await promptDomainBlock(ctx, domain);
      if (choice === "abort") {
        return {
          block: true,
          reason: `Network access to "${domain}" is blocked (not in allowedDomains).`,
        };
      }
      await applyDomainChoice(choice, domain, ctx.cwd);
    }
    const sshBlockedHost = await enforceSshGate(command, ctx);
    if (sshBlockedHost) {
      return {
        block: true,
        reason: `Sandbox: SSH to "${sshBlockedHost}" requires confirmation.`,
      };
    }
    return undefined;
  }

  /**
   * Rewrite a hub op:"start" launch so the daemon broker itself spawns the
   * process inside the OS sandbox: application -> shell, args -> bwrap-wrapped
   * command. The rewritten spec passes the hub tool's own schema validation,
   * and the broker's records/logs/stop/restart keep working unchanged.
   */
  async function wrapHubLaunch(
    input: {
      application: string;
      args?: string[];
      ready?: { port?: number };
      detached?: boolean;
      persist?: boolean;
      [key: string]: unknown;
    },
    ctx: ExtensionContext,
    config: SandboxConfig,
  ): Promise<{ input: Record<string, unknown> } | { block: true; reason: string }> {
    const argv = [input.application, ...(input.args ?? [])];
    const gate = await enforceNetworkAndSshGate(argv.join(" "), ctx);
    if (gate) return gate;

    let wrapped: string;
    try {
      wrapped = await SandboxManager.wrapWithSandbox(shellQuoteJoin(argv), bashShellPath());
    } catch (err) {
      return {
        block: true,
        reason: `Sandbox: failed to wrap hub launch in the OS sandbox: ${err instanceof Error ? err.message : err}`,
      };
    }

    if (input.ready?.port !== undefined && !isUnrestrictedNetwork(config.network)) {
      ctx.ui.notify(
        `⚠️ Sandbox network isolation is on: daemon "${String(input.name)}" listens inside the sandbox namespace, ` +
          `so ready.port ${input.ready.port} will not accept host connections and readiness will time out. ` +
          `Use ready.log, or allow "*" with no deniedDomains to share the host network.`,
        "warning",
      );
    }
    if (input.detached || input.persist) {
      ctx.ui.notify(
        `⚠️ Sandboxed daemons are tied to the broker's lifetime (bubblewrap --die-with-parent): ` +
          `"${String(input.name)}" will not survive broker shutdown despite ${input.detached ? "detached" : "persist"}.`,
        "warning",
      );
    }

    return {
      input: {
        ...input,
        application: bashShellPath(),
        args: ["-c", wrapped],
      },
    };
  }

  pi.on("tool_call", withExtensionHandlerTimeoutBridge(timeoutBridge, async (event, ctx) => {
    if (!sandboxEnabled) return;

    const config = loadConfig(ctx.cwd);
    if (!config.enabled) return;

    const { projectPath, globalPath } = getConfigPaths(ctx.cwd);

    // Network pre-check for bash tool calls.
    if (sandboxInitialized && isToolCallEventType("bash", event)) {
      const gate = await enforceNetworkAndSshGate(event.input.command, ctx);
      if (gate) return gate;
    }

    // Hub launches: rewrite the daemon spec so the broker spawns it inside
    // the OS sandbox (same filesystem/network policy as bash).
    if (sandboxInitialized && isToolCallEventType("hub", event)) {
      const hubInput = event.input as {
        op?: string;
        application?: string;
        args?: string[];
      };
      if (hubInput.op === "start" && typeof hubInput.application === "string" && hubInput.application.length > 0) {
        return await wrapHubLaunch(
          {
            ...(event.input as Record<string, unknown>),
            application: hubInput.application,
            args: Array.isArray(hubInput.args) ? hubInput.args.map(String) : [],
          },
          ctx,
          config,
        );
      }
    }


    // Path policy: read tool.
    //   - If the path is already in effectiveAllowRead, allow silently.
    //   - Otherwise always prompt, regardless of denyRead.
    //   - Granting (session or permanent) adds to allowRead, which overrides denyRead.
    //   - denyRead is never a hard-block on its own — it just sets the default
    //     denied state that the prompt can override.
    if (isToolCallEventType("read", event)) {
      const filePath = canonicalizePath(event.input.path);
      const effectiveAllowRead = getEffectiveAllowRead(ctx.cwd);

      if (!matchesPattern(filePath, effectiveAllowRead)) {
        const choice = await promptReadBlock(ctx, filePath);
        if (choice === "abort") {
          return {
            block: true,
            reason: `Sandbox: read access denied for "${filePath}"`,
          };
        }
        await applyReadChoice(choice, filePath, ctx.cwd);
        // Allowed — fall through, tool runs.
        return;
      }
    }

    // Path policy: prompt for allowWrite, hard-block for denyWrite. Covers
    // write/edit plus any other tool that declares its write targets
    // (ast_edit, lsp rename_file) — see collectWriteTargets. Tools running
    // opaque code (eval, browser) cannot be path-gated here.
    const writeTargets = collectWriteTargets(
      event.toolName,
      event.input as Record<string, unknown>,
    );
    if (writeTargets.length > 0) {
      const denyWrite = config.filesystem?.denyWrite ?? [];

      for (const rawTarget of writeTargets) {
        const path = canonicalizePath(rawTarget);

        // denyWrite takes precedence and is never prompted.
        if (matchesPattern(path, denyWrite)) {
          return {
            block: true,
            reason:
              `Sandbox: write access denied for "${path}" (in denyWrite). ` +
              `To change this, edit denyWrite in:\n  ${projectPath}\n  ${globalPath}`,
          };
        }

        if (shouldPromptForWrite(path, getEffectiveAllowWrite(ctx.cwd), matchesPattern)) {
          const choice = await promptWriteBlock(ctx, path);
          if (choice === "abort") {
            return {
              block: true,
              reason: `Sandbox: write access denied for "${path}" (not in allowWrite)`,
            };
          }
          await applyWriteChoice(choice, path, ctx.cwd);
          // Allowed — continue checking remaining targets, then the tool runs.
        }
      }
    }

    // xd:// device executions: omp spawns the device's host subprocesses
    // (github -> gh CLI, browser -> Chromium) in-process while the call runs.
    // Open a launch window so the patched Bun.spawn / child_process.spawn
    // re-route them through the sandbox template; tool_result closes it.
    if (sandboxInitialized && isToolCallEventType("write", event)) {
      const writeInput = event.input as { path?: unknown };
      if (typeof writeInput.path === "string" && writeInput.path.startsWith("xd://")) {
        const device = writeInput.path.slice("xd://".length).split("/")[0];
        if (device && getEffectiveSandboxedDevices(ctx.cwd).has(device)) {
          try {
            await ensureLaunchTemplate();
          } catch (err) {
            return {
              block: true,
              reason:
                `Sandbox: failed to prepare the OS sandbox for xd://${device} launches: ` +
                `${err instanceof Error ? err.message : err}. Retry the tool call.`,
            };
          }
          launchGuard.activeCalls.set(event.toolCallId, Date.now());
        }
      }
    }
  }));

  // ── tool_result — close launch windows ──────────────────────────────────────

  pi.on("tool_result", withExtensionHandlerTimeoutBridge(timeoutBridge, async (event) => {
    launchGuard.activeCalls.delete(event.toolCallId);
  }));

  // ── session_start ───────────────────────────────────────────────────────────

  pi.on("session_start", async (_event, ctx) => {
    const noSandbox = pi.getFlag("no-sandbox") as boolean;

    if (noSandbox) {
      sandboxEnabled = false;
      ctx.ui.notify("Sandbox disabled via --no-sandbox", "warning");
      return;
    }

    const config = loadConfig(ctx.cwd);

    if (!config.enabled) {
      sandboxEnabled = false;
      ctx.ui.notify("Sandbox disabled via config", "info");
      return;
    }

    const platform = process.platform;
    if (platform !== "darwin" && platform !== "linux") {
      sandboxEnabled = false;
      ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
      return;
    }

    try {
      const configExt = config as unknown as {
        ignoreViolations?: Record<string, string[]>;
        enableWeakerNestedSandbox?: boolean;
        allowBrowserProcess?: boolean;
      };

      await SandboxManager.initialize(
        {
          network: buildRuntimeNetwork(config.network, sessionAllowedDomains),
          filesystem: config.filesystem,
          ignoreViolations: configExt.ignoreViolations,
          enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
          allowBrowserProcess: configExt.allowBrowserProcess,
          enableWeakerNetworkIsolation: true,
        },
        createNetworkAskCallback(config.network?.allowedDomains ?? []),
      );

      // Make Node's built-in fetch() honour HTTP_PROXY / HTTPS_PROXY in this
      // process and any child processes that inherit the environment.
      // NODE_USE_ENV_PROXY avoids NODE_OPTIONS allowlisting issues on older Node
      // versions while still propagating naturally to child `node` processes.
      // fetch() supports this on Node 22.21.0+ and 24.0.0+.
      const [nodeMajor, nodeMinor] = process.versions.node.split(".").map(Number);
      const supportsEnvProxy = (nodeMajor === 22 && nodeMinor >= 21) || nodeMajor >= 24;
      if (supportsEnvProxy) {
        process.env.NODE_USE_ENV_PROXY ??= "1";
      }

      sandboxEnabled = true;
      sandboxInitialized = true;
      launchTemplateGeneration++;
      launchTemplatePromise = null;
      configureLaunchGuard((message) => console.error(message));

      warnIfAllDomainsAllowed(ctx, config);

      const networkLabel = formatNetworkLabel(config.network);
      const writeCount = config.filesystem?.allowWrite?.length ?? 0;
      ctx.ui.setStatus(
        "sandbox",
        ctx.ui.theme.fg("accent", `🔒 Sandbox: ${networkLabel}, ${writeCount} write paths`),
      );
    } catch (err) {
      sandboxEnabled = false;
      ctx.ui.notify(
        `Sandbox initialization failed: ${err instanceof Error ? err.message : err}`,
        "error",
      );
    }
  });

  // ── session_shutdown ────────────────────────────────────────────────────────

  pi.on("session_shutdown", async () => {
    launchGuard.activeCalls.clear();
    if (sandboxInitialized) {
      try {
        await SandboxManager.reset();
      } catch {
        // Ignore cleanup errors
      }
    }
  });

  // ── /sandbox command ────────────────────────────────────────────────────────

  pi.registerCommand("sandbox-enable", {
    description: "Enable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (sandboxEnabled) {
        ctx.ui.notify("Sandbox is already enabled", "info");
        return;
      }

      const config = loadConfig(ctx.cwd);
      const platform = process.platform;
      if (platform !== "darwin" && platform !== "linux") {
        ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
        return;
      }

      try {
        const configExt = config as unknown as {
          ignoreViolations?: Record<string, string[]>;
          enableWeakerNestedSandbox?: boolean;
          allowBrowserProcess?: boolean;
        };

        await SandboxManager.initialize(
          {
            network: buildRuntimeNetwork(config.network, sessionAllowedDomains),
            filesystem: config.filesystem,
            ignoreViolations: configExt.ignoreViolations,
            enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
            allowBrowserProcess: configExt.allowBrowserProcess,
            enableWeakerNetworkIsolation: true,
          },
          createNetworkAskCallback(config.network?.allowedDomains ?? []),
        );

        sandboxEnabled = true;
        sandboxInitialized = true;
        launchTemplateGeneration++;
        launchTemplatePromise = null;
        configureLaunchGuard(ctx.cwd, (message) => ctx.ui.notify(message, "warning"));

        warnIfAllDomainsAllowed(ctx, config);
        configureLaunchGuard((message) => ctx.ui.notify(message, "warning"));
        const networkLabel = formatNetworkLabel(config.network);
        const writeCount = config.filesystem?.allowWrite?.length ?? 0;
        ctx.ui.setStatus(
          "sandbox",
          ctx.ui.theme.fg("accent", `🔒 Sandbox: ${networkLabel}, ${writeCount} write paths`),
        );
        ctx.ui.notify("Sandbox enabled", "info");
      } catch (err) {
        ctx.ui.notify(
          `Sandbox initialization failed: ${err instanceof Error ? err.message : err}`,
          "error",
        );
      }
    },
  });

  pi.registerCommand("sandbox-disable", {
    description: "Disable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (!sandboxEnabled) {
        ctx.ui.notify("Sandbox is already disabled", "info");
        return;
      }

      if (sandboxInitialized) {
        try {
          await SandboxManager.reset();
        } catch {
          // Ignore cleanup errors
        }
      }

      sandboxEnabled = false;
      sandboxInitialized = false;
      ctx.ui.setStatus("sandbox", "");
      ctx.ui.notify("Sandbox disabled", "info");
    },
  });

  pi.registerCommand("sandbox", {
    description: "Show sandbox configuration",
    handler: async (_args, ctx) => {
      if (!sandboxEnabled) {
        ctx.ui.notify("Sandbox is disabled", "info");
        return;
      }

      const config = loadConfig(ctx.cwd);
      const { globalPath, projectPath } = getConfigPaths(ctx.cwd);

      const lines = [
        "Sandbox Configuration",
        `  Project config: ${projectPath}`,
        `  Global config:  ${globalPath}`,
        "",
        "Network (bash + !cmd):",
        `  Allowed domains: ${config.network?.allowedDomains?.join(", ") || "(none)"}`,
        ...(isUnrestrictedNetwork(config.network)
          ? ['  ⚠️ "*" with no deniedDomains: network isolation disabled (host network shared).']
          : allowsAllDomains(config.network?.allowedDomains)
            ? ['  ⚠️ "*" allows all domains and disables per-domain prompts.']
            : []),
        `  Denied domains:  ${config.network?.deniedDomains?.join(", ") || "(none)"}`,
        ...(sessionAllowedDomains.length > 0
          ? [`  Session allowed: ${sessionAllowedDomains.join(", ")}`]
          : []),
        "",
        "Filesystem (bash + read/write/edit tools):",
        `  Deny Read:   ${config.filesystem?.denyRead?.join(", ") || "(none)"}`,
        `  Allow Read:  ${config.filesystem?.allowRead?.join(", ") || "(none)"}`,
        `  Allow Write: ${config.filesystem?.allowWrite?.join(", ") || "(none)"}`,
        `  Deny Write:  ${config.filesystem?.denyWrite?.join(", ") || "(none)"}`,
        ...(sessionAllowedReadPaths.length > 0
          ? [`  Session read:  ${sessionAllowedReadPaths.join(", ")}`]
          : []),
        ...(sessionAllowedWritePaths.length > 0
          ? [`  Session write: ${sessionAllowedWritePaths.join(", ")}`]
          : []),
        "",
        "Launches (hub op:\"start\" + xd:// devices):",
        `  Sandboxed devices: ${(config.sandboxedDevices ?? DEFAULT_SANDBOXED_DEVICES).join(", ")}`,
        "  hub start launches are rewritten to run inside the OS sandbox.",
        ...(launchGuard.activeCalls.size > 0
          ? [`  Active sandboxed device calls: ${launchGuard.activeCalls.size}`]
          : []),
        "",
        "Note: ALL reads are prompted unless the path is already in allowRead.",
        "Note: denyRead is not a hard-block — granting a prompt adds to allowRead, overriding denyRead.",
        "Note: denyWrite takes PRECEDENCE over allowWrite and is never prompted.",
        "Note: hub daemons started before the sandbox was enabled (or restarted from a pre-sandbox spec) run unsandboxed.",
        "Note: lsp/eval devices run in separate worker processes and are not launch-sandboxed.",
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
