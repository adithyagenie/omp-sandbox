import type { SandboxRuntimeConfig } from "@carderne/sandbox-runtime";
import { existsSync, mkdirSync, readFileSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { getAgentDir } from "@oh-my-pi/pi-coding-agent";

export interface SshPolicy {
  allow?: string[];
  deny?: string[];
}

export interface ToolPolicyOverride {
  filesystem?: {
    denyRead?: string[];
    allowRead?: string[];
    allowWrite?: string[];
    denyWrite?: string[];
  };
  network?: { allowedDomains?: string[]; deniedDomains?: string[] };
  ssh?: SshPolicy;
}

export interface SandboxConfig extends SandboxRuntimeConfig {
  enabled?: boolean;
  sandboxedDevices?: string[];
  ssh?: SshPolicy;
  tools?: Record<string, ToolPolicyOverride>;
}

export interface GlobalConfigFile extends SandboxConfig {
  projects?: Record<string, SandboxConfig>;
}

export interface SessionAllowances {
  domains: string[];
  read: string[];
  write: string[];
  ssh: string[];
}

export interface ResolvedLists {
  allowRead: string[];
  denyRead: string[];
  allowWrite: string[];
  denyWrite: string[];
  allowedDomains: string[];
  deniedDomains: string[];
  sshAllow: string[];
  sshDeny: string[];
}

export interface MigrationState {
  migrationDone: boolean;
}

export const DEFAULT_SANDBOXED_DEVICES = ["github", "browser"];
const agentDir = getAgentDir();

export const DEFAULT_CONFIG: SandboxConfig = {
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
    denyRead: ["/Users", "/home", agentDir],
    allowRead: [".", "~/.config", "~/.local", "Library"],
    allowWrite: [".", "/tmp"],
    denyWrite: [".env", ".env.*", "*.pem", "*.key", agentDir],
  },
  sandboxedDevices: [...DEFAULT_SANDBOXED_DEVICES],
  ssh: { allow: [], deny: [] },
};

function canonicalProjectDir(filePath: string): string {
  const abs = resolve(filePath);
  try {
    return realpathSync.native(abs);
  } catch {
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

export function getGlobalConfigPath(): string {
  return join(getAgentDir(), "sandbox.json");
}

/** Union two path/domain lists, preserving order and dropping duplicates. */
export function unionPaths(a?: string[], b?: string[]): string[] {
  return [...new Set([...(a ?? []), ...(b ?? [])])];
}

function mergeToolOverride(
  base: ToolPolicyOverride | undefined,
  override: ToolPolicyOverride,
  additive: boolean,
): ToolPolicyOverride {
  const result: ToolPolicyOverride = { ...base, ...override };
  if (override.filesystem) {
    result.filesystem = { ...base?.filesystem, ...override.filesystem };
    if (additive) {
      for (const key of ["denyRead", "allowRead", "allowWrite", "denyWrite"] as const) {
        result.filesystem[key] = unionPaths(base?.filesystem?.[key], override.filesystem[key]);
      }
    }
  }
  if (override.network) {
    result.network = { ...base?.network, ...override.network };
    if (additive) {
      result.network.allowedDomains = unionPaths(base?.network?.allowedDomains, override.network.allowedDomains);
      result.network.deniedDomains = unionPaths(base?.network?.deniedDomains, override.network.deniedDomains);
    }
  }
  if (override.ssh) {
    result.ssh = { ...base?.ssh, ...override.ssh };
    if (additive) {
      result.ssh.allow = unionPaths(base?.ssh?.allow, override.ssh.allow);
      result.ssh.deny = unionPaths(base?.ssh?.deny, override.ssh.deny);
    }
  }
  return result;
}

export function deepMerge(
  base: SandboxConfig,
  overrides: Partial<SandboxConfig>,
  additive = false,
): SandboxConfig {
  const result: SandboxConfig = { ...base, ...overrides };
  if (overrides.network) {
    result.network = { ...base.network, ...overrides.network };
    if (additive) {
      result.network.allowedDomains = unionPaths(base.network?.allowedDomains, overrides.network.allowedDomains);
      result.network.deniedDomains = unionPaths(base.network?.deniedDomains, overrides.network.deniedDomains);
    }
  }
  if (overrides.filesystem) {
    result.filesystem = { ...base.filesystem, ...overrides.filesystem };
    if (additive) {
      result.filesystem.allowRead = unionPaths(base.filesystem?.allowRead, overrides.filesystem.allowRead);
      result.filesystem.denyRead = unionPaths(base.filesystem?.denyRead, overrides.filesystem.denyRead);
      result.filesystem.allowWrite = unionPaths(base.filesystem?.allowWrite, overrides.filesystem.allowWrite);
      result.filesystem.denyWrite = unionPaths(base.filesystem?.denyWrite, overrides.filesystem.denyWrite);
    }
  }
  if (overrides.ssh) {
    result.ssh = { ...base.ssh, ...overrides.ssh };
    if (additive) {
      result.ssh.allow = unionPaths(base.ssh?.allow, overrides.ssh.allow);
      result.ssh.deny = unionPaths(base.ssh?.deny, overrides.ssh.deny);
    }
  }
  if (overrides.sandboxedDevices !== undefined) {
    result.sandboxedDevices = additive
      ? unionPaths(base.sandboxedDevices, overrides.sandboxedDevices)
      : overrides.sandboxedDevices;
  }
  if (overrides.tools) {
    result.tools = { ...base.tools };
    for (const [tool, policy] of Object.entries(overrides.tools)) {
      result.tools[tool] = mergeToolOverride(base.tools?.[tool], policy, additive);
    }
  }
  return result;
}

export function readOrEmptyConfig(configPath = getGlobalConfigPath()): GlobalConfigFile {
  if (!existsSync(configPath)) return {};
  try {
    return JSON.parse(readFileSync(configPath, "utf-8")) as GlobalConfigFile;
  } catch {
    return {};
  }
}

export function writeConfigFile(config: GlobalConfigFile, configPath = getGlobalConfigPath()): void {
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
}

const migrationNotices: string[] = [];
const moduleMigrationState: MigrationState = { migrationDone: false };

function migrateLegacyConfig(cwd: string, state: MigrationState): void {
  if (state.migrationDone) return;
  state.migrationDone = true;
  const legacyPath = join(cwd, ".omp", "sandbox.json");
  if (!existsSync(legacyPath)) return;
  try {
    const legacy = JSON.parse(readFileSync(legacyPath, "utf-8")) as SandboxConfig;
    const file = readOrEmptyConfig();
    const key = canonicalProjectDir(cwd);
    file.projects ??= {};
    file.projects[key] = deepMerge(file.projects[key] ?? {}, legacy, true);
    writeConfigFile(file);
    try {
      unlinkSync(legacyPath);
      migrationNotices.push(`Migrated ${legacyPath} to projects[${JSON.stringify(key)}] in ${getGlobalConfigPath()}.`);
    } catch (error) {
      console.error(`Warning: Could not delete migrated config ${legacyPath}: ${error}`);
    }
  } catch (error) {
    console.error(`Warning: Could not migrate ${legacyPath}: ${error}`);
  }
}

export function takeMigrationNotices(): string[] {
  return migrationNotices.splice(0);
}

export function loadConfig(
  cwd: string,
  migrationState: MigrationState = moduleMigrationState,
): { config: SandboxConfig; globalSection: SandboxConfig; projectSection: SandboxConfig } {
  migrateLegacyConfig(cwd, migrationState);
  const path = getGlobalConfigPath();
  let file: GlobalConfigFile = {};
  if (existsSync(path)) {
    try {
      file = JSON.parse(readFileSync(path, "utf-8")) as GlobalConfigFile;
    } catch (error) {
      console.error(`Warning: Could not parse ${path}: ${error}`);
    }
  }
  const { projects: _projects, ...globalSection } = file;
  const projectSection = file.projects?.[canonicalProjectDir(cwd)] ?? {};
  const config = deepMerge(deepMerge(DEFAULT_CONFIG, globalSection), projectSection, true);
  return { config, globalSection, projectSection };
}

function updateScopedConfig(
  scope: "project" | "global",
  cwd: string,
  update: (section: SandboxConfig) => void,
): void {
  const file = readOrEmptyConfig();
  if (scope === "global") {
    update(file);
  } else {
    const key = canonicalProjectDir(cwd);
    file.projects ??= {};
    file.projects[key] ??= {};
    update(file.projects[key]);
  }
  writeConfigFile(file);
}

export function addDomainToConfig(scope: "project" | "global", cwd: string, domain: string): void {
  updateScopedConfig(scope, cwd, (config) => {
    const existing = config.network?.allowedDomains ?? [];
    if (!existing.includes(domain)) config.network = { ...config.network, allowedDomains: [...existing, domain] };
  });
}

export function addReadPathToConfig(scope: "project" | "global", cwd: string, path: string): void {
  updateScopedConfig(scope, cwd, (config) => {
    const existing = config.filesystem?.allowRead ?? [];
    if (!existing.includes(path)) config.filesystem = { ...config.filesystem, allowRead: [...existing, path] };
  });
}

export function addWritePathToConfig(scope: "project" | "global", cwd: string, path: string): void {
  updateScopedConfig(scope, cwd, (config) => {
    const existing = config.filesystem?.allowWrite ?? [];
    if (!existing.includes(path)) config.filesystem = { ...config.filesystem, allowWrite: [...existing, path] };
  });
}

export function addSshHostToConfig(scope: "project" | "global", cwd: string, host: string): void {
  updateScopedConfig(scope, cwd, (config) => {
    const existing = config.ssh?.allow ?? [];
    if (!existing.includes(host)) config.ssh = { ...config.ssh, allow: [...existing, host] };
  });
}

function allSections(
  raw: { globalSection: SandboxConfig; projectSection: SandboxConfig },
  tool: string | null,
): Array<SandboxConfig | ToolPolicyOverride | undefined> {
  return [
    DEFAULT_CONFIG,
    raw.globalSection,
    tool ? raw.globalSection.tools?.[tool] : undefined,
    raw.projectSection,
    tool ? raw.projectSection.tools?.[tool] : undefined,
  ];
}

export function unionListsForTool(
  raw: { globalSection: SandboxConfig; projectSection: SandboxConfig },
  tool: string | null,
  session: SessionAllowances,
): ResolvedLists {
  const result: ResolvedLists = {
    allowRead: [...session.read], denyRead: [], allowWrite: [...session.write], denyWrite: [],
    allowedDomains: [...session.domains], deniedDomains: [], sshAllow: [...session.ssh], sshDeny: [],
  };
  for (const section of allSections(raw, tool)) {
    result.allowRead = unionPaths(result.allowRead, section?.filesystem?.allowRead);
    result.denyRead = unionPaths(result.denyRead, section?.filesystem?.denyRead);
    result.allowWrite = unionPaths(result.allowWrite, section?.filesystem?.allowWrite);
    result.denyWrite = unionPaths(result.denyWrite, section?.filesystem?.denyWrite);
    result.allowedDomains = unionPaths(result.allowedDomains, section?.network?.allowedDomains);
    result.deniedDomains = unionPaths(result.deniedDomains, section?.network?.deniedDomains);
    result.sshAllow = unionPaths(result.sshAllow, section?.ssh?.allow);
    result.sshDeny = unionPaths(result.sshDeny, section?.ssh?.deny);
  }
  return result;
}

type RuleLayer = { list: string[]; effect: "allow" | "deny" };

export function ruleLayersForTool(
  raw: { globalSection: SandboxConfig; projectSection: SandboxConfig },
  tool: string | null,
  session: SessionAllowances,
): { read: RuleLayer[]; write: RuleLayer[]; domains: RuleLayer[]; ssh: RuleLayer[] } {
  const globalTool = tool ? raw.globalSection.tools?.[tool] : undefined;
  const projectTool = tool ? raw.projectSection.tools?.[tool] : undefined;
  const build = (
    sessionList: string[],
    allow: (section: SandboxConfig | ToolPolicyOverride | undefined) => string[] | undefined,
    deny: (section: SandboxConfig | ToolPolicyOverride | undefined) => string[] | undefined,
  ): RuleLayer[] => [
    { list: sessionList, effect: "allow" },
    { list: allow(projectTool) ?? [], effect: "allow" },
    { list: deny(projectTool) ?? [], effect: "deny" },
    { list: allow(raw.projectSection) ?? [], effect: "allow" },
    { list: deny(raw.projectSection) ?? [], effect: "deny" },
    { list: allow(globalTool) ?? [], effect: "allow" },
    { list: deny(globalTool) ?? [], effect: "deny" },
    { list: unionPaths(deny(DEFAULT_CONFIG), deny(raw.globalSection)), effect: "deny" },
    { list: unionPaths(allow(DEFAULT_CONFIG), allow(raw.globalSection)), effect: "allow" },
  ];
  return {
    read: build(session.read, (s) => s?.filesystem?.allowRead, (s) => s?.filesystem?.denyRead),
    write: build(session.write, (s) => s?.filesystem?.allowWrite, (s) => s?.filesystem?.denyWrite),
    domains: build(session.domains, (s) => s?.network?.allowedDomains, (s) => s?.network?.deniedDomains),
    ssh: build(session.ssh, (s) => s?.ssh?.allow, (s) => s?.ssh?.deny),
  };
}
