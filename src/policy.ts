import type { SandboxRuntimeConfig } from "@carderne/sandbox-runtime";
import { existsSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, resolve } from "node:path";

export function extractDomainsFromCommand(command: string): string[] {
  const urlRegex = /https?:\/\/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
  const domains = new Set<string>();
  let match: RegExpExecArray | null;
  while ((match = urlRegex.exec(command)) !== null) domains.add(match[1]);
  return [...domains];
}

const SSH_BINARIES: Record<string, true> = {
  ssh: true, scp: true, sftp: true, rsync: true, git: true,
};

const SSH_OPT_TAKES_ARG: Record<string, Record<string, true>> = {
  ssh: { b: true, c: true, F: true, i: true, J: true, L: true, l: true, m: true, o: true, O: true, p: true, R: true, w: true, D: true, W: true, S: true, I: true, E: true, B: true, Q: true },
  scp: { i: true, l: true, o: true, P: true, F: true, c: true, J: true, S: true },
  sftp: { i: true, b: true, c: true, F: true, J: true, l: true, o: true, P: true, S: true },
  rsync: { e: true },
};

const SHELL_WRAPPERS: Record<string, true> = {
  sudo: true, doas: true, nice: true, time: true, nohup: true, env: true, command: true,
  exec: true, xargs: true, strace: true, ltrace: true,
};

export function shellTokens(source: string): string[] {
  const out: string[] = [];
  let current = "";
  let quote: string | null = null;
  for (const character of source) {
    if (quote) {
      if (character === quote) quote = null;
      else current += character;
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (/\s/.test(character)) {
      if (current) {
        out.push(current);
        current = "";
      }
    } else {
      current += character;
    }
  }
  if (current) out.push(current);
  return out;
}

export function isHostLike(host: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}$/.test(host) || /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

export function hostFromRemoteToken(token: string): string | null {
  if (/^[A-Za-z]:[\\/]/.test(token) || token.startsWith("/")) return null;
  const hadAt = token.includes("@");
  const at = token.lastIndexOf("@");
  const remote = at >= 0 ? token.slice(at + 1) : token;
  const daemon = remote.match(/^([A-Za-z0-9][A-Za-z0-9.\-]*)::/);
  if (daemon) return daemon[1];
  const colon = remote.indexOf(":");
  if (colon > 0) {
    const host = remote.slice(0, colon);
    return /^[A-Za-z0-9][A-Za-z0-9.\-]*$/.test(host) ? host : null;
  }
  return hadAt && isHostLike(remote) ? remote : null;
}

export function extractSshTargets(command: string): string[] {
  const targets = new Set<string>();
  const sshUrl = /ssh:\/\/(?:[^@\s/]+@)?([A-Za-z0-9][A-Za-z0-9.\-]+)/g;
  let match: RegExpExecArray | null;
  while ((match = sshUrl.exec(command)) !== null) targets.add(match[1]);

  for (const segment of command.split(/[\n;|&]+/)) {
    const tokens = shellTokens(segment);
    if (tokens.length === 0) continue;
    let index = 0;
    while (index < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[index])) index++;
    while (index < tokens.length && SHELL_WRAPPERS[tokens[index]]) {
      index++;
      while (index < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[index])) index++;
    }
    if (index >= tokens.length) continue;
    const binary = basename(tokens[index]);
    if (!SSH_BINARIES[binary]) continue;

    if (binary === "git") {
      if (tokens[index + 1] !== "clone") continue;
      for (let cursor = index + 2; cursor < tokens.length; cursor++) {
        const token = tokens[cursor];
        if (token.startsWith("-")) continue;
        if (!token.includes("://")) {
          const host = hostFromRemoteToken(token);
          if (host) targets.add(host);
        }
        break;
      }
      continue;
    }

    const argumentOptions = SSH_OPT_TAKES_ARG[binary];
    const scanAll = binary === "scp" || binary === "rsync";
    for (let cursor = index + 1; cursor < tokens.length; cursor++) {
      const token = tokens[cursor];
      if (token.startsWith("--")) continue;
      if (/^-[A-Za-z]/.test(token)) {
        const last = token[token.length - 1];
        if (argumentOptions?.[last] && !token.includes("=") && cursor + 1 < tokens.length) cursor++;
        continue;
      }
      const host = hostFromRemoteToken(token);
      if (host) {
        targets.add(host);
        if (!scanAll) break;
      } else if (!scanAll) {
        const at = token.lastIndexOf("@");
        targets.add(at >= 0 ? token.slice(at + 1) : token);
        break;
      }
    }
  }
  return [...targets];
}

export function domainMatchesPattern(domain: string, pattern: string): boolean {
  if (pattern === "*") return true;
  if (pattern.startsWith("*.")) {
    const base = pattern.slice(2);
    return domain === base || domain.endsWith("." + base);
  }
  return domain === pattern;
}

export function allowsAllDomains(allowedDomains: string[] | undefined): boolean {
  return allowedDomains?.includes("*") ?? false;
}

export function domainIsAllowed(domain: string, allowedDomains: string[]): boolean {
  return allowedDomains.some((pattern) => domainMatchesPattern(domain, pattern));
}

export function isUnrestrictedNetwork(network: SandboxConfig["network"]): boolean {
  return allowsAllDomains(network?.allowedDomains) && (network?.deniedDomains?.length ?? 0) === 0;
}

export function buildRuntimeNetwork(
  network: SandboxConfig["network"],
  sessionDomains: string[],
): SandboxRuntimeConfig["network"] {
  if (isUnrestrictedNetwork(network)) {
    return {
      ...network,
      allowedDomains: undefined,
      deniedDomains: [],
      allowAllUnixSockets: true,
    } as unknown as SandboxRuntimeConfig["network"];
  }
  return {
    ...network,
    allowedDomains: [...(network?.allowedDomains ?? []), ...sessionDomains],
    deniedDomains: network?.deniedDomains ?? [],
  };
}

export function formatNetworkLabel(network: SandboxConfig["network"]): string {
  if (isUnrestrictedNetwork(network)) return "unrestricted (host network)";
  if (allowsAllDomains(network?.allowedDomains)) return "all domains";
  return `${network?.allowedDomains?.length ?? 0} domains`;
}

export function extractBlockedWritePath(output: string): string | null {
  const match = output.match(
    /(?:\/bin\/bash|bash|sh): (?:line \d+: )?(\/[^\s:]+): (?:Operation not permitted|Read-only file system|Permission denied)/,
  );
  return match ? match[1] : null;
}

export function expandPath(filePath: string): string {
  return resolve(filePath.replace(/^~(?=$|\/)/, homedir()));
}

export function canonicalizePath(filePath: string): string {
  const absolute = expandPath(filePath);
  try {
    return realpathSync.native(absolute);
  } catch {
    const tail: string[] = [];
    let probe = absolute;
    while (!existsSync(probe)) {
      const parent = dirname(probe);
      if (parent === probe) return absolute;
      tail.unshift(basename(probe));
      probe = parent;
    }
    try {
      return resolve(realpathSync.native(probe), ...tail);
    } catch {
      return absolute;
    }
  }
}

export function matchesPattern(filePath: string, patterns: string[], exactWildcardMatchesAll = false): boolean {
  const absolute = canonicalizePath(filePath);
  return patterns.some((pattern) => {
    if (pattern === "*" && exactWildcardMatchesAll) return true;
    const candidate = pattern.includes("*") ? expandPath(pattern) : canonicalizePath(pattern);
    if (pattern.includes("*")) {
      const escaped = candidate.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
      return new RegExp(`^${escaped}$`).test(absolute);
    }
    const separator = candidate.endsWith("/") ? "" : "/";
    return absolute === candidate || absolute.startsWith(candidate + separator);
  });
}

export type ClassifiedPath =
  | { kind: "fs"; path: string }
  | { kind: "ssh"; host: string }
  | { kind: "url"; domain: string }
  | { kind: "internal" };

export function classifyToolPath(raw: string): ClassifiedPath {
  if (raw.includes("://")) {
    try {
      const url = new URL(raw);
      if (url.protocol === "ssh:") return { kind: "ssh", host: url.hostname };
      if (url.protocol === "http:" || url.protocol === "https:") return { kind: "url", domain: url.hostname };
      return { kind: "internal" };
    } catch {
      return { kind: "internal" };
    }
  }

  let path = raw.replace(/\?.*$/, "");
  for (let index = 0; index < 5 && !existsSync(path) && path.includes(":"); index++) {
    const stripped = path.replace(/:[A-Za-z0-9,+._-]+$/, "");
    if (stripped === path) break;
    path = stripped;
  }
  return { kind: "fs", path };
}

export function splitPathList(raw: string): string[] {
  return raw.split(";").map((path) => path.trim()).filter(Boolean);
}

function stringTargets(...values: unknown[]): string[] {
  return values.flatMap((value) => typeof value === "string" && value.length > 0 ? [value] : []);
}

export function collectReadTargets(toolName: string, input: Record<string, unknown>): string[] {
  switch (toolName) {
    case "read": return stringTargets(input.path);
    case "glob": return stringTargets(input.path ?? ".");
    case "grep": return splitPathList(typeof input.path === "string" ? input.path : ".");
    case "ast_grep": return stringTargets(input.path, ...(Array.isArray(input.paths) ? input.paths : []));
    default: return [];
  }
}

export function collectWriteTargets(toolName: string, input: Record<string, unknown>): string[] {
  switch (toolName) {
    case "write":
      return stringTargets(input.path);
    case "edit": {
      const declared = stringTargets(...(Array.isArray(input.paths) ? input.paths : []), input.path);
      if (declared.length > 0) return declared;
      const targets: string[] = [];
      for (const value of Object.values(input)) {
        if (typeof value !== "string") continue;
        for (const match of value.matchAll(/^\[([^\]\n]+?)#[0-9A-Za-z]{2,}\]/gm)) targets.push(match[1]);
      }
      return targets;
    }
    case "ast_edit":
      return stringTargets(input.path, ...(Array.isArray(input.paths) ? input.paths : []));
    case "lsp":
      return input.action === "rename_file" ? stringTargets(input.file, input.new_name) : [];
    default:
      return [];
  }
}

export type PolicyDecision = "allow" | "deny" | "prompt";
export type PolicyRuleLayer = { list: string[]; effect: "allow" | "deny" };

export function decidePath(
  layers: PolicyRuleLayer[],
  absolutePath: string,
  cwd: string,
  exactWildcardMatchesAll = false,
): PolicyDecision {
  const canonicalCwd = canonicalizePath(cwd);
  const canonicalPath = canonicalizePath(absolutePath);
  for (const layer of layers) {
    const wildcardMatchesAll = exactWildcardMatchesAll && layer.effect === "allow";
    const patterns = layer.list.map((pattern) =>
      pattern === "*" && wildcardMatchesAll
        ? pattern
        : pattern.startsWith("~") || isAbsolute(pattern)
          ? pattern
          : resolve(canonicalCwd, pattern),
    );
    if (matchesPattern(canonicalPath, patterns, wildcardMatchesAll)) return layer.effect;
  }
  const canonicalTmp = canonicalizePath("/tmp");
  const implicitlyAllowed =
    canonicalPath === canonicalCwd ||
    canonicalPath.startsWith(canonicalCwd + "/") ||
    canonicalPath === canonicalTmp ||
    canonicalPath.startsWith(canonicalTmp + "/");
  return implicitlyAllowed ? "allow" : "prompt";
}

export function decideHost(layers: PolicyRuleLayer[], host: string): PolicyDecision {
  for (const layer of layers) {
    if (layer.list.some((pattern) => domainMatchesPattern(host, pattern))) return layer.effect;
  }
  return "prompt";
}

export function shellQuoteArg(arg: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'\\''`)}'`;
}

export function shellQuoteJoin(argv: string[]): string {
  return argv.map(shellQuoteArg).join(" ");
}
