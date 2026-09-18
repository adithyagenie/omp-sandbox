import type { SandboxRuntimeConfig } from "@carderne/sandbox-runtime";
import type { PathRuleScope, SandboxConfig } from "./config.ts";
import { existsSync, lstatSync, readlinkSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, parse, resolve, sep } from "node:path";

export function extractDomainsFromCommand(command: string): string[] {
  const domains = new Set<string>();
  for (const match of command.matchAll(/https?:\/\/[^\s"'`<>\\]+/gi)) {
    try {
      const url = new URL(match[0]);
      if (url.protocol === "http:" || url.protocol === "https:") domains.add(url.hostname);
    } catch {
      // A shell fragment that starts like a URL is not necessarily a valid URL.
    }
  }
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

function stripHeredocBodies(source: string): string {
  const kept: string[] = [];
  const pending: Array<{ delimiter: string; stripTabs: boolean }> = [];
  let active: { delimiter: string; stripTabs: boolean } | undefined;
  for (const line of source.split(/\r?\n/)) {
    if (active) {
      const candidate = active.stripTabs ? line.replace(/^\t+/, "") : line;
      if (candidate === active.delimiter) active = pending.shift();
      continue;
    }
    kept.push(line);
    for (const match of line.matchAll(/<<(?!<)(-)?\s*(?:'([^']+)'|"([^"]+)"|\\?([A-Za-z0-9_][A-Za-z0-9_.-]*))/g)) {
      pending.push({
        delimiter: match[2] ?? match[3] ?? match[4],
        stripTabs: match[1] === "-",
      });
    }
    active = pending.shift();
  }
  return kept.join("\n");
}

function shellCommandSegments(source: string): string[] {
  const segments: string[] = [];
  let current = "";
  let quote: string | null = null;
  let escaped = false;
  for (const character of stripHeredocBodies(source)) {
    if (escaped) {
      current += character;
      escaped = false;
      continue;
    }
    if (character === "\\") {
      current += character;
      escaped = true;
      continue;
    }
    if (quote) {
      current += character;
      if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'") {
      current += character;
      quote = character;
      continue;
    }
    const redirectsFileDescriptor = character === "&" && /[<>]$/.test(current);
    if (character === "\n" || character === ";" || character === "|" || (character === "&" && !redirectsFileDescriptor)) {
      if (current.trim()) segments.push(current);
      current = "";
      continue;
    }
    current += character;
  }
  if (current.trim()) segments.push(current);
  return segments;
}

function hostFromSshDestination(token: string): string | null {
  if (/[\s<>&$`(){}[\]]/.test(token) || token.startsWith("-")) return null;
  const at = token.lastIndexOf("@");
  const host = at >= 0 ? token.slice(at + 1) : token;
  return /^[A-Za-z0-9][A-Za-z0-9.\-]*$/.test(host) ? host : null;
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
  for (const match of command.matchAll(/ssh:\/\/[^\s"'`<>\\]+/gi)) {
    try {
      const url = new URL(match[0]);
      if (url.protocol === "ssh:" && url.hostname) targets.add(url.hostname);
    } catch {
      // Runtime protocol enforcement remains the security boundary.
    }
  }

  for (const segment of shellCommandSegments(command)) {
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
      for (let cursor = index + 1; cursor < tokens.length; cursor++) {
        const token = tokens[cursor];
        if (!token.includes("@")) continue;
        const host = hostFromRemoteToken(token);
        if (host) targets.add(host);
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
      const host = binary === "ssh" || binary === "sftp"
        ? hostFromSshDestination(token)
        : hostFromRemoteToken(token);
      if (!host) continue;
      targets.add(host);
      if (!scanAll) break;
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

export function allowsAllNetworkDomains(network: SandboxConfig["network"]): boolean {
  return allowsAllDomains(network?.allowedDomains) && (network?.deniedDomains?.length ?? 0) === 0;
}

export function buildRuntimeNetwork(
  network: SandboxConfig["network"],
  sessionDomains: string[],
): SandboxRuntimeConfig["network"] {
  return {
    ...network,
    allowedDomains: [...(network?.allowedDomains ?? []), ...sessionDomains],
    deniedDomains: network?.deniedDomains ?? [],
    allowAllUnixSockets: allowsAllNetworkDomains(network) || undefined,
  };
}

export function formatNetworkLabel(network: SandboxConfig["network"]): string {
  if (allowsAllNetworkDomains(network)) return "all domains (proxied)";
  if (allowsAllDomains(network?.allowedDomains)) {
    return `all domains except ${network?.deniedDomains?.length ?? 0} denied`;
  }
  return `${network?.allowedDomains?.length ?? 0} domains`;
}

export function extractBlockedWritePath(output: string): string | null {
  const match = output.match(
    /(?:\/bin\/bash|bash|sh): (?:line \d+: )?(\/[^\s:]+): (?:Operation not permitted|Read-only file system|Permission denied)/,
  );
  return match ? match[1] : null;
}

function isHomePath(filePath: string): boolean {
  return /^~(?=$|[\\/])/.test(filePath);
}

function absolutePathPreservingTraversal(filePath: string, cwd = process.cwd()): string {
  if (isHomePath(filePath)) return homedir() + filePath.slice(1);
  if (process.platform === "win32" && /^[\\/](?![\\/])/.test(filePath)) {
    return parse(resolve(cwd)).root + filePath.replace(/^[\\/]+/, "");
  }
  if (isAbsolute(filePath)) return filePath;
  if (process.platform === "win32" && /^[A-Za-z]:/.test(filePath)) {
    const cwdRoot = parse(resolve(cwd)).root;
    if (cwdRoot.slice(0, 2).toLowerCase() !== filePath.slice(0, 2).toLowerCase()) return resolve(filePath);
    filePath = filePath.slice(2);
  }
  const base = isAbsolute(cwd) ? cwd : resolve(cwd);
  return base.endsWith(sep) ? base + filePath : base + sep + filePath;
}

export function expandPath(filePath: string): string {
  return resolve(filePath.replace(/^~(?=$|[\\/])/, homedir()));
}

function splitPathComponents(filePath: string): string[] {
  return process.platform === "win32"
    ? filePath.split(/[\\/]+/)
    : filePath.split("/");
}

function canonicalizeAbsolutePath(absolute: string): string {
  const initialRoot = parse(absolute).root;
  let resolved = initialRoot;
  let pending = splitPathComponents(absolute.slice(initialRoot.length));
  let symlinkDepth = 0;
  while (pending.length > 0) {
    const component = pending.shift();
    if (!component || component === ".") continue;
    if (component === "..") {
      resolved = dirname(resolved);
      continue;
    }
    const candidate = resolved.endsWith(sep) ? resolved + component : resolved + sep + component;
    try {
      if (!lstatSync(candidate).isSymbolicLink()) {
        resolved = candidate;
        continue;
      }
      if (symlinkDepth++ >= 40) return absolute;
      const link = readlinkSync(candidate);
      const target = isAbsolute(link)
        ? link
        : dirname(candidate) + (dirname(candidate).endsWith(sep) ? "" : sep) + link;
      const targetRoot = parse(target).root;
      resolved = targetRoot;
      pending = [...splitPathComponents(target.slice(targetRoot.length)), ...pending];
    } catch {
      resolved = candidate;
    }
  }
  return resolved;
}

export function canonicalizePath(filePath: string, cwd = process.cwd()): string {
  return canonicalizeAbsolutePath(absolutePathPreservingTraversal(filePath, cwd));
}
function canonicalizePattern(pattern: string): string {
  const raw = absolutePathPreservingTraversal(pattern);
  const expanded = process.platform === "win32" ? raw.replace(/\//g, sep) : raw;
  const wildcardIndex = expanded.indexOf("*");
  if (wildcardIndex < 0) return canonicalizePath(expanded);
  const boundary = expanded.lastIndexOf(sep, wildcardIndex);
  if (boundary < 0) return expanded;
  const literalDirectory = expanded.slice(0, boundary + 1);
  const canonicalDirectory = canonicalizePath(literalDirectory);
  const suffix = expanded.slice(boundary + 1);
  return canonicalDirectory.endsWith(sep)
    ? canonicalDirectory + suffix
    : canonicalDirectory + sep + suffix;
}

function comparablePath(filePath: string, insensitive: boolean): string {
  return insensitive ? filePath.toLowerCase() : filePath;
}

function matchesResolvedPattern(filePath: string, pattern: string, insensitive = false): boolean {
  const candidatePath = comparablePath(filePath, insensitive);
  const candidatePattern = comparablePath(pattern, insensitive);
  if (candidatePattern.includes("*")) {
    const escaped = candidatePattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
    return new RegExp(`^${escaped}$`).test(candidatePath);
  }
  const separator = candidatePattern.endsWith(sep) ? "" : sep;
  return candidatePath === candidatePattern || candidatePath.startsWith(candidatePattern + separator);
}

export function matchesPattern(filePath: string, patterns: string[], exactWildcardMatchesAll = false): boolean {
  const absolute = canonicalizePath(filePath);
  return patterns.some((pattern) =>
    pattern === "*" && exactWildcardMatchesAll
      ? true
      : matchesResolvedPattern(absolute, canonicalizePattern(pattern)),
  );
}
type PathSpecificity = readonly [depth: number, literalLength: number, kind: number];

function compareSpecificity(left: PathSpecificity, right: PathSpecificity): number {
  for (let index = 0; index < left.length; index++) {
    const difference = left[index] - right[index];
    if (difference !== 0) return difference;
  }
  return 0;
}

function pathDepth(filePath: string): number {
  return splitPathComponents(filePath).filter(Boolean).length;
}

function specificityForCandidate(
  canonicalPath: string,
  candidate: string,
  insensitive: boolean,
): PathSpecificity {
  const wildcardIndex = candidate.indexOf("*");
  if (wildcardIndex >= 0) {
    const literalPrefix = candidate.slice(0, wildcardIndex);
    return [pathDepth(literalPrefix), literalPrefix.length, 2];
  }
  return [
    pathDepth(candidate),
    candidate.length,
    comparablePath(canonicalPath, insensitive) === comparablePath(candidate, insensitive) ? 3 : 1,
  ];
}

function matchSpecificity(
  canonicalPath: string,
  lexicalPath: string,
  pattern: string,
  canonicalCwd: string,
  exactWildcardMatchesAll: boolean,
  matchLexicalPath: boolean,
): PathSpecificity | null {
  if (pattern === "*" && exactWildcardMatchesAll) return [0, 0, 0];
  const resolvedPattern = absolutePathPreservingTraversal(pattern, canonicalCwd);
  const canonicalPattern = canonicalizePattern(resolvedPattern);
  const insensitiveDeny = matchLexicalPath &&
    (process.platform === "win32" || process.platform === "darwin");
  let best = matchesResolvedPattern(canonicalPath, canonicalPattern, insensitiveDeny)
    ? specificityForCandidate(canonicalPath, canonicalPattern, insensitiveDeny)
    : null;
  if (matchLexicalPath) {
    const lexicalPattern = absolutePathPreservingTraversal(resolvedPattern, canonicalCwd);
    if (matchesResolvedPattern(lexicalPath, lexicalPattern, insensitiveDeny)) {
      const lexical = specificityForCandidate(lexicalPath, lexicalPattern, insensitiveDeny);
      if (!best || compareSpecificity(lexical, best) > 0) best = lexical;
    }
  }
  return best;
}

function bestSpecificity(
  canonicalPath: string,
  lexicalPath: string,
  patterns: string[],
  canonicalCwd: string,
  exactWildcardMatchesAll: boolean,
  matchLexicalPath: boolean,
): PathSpecificity | null {
  let best: PathSpecificity | null = null;
  for (const pattern of patterns) {
    const specificity = matchSpecificity(
      canonicalPath,
      lexicalPath,
      pattern,
      canonicalCwd,
      exactWildcardMatchesAll,
      matchLexicalPath,
    );
    if (specificity && (!best || compareSpecificity(specificity, best) > 0)) best = specificity;
  }
  return best;
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
  scopes: PathRuleScope[],
  absolutePath: string,
  cwd: string,
  exactAllowWildcardMatchesAll = false,
): PolicyDecision {
  const lexicalCwd = absolutePathPreservingTraversal(cwd);
  const canonicalCwd = canonicalizePath(lexicalCwd);
  const lexicalPath = absolutePathPreservingTraversal(absolutePath, lexicalCwd);
  const canonicalPath = canonicalizePath(lexicalPath);
  for (const scope of scopes) {
    const allow = bestSpecificity(
      canonicalPath,
      lexicalPath,
      scope.allow,
      lexicalCwd,
      exactAllowWildcardMatchesAll,
      false,
    );
    const deny = bestSpecificity(canonicalPath, lexicalPath, scope.deny, lexicalCwd, false, true);
    if (!allow && !deny) continue;
    if (deny && (!allow || compareSpecificity(deny, allow) >= 0)) return "deny";
    return "allow";
  }
  const canonicalTmp = canonicalizePath("/tmp");
  const implicitlyAllowed =
    matchesResolvedPattern(canonicalPath, canonicalCwd) ||
    matchesResolvedPattern(canonicalPath, canonicalTmp);
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
