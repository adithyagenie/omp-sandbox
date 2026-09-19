import type { ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { Key, matchesKey, truncateToWidth } from "@oh-my-pi/pi-tui";
import type { SandboxConfig, SessionAllowances } from "./config.ts";
import { getGlobalConfigPath } from "./config.ts";
import { canonicalizePath, allowsAllDomains, formatNetworkLabel } from "./policy.ts";

export type PermissionChoice = "abort" | "session" | "project" | "global";

export interface PromptOption {
  label: string;
  key: string;
  action: PermissionChoice;
  confirm?: boolean;
  hint?: string;
}

export interface PermissionRequestDetails {
  agent?: string;
  tool: string;
  request: string;
  reason: string;
}

interface PermissionGrantDetails {
  sessionKey: keyof SessionAllowances;
  configPath: string;
  value: string;
}

interface PermissionPromptDetails extends PermissionRequestDetails {
  grant: PermissionGrantDetails;
}

export const PERMISSION_OPTIONS: PromptOption[] = [
  { label: "Allow for this session only", key: "s", action: "session" },
  { label: "Abort (keep blocked)", key: "esc", action: "abort" },
  { label: "Allow for this project", key: "P", action: "project", confirm: true },
  { label: "Allow for all projects", key: "A", action: "global", confirm: true },
];

export interface PromptSharedState {
  mainUi: ExtensionContext["ui"] | null;
  promptQueue: Promise<void>;
}

const SUBAGENT_CONTEXT = Symbol("pi-sandbox-omp.subagentContext");
type RoutedContext = ExtensionContext & { [SUBAGENT_CONTEXT]?: true };

export async function routePrompt<T>(
  ctx: ExtensionContext,
  shared: PromptSharedState,
  run: (routed: ExtensionContext) => Promise<T>,
): Promise<T | "abort-unavailable"> {
  let routed: RoutedContext;
  if (ctx.hasUI) {
    routed = ctx;
  } else if (shared.mainUi) {
    routed = { ...ctx, ui: shared.mainUi, hasUI: true, [SUBAGENT_CONTEXT]: true };
  } else {
    return "abort-unavailable";
  }

  const previous = shared.promptQueue.catch(() => {});
  const gate = Promise.withResolvers<void>();
  shared.promptQueue = previous.then(() => gate.promise);
  await previous;
  try {
    return await run(routed);
  } finally {
    gate.resolve();
  }
}

export async function showPermissionPrompt(
  ctx: ExtensionContext,
  title: string,
  details?: PermissionPromptDetails,
  options: PromptOption[] = PERMISSION_OPTIONS,
): Promise<PermissionChoice> {
  if (!ctx.hasUI) return "abort";
  const isSubagent = (ctx as RoutedContext)[SUBAGENT_CONTEXT] === true;
  const routedTitle = isSubagent ? `[subagent] ${title}` : title;
  const globalPath = getGlobalConfigPath();
  const projectKey = canonicalizePath(ctx.cwd);
  const displayedOptions = options.map((option) => {
    if (!details) return option;
    const value = JSON.stringify(details.grant.value);
    if (option.action === "session") {
      return { ...option, hint: `→ add ${value} to session.${details.grant.sessionKey}` };
    }
    if (option.action === "project") {
      return {
        ...option,
        hint: `→ add ${value} to projects[${JSON.stringify(projectKey)}].${details.grant.configPath} in ${globalPath}`,
      };
    }
    if (option.action === "global") {
      return { ...option, hint: `→ add ${value} to ${details.grant.configPath} in ${globalPath}` };
    }
    return { ...option, hint: "→ no policy change" };
  });

  const result = await ctx.ui.custom<PermissionChoice>((tui, theme, _keyboard, done) => {
    let selectedIndex = 0;
    let pendingAction: PermissionChoice | null = null;
    return {
      render(width: number): string[] {
        const lines = [truncateToWidth(theme.fg("warning", routedTitle), width)];
        if (details) {
          if (details.agent) lines.push(truncateToWidth(`Agent: ${details.agent}`, width));
          lines.push(
            truncateToWidth(`Tool: ${details.tool}`, width),
            truncateToWidth(`Request: ${details.request}`, width),
            truncateToWidth(`Why blocked: ${details.reason}`, width),
          );
        }
        lines.push("");
        for (let index = 0; index < displayedOptions.length; index++) {
          const option = displayedOptions[index];
          const prefix = index === selectedIndex ? " → " : "   ";
          const keyHint = theme.fg("accent", `[${option.key}]`);
          let label = option.label;
          if (option.hint) label += `  ${theme.fg("dim", option.hint)}`;
          if (pendingAction === option.action) label += `  ${theme.fg("warning", "→ press Enter to confirm")}`;
          lines.push(truncateToWidth(`${prefix}${keyHint} ${label}`, width));
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
          done("abort");
          return;
        }
        if (matchesKey(data, Key.enter)) {
          done(pendingAction ?? displayedOptions[selectedIndex]?.action ?? "abort");
          return;
        }
        if (matchesKey(data, Key.up) || matchesKey(data, Key.down)) {
          const delta = matchesKey(data, Key.up) ? -1 : 1;
          selectedIndex = Math.max(0, Math.min(displayedOptions.length - 1, selectedIndex + delta));
          pendingAction = null;
          tui.requestRender();
          return;
        }
        for (let index = 0; index < displayedOptions.length; index++) {
          const option = displayedOptions[index];
          if (data === option.key) {
            done(option.action);
            return;
          }
          if (data.toLowerCase() === option.key.toLowerCase()) {
            if (option.confirm) {
              pendingAction = option.action;
              selectedIndex = index;
              tui.requestRender();
            } else {
              done(option.action);
            }
            return;
          }
        }
      },
      invalidate(): void {},
    };
  });
  return result ?? "abort";
}

export function promptDomainBlock(
  ctx: ExtensionContext,
  domain: string,
  details: PermissionRequestDetails,
): Promise<PermissionChoice> {
  return showPermissionPrompt(ctx, `🌐 Network blocked: "${domain}"`, {
    ...details,
    grant: { sessionKey: "domains", configPath: "network.allowedDomains", value: domain },
  });
}

export function promptReadBlock(
  ctx: ExtensionContext,
  path: string,
  details: PermissionRequestDetails,
): Promise<PermissionChoice> {
  return showPermissionPrompt(ctx, `📖 Read blocked: "${path}"`, {
    ...details,
    grant: { sessionKey: "read", configPath: "filesystem.allowRead", value: path },
  });
}

export function promptWriteBlock(
  ctx: ExtensionContext,
  path: string,
  details: PermissionRequestDetails,
): Promise<PermissionChoice> {
  return showPermissionPrompt(ctx, `📝 Write blocked: "${path}"`, {
    ...details,
    grant: { sessionKey: "write", configPath: "filesystem.allowWrite", value: path },
  });
}

export function promptSshBlock(
  ctx: ExtensionContext,
  host: string,
  details: PermissionRequestDetails,
): Promise<PermissionChoice> {
  return showPermissionPrompt(ctx, `🔐 SSH blocked: "${host}"`, {
    ...details,
    grant: { sessionKey: "ssh", configPath: "ssh.allow", value: host },
  });
}

export function warnIfAllDomainsAllowed(ctx: ExtensionContext, config: SandboxConfig): void {
  if (!allowsAllDomains(config.network?.allowedDomains)) return;
  const deniedCount = config.network?.deniedDomains?.length ?? 0;
  const message =
    deniedCount === 0
      ? '⚠️ Network sandbox allows all domains through its filtering proxy because allowedDomains contains "*". Unix socket access is also enabled.'
      : `⚠️ Network sandbox allows every domain not matched by ${deniedCount} deniedDomains rule${deniedCount === 1 ? "" : "s"}.`;
  ctx.ui.notify(message, "warning");
}

export function formatSandboxStatus(config: SandboxConfig): string {
  const writeCount = config.filesystem?.allowWrite?.length ?? 0;
  return `🔒 Sandbox: ${formatNetworkLabel(config.network)}, ${writeCount} write paths`;
}

export interface ConfigurationExtras {
  session: SessionAllowances;
  projectKeys: string[];
}

function list(values: string[] | undefined): string {
  return values?.length ? values.join(", ") : "(none)";
}

export function formatSandboxConfiguration(config: SandboxConfig, extras: ConfigurationExtras): string {
  const lines = [
    `Sandbox: ${config.enabled === false ? "disabled" : "enabled"}`,
    `config: ${getGlobalConfigPath()}`,
    `projects: ${list(extras.projectKeys)}`,
    `network allow: ${list(config.network?.allowedDomains)}`,
    `network deny: ${list(config.network?.deniedDomains)}`,
    `read allow: ${list(config.filesystem?.allowRead)}`,
    `read deny: ${list(config.filesystem?.denyRead)}`,
    `write allow: ${list(config.filesystem?.allowWrite)}`,
    `write deny: ${list(config.filesystem?.denyWrite)}`,
    `ssh allow: ${list(config.ssh?.allow)}`,
    `ssh deny: ${list(config.ssh?.deny)}`,
    `session domains: ${list(extras.session.domains)}`,
    `session read: ${list(extras.session.read)}`,
    `session write: ${list(extras.session.write)}`,
    `session ssh: ${list(extras.session.ssh)}`,
    `sandboxed devices: ${list(config.sandboxedDevices)}`,
    "eval py kernel: sandboxed via launch guard; eval js kernel: NOT sandboxed (omp worker IPC)",
    'hub restart is blocked for daemons not started sandboxed in this process',
  ];
  const toolEntries = Object.entries(config.tools ?? {});
  lines.push("tools:");
  if (toolEntries.length === 0) lines.push("  (none)");
  for (const [tool, override] of toolEntries) lines.push(`  ${tool}: ${JSON.stringify(override)}`);
  if (allowsAllDomains(config.network?.allowedDomains)) lines.push("warning: sandboxed subprocesses can reach all non-denied domains through the filtering proxy");
  return lines.join("\n");
}
