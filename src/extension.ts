import type { AgentToolResult, ExtensionAPI, ExtensionContext } from "@oh-my-pi/pi-coding-agent";
import { SandboxManager, type SandboxRuntimeConfig } from "@carderne/sandbox-runtime";
import { randomBytes } from "node:crypto";
import {
  addDomainToConfig,
  addReadPathToConfig,
  addSshHostToConfig,
  addWritePathToConfig,
  DEFAULT_SANDBOXED_DEVICES,
  defaultDenyReadFilesystem,
  loadConfig,
  readOrEmptyConfig,
  ruleLayersForTool,
  takeMigrationNotices,
  unionListsForTool,
  type LoadedConfig,
  type SandboxConfig,
  type SessionAllowances,
} from "./config.ts";
import {
  canonicalizePath,
  classifyToolPath,
  collectReadTargets,
  collectWriteTargets,
  decideHost,
  decidePath,
  extractBlockedWritePath,
  extractFileMentionPaths,
  extractDomainsFromCommand,
  extractSshTargets,
  allowsAllNetworkDomains,
  shellQuoteJoin,
} from "./policy.ts";
import {
  bashShellPath,
  cleanupAfterCommand,
  createLaunchTemplate,
  ensureSandboxTmpdir,
  getExtensionHandlerTimeoutBridge,
  sandboxShellPath,
  initializeSandboxOnce,
  outputStats,
  resetSandbox,
  runSandboxedShell,
  toToolResult,
  updateSandboxConfig,
  withExtensionHandlerTimeoutBridge,
  type LaunchTemplate,
  type RuntimeSharedState,
} from "./sandbox-runtime.ts";
import {
  getLaunchGuardState,
  installLaunchSandboxGuard,
  withLaunchWindow,
  type LaunchGuardState,
} from "./launch-guard.ts";
import {
  formatSandboxConfiguration,
  formatSandboxStatus,
  promptDomainBlock,
  promptReadBlock,
  promptSshBlock,
  promptWriteBlock,
  routePrompt,
  warnIfAllDomainsAllowed,
  type PermissionChoice,
  type PromptSharedState,
  type PermissionRequestDetails,
} from "./ui.ts";

interface WrappedDaemon {
  phase: "starting" | "running";
  cleanupToken?: string;
}

interface ActiveSshContext {
  ctx: ExtensionContext;
  tool: string;
  request: string;
  deferredHosts: Set<string>;
}

interface SharedSandboxState extends RuntimeSharedState, PromptSharedState {
  enabled: boolean;
  sessionCount: number;
  launchGuard: LaunchGuardState;
  wrappedDaemons: Map<string, WrappedDaemon>;
  sshContexts: Map<string, ActiveSshContext>;
  migrationDone: boolean;
}

const SHARED_KEY = Symbol.for("pi-sandbox-omp.shared");
interface GlobalWithSharedSandbox {
  [SHARED_KEY]?: SharedSandboxState;
}

function getSharedState(): SharedSandboxState {
  const global = globalThis as typeof globalThis & GlobalWithSharedSandbox;
  const existing = global[SHARED_KEY];
  if (existing) {
    if (existing.wrappedDaemons instanceof Set) {
      existing.wrappedDaemons = new Map([...existing.wrappedDaemons].map((name) => [name, { phase: "running" as const }]));
    } else {
      for (const [name, value] of existing.wrappedDaemons) {
        if (typeof value === "string" || value === undefined) {
          existing.wrappedDaemons.set(name, { phase: "running", cleanupToken: value });
        }
      }
    }
    return existing;
  }
  const shared: SharedSandboxState = {
    enabled: false,
    managerInitialized: false,
    initPromise: null,
    sessionCount: 0,
    session: { domains: [], read: [], write: [], ssh: [] },
    launchGuard: getLaunchGuardState(),
    sshContexts: new Map(),
    runtimeRawConfig: { globalSection: {}, projectSection: {} },
    mainUi: null,
    promptQueue: Promise.resolve(),
    wrappedDaemons: new Map(),
    migrationDone: false,
  };
  global[SHARED_KEY] = shared;
  return shared;
}

function filesystemConfig(
  raw: { globalSection: SandboxConfig; projectSection: SandboxConfig },
  tool: string | null,
  session: SessionAllowances,
): SandboxRuntimeConfig {
  const lists = unionListsForTool(raw, tool, session);
  return {
    filesystem: defaultDenyReadFilesystem({
      allowRead: lists.allowRead,
      denyRead: lists.denyRead,
      allowWrite: lists.allowWrite,
      denyWrite: lists.denyWrite,
    }),
  } as SandboxRuntimeConfig;
}

function errorResult(reason: string): AgentToolResult<unknown> {
  return { content: [{ type: "text", text: reason }], details: {} };
}

export default function sandboxExtension(pi: ExtensionAPI): void {
  ensureSandboxTmpdir();
  const shared = getSharedState();
  const timeoutBridge = getExtensionHandlerTimeoutBridge();

  pi.registerFlag("no-sandbox", {
    description: "Disable OS-level sandboxing for bash commands",
    type: "boolean",
    default: false,
  });

  function refreshMainUi(ctx: ExtensionContext): void {
    if (ctx.hasUI) shared.mainUi = ctx.ui;
  }

  function load(cwd: string): LoadedConfig {
    const loaded = loadConfig(cwd, shared);
    shared.runtimeRawConfig = {
      globalSection: loaded.globalSection,
      projectSection: loaded.projectSection,
    };
    return loaded;
  }

  async function updateAfterGrant(cwd: string): Promise<void> {
    const loaded = load(cwd);
    if (shared.managerInitialized) await updateSandboxConfig(loaded.config, shared.session);
  }

  async function askChoice(
    ctx: ExtensionContext,
    prompt: (routed: ExtensionContext) => Promise<PermissionChoice>,
  ): Promise<PermissionChoice> {
    const choice = await routePrompt(ctx, shared, prompt);
    return choice === "abort-unavailable" ? "abort" : choice;
  }

  function permissionDetails(
    ctx: ExtensionContext,
    tool: string,
    request: string,
    reason: string,
  ): PermissionRequestDetails {
    return {
      agent: ctx.hasUI ? undefined : (pi.getSessionName() ?? "unnamed subagent"),
      tool,
      request,
      reason,
    };
  }

  async function applyDomainChoice(choice: Exclude<PermissionChoice, "abort">, domain: string, cwd: string): Promise<void> {
    if (!shared.session.domains.includes(domain)) shared.session.domains.push(domain);
    if (choice === "project" || choice === "global") addDomainToConfig(choice, cwd, domain);
    await updateAfterGrant(cwd);
  }

  async function applyReadChoice(choice: Exclude<PermissionChoice, "abort">, path: string, cwd: string): Promise<void> {
    if (!shared.session.read.includes(path)) shared.session.read.push(path);
    if (choice === "project" || choice === "global") addReadPathToConfig(choice, cwd, path);
    await updateAfterGrant(cwd);
  }

  async function applyWriteChoice(choice: Exclude<PermissionChoice, "abort">, path: string, cwd: string): Promise<void> {
    if (!shared.session.write.includes(path)) shared.session.write.push(path);
    if (choice === "project" || choice === "global") addWritePathToConfig(choice, cwd, path);
    await updateAfterGrant(cwd);
  }

  async function applySshChoice(choice: Exclude<PermissionChoice, "abort">, host: string, cwd: string): Promise<void> {
    if (!shared.session.ssh.includes(host)) shared.session.ssh.push(host);
    if (choice === "project" || choice === "global") addSshHostToConfig(choice, cwd, host);
  }

  async function enforceDomainGate(
    domain: string,
    ctx: ExtensionContext,
    tool: string,
    request: string,
  ): Promise<{ block: true; reason: string } | undefined> {
    const loaded = load(ctx.cwd);
    if (allowsAllNetworkDomains(loaded.config.network)) return undefined;
    const decision = decideHost(ruleLayersForTool(loaded, tool, shared.session).domains, domain);
    if (decision === "allow") return undefined;
    if (decision === "deny" && ctx.hasUI) {
      return { block: true, reason: `Sandbox: network access to "${domain}" denied by policy.` };
    }
    const reason = decision === "deny"
      ? "A deny rule matched in the effective layered network policy."
      : "No allow rule matched in the effective layered network policy.";
    const details = permissionDetails(ctx, tool, request, reason);
    const choice = await askChoice(ctx, (routed) => promptDomainBlock(routed, domain, details));
    if (choice === "abort") return { block: true, reason: `Sandbox: network access to "${domain}" requires confirmation.` };
    await applyDomainChoice(choice, domain, ctx.cwd);
    const refreshed = load(ctx.cwd);
    if (decideHost(ruleLayersForTool(refreshed, tool, shared.session).domains, domain) !== "allow") {
      return { block: true, reason: `Sandbox: network access to "${domain}" remains denied after the grant.` };
    }
    return undefined;
  }

  async function enforceSshHostGate(
    host: string,
    ctx: ExtensionContext,
    tool: string,
    request: string,
  ): Promise<{ block: true; reason: string } | undefined> {
    const loaded = load(ctx.cwd);
    const decision = decideHost(ruleLayersForTool(loaded, tool, shared.session).ssh, host);
    if (decision === "allow") return undefined;
    if (decision === "deny" && ctx.hasUI) {
      return { block: true, reason: `Sandbox: ssh to "${host}" denied by ssh.deny.` };
    }
    const reason = decision === "deny"
      ? "A deny rule matched in the effective layered SSH policy."
      : "No SSH allow rule matched; direct SSH requires confirmation.";
    const details = permissionDetails(ctx, tool, request, reason);
    const choice = await askChoice(ctx, (routed) => promptSshBlock(routed, host, details));
    if (choice === "abort") return { block: true, reason: `Sandbox: ssh to "${host}" requires confirmation.` };
    await applySshChoice(choice, host, ctx.cwd);
    const refreshed = load(ctx.cwd);
    if (decideHost(ruleLayersForTool(refreshed, tool, shared.session).ssh, host) !== "allow") {
      return { block: true, reason: `Sandbox: ssh to "${host}" remains denied after the grant.` };
    }
    return undefined;
  }

  async function authorizeRuntimeSsh(host: string, networkContext: string | undefined): Promise<boolean> {
    if (!networkContext) {
      shared.launchGuard.note(`[pi-sandbox-omp] denied runtime SSH to ${host}: launch context is missing`);
      return false;
    }
    const active = shared.sshContexts.get(networkContext);
    if (!active) {
      shared.launchGuard.note(`[pi-sandbox-omp] denied runtime SSH to ${host}: launch context is no longer active`);
      return false;
    }
    const loaded = load(active.ctx.cwd);
    const decision = decideHost(ruleLayersForTool(loaded, active.tool, shared.session).ssh, host);
    if (decision === "allow") return true;
    if (decision === "prompt" || (decision === "deny" && !active.ctx.hasUI)) active.deferredHosts.add(host);
    return false;
  }

  async function promptDeferredSshHosts(active: ActiveSshContext): Promise<void> {
    for (const host of active.deferredHosts) {
      const block = await enforceSshHostGate(host, active.ctx, active.tool, active.request);
      if (block) continue;
      const ui = active.ctx.hasUI ? active.ctx.ui : shared.mainUi;
      ui?.notify(`SSH access to "${host}" granted. Retry the command.`, "info");
    }
  }

  async function withRuntimeSshContext<TResult>(
    ctx: ExtensionContext,
    tool: string,
    request: string,
    run: (networkContext: string) => Promise<TResult>,
  ): Promise<TResult> {
    const networkContext = randomBytes(16).toString("hex");
    const active: ActiveSshContext = { ctx, tool, request, deferredHosts: new Set() };
    shared.sshContexts.set(networkContext, active);
    try {
      return await run(networkContext);
    } finally {
      if (shared.sshContexts.get(networkContext) === active) {
        shared.sshContexts.delete(networkContext);
        await promptDeferredSshHosts(active);
      }
    }
  }

  async function enforceNetworkAndSshGate(
    command: string,
    ctx: ExtensionContext,
    tool: string,
  ): Promise<{ block: true; reason: string } | undefined> {
    const request = `${tool}: ${command}`;
    for (const domain of extractDomainsFromCommand(command)) {
      const block = await enforceDomainGate(domain, ctx, tool, request);
      if (block) return block;
    }
    for (const host of extractSshTargets(command)) {
      const block = await enforceSshHostGate(host, ctx, tool, request);
      if (block) return block;
    }
    return undefined;
  }


  function installGuard(): void {
    shared.launchGuard.bashPath = bashShellPath();
    shared.launchGuard.isEnabled = () => shared.enabled && shared.managerInitialized;
    shared.launchGuard.note = (message) => console.error(message);
    installLaunchSandboxGuard(shared.launchGuard);
  }

  const z = pi.zod;
  pi.registerTool({
    name: "bash",
    label: "bash (sandboxed)",
    description: "Run a shell command. When the sandbox is enabled the command runs inside an OS-level sandbox (bubblewrap) restricting filesystem writes and network per the sandbox config.",
    parameters: z.object({
      command: z.string().describe("The shell command to run"),
      timeout: z.number().optional().describe("Timeout in seconds"),
      cwd: z.string().optional().describe("Working directory (defaults to session cwd)"),
    }),
    async execute(_toolCallId, params, signal, onUpdate, ctx) {
      refreshMainUi(ctx);
      const cwd = params.cwd ?? ctx.cwd;
      const run = (): Promise<AgentToolResult<unknown>> =>
        withRuntimeSshContext(ctx, "bash", `bash: ${params.command}`, async (networkContext) =>
          toToolResult(await runSandboxedShell(params.command, cwd, bashShellPath(), {
            signal,
            timeout: params.timeout,
            wrap: shared.enabled && shared.managerInitialized,
            customConfig: filesystemConfig(load(cwd), "bash", shared.session),
            networkContext,
          })));
      let result: AgentToolResult<unknown>;
      try {
        result = await run();
      } catch (error) {
        if (!(error instanceof Error) || !/Operation not permitted|Read-only file system|Permission denied/.test(error.message)) throw error;
        result = errorResult(`Error: Command failed with OS-level sandbox restriction: ${error.message}`);
      }
      if (!shared.enabled || !shared.managerInitialized) return result;
      const output = result.content.filter((content) => content.type === "text").map((content) => content.text).join("\n");
      const blockedPath = extractBlockedWritePath(output);
      if (!blockedPath) return result;
      const details = permissionDetails(
        ctx,
        "bash",
        `bash: ${params.command}`,
        "The OS sandbox reported a write blocked by the effective write policy.",
      );
      const choice = await askChoice(ctx, (routed) => promptWriteBlock(routed, blockedPath, details));
      if (choice === "abort") return result;
      await applyWriteChoice(choice, blockedPath, ctx.cwd);
      const loaded = load(ctx.cwd);
      if (decidePath(ruleLayersForTool(loaded, "bash", shared.session).write, canonicalizePath(blockedPath), ctx.cwd) === "deny") {
        ctx.ui.notify(`"${blockedPath}" remains denied by a stronger write policy.`, "warning");
        return result;
      }
      onUpdate?.({ content: [{ type: "text", text: `\n--- Write access granted for "${blockedPath}", retrying ---\n` }], details: {} });
      return run();
    },
  });

  pi.registerTool({
    name: "eval",
    label: "eval (sandboxed)",
    description: "Run code in a persistent Python or JavaScript kernel with sandboxed child-process launches.",
    parameters: z.object({
      language: z.enum(["py", "js"]),
      code: z.string(),
      title: z.string().nullable().optional(),
      timeout: z.number().nullable().optional(),
      reset: z.boolean().nullable().optional(),
    }),
    async execute(_toolCallId, params, signal, onUpdate, ctx) {
      refreshMainUi(ctx);
      if (!ctx.invokeTool) return errorResult("Sandbox: native eval delegation requires omp 18.x with ExtensionContext.invokeTool.");
      if (!shared.enabled || !shared.managerInitialized) return ctx.invokeTool(params, { signal, onUpdate });
      const loaded = load(ctx.cwd);
      const request = `eval: ${JSON.stringify({ language: params.language, title: params.title })}`;
      return withRuntimeSshContext(ctx, "eval", request, async (networkContext) => {
        let launch: LaunchTemplate;
        try {
          launch = await createLaunchTemplate(shared, "eval", networkContext, loaded);
        } catch (error) {
          return errorResult(`Sandbox: failed to prepare eval sandbox: ${error instanceof Error ? error.message : error}. Retry the tool call.`);
        }
        try {
          return await withLaunchWindow(
            shared.launchGuard,
            "eval",
            launch.template,
            () => ctx.invokeTool(params, { signal, onUpdate }),
          );
        } finally {
          if (launch.cleanupToken) cleanupAfterCommand(launch.cleanupToken);
        }
      });
    },
  });

  pi.registerTool({
    name: "write",
    label: "write",
    description: "Create or overwrite a file or invoke a writable internal device.",
    parameters: z.object({
      path: z.string(),
      content: z.string(),
    }),
    async execute(_toolCallId, params, signal, onUpdate, ctx) {
      refreshMainUi(ctx);
      if (!ctx.invokeTool) return errorResult("Sandbox: native write delegation requires omp 18.x with ExtensionContext.invokeTool.");
      if (!shared.enabled || !shared.managerInitialized || !params.path.startsWith("xd://")) {
        return ctx.invokeTool(params, { signal, onUpdate });
      }
      const loaded = load(ctx.cwd);
      const device = params.path.slice(5).split("/")[0];
      const devices = new Set(loaded.config.sandboxedDevices ?? DEFAULT_SANDBOXED_DEVICES);
      if (!device || !devices.has(device)) return ctx.invokeTool(params, { signal, onUpdate });
      return withRuntimeSshContext(ctx, "write", `write device: ${params.path}`, async (networkContext) => {
        let launch: LaunchTemplate;
        try {
          launch = await createLaunchTemplate(shared, "device", networkContext, loaded);
        } catch (error) {
          return errorResult(`Sandbox: failed to prepare the OS sandbox for xd://${device} launches: ${error instanceof Error ? error.message : error}. Retry the tool call.`);
        }
        try {
          return await withLaunchWindow(
            shared.launchGuard,
            "device",
            launch.template,
            () => ctx.invokeTool(params, { signal, onUpdate }),
          );
        } finally {
          if (launch.cleanupToken) cleanupAfterCommand(launch.cleanupToken);
        }
      });
    },
  });

  const hubParameters = z.object({
    op: z.enum(["send", "wait", "inbox", "list", "jobs", "cancel", "start", "ps", "logs", "stop", "restart", "describe"]),
    to: z.string().optional(), message: z.string().optional(), replyTo: z.string().optional(), await: z.boolean().optional(),
    from: z.string().optional(), ids: z.array(z.string()).optional(), timeoutMs: z.number().optional(), peek: z.boolean().optional(),
    status: z.enum(["running", "idle", "parked"]).optional(), limit: z.number().optional(), name: z.string().optional(),
    application: z.string().optional(), args: z.array(z.string()).optional(), env: z.record(z.string(), z.string()).optional(), cwd: z.string().optional(),
    pty: z.boolean().optional(), ready: z.object({ log: z.string().optional(), port: z.number().optional(), host: z.string().optional(), timeout: z.number().optional() }).optional(),
    restart: z.enum(["no", "on-failure", "always"]).optional(), persist: z.boolean().optional(), detached: z.boolean().optional(),
    lines: z.number().optional(), head: z.boolean().optional(), grep: z.string().optional(), follow: z.boolean().optional(), cursor: z.number().optional(),
    for: z.enum(["ready", "exit"]).optional(), pattern: z.string().optional(), text: z.string().optional(), enter: z.boolean().optional(),
    keys: z.array(z.string()).optional(), signal: z.enum(["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT", "SIGKILL"]).optional(), timeout: z.number().optional(),
  });

  pi.registerTool({
    name: "hub",
    label: "hub",
    description: "Agent coordination, background-job control, and supervised long-running processes.",
    parameters: hubParameters,
    async execute(_toolCallId, params, signal, onUpdate, ctx) {
      refreshMainUi(ctx);
      if (!ctx.invokeTool) return errorResult("Sandbox: native hub delegation requires omp 18.x with ExtensionContext.invokeTool.");
      if (!shared.enabled) return ctx.invokeTool(params, { signal, onUpdate });
      if (params.op === "restart" && params.name && !shared.wrappedDaemons.has(params.name)) {
        return errorResult(`Sandbox: refusing to restart daemon "${params.name}": it was not started under the sandbox by this process (its broker-stored launch spec is unverified). Use hub op:"stop" then op:"start" to relaunch it sandboxed.`);
      }
      if (params.op === "stop") {
        if ([...shared.wrappedDaemons.values()].some((daemon) => daemon.phase === "starting")) {
          return errorResult("Sandbox: cannot stop daemons while a sandboxed hub start is still in progress. Retry after the start completes.");
        }
        const daemons = params.name
          ? [shared.wrappedDaemons.get(params.name)]
          : [...shared.wrappedDaemons.values()];
        const result = await ctx.invokeTool(params, { signal, onUpdate });
        if (params.name) shared.wrappedDaemons.delete(params.name);
        else shared.wrappedDaemons.clear();
        for (const daemon of daemons) {
          if (daemon?.cleanupToken) cleanupAfterCommand(daemon.cleanupToken);
        }
        return result;
      }
      if (params.op !== "start" || !params.application) return ctx.invokeTool(params, { signal, onUpdate });
      if (!params.name) {
        return errorResult("Sandbox: hub start requires an explicit name so its sandbox resources can be released safely on stop.");
      }
      if (shared.wrappedDaemons.has(params.name)) {
        return errorResult(`Sandbox: daemon "${params.name}" already owns a sandbox launch. Stop it before starting a replacement.`);
      }
      const daemon: WrappedDaemon = { phase: "starting" };
      shared.wrappedDaemons.set(params.name, daemon);
      try {
        const loaded = load(ctx.cwd);
        const argv = [params.application, ...(params.args ?? [])];
        const gate = await enforceNetworkAndSshGate(shellQuoteJoin(argv), ctx, "hub");
        if (gate) return errorResult(gate.reason);
        const ui = ctx.hasUI ? ctx.ui : shared.mainUi;
        if (ui && params.ready?.port !== undefined) {
          ui.notify(`Sandbox network isolation is on: ready.port ${params.ready.port} cannot accept host connections; use ready.log.`, "warning");
        }
        if (ui && (params.detached || params.persist)) {
          ui.notify("Sandboxed daemons are tied to the broker lifetime despite persist/detached.", "warning");
        }
        return await withRuntimeSshContext(ctx, "hub", `hub start: ${shellQuoteJoin(argv)}`, async (networkContext) => {
          let lease: { command: string; cleanupToken?: string };
          try {
            lease = await SandboxManager.wrapWithSandboxLease(
              shellQuoteJoin(argv),
              sandboxShellPath(),
              filesystemConfig(loaded, "hub", shared.session),
              undefined,
              networkContext,
            );
          } catch (error) {
            return errorResult(`Sandbox: failed to wrap hub launch in the OS sandbox: ${error instanceof Error ? error.message : error}`);
          }
          try {
            const result = await ctx.invokeTool(
              { ...params, application: bashShellPath(), args: ["-c", lease.command] },
              { signal, onUpdate },
            );
            daemon.phase = "running";
            daemon.cleanupToken = lease.cleanupToken;
            return result;
          } catch (error) {
            if (lease.cleanupToken) cleanupAfterCommand(lease.cleanupToken);
            throw error;
          }
        });
      } finally {
        if (daemon.phase === "starting" && shared.wrappedDaemons.get(params.name) === daemon) {
          shared.wrappedDaemons.delete(params.name);
        }
      }
    },
  });

  pi.on("input", withExtensionHandlerTimeoutBridge(timeoutBridge, async (event, ctx) => {
    refreshMainUi(ctx);
    if (!shared.enabled) return;
    const loaded = load(ctx.cwd);
    if (!loaded.config.enabled) return;
    for (const rawTarget of extractFileMentionPaths(event.text)) {
      const target = classifyToolPath(rawTarget);
      if (target.kind !== "fs") continue;
      const path = canonicalizePath(target.path, ctx.cwd);
      const layers = ruleLayersForTool(loaded, "read", shared.session).read;
      let decision = decidePath(layers, target.path, ctx.cwd, true);
      if (decision === "deny") {
        decision = decidePath(layers.slice(0, -1), target.path, ctx.cwd, true);
        if (decision === "deny") {
          if (ctx.hasUI) ctx.ui.notify(`Sandbox: attachment read access denied for "${path}" by policy.`, "warning");
          return { action: "handled" as const };
        }
      }
      if (decision === "prompt") {
        const details = permissionDetails(
          ctx,
          "read",
          `input attachment: ${rawTarget}`,
          "No read allow rule matched the attachment path.",
        );
        const choice = await askChoice(ctx, (routed) => promptReadBlock(routed, path, details));
        if (choice === "abort") return { action: "handled" as const };
        await applyReadChoice(choice, path, ctx.cwd);
        const refreshed = load(ctx.cwd);
        if (decidePath(ruleLayersForTool(refreshed, "read", shared.session).read, target.path, ctx.cwd, true) !== "allow") {
          if (ctx.hasUI) ctx.ui.notify(`"${path}" remains denied after the grant.`, "warning");
          return { action: "handled" as const };
        }
      }
    }
  }));

  pi.on("user_bash", withExtensionHandlerTimeoutBridge(timeoutBridge, async (event, ctx) => {
    refreshMainUi(ctx);
    if (!shared.enabled || !shared.managerInitialized) return;
    const gate = await enforceNetworkAndSshGate(event.command, ctx, "bash");
    if (gate) {
      const output = `Blocked: ${gate.reason}`;
      return { result: { output, exitCode: 1, cancelled: false, truncated: false, ...outputStats(output) } };
    }
    return withRuntimeSshContext(ctx, "bash", `bash: ${event.command}`, async (networkContext) => {
      const run = await runSandboxedShell(event.command, ctx.cwd, bashShellPath(), {
        wrap: true,
        customConfig: filesystemConfig(load(ctx.cwd), "bash", shared.session),
        networkContext,
      });
      return { result: { output: run.output, exitCode: run.exitCode ?? 0, cancelled: false, truncated: false, ...outputStats(run.output) } };
    });
  }));

  pi.on("tool_call", withExtensionHandlerTimeoutBridge(timeoutBridge, async (event, ctx) => {
    refreshMainUi(ctx);
    if (!shared.enabled) return;
    const loaded = load(ctx.cwd);
    if (!loaded.config.enabled) return;
    const input = event.input as Record<string, unknown>;
    const tool = event.toolName;

    if (shared.managerInitialized && tool === "bash" && typeof input.command === "string") {
      const gate = await enforceNetworkAndSshGate(input.command, ctx, "bash");
      if (gate) return gate;
    }

    for (const rawTarget of collectReadTargets(tool, input)) {
      const target = classifyToolPath(rawTarget);
      if (target.kind === "internal") continue;
      const request = `${tool} read target: ${rawTarget}`;
      if (target.kind === "url") {
        const block = await enforceDomainGate(target.domain, ctx, tool, request);
        if (block) return block;
        continue;
      }
      if (target.kind === "ssh") {
        const block = await enforceSshHostGate(target.host, ctx, tool, request);
        if (block) return block;
        continue;
      }
      const path = canonicalizePath(target.path, ctx.cwd);
      const decision = decidePath(ruleLayersForTool(loaded, tool, shared.session).read, target.path, ctx.cwd, true);
      if (decision === "deny" && ctx.hasUI) {
        return { block: true, reason: `Sandbox: read access denied for "${path}" (denied by policy).` };
      }
      if (decision !== "allow") {
        const reason = decision === "deny"
          ? "A deny rule matched in the effective layered read policy."
          : "No allow rule matched in the effective layered read policy.";
        const details = permissionDetails(ctx, tool, request, reason);
        const choice = await askChoice(ctx, (routed) => promptReadBlock(routed, path, details));
        if (choice === "abort") return { block: true, reason: `Sandbox: read access denied for "${path}".` };
        await applyReadChoice(choice, path, ctx.cwd);
        const refreshed = load(ctx.cwd);
        if (decidePath(ruleLayersForTool(refreshed, tool, shared.session).read, target.path, ctx.cwd, true) !== "allow") {
          return { block: true, reason: `Sandbox: read access to "${path}" remains denied after the grant.` };
        }
      }
    }

    for (const rawTarget of collectWriteTargets(tool, input)) {
      const target = classifyToolPath(rawTarget);
      if (target.kind === "internal" || target.kind === "url") continue;
      const request = `${tool} write target: ${rawTarget}`;
      if (target.kind === "ssh") {
        const block = await enforceSshHostGate(target.host, ctx, tool, request);
        if (block) return block;
        continue;
      }
      const path = canonicalizePath(target.path, ctx.cwd);
      const decision = decidePath(ruleLayersForTool(loaded, tool, shared.session).write, target.path, ctx.cwd);
      if (decision === "deny" && ctx.hasUI) {
        return { block: true, reason: `Sandbox: write access denied for "${path}" (denied by policy).` };
      }
      if (decision !== "allow") {
        const reason = decision === "deny"
          ? "A deny rule matched in the effective layered write policy."
          : "No allow rule matched in the effective layered write policy.";
        const details = permissionDetails(ctx, tool, request, reason);
        const choice = await askChoice(ctx, (routed) => promptWriteBlock(routed, path, details));
        if (choice === "abort") return { block: true, reason: `Sandbox: write access denied for "${path}".` };
        await applyWriteChoice(choice, path, ctx.cwd);
        const refreshed = load(ctx.cwd);
        if (decidePath(ruleLayersForTool(refreshed, tool, shared.session).write, target.path, ctx.cwd) !== "allow") {
          return { block: true, reason: `Sandbox: write access to "${path}" remains denied after the grant.` };
        }
      }
    }


  }));

  pi.on("session_start", async (_event, ctx) => {
    refreshMainUi(ctx);
    shared.sessionCount += 1;
    const noSandbox = pi.getFlag("no-sandbox") as boolean;
    const loaded = load(ctx.cwd);
    for (const notice of takeMigrationNotices()) ctx.ui.notify(notice, "info");
    if (noSandbox || loaded.config.enabled === false) {
      shared.enabled = false;
      if (ctx.hasUI) ctx.ui.notify(noSandbox ? "Sandbox disabled via --no-sandbox" : "Sandbox disabled via config", "warning");
      return;
    }
    if (process.platform !== "darwin" && process.platform !== "linux") {
      shared.enabled = false;
      if (ctx.hasUI) ctx.ui.notify(`Sandbox not supported on ${process.platform}`, "warning");
      return;
    }
    try {
      await initializeSandboxOnce(shared, loaded.config, shared.session, authorizeRuntimeSsh);
      shared.enabled = true;
      installGuard();
      if (ctx.hasUI) {
        warnIfAllDomainsAllowed(ctx, loaded.config);
        ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("accent", formatSandboxStatus(loaded.config)));
      }
    } catch (error) {
      shared.enabled = false;
      if (ctx.hasUI) ctx.ui.notify(`Sandbox initialization failed: ${error instanceof Error ? error.message : error}`, "error");
    }
  });

  pi.on("session_shutdown", async () => {
    shared.sessionCount = Math.max(0, shared.sessionCount - 1);
    if (shared.sessionCount === 0) {
      await resetSandbox();
      shared.sshContexts.clear();
      shared.managerInitialized = false;
      shared.initPromise = null;
    }
  });

  pi.registerCommand("sandbox-enable", {
    description: "Enable the sandbox for this session",
    handler: async (_args, ctx) => {
      refreshMainUi(ctx);
      if (shared.enabled) {
        ctx.ui.notify("Sandbox is already enabled", "info");
        return;
      }
      const loaded = load(ctx.cwd);
      try {
        await initializeSandboxOnce(shared, loaded.config, shared.session, authorizeRuntimeSsh);
        shared.enabled = true;
        installGuard();
        ctx.ui.setStatus("sandbox", ctx.ui.theme.fg("accent", formatSandboxStatus(loaded.config)));
        ctx.ui.notify("Sandbox enabled", "info");
      } catch (error) {
        ctx.ui.notify(`Sandbox initialization failed: ${error instanceof Error ? error.message : error}`, "error");
      }
    },
  });

  pi.registerCommand("sandbox-disable", {
    description: "Disable the sandbox for this session",
    handler: async (_args, ctx) => {
      if (!shared.enabled) {
        ctx.ui.notify("Sandbox is already disabled", "info");
        return;
      }
      await resetSandbox();
      shared.enabled = false;
      shared.managerInitialized = false;
      shared.initPromise = null;
      shared.sshContexts.clear();
      ctx.ui.setStatus("sandbox", "");
      ctx.ui.notify("Sandbox disabled", "info");
    },
  });

  pi.registerCommand("sandbox", {
    description: "Show sandbox configuration",
    handler: async (_args, ctx) => {
      const loaded = load(ctx.cwd);
      const file = readOrEmptyConfig();
      ctx.ui.notify(formatSandboxConfiguration(loaded.config, {
        session: shared.session,
        projectKeys: Object.keys(file.projects ?? {}),
      }), "info");
    },
  });
}
