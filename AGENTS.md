# Coding conventions

## Repository layout

| File | Responsibility |
|---|---|
| `index.ts` | Re-export the extension factory |
| `src/config.ts` | Config types, defaults, migration, persistence, and layered resolution |
| `src/policy.ts` | Pure path/domain/SSH matching, extraction, and decisions |
| `src/sandbox-runtime.ts` | SandboxManager lifecycle, shell runner, templates, environment, and timeout bridge |
| `src/launch-guard.ts` | Idempotent Bun/Node spawn patching and guarded launch windows |
| `src/ui.ts` | Permission prompts, routing, serialization, status, and configuration formatting |
| `src/extension.ts` | Shared state, shadow tools, event handlers, and slash commands |

## Imports and APIs

Relative imports include explicit `.ts` suffixes. Runtime types come from `@oh-my-pi/pi-coding-agent`. Sandbox APIs come from `@carderne/sandbox-runtime`. Do not introduce a second configuration, policy, prompt, or runtime abstraction beside these modules.

## Shared state

All cross-session mutable state lives in the `Symbol.for("pi-sandbox-omp.shared")` object in `src/extension.ts`. Task subagent sessions re-bind the extension factory: module state is process-shared, while ordinary factory-local state is per session. Choose deliberately. SandboxManager initialization, grants, prompt serialization, daemon attestation, launch generations, and launch templates must remain process-shared.

## Spawn guard

Spawn patching is idempotent through `state.installed` and stored original functions. Never wrap `process.execPath`, `__omp_worker_*` argv, IPC spawns, or names in `INFRA_SPAWN_BASENAMES`. Payload commands travel only through `OMP_SANDBOX_LAUNCH_CMD`; never parse or string-edit a generated bwrap or sandbox-exec command. Every launch window pins a prepared template and must close on all completion paths. Overlapping guarded windows fail closed rather than selecting another call's policy.

## Policy decisions

Every filesystem, domain, and SSH decision uses `ruleLayersForTool` followed by `decidePath` or `decideHost`. Do not decide from the merged config: merging destroys layer origin and breaks stronger-scope precedence. OS wrappers receive `unionListsForTool`; in-process gates receive ordered layers. Classify tool paths before treating them as local filesystem paths. Internal URIs are not files; HTTP(S) paths are domains; `ssh://` paths are SSH targets.

Session grants precede project-tool allow/deny, project generic allow/deny, global-tool allow/deny, global generic deny, and global generic allow. Within one scope, allow is stronger than deny. Network `"*"` never approves SSH.

## Configuration persistence

All persistent writes target `getAgentDir()/sandbox.json`. Project grants update `projects[canonicalizePath(cwd)]`; never recreate `<cwd>/.omp/sandbox.json`. Legacy migration is one-shot per process and failures warn without blocking load. Per-tool overrides are user-authored; interactive grants update generic lists only.

## Hub shadow tool

The hub shadow delegates through `ctx.invokeTool`; never rewrite a `tool_call` input. OMP persists revised inputs in the transcript, which would expose the full sandbox wrapper to later model turns. `hub start` wraps before native delegation. `hub restart` fails closed unless the daemon name was started sandboxed by this process. A stopped daemon loses that attestation.

## Prompt routing

All prompts use `routePrompt`. Headless subagents route to the latest main UI and carry the `[subagent]` prefix. `shared.promptQueue` serializes prompts. No available main UI means deny; never invoke the no-op headless `ui.custom()` directly.

## Runtime lifecycle

Initialize SandboxManager once per process, reference-count active sessions, and reset only when the final session shuts down or the user explicitly disables the sandbox. Use `updateConfig` for grants; resetting live proxies can hang active keep-alive traffic. Call `cleanupAfterCommand()` after every sandboxed shell execution. Bump the launch generation and clear cached templates whenever effective filesystem policy changes.

## Verification

Build with Bun targeting Bun and externalizing omp runtime packages. Smoke-load the actual extension with `omp -e ./index.ts --no-sandbox`; reaching provider startup proves registration completed. Behavioral changes require exercising the actual tool surface. Linux sandbox checks cover denied-path creation and cleanup, dangerous `.omp` writes, hub transcript hygiene and restart refusal, layered policy precedence, SSH, Python eval, glob/grep prompts, subagent prompt routing, migration, and `/sandbox` output. macOS changes require review unless run on macOS.

Commits are step-scoped. Do not batch independent rewrite phases. Preserve signed commits; if signing fails, stop rather than bypassing it.
