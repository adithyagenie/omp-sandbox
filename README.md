# pi-sandbox-omp

OS-level process sandboxing and policy gates for Oh My Pi tools.

> [!WARNING]
> This sandbox is vibe-coded. Expect it to break. Treat it as experimental,
> review the source and effective permissions, and do not rely on it as a
> hardened security boundary.

## Features

- Runs `bash`, `!` commands, hub-launched daemons, Python eval kernels, and configured `xd://` devices under bubblewrap on Linux or `sandbox-exec` on macOS.
- Applies filesystem policy to in-process `read`, `write`, `edit`, `glob`, `grep`, `ast_grep`, and `ast_edit` calls, including selectors, archives, SQLite targets, semicolon-separated grep roots, and `ssh://` URIs.
- Shadows `hub` and delegates internally with `ctx.invokeTool`, so the transcript retains the original application and arguments instead of the generated sandbox wrapper. Restart refuses broker specs not started sandboxed by this process.
- Sandboxes Python `eval` kernel launches. JavaScript eval remains unsandboxed because omp launches its worker over IPC and a shell intermediary would break that channel.
- Shares sandbox state with task subagents and routes their permission prompts to the main TUI, serialized with main-session prompts.
- Gates SSH separately from network egress. `ssh`, `scp`, `sftp`, rsync-over-SSH, Git SSH clones, and `ssh://` tool paths use `ssh.allow` and `ssh.deny`.
- Supports generic and per-tool filesystem, network, and SSH policy.
- Stores global and project configuration in one global `sandbox.json`; project sections are keyed by canonical project directory. Legacy `<project>/.omp/sandbox.json` files migrate automatically.

## Requirements

### Linux

- `bwrap` (bubblewrap)
- `socat`
- `rg` (ripgrep)
- Optional: the sandbox-runtime `apply-seccomp` helper for stronger syscall filtering

### macOS

- `sandbox-exec`
- `rg` (ripgrep)

OMP 18.x and Bun are required on both platforms.

## Install

```bash
bun install
omp plugin link .
```

`bun install` applies the pinned `@carderne/sandbox-runtime@0.0.72` patch.

## Configuration

Configuration lives at `~/.omp/agent/sandbox.json`. Project policy belongs under `projects["<canonical-project-directory>"]`; no project-local config is created.

```json
{
  "enabled": true,
  "network": {
    "allowedDomains": ["github.com", "*.github.com"],
    "deniedDomains": ["blocked.example"]
  },
  "filesystem": {
    "denyRead": ["~/.omp/agent"],
    "allowRead": ["~/.config"],
    "allowWrite": ["~/.cache/uv"],
    "denyWrite": [".env", "*.pem", "~/.omp/agent"]
  },
  "ssh": {
    "allow": ["github.com"],
    "deny": ["production.internal"]
  },
  "sandboxedDevices": ["github", "browser"],
  "tools": {
    "write": {
      "filesystem": { "allowWrite": ["/tmp/generated"] }
    },
    "hub": {
      "network": { "allowedDomains": ["registry.example"] },
      "ssh": { "deny": ["bastion.internal"] }
    }
  },
  "projects": {
    "/absolute/project": {
      "filesystem": { "allowWrite": ["./generated"] },
      "tools": {
        "grep": { "filesystem": { "allowRead": ["/opt/reference"] } }
      }
    }
  }
}
```

List fields accumulate for the OS sandbox. In-process gates retain layer identity and evaluate the first matching rule in this order, strongest first:

1. Session allow
2. Project tool allow
3. Project tool deny
4. Project generic allow
5. Project generic deny
6. Global tool allow
7. Global tool deny
8. Global generic deny
9. Global generic allow
10. No match: paths under the project directory are allowed; other paths, domains, and SSH hosts prompt

An allow in a stronger layer can therefore punch through a weaker deny. Subprocess policy is intentionally broader: sandbox-runtime receives the union of applicable lists and applies its own OS-level deny/allow semantics.

The default policy makes the project directory readable and writable without listing `"."`; stronger explicit denies still win. Subprocess reads are deny-by-default outside configured paths, and exact `"*"` in `allowRead` opts into read-all. In-process tools may use host `/tmp` by default. Subprocesses instead receive a private tmpfs-backed `/tmp` unless `/tmp` is explicitly present in `allowRead` or `allowWrite`.

`network.allowedDomains: ["*"]` with an empty deny list disables network isolation, shares the host network, and allows all Unix sockets. This does not approve SSH; use `ssh.allow: ["*"]` explicitly if that behavior is intended.

Default policy denies reads and writes under `~/.omp/agent`. These are ordinary defaults and can be overridden by a stronger project, tool, or session allow.

## Permission prompts

A prompt offers:

- Allow for this session
- Abort
- Allow for this project, persisted under `projects["<cwd>"]`
- Allow globally

Persistent grants update generic allow lists. Per-tool overrides are hand-edited only. Headless subagent prompts surface in the main TUI with a `[subagent]` prefix. If no main UI exists, the operation fails closed.

## Commands and flag

- `omp --no-sandbox` disables the plugin for the session.
- `/sandbox` shows effective network, filesystem, SSH, tool overrides, session grants, configured devices, and eval limitations.
- `/sandbox-enable` enables and initializes the sandbox.
- `/sandbox-disable` resets and disables it.

## Coverage and limitations

| Surface | Coverage |
|---|---|
| `bash`, `!cmd` | OS filesystem and network sandbox; network and SSH pre-gates |
| `read`, `glob`, `grep`, `ast_grep` | In-process read/domain/SSH policy |
| `write`, `edit`, `ast_edit`, LSP file rename | In-process write/SSH policy |
| `hub start` | Transcript-invisible OS wrapper; filesystem/network/SSH gates |
| `hub restart` | Allowed only for names started sandboxed by this process |
| Python `eval` | Kernel launch under OS sandbox |
| JavaScript `eval` | Not sandboxed; omp IPC worker limitation |
| `xd://github`, `xd://browser` | Host subprocess launch under OS sandbox by default |
| Task subagents | Shared runtime and session grants; prompts routed to main TUI |

The launch guard never wraps omp worker/broker processes, `process.execPath`, sandbox infrastructure helpers, or IPC spawns. Sandboxed daemons remain tied to the broker lifetime despite `persist` or `detached`, because bubblewrap uses parent-death containment. A restricted daemon listening on `ready.port` is inside the sandbox network namespace; use log readiness unless the host network is intentionally shared.

Linux behavior is functionally verified. The macOS `sandbox-exec` path follows sandbox-runtime's supported API but is not exercised by this repository's Linux verification workflow.
