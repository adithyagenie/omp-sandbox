# pi-sandbox-omp

OS-level sandboxing for [omp](https://omp.sh/), ported from
[`carderne/pi-sandbox`](https://github.com/carderne/pi-sandbox).

It restricts filesystem and network access for bash commands, applies the same
policy to omp's in-process file tools, and puts ssh behind an explicit
confirmation gate.

> [!WARNING]
> This sandbox is vibe-coded. Expect it to break. Treat it as experimental,
> review the source and effective permissions, and do not rely on it as a
> hardened security boundary.

## Features

- **OS-level bash sandbox** — `bubblewrap` on Linux and `sandbox-exec` on macOS.
- **File-tool policy** — intercepts omp's `read`, `write`, and `edit` tools,
  which do not run inside the subprocess sandbox.
- **Network policy** — per-domain allow/deny rules with interactive approvals.
- **SSH gate** — detects `ssh`, `scp`, `sftp`, remote `rsync`, and ssh-based
  `git clone`; each target host requires explicit approval.
- **Scoped approvals** — allow once for the session, project, or all projects.
- **OMP-native paths** — configuration and runtime paths use `.omp`.

## Requirements

### Linux

- `bwrap` (bubblewrap) — required
- `socat` — required
- `rg` (ripgrep) — required
- seccomp — optional hardening; missing support is a warning, not an error

### macOS

- `sandbox-exec` (provided by macOS)
- `rg` (ripgrep)

## Install

From the plugin source directory:

```sh
bun install
omp plugin link .
```

Or link it by absolute path:

```sh
omp plugin link ~/.omp/plugins/pi-sandbox-omp
```

Restart omp, then verify:

```sh
omp plugin list
omp plugin doctor
```

`bun install` also applies the committed runtime patch from
`patches/sandbox-runtime@0.0.49.patch`.

## Configuration

Configuration is loaded from:

- Global: `~/.omp/agent/sandbox.json`
- Project: `<cwd>/.omp/sandbox.json`

Project settings override global scalars and deny-lists. Allow-lists accumulate
and are deduplicated.

```jsonc
{
  "enabled": true,
  "network": {
    "allowedDomains": ["github.com", "*.github.com"],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["/home"],
    "allowRead": [".", "~/.config"],
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".env", ".env.*", "*.pem", "*.key"]
  }
}
```

### Network modes

- `allowedDomains: ["*"]` with no denied domains shares the host network.
  HTTP, UDP, raw sockets, and ssh work without per-domain prompts.
- An explicit allow-list enables domain prompts and the filtering proxy.
- `["*"]` with denied domains also uses the filtering proxy so the deny-list
  can be enforced. On Linux, UDP, raw sockets, and bare ssh do not work through
  this restricted proxy path.

### Filesystem precedence

- **Read:** `allowRead` overrides `denyRead`. An approved prompt adds the path
  to `allowRead`.
- **Write:** `denyWrite` overrides `allowWrite` and is never prompted.
  Other writes outside `allowWrite` prompt for approval.

### SSH confirmation

A network wildcard does not approve ssh. The first ssh-family command to a host
prompts independently; approval is stored per host at the selected scope.

## Prompts and commands

Blocked actions offer:

- Abort
- Allow for this session
- Allow for this project — writes `<cwd>/.omp/sandbox.json`
- Allow for all projects — writes `~/.omp/agent/sandbox.json`

Controls:

- `omp --no-sandbox` — disable sandboxing for the session
- `/sandbox` — show effective policy and session approvals
- `/sandbox-enable` / `/sandbox-disable` — toggle sandboxing for the session

## Changes from `carderne/pi-sandbox`

- Ported the manifest and runtime APIs from pi to omp
  (`omp.extensions`, `@oh-my-pi/pi-coding-agent`, and `@oh-my-pi/pi-tui`).
- Migrated global/project configuration from `.pi` to `.omp`.
- Added local installation through `omp plugin link`.
- Added per-host ssh-family confirmation that is independent of the network
  wildcard.
- Added unrestricted host networking for `["*"]` with no denied domains.
- Added a reproducible Bun patch for OMP-native runtime paths and ghost-file
  prevention.

## Runtime patch

`package.json#patchedDependencies` registers
`patches/sandbox-runtime@0.0.49.patch`, which Bun applies during installation.
The patch:

- skips non-existent deny paths instead of mount-pointing them, preventing
  bwrap from creating ghost files in the working directory;
- retains read-only binding for deny paths that already exist;
- uses `OMP_TMPDIR` (default `/tmp/omp`), `.omp/commands`, `.omp/agents`, and
  `~/.omp/debug`.

Skipping non-existent deny paths means a sandboxed process can create a path
that would have been denied had it already existed. This tradeoff avoids
polluting the host working directory.

The patch is pinned to `@carderne/sandbox-runtime@0.0.49`; regenerate it when
upgrading the runtime.

## License

[MIT](./LICENSE). The original project is
[`carderne/pi-sandbox`](https://github.com/carderne/pi-sandbox).
