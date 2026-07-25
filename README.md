# pi-sandbox-omp

OS-level sandboxing for [omp](https://omp.sh/): restricts what bash commands
can read/write, what network hosts they can reach, and gates every ssh command
behind an interactive confirmation.

This project is ported from
[`carderne/pi-sandbox`](https://github.com/carderne/pi-sandbox), originally
written for [pi](https://pi.dev/).

> [!WARNING]
> This sandbox is vibe-coded. Expect it to break. Treat it as experimental,
> review its permissions and source, and do not rely on it as a hardened
> security boundary.

It uses `@carderne/sandbox-runtime` (Anthropic Sandbox Runtime / ASRT) to enforce
filesystem and network restrictions on bash commands at the OS level
(`sandbox-exec` on macOS, `bubblewrap` + a filtering proxy on Linux), and
intercepts omp's `read`, `write`, `edit`, and `bash` tools to apply the same
allow/deny rules in-process (those tools run in Node, not in a subprocess, so the
OS sandbox cannot see them).

## Changes from `carderne/pi-sandbox`

- Ported the extension manifest and runtime imports from pi to omp
  (`omp.extensions`, `@oh-my-pi/pi-coding-agent`, and `@oh-my-pi/pi-tui`).
- Migrated user and project configuration from `.pi` to `.omp`
  (`~/.omp/agent/sandbox.json` and `<cwd>/.omp/sandbox.json`).
- Added local installation through `omp plugin link`.
- Added an explicit per-host confirmation gate for `ssh`, `scp`, `sftp`,
  remote `rsync`, and ssh-based `git clone`; a network wildcard does not
  automatically approve ssh.
- Added true unrestricted networking for `allowedDomains: ["*"]` with no
  denied domains, sharing the host network so UDP, raw sockets, and ssh work.
- Added a reproducible Bun patch for `@carderne/sandbox-runtime` that prevents
  non-existent deny paths from creating ghost dotfiles and migrates runtime
  paths/TMPDIR handling to `.omp`.

## What it sandboxes

- **Bash (OS-level)** — every `bash` tool call (and `!cmd` user bash) runs inside
  `bwrap`/`sandbox-exec` with filesystem write restrictions and (optionally) a
  network filtering proxy.
- **Filesystem read/write/edit** — the `read`, `write`, `edit` tools are
  intercepted so `denyRead` / `allowRead` / `allowWrite` / `denyWrite` rules
  apply to them too.
- **Network (bash)** — outbound domains are filtered through an HTTP/SOCKS proxy
  (Linux) or kernel-level allowlist (macOS). Domains not in `allowedDomains` are
  blocked unless explicitly approved.
- **SSH confirmation gate** — `ssh`, `scp`, `sftp`, `rsync`-with-a-remote, and
  `git clone` over ssh are detected and prompt for confirmation per target host,
  even when the network is otherwise unrestricted. A bare `"*"` in
  `allowedDomains` does **not** auto-approve ssh — every ssh host prompts the
  first time, mirroring the read/write path-confirmation UX. Approval persists
  per host (session / project / global).

## Requirements

### Linux
- `bwrap` (bubblewrap) — **required**
- `socat` — **required** (the network filtering proxy bridges through socat Unix
  sockets; without it the sandbox cannot initialize)
- `ripgrep` (`rg`) — **required**
- `seccomp` — **optional** (hardening only; restricts Unix-socket access inside
  the namespace). The runtime ships the C sources unbuilt; if you want it, build
  with `libseccomp` + `cc`. Missing it is a warning, not an error.

On NixOS: `nix profile install nixpkgs#socat` (bwrap/rg are usually already
present). Restart omp after installing so the sandbox re-initializes.

### macOS
- `sandbox-exec` (system-provided)

## Setup

This plugin is a local package, not on a registry. Install it with omp's
`plugin link` (symlinks the source into omp's plugin node_modules):

```sh
# from the omp agent dir (or anywhere you keep plugin sources)
omp plugin link ~/.omp/plugins/pi-sandbox-omp
```

Then install the runtime dependency (the plugin's `package.json` declares
`@carderne/sandbox-runtime`):

```sh
cd ~/.omp/plugins/pi-sandbox-omp
bun install            # or: nix shell nixpkgs#bun -c 'bun install'
```

Restart omp. On startup the extension loads and the sandbox initializes; the
status line shows `🔒 Sandbox: <network mode>, <N> write paths`.

Verify:
```sh
omp plugin list       # should list pi-sandbox-omp@0.1.0
omp plugin doctor     # health check (deps + manifest)
```

## Configuration

Config files are merged (project takes precedence over global; allow-lists
accumulate across layers, deny-lists and scalars replace):

- **Global**: `~/.omp/agent/sandbox.json`
- **Project**: `<cwd>/.omp/sandbox.json`

```jsonc
{
  "enabled": true,
  "network": {
    "allowedDomains": ["github.com", "*.github.com"],  // ["*"] = allow all
    "deniedDomains": []                                 //   (see "Network modes")
  },
  "filesystem": {
    "denyRead":  ["/home"],   // broad read block (allowRead overrides denyRead)
    "allowRead":  [".", "~/.config"],
    "allowWrite": [".", "/tmp"],
    "denyWrite":  [".env", ".env.*", "*.pem", "*.key"]  // always denied
  }
}
```

### Network modes
- **`allowedDomains: ["*"]` with no `deniedDomains`** → unrestricted: the
  network namespace is shared with the host, so **all protocols work** (HTTP,
  UDP, raw, ssh). No per-domain prompts. Use intentionally.
- **`["*"]` + a `deniedDomains` list** → restricted: `bwrap --unshare-net`
  isolates the network and only HTTP/SOCKS-proxy-aware traffic is filtered
  against the denylist. UDP / raw / bare-`ssh` will not work in this mode on
  Linux (kernel limitation).
- **Explicit domain list** → restricted + per-domain prompts for anything not
  listed.

### Filesystem precedence
- **Read**: `allowRead` **overrides** `denyRead` (prompt grants add to
  `allowRead`). Reads are always prompted unless already in `allowRead`.
- **Write**: `denyWrite` **overrides** `allowWrite` (most-specific deny wins).
  Writes are prompted unless in `allowWrite`; `denyWrite` entries are
  hard-blocked.

## Slash commands
- `/sandbox` — show the effective config.
- `/sandbox-enable` / `/sandbox-disable` — toggle the sandbox for the session.

## Permission prompts

When a read/write/network/ssh action is not pre-approved, a prompt offers:
- **Abort** — keep it blocked.
- **Allow for this session** — in-memory only.
- **Allow for this project** — written to `<cwd>/.omp/sandbox.json`.
- **Allow for all projects** — written to `~/.omp/agent/sandbox.json`.

## Known behaviors & limitations

- **Ghost dotfiles (prevented)**: on Linux, the upstream runtime mounts
  `/dev/null` over non-existent deny paths (e.g. `.env`, `.bashrc`, `.omp`)
  to block their creation, which forces bwrap to create empty host mount-point
  files — leaving ghost dotfiles in the working directory. This is prevented by
  a **reproducible bun patch** (`patches/sandbox-runtime@0.0.49.patch`,
  registered in `package.json#patchedDependencies`) that makes the runtime skip
  non-existent deny paths instead of mount-pointing them. `bun install` applies
  it automatically — no direct `node_modules` editing, and a fresh clone gets
  the fix. Existing deny paths are still bound read-only. Tradeoff: a sandboxed
  process could create a previously-non-existent denied path and write to it.
- **ssh in restricted mode**: bare `ssh` does not honor `ALL_PROXY`, so once
  approved it may still fail to connect under `--unshare-net`. In unrestricted
  (`["*"]`) mode ssh connects natively (host network shared).
- **OMP runtime paths**: the reproducible patch changes runtime tmpdir,
  command-directory, and debug paths to OMP-native names: `OMP_TMPDIR`
  (default `/tmp/omp`), `.omp/commands`, `.omp/agents`, and `~/.omp/debug`.
