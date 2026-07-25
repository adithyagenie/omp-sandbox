# pi-sandbox-omp

OS-level sandboxing for [omp](https://github.com/) (oh-my-pi): restricts what
bash commands can write/read, what network hosts they can reach, and gates every
ssh command behind a confirmation — with interactive permission prompts. A
functional rewrite of `carderne/pi-sandbox` for the `@oh-my-pi` runtime.

It uses `@carderne/sandbox-runtime` (Anthropic Sandbox Runtime / ASRT) to enforce
filesystem and network restrictions on bash commands at the OS level
(`sandbox-exec` on macOS, `bubblewrap` + a filtering proxy on Linux), and
intercepts omp's `read`, `write`, `edit`, and `bash` tools to apply the same
allow/deny rules in-process (those tools run in Node, not in a subprocess, so the
OS sandbox can't see them).

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
  `/dev/null` over non-existent deny paths (e.g. `.env`, `.bashrc`, `.claude`)
  to block their creation, which forces bwrap to create empty host mount-point
  files — leaving ghost dotfiles in the working directory. This is prevented by
  a **reproducible bun patch** (`patches/@carderne%2Fsandbox-runtime@0.0.49.patch`,
  registered in `package.json#patchedDependencies`) that makes the runtime skip
  non-existent deny paths instead of mount-pointing them. `bun install` applies
  it automatically — no direct `node_modules` editing, and a fresh clone gets
  the fix. Existing deny paths are still bound read-only. Tradeoff: a sandboxed
  process could create a previously-non-existent denied path and write to it.
- **ssh in restricted mode**: bare `ssh` does not honor `ALL_PROXY`, so once
  approved it may still fail to connect under `--unshare-net`. In unrestricted
  (`["*"]`) mode ssh connects natively (host network shared).
- **`CLAUDE_TMPDIR`**: the runtime reads this env var for its proxy/bridge
  tmpdir (defaulting to `/tmp/claude`). The plugin sets it to `OMP_TMPDIR` or
  `/tmp` so no `.claude` path is created; the var name is the runtime's public
  contract and can't be renamed without patching.
- **`.claude/debug` bind**: the upstream runtime binds `~/.claude/debug` for
  proxy debug logs. This is an upstream behavior the plugin does not alter.
