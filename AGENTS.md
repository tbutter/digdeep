# Repository Agent Guidelines

## Running Node.js, npm, and DNS CLI Tools via `nix-shell`

`node` and `npm` are not installed globally in `/usr/bin` on this machine. Always run Node.js, `npm`, `npx`, Vite, Vitest, and DNS CLI commands (`dig`, `delv`) inside the repository's `nix-shell` (`shell.nix`).

Because non-login shells may not include `/nix/var/nix/profiles/default/bin` in `PATH`, invoke `nix-shell` via its full path (or source `nix-daemon.sh` first):

```bash
/nix/var/nix/profiles/default/bin/nix-shell --run "npm test"
/nix/var/nix/profiles/default/bin/nix-shell --run "npm run build"
```
