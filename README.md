# opencode-secret-guard

OpenCode port of
[claude-code-secret-guard](https://github.com/banterny/claude-code-secret-guard):
blocks `git commit` / `git push` when the change contains a hardcoded secret
(API key, token, private key, …), detected with
[gitleaks](https://github.com/gitleaks/gitleaks).

It only scans on actual commit/push — every other Bash call returns in
milliseconds with no scan — and fails open (allows) when `gitleaks`/`git`
are missing or the directory is not a git repo.

> Want to stop personal data (your email address, for instance) leaking out of
> an agent into web requests as well? See
> [agent-privacy-guard](https://github.com/banterny/agent-privacy-guard), for
> OpenCode, Claude Code and Codex.

No secrets are stored in this repo. Tests generate fake tokens at runtime.

## Why this instead of a general secret-scan-everything hook

Hooks that scan *every* Bash call pay their cost in the wrong place: the
check that matters — scanning a diff for secrets before it enters git
history — only applies to the rare `git commit`/`git push`, yet a
scan-everything hook runs its full pipeline on every `ls`, `cat`, and
`npm install` too.

This plugin matches on the command *before* deciding whether to scan
anything, so non-git Bash calls return immediately (no gitleaks fork),
and the gitleaks scan only runs on an actual commit/push.

## Prereqs (each machine)

```sh
brew install gitleaks jq
gitleaks version   # should print e.g. 8.30.1
```

Needs gitleaks 8.19.0 or later (for its `git` and `stdin` commands).

## Install (global, recommended)

```sh
mkdir -p ~/.config/opencode/plugins
cp secret-guard.js ~/.config/opencode/plugins/secret-guard.js
```

Then restart OpenCode's background server so it picks the file up:

```sh
opencode service restart
```

### Verify it loads

```sh
opencode plugin list
```

The row for `.../plugins/secret-guard.js` must show `secret-guard` in the
`ID` column. A `-` there means OpenCode found the file but refused to load
it, and **the guard is not running**; the reason is in OpenCode's log
(`opencode debug paths` shows where) as `failed to load plugin`. The first
`plugin list` in a folder can come back before loading has finished — run
it twice.

This matters because OpenCode 2 changed the plugin format: a plugin written
for OpenCode 1 is silently skipped, not loaded. This file is written for
OpenCode 2 and also carries the OpenCode 1 entry point (1.18.29 or later).

## Install (single project only)

```sh
mkdir -p .opencode/plugins
cp secret-guard.js .opencode/plugins/secret-guard.js
```

Restart OpenCode's background server and verify as above.

## What it blocks

- `git commit` — scans the staged diff (`gitleaks git --pre-commit --staged`).
- `git commit -a` / `-am` / `--all` — also scans unstaged changes to
  tracked files and untracked files that aren't git-ignored (piped into
  `gitleaks stdin`), since those flags — or a `git add --all` chained ahead
  of the commit — fold in changes `--staged` can't see yet. Git-ignored
  files (build output such as `.next/`) can't be committed and are never
  scanned.
- `git push` — scans commits not yet on the upstream branch
  (falls back to `origin/HEAD`, then to the tip commit).

Trigger matching is deliberately loose (word `git` + word `commit`/`push`
anywhere in the command). Over-matching just costs one fast scan;
under-matching could leak a secret into history.

## Test

```sh
./test-scan.sh
node test-plugin.mjs
```

`test-scan.sh` builds a real scratch repo and exercises the exact gitleaks
commands the plugin shells out to — staged/unstaged/untracked/tip-commit
secrets plus clean counterparts, a secret in a git-ignored build folder
(must not block), and a repo with no commits yet.

`test-plugin.mjs` tests the plugin file itself: that it has the shape
OpenCode 2 will load, and that its hook allows and blocks the right
commands in scratch repos (including a file search that merely mentions
`.git` and "commit", which must not block).

No network access, nothing touches your real repos. Neither test proves
that a running OpenCode has loaded the plugin — see "Verify it loads".

For end-to-end on a new machine: in a scratch repo (never a real one),
stage a file containing a fake token and ask the agent to commit — it
should be blocked with a `Blocked by secret-guard…` message. Clean files
should commit normally.

Tested on macOS with gitleaks 8.30.1 and OpenCode 2.0.25/2.0.26, including
a real session being blocked. The OpenCode 1
entry point is carried over from the earlier version of this plugin and has
not been re-tested against a real OpenCode 1 install.

## Limitations

- Fails open: if `gitleaks` or `git` isn't on `PATH`, commits are allowed
  silently. Re-run `gitleaks version` if you're unsure protection is active.
- Format-based detection: gitleaks matches known secret shapes. A bare
  `password = "…"` in an unknown format can slip through. This raises the
  floor, it's not a guarantee.
- The `-a` scan reads removed lines too: it scans the raw `git diff` text,
  so `git commit -am "remove leaked key"` is blocked by the very line being
  deleted. Stage the change and commit without `-a` instead; the staged
  scan only looks at added lines.
- First push of a brand-new branch scans only the tip commit (no upstream
  to diff against). Commit-time scanning is the primary control.

## License

MIT — see [LICENSE](LICENSE).
