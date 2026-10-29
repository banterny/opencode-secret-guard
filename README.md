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

- `git commit` — scans the staged diff (`gitleaks git --pre-commit --staged`),
  from the top of the repo, so a commit made from a subfolder is scanned
  in full. A command that starts with `cd <folder> &&` (or `;`), or uses
  `git -C <folder>`, is scanned in that folder.
- `git commit -a` / `-i` / `-o` (or `--all`, `--include`, `--only`, also
  inside a cluster such as `-am`), or a `git add` / `git stage` earlier in
  the same command — also scans lines added by unstaged changes to tracked
  files, and untracked files that aren't git-ignored (piped into
  `gitleaks stdin`), since these fold in changes `--staged` can't see yet.
  Removed lines are not scanned, so a commit that deletes a leaked secret
  goes through. Git-ignored files (build output such as `.next/`) can't be
  committed and are never scanned.
- `git push` — scans every commit on a local branch or tag that no remote
  has yet, so `git push origin <other branch>`, `--all` and `--tags` are
  covered as well as the current branch. On a first push, with no
  remote-tracking branches, that is the whole history.

It also refuses to let the scan be switched off from inside the repo or
the command:

- A `gitleaks:allow` note on a line does not exempt it
  (`--ignore-gitleaks-allow`).
- The `GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML` environment variables
  are ignored.
- gitleaks reads `.gitleaks.toml` and `.gitleaksignore` from the folder it
  scans and skips what they say. Copies committed exactly as they are are
  trusted. A commit or push is refused while either file is new, edited
  or uncommitted, and a commit that changes either is refused too: you
  check the change and commit it yourself (with `git commit --no-verify`
  if the git-level hooks from claude-code-secret-guard are installed).

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
- A secret on any unpushed local branch blocks every push, including a
  push of a different, clean branch. Remove the secret from that branch
  (or delete the branch) first.
- Reading the command is approximate. A folder reached any other way than
  a leading `cd` or `git -C`, a commit through a git alias, or
  `git commit <path>` with no flag (which commits that file's unstaged
  changes) is not seen as it really is. The git-level hooks in
  [claude-code-secret-guard](https://github.com/banterny/claude-code-secret-guard#git-level-hooks-any-agent-or-you)
  run inside git itself and cover these.
- Settings files committed before this plugin was installed are trusted
  as they are. Read a repo's `.gitleaks.toml` and `.gitleaksignore`
  before relying on the scan there.

## License

MIT — see [LICENSE](LICENSE).
