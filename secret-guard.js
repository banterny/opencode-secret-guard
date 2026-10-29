// OpenCode port of https://github.com/banterny/claude-code-secret-guard
// Blocks `git commit` / `git push` when the change contains a hardcoded secret,
// detected with gitleaks. Only scans on actual commit/push; all other shell
// calls return in ~ms with no scan.
//
// Install: requires `gitleaks` 8.19.0+ on PATH (`brew install gitleaks`).
// Loaded automatically from ~/.config/opencode/plugins/ (global).
// Fails open (allow) when gitleaks/git are unavailable or cwd is not a repo.
//
// Written for OpenCode 2, which only loads a plugin whose default export is
// a definition with an `id` and a `setup` function. `server` is the same
// guard for OpenCode 1 (1.18.29 and later read it from the same object).

import { spawn } from "node:child_process";
import { statSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const hasWord = (cmd, w) =>
  new RegExp(`(^|[^a-zA-Z0-9_])${w}([^a-zA-Z0-9_]|$)`).test(cmd);

// Changes that are not staged yet but could still end up in this commit:
// `-a`/`--all`, `-i`/`--include` and `-o`/`--only` (bare or inside a
// short-flag cluster like `-am`), or a `git add`/`git stage` earlier in the
// same command, which has not run yet when this hook fires. Matched loosely:
// an unrelated flag elsewhere in a chained command only costs a wider scan.
const isWide = (cmd) =>
  /(^|\s)(--all|--include|--only|-[a-zA-Z]*[aio][a-zA-Z]*)(\s|$)/.test(cmd) ||
  /(^|[^a-zA-Z0-9_])git(\s+-\S+(\s+[^-\s]\S*)?)*\s+(add|stage)(\s|$)/.test(cmd);

// Which folders the command may act on: where it starts, plus the folder of
// a leading `cd <dir> &&` (or `;`) and of a `git -C <dir>`, each relative to
// where it applies. A folder may be quoted. All of them are scanned, and any
// finding blocks, so a decoy `cd` cannot steer the scan away from the repo
// the commit really lands in. Anything cleverer than that is left to the
// git-level hooks.
const DIR = String.raw`(?:"([^"]*)"|'([^']*)'|([^\s;&|"']+))`;
const CD_RE = new RegExp(String.raw`^\s*cd\s+${DIR}\s*(?:&&|;)`);
const GIT_C_RE = new RegExp(String.raw`(?:^|[^a-zA-Z0-9_])git\s+-C\s+${DIR}`);
const expandHome = (d) =>
  d === "~" ? os.homedir() : d.startsWith("~/") ? path.join(os.homedir(), d.slice(2)) : d;
function candidateDirs(cmd, cwd) {
  const dirs = [cwd];
  let base = cwd;
  for (const re of [CD_RE, GIT_C_RE]) {
    const m = re.exec(cmd);
    const d = m && (m[1] ?? m[2] ?? m[3]);
    if (!d) continue;
    const next = path.resolve(base, expandHome(d));
    // A folder that isn't there adds nothing.
    try {
      if (statSync(next).isDirectory()) {
        dirs.push(next);
        base = next;
      }
    } catch {}
  }
  return dirs;
}

// The scans are fixed shell scripts, the same commands deny-secret-commit.sh
// runs. Nothing from the agent's command is ever interpolated into them; the
// working directory is passed to the process, not written into the script.
// A `gitleaks:allow` note on a line does not exempt it.
const GITLEAKS_FLAGS = "--no-banner --redact --no-color --ignore-gitleaks-allow";

// gitleaks reads .gitleaks.toml and .gitleaksignore from the folder it scans
// and skips whatever they tell it to, so anyone who can edit them can switch
// the scan off. Only copies exactly as committed are trusted, and never a
// link, whose target git does not track: this prints any others.
const UNSETTLED_SETTINGS = `for f in .gitleaks.toml .gitleaksignore; do
  [ -L "$f" ] && { printf '%s\\n' "$f"; continue; }
  [ -e "$f" ] || continue
  git ls-files --error-unmatch -- "$f" >/dev/null 2>&1 &&
    git diff --quiet HEAD -- "$f" >/dev/null 2>&1 && continue
  printf '%s\\n' "$f"
done`;
// ...plus any whose staged copy differs from the last commit.
const COMMIT_SETTINGS = `${UNSETTLED_SETTINGS}
if git rev-parse -q --verify HEAD >/dev/null 2>&1; then
  git diff --cached --name-only HEAD -- .gitleaks.toml .gitleaksignore
else
  git ls-files --cached -- .gitleaks.toml .gitleaksignore
fi 2>/dev/null`;

const STAGED_SCAN = `gitleaks git --pre-commit --staged ${GITLEAKS_FLAGS} 2>&1`;

// Wider scan: lines added by unstaged changes to tracked files (`git diff`,
// which unlike `git diff HEAD` also works before the first commit; added
// lines only, so a commit that removes a secret is not refused), plus
// untracked files that are not git-ignored. Piped into `gitleaks stdin` so
// only that text is scanned: `detect --no-git --pipe` ignores the pipe and
// scans the whole folder, git-ignored build output included.
const WIDER_SCAN = `{
  git diff --no-ext-diff --no-color -U0 | sed -n 's/^+//p'
  git ls-files --others --exclude-standard -z -- ':/' | xargs -0 cat --
} 2>/dev/null | gitleaks stdin ${GITLEAKS_FLAGS} 2>&1`;

// Every commit on HEAD (even when it is not on a branch), a local branch or
// a tag that no remote has yet. Reading the command for which branches it
// pushes is easy to get wrong, so this covers them all; the cost is that a
// secret on an unpushed branch also blocks pushing another. With no
// remote-tracking branches at all, that is the whole history, which is what
// a first push publishes.
const PUSH_SCAN = `gitleaks git ${GITLEAKS_FLAGS} --log-opts="HEAD --branches --tags --not --remotes" 2>&1`;

// gitleaks also takes its settings from these environment variables, which
// would let them replace the rules the scans rely on.
function scanEnv() {
  const env = { ...process.env };
  delete env.GITLEAKS_CONFIG;
  delete env.GITLEAKS_CONFIG_TOML;
  return env;
}

// Runs a script with `sh` in `cwd`. Resolves to its exit code and output;
// the code is null if it could not be run at all.
function sh(script, cwd) {
  return new Promise((resolve) => {
    let out = "";
    let child;
    try {
      child = spawn("sh", ["-c", script], {
        cwd,
        env: scanEnv(),
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      resolve({ code: null, out });
      return;
    }
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("error", () => resolve({ code: null, out }));
    child.on("close", (code) => resolve({ code, out }));
  });
}

const settingsReason = (files) =>
  `Blocked by secret-guard: gitleaks's settings file(s) ${[...new Set(files.split("\n").filter(Boolean))].join(" ")} are new, changed or a link, or this commit changes them. gitleaks reads these files to decide what to skip, so a change to them can switch the secret scan off. Do not edit, delete or work around them; explain the block to the user, who can check the change and commit it themselves.`;

// Returns the reason to block `cmd` when run in `cwd`, or null to allow it.
// gitleaks exits 1 when it finds a leak; anything else (missing binary, git
// error) is not a finding, so it fails open.
async function blockReason(cmd, cwd) {
  if (!cmd || typeof cmd !== "string" || !cwd) return null;

  // Deliberately loose trigger match (word `git` + word `commit`/`push`
  // anywhere in the command): a false trigger just costs one fast scan, a
  // missed trigger would let a real secret slip into git history.
  const isCommit = hasWord(cmd, "git") && hasWord(cmd, "commit");
  const isPush = hasWord(cmd, "git") && hasWord(cmd, "push");
  if (!isCommit && !isPush) return null;

  // The top of each work tree among the candidate folders; none -> allow
  // (matches deny-secret-commit.sh). Scans run from there: from a subfolder,
  // gitleaks only looks at that subfolder's changes, and reads its settings
  // files there.
  const roots = new Set();
  for (const dir of candidateDirs(cmd, cwd)) {
    const top = await sh("git rev-parse --show-toplevel", dir);
    if (top.code === 0 && top.out.trim()) roots.add(top.out.trim());
  }
  for (const root of roots) {
    const reason = await repoReason(cmd, root, isCommit, isPush);
    if (reason) return reason;
  }
  return null;
}

// The reason to block `cmd` in the work tree whose top is `root`, or null.
async function repoReason(cmd, root, isCommit, isPush) {
  if (isCommit) {
    const settings = await sh(COMMIT_SETTINGS, root);
    if (settings.out.trim()) return settingsReason(settings.out);
    // The staged scan always runs, so the wider scan can only add coverage.
    let scan = await sh(STAGED_SCAN, root);
    if (scan.code !== 1 && isWide(cmd)) scan = await sh(WIDER_SCAN, root);
    if (scan.code === 1) {
      return `Blocked by secret-guard: changes being committed appear to contain a secret (gitleaks detected a match). Do not retry or work around this; unstage/revert the file, rotate the credential, and explain the block to the user.\n${scan.out}`;
    }
  }

  if (isPush) {
    const settings = await sh(UNSETTLED_SETTINGS, root);
    if (settings.out.trim()) return settingsReason(settings.out);
    const scan = await sh(PUSH_SCAN, root);
    if (scan.code === 1) {
      return `Blocked by secret-guard: commit(s) that are not on any remote yet appear to contain a secret (gitleaks detected a match). Do not retry or work around this; rotate the credential and explain the block to the user.\n${scan.out}`;
    }
  }

  return null;
}

// Only a finding blocks: an unexpected error inside the guard must never
// stop an unrelated command.
async function findReason(cmd, cwd) {
  try {
    return await blockReason(cmd, cwd);
  } catch {
    return null;
  }
}

// What the shell tool is left holding once a command is blocked.
const BLOCKED_COMMAND =
  "echo 'Blocked by secret-guard: a secret was detected, so the original command was not run.' >&2; exit 1";

// OpenCode 2. The shell tool is called `shell` (it was `bash` in OpenCode 1);
// its input carries the command and, optionally, a working directory, which
// otherwise defaults to the directory this plugin instance was loaded for.
async function setup(ctx) {
  // OpenCode may probe setup() without a usable context; never throw here.
  if (typeof ctx?.tool?.hook !== "function") return;
  try {
    await ctx.tool.hook("execute.before", async (event) => {
      if (event?.tool !== "shell" && event?.tool !== "bash") return;
      const input = event.input ?? {};
      const base = ctx.location?.directory;
      const workdir = typeof input.workdir === "string" ? input.workdir : "";
      const cwd =
        workdir && (base || path.isAbsolute(workdir))
          ? path.resolve(base ?? "/", workdir)
          : base;
      const reason = await findReason(input.command, cwd);
      if (!reason) return;
      // Throwing rejects the tool call. The command is swapped out first so
      // that the original could not run even if a host ignored the error.
      event.input = { ...input, command: BLOCKED_COMMAND };
      throw new Error(reason);
    });
  } catch {
    // Hook API not available as expected: load without the guard rather
    // than surface as a failed plugin.
  }
}

// OpenCode 1 (1.18.29+).
async function server({ directory } = {}) {
  return {
    "tool.execute.before": async (input, output) => {
      if (input?.tool !== "bash") return;
      const cmd = output?.args?.command ?? input?.args?.command ?? "";
      const cwd =
        output?.args?.workdir ||
        output?.args?.cwd ||
        output?.args?.dir ||
        directory;
      const reason = await findReason(cmd, cwd);
      if (reason) throw new Error(reason);
    },
  };
}

export default {
  id: "secret-guard",
  setup,
  server,
};
