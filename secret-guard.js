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
import path from "node:path";

const hasWord = (cmd, w) =>
  new RegExp(`(^|[^a-zA-Z0-9_])${w}([^a-zA-Z0-9_]|$)`).test(cmd);

const isAllFlag = (cmd) =>
  /(^|\s)(--all|-[a-zA-Z]*a[a-zA-Z]*)(\s|$)/.test(cmd);

// The scans are fixed shell scripts, the same commands deny-secret-commit.sh
// runs. Nothing from the agent's command is ever interpolated into them; the
// working directory is passed to the process, not written into the script.
const GITLEAKS_FLAGS = "--no-banner --redact --no-color";

const STAGED_SCAN = `gitleaks git --pre-commit --staged ${GITLEAKS_FLAGS} 2>&1`;

// Wider scan: what is not staged yet but could still end up in this commit —
// unstaged changes to tracked files (`git diff`, which unlike `git diff HEAD`
// also works before the first commit), plus untracked files that are not
// git-ignored (a `git add --all` chained ahead of the commit hasn't run yet
// when this hook fires). Piped into `gitleaks stdin` so only that text is
// scanned: `detect --no-git --pipe` ignores the pipe and scans the whole
// folder, git-ignored build output included.
const WIDER_SCAN = `{
  git diff --no-ext-diff --no-color
  git ls-files --others --exclude-standard -z -- ':/' | xargs -0 cat --
} 2>/dev/null | gitleaks stdin ${GITLEAKS_FLAGS} 2>&1`;

// Note: `git rev-parse` can print a best-effort guess to stdout even when it
// exits non-zero, so branch on its exit status, not on the captured string.
const PUSH_SCAN = `if upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null) && [ -n "$upstream" ]; then
  range="\${upstream}..HEAD"
elif origin_head=$(git rev-parse --abbrev-ref origin/HEAD 2>/dev/null) && [ -n "$origin_head" ]; then
  range="\${origin_head}..HEAD"
else
  range="-1"
fi
gitleaks git ${GITLEAKS_FLAGS} --log-opts="$range" 2>&1`;

// Runs a script with `sh` in `cwd`. Resolves to its exit code and output;
// the code is null if it could not be run at all.
function sh(script, cwd) {
  return new Promise((resolve) => {
    let out = "";
    let child;
    try {
      child = spawn("sh", ["-c", script], {
        cwd,
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

  // Not inside a git work tree -> allow (matches deny-secret-commit.sh)
  const inRepo = await sh("git rev-parse --is-inside-work-tree", cwd);
  if (inRepo.code !== 0) return null;

  if (isCommit) {
    // The staged scan always runs, so the wider scan can only add coverage.
    let scan = await sh(STAGED_SCAN, cwd);
    if (scan.code !== 1 && isAllFlag(cmd)) scan = await sh(WIDER_SCAN, cwd);
    if (scan.code === 1) {
      return `Blocked by secret-guard: changes being committed appear to contain a secret (gitleaks detected a match). Do not retry or work around this; unstage/revert the file, rotate the credential, and explain the block to the user.\n${scan.out}`;
    }
  }

  if (isPush) {
    const scan = await sh(PUSH_SCAN, cwd);
    if (scan.code === 1) {
      return `Blocked by secret-guard: commit(s) about to be pushed appear to contain a secret (gitleaks detected a match). Do not retry or work around this; rotate the credential and explain the block to the user.\n${scan.out}`;
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
