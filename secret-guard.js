// OpenCode port of https://github.com/banterny/claude-code-secret-guard
// Blocks `git commit` / `git push` when the change contains a hardcoded secret,
// detected with gitleaks. Only scans on actual commit/push; all other Bash
// calls return in ~ms with no scan.
//
// Install: requires `gitleaks` 8.19.0+ on PATH (`brew install gitleaks`).
// Loaded automatically from ~/.config/opencode/plugins/ (global) after restart.
// Fails open (allow) when gitleaks/git are unavailable or cwd is not a repo.

export const SecretGuard = async ({ $, directory }) => {
  const hasWord = (cmd, w) =>
    new RegExp(`(^|[^a-zA-Z0-9_])${w}([^a-zA-Z0-9_]|$)`).test(cmd);

  const isAllFlag = (cmd) =>
    /(^|\s)(--all|-[a-zA-Z]*a[a-zA-Z]*)(\s|$)/.test(cmd);

  function shellErrorDetail(e) {
    if (!e) return "";
    if (typeof e.text === "string") return e.text;
    const out = e.stdout ?? e.stderr ?? "";
    try {
      return out?.toString?.() ?? String(out);
    } catch {
      return "";
    }
  }

  return {
    "tool.execute.before": async (input, output) => {
      if (input?.tool !== "bash") return;
      const cmd =
        output?.args?.command ?? input?.args?.command ?? "";
      if (!cmd || typeof cmd !== "string") return;

      const isCommit = hasWord(cmd, "git") && hasWord(cmd, "commit");
      const isPush = hasWord(cmd, "git") && hasWord(cmd, "push");
      if (!isCommit && !isPush) return;

      const cwd =
        output?.args?.workdir ||
        output?.args?.cwd ||
        output?.args?.dir ||
        directory;
      if (!cwd) return;

      // Not inside a git work tree -> allow (matches deny-secret-commit.sh)
      try {
        await $`git rev-parse --is-inside-work-tree`.cwd(cwd).quiet();
      } catch {
        return;
      }

      if (isCommit) {
        try {
          // The staged scan always runs, so the wider scan can only add coverage.
          await $`gitleaks git --pre-commit --staged --no-banner --redact --no-color`.cwd(
            cwd
          ).quiet();
          if (isAllFlag(cmd)) {
            // Wider scan: what is not staged yet but could still end up in
            // this commit — unstaged changes to tracked files (`git diff`,
            // which unlike `git diff HEAD` also works before the first
            // commit), plus untracked files that are not git-ignored (a
            // `git add --all` chained ahead of the commit hasn't run yet
            // when this hook fires). Piped into `gitleaks stdin` so only
            // that text is scanned: `detect --no-git --pipe` ignores the
            // pipe and scans the whole folder, git-ignored build output
            // included.
            await $`git diff --no-ext-diff --no-color | gitleaks stdin --no-banner --redact --no-color`.cwd(
              cwd
            ).quiet();
            await $`git ls-files --others --exclude-standard -z -- :/ | xargs -0 cat -- | gitleaks stdin --no-banner --redact --no-color`.cwd(
              cwd
            ).quiet();
          }
        } catch (e) {
          if (e?.exitCode === 1) {
            throw new Error(
              `Blocked by secret-guard: changes being committed appear to contain a secret (gitleaks detected a match). Do not retry or work around this; unstage/revert the file, rotate the credential, and explain the block to the user.\n${shellErrorDetail(e)}`
            );
          }
          return; // fail open: missing binary, git error, etc.
        }
      }

      if (isPush) {
        let range = "-1";
        try {
          const u = await $`git rev-parse --abbrev-ref --symbolic-full-name '@{u}'`.cwd(cwd).quiet().text();
          if (u?.trim()) range = `${u.trim()}..HEAD`;
          else throw new Error("no upstream");
        } catch {
          try {
            const o = await $`git rev-parse --abbrev-ref origin/HEAD`.cwd(cwd).quiet().text();
            if (o?.trim()) range = `${o.trim()}..HEAD`;
          } catch {
            range = "-1";
          }
        }
        try {
          await $`gitleaks git --no-banner --redact --no-color --log-opts=${range}`.cwd(cwd).quiet();
        } catch (e) {
          if (e?.exitCode === 1) {
            throw new Error(
              `Blocked by secret-guard: commit(s) about to be pushed appear to contain a secret (gitleaks detected a match). Do not retry or work around this; rotate the credential and explain the block to the user.\n${shellErrorDetail(e)}`
            );
          }
          return;
        }
      }
    },
  };
};
