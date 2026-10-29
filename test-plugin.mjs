#!/usr/bin/env node
// Test harness for the plugin file itself (test-scan.sh only tests the
// gitleaks commands). Checks that secret-guard.js has the shape OpenCode 2
// will load, then registers it against a stand-in plugin context and feeds
// the hook real commands in scratch git repos.
//
// Run with `node test-plugin.mjs` (or `bun test-plugin.mjs`). No network
// access, no OpenCode session, nothing touches your real repos.
//
// NOTE: this proves the plugin's own logic, not that a running OpenCode
// loads it — for that, see "Verify it loads" in the README.
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Hermetic: ignore the user's and the system's git config, so the fixture
// commits below are not refused by a globally installed git hook (such as
// the pre-commit hook from claude-code-secret-guard, via core.hooksPath).
process.env.GIT_CONFIG_GLOBAL = "/dev/null";
process.env.GIT_CONFIG_NOSYSTEM = "1";

// Generated at runtime, not a literal, so this file itself never contains a
// real token-shaped string (it would trip gitleaks/GitHub push protection).
const TOK =
  "ghp_" + randomBytes(64).toString("base64").replace(/[^A-Za-z0-9]/g, "").slice(0, 36);

let pass = 0;
let fail = 0;
const repos = [];

function ok(cond, desc) {
  if (cond) pass++;
  else {
    fail++;
    console.log(`FAIL ${desc}`);
  }
}
function git(dir, ...args) {
  execFileSync("git", args, { cwd: dir, stdio: "ignore" });
}
function newDir() {
  const dir = mkdtempSync(join(tmpdir(), "opencode-secret-guard-plugin."));
  repos.push(dir);
  return dir;
}
function newRepo() {
  const dir = newDir();
  git(dir, "init", "-q");
  git(dir, "config", "user.email", "test@test.com");
  git(dir, "config", "user.name", "test");
  return dir;
}

// ---- shape: what OpenCode 2 checks before it will load a plugin ----
const mod = await import(new URL("./secret-guard.js", import.meta.url).href);
const plugin = mod.default;
ok(plugin && typeof plugin === "object", "default export is a plugin definition object");
ok(typeof plugin?.id === "string" && plugin.id.length > 0, "definition has an id");
ok(typeof plugin?.setup === "function", "definition has a setup function (OpenCode 2)");
ok(typeof plugin?.server === "function", "definition has a server function (OpenCode 1.18.29+)");

if (fail > 0) {
  console.log(`\npassed: ${pass}, failed: ${fail}`);
  console.log("secret-guard.js is not in the OpenCode 2 plugin format; skipping behaviour tests.");
  process.exit(1);
}

// OpenCode may probe setup() with no context; it must not throw.
try {
  await plugin.setup(undefined);
  await plugin.setup({});
  pass++;
} catch {
  fail++;
  console.log("FAIL setup() must not throw when given no usable context");
}

// ---- stand-ins for the two hosts ----
async function v2Hook(directory) {
  const hooks = {};
  await plugin.setup({
    location: { directory },
    tool: {
      hook: async (name, callback) => {
        hooks[name] = callback;
        return { dispose: async () => {} };
      },
    },
  });
  return hooks["execute.before"];
}
async function check(expected, dir, command, { tool = "shell", workdir, base = dir } = {}) {
  const hook = await v2Hook(base);
  let verdict = "allow";
  let detail = "";
  const event = { tool, input: workdir ? { command, workdir } : { command } };
  if (typeof hook !== "function") {
    verdict = "no hook registered";
  } else {
    try {
      await hook(event);
    } catch (e) {
      verdict = "block";
      detail = String(e?.message ?? e).split("\n")[0].slice(0, 160);
    }
  }
  ok(verdict === expected, `expected=${expected} got=${verdict} : ${command}${detail ? `\n    ${detail}` : ""}`);
  // A blocked command must also be swapped out of the tool's input, and an
  // allowed one must be left exactly as it was.
  ok(
    (event.input.command === command) === (verdict !== "block"),
    `command ${verdict === "block" ? "should be replaced when blocked" : "should be untouched when allowed"} : ${command}`,
  );
}
async function checkV1(expected, dir, command, tool = "bash") {
  const hooks = await plugin.server({ directory: dir });
  let verdict = "allow";
  try {
    await hooks["tool.execute.before"]({ tool }, { args: { command } });
  } catch {
    verdict = "block";
  }
  ok(verdict === expected, `[OpenCode 1 path] expected=${expected} got=${verdict} : ${command}`);
}

// ---- repo with a git-ignored build folder holding a fake secret ----
const r = newRepo();
writeFileSync(join(r, ".gitignore"), "build/\n");
writeFileSync(join(r, "README.md"), "hello\n");
git(r, "add", ".gitignore", "README.md");
git(r, "commit", "-qm", "init");
mkdirSync(join(r, "build"));
writeFileSync(join(r, "build", "generated.js"), `TOKEN=${TOK}\n`);

// trigger matching: must allow without scanning
await check("allow", r, "ls -la");
await check("allow", r, "git status");
await check("allow", r, "docker push myimage");
await check("allow", r, 'git commit -m "x"', { tool: "read" });

// clean staged change, unrelated `-a` later in the chain -> allow
writeFileSync(join(r, "file.txt"), "clean\n");
git(r, "add", "file.txt");
await check("allow", r, 'git add file.txt && git commit -m "x" && git branch -a');
// not a commit at all: a file search naming `.git` and "commit" -> allow
await check("allow", r, 'find . -maxdepth 3 -name "deny-secret-commit.sh" -not -path "./.git/*"');
// clean unstaged edit under -a -> allow
appendFileSync(join(r, "README.md"), "a harmless edit\n");
await check("allow", r, 'git commit -am "x"');
git(r, "checkout", "-q", "--", "README.md");

// real secret under -a (tracked file, modified, not staged) -> block
appendFileSync(join(r, "README.md"), `TOKEN=${TOK}\n`);
await check("block", r, 'git commit -am "x"');
await check("allow", r, 'git commit -m "x"');
git(r, "checkout", "-q", "--", "README.md");

// real secret, staged -> block; and block again (the hook must survive its own block)
writeFileSync(join(r, "secret4.txt"), `TOKEN=${TOK}\n`);
git(r, "add", "secret4.txt");
await check("block", r, 'git commit -m "x"');
await check("block", r, 'git commit -m "x"');
await check("block", r, 'git commit -am "x"');
await check("block", r, 'git commit -m "x"', { tool: "bash" });
await checkV1("block", r, 'git commit -m "x"');
await checkV1("allow", r, 'git commit -m "x"', "read");
// working folder given by the tool call rather than the plugin's location
await check("block", r, 'git commit -m "x"', { workdir: r, base: tmpdir() });
await check("block", r, 'git commit -m "x"', { workdir: ".", base: r });
git(r, "reset", "-q", "--", "secret4.txt");
rmSync(join(r, "secret4.txt"));
await checkV1("allow", r, 'git commit -m "x"');

// brand-new untracked secret file, added earlier in the same chain -> block
writeFileSync(join(r, "new secret.txt"), `TOKEN=${TOK}\n`);
await check("block", r, 'git add --all && git commit -m "x"');
await check("block", r, 'git add . && git commit -am "x"');
rmSync(join(r, "new secret.txt"));
await check("allow", r, 'git commit -am "x"');

// push: clean tip commit, secret only in the ignored folder -> allow
git(r, "commit", "-qm", "clean commit");
await check("allow", r, "git push");
// push: real secret in a commit being pushed -> block
writeFileSync(join(r, "secret5.txt"), `TOKEN=${TOK}\n`);
git(r, "add", "secret5.txt");
git(r, "commit", "-qm", "leak commit");
await check("block", r, "git push origin main");
await checkV1("block", r, "git push origin main");

// ---- repo with no commits yet (no HEAD to diff against) ----
const r3 = newRepo();
writeFileSync(join(r3, "first.txt"), `TOKEN=${TOK}\n`);
git(r3, "add", "first.txt");
await check("block", r3, 'git commit -am "first"');
writeFileSync(join(r3, "first.txt"), "clean\n");
git(r3, "add", "first.txt");
appendFileSync(join(r3, "first.txt"), `TOKEN=${TOK}\n`);
await check("block", r3, 'git commit -am "first"');

// ---- not a git repo -> allow (skip silently, no crash) ----
await check("allow", newDir(), 'git commit -am "x"');

// ==== gaps found in review (Oct 2026) ====
function repoWith(name) {
  // repo with one commit, in a fresh scratch folder; name may contain spaces
  const dir = join(newDir(), name);
  mkdirSync(dir);
  git(dir, "init", "-q");
  git(dir, "config", "user.email", "test@test.com");
  git(dir, "config", "user.name", "test");
  writeFileSync(join(dir, "README.md"), "hello\n");
  git(dir, "add", "README.md");
  git(dir, "commit", "-qm", "init");
  return dir;
}
const ALLOW_ALL = '[allowlist]\npaths = [".*"]\n';

// a gitleaks:allow note on the line does not exempt it
const g1 = repoWith("allow-note");
writeFileSync(join(g1, "s.txt"), `TOKEN=${TOK} # gitleaks:allow\n`);
git(g1, "add", "s.txt");
await check("block", g1, 'git commit -m "x"');

// gitleaks settings files not committed exactly as they are
const g2 = repoWith("settings");
writeFileSync(join(g2, ".gitleaks.toml"), ALLOW_ALL);
writeFileSync(join(g2, "s.txt"), `TOKEN=${TOK}\n`);
git(g2, "add", "s.txt");
await check("block", g2, 'git commit -m "x"');
await check("block", g2, "git push");
rmSync(join(g2, ".gitleaks.toml"));
writeFileSync(join(g2, ".gitleaksignore"), "s.txt:github-pat:1\n");
await check("block", g2, 'git commit -m "x"');
rmSync(join(g2, ".gitleaksignore"));
git(g2, "reset", "-q");
writeFileSync(join(g2, ".gitleaks.toml"), '[extend]\nuseDefault = true\n[allowlist]\npaths = ["fixtures/"]\n');
git(g2, "add", ".gitleaks.toml");
await check("block", g2, 'git commit -m "add scanner settings"');
git(g2, "commit", "-qm", "settings, committed by the user");
mkdirSync(join(g2, "fixtures"));
writeFileSync(join(g2, "fixtures", "sample.txt"), `TOKEN=${TOK}\n`);
git(g2, "add", "fixtures");
await check("allow", g2, 'git commit -m "x"'); // committed settings are trusted...
git(g2, "add", "s.txt");
await check("block", g2, 'git commit -m "x"'); // ...and skip only what they say
writeFileSync(join(g2, ".gitleaks.toml"), ALLOW_ALL);
await check("block", g2, 'git commit -m "x"'); // committed settings, edited in place
git(g2, "checkout", "-q", "--", ".gitleaks.toml");
// GITLEAKS_CONFIG in the environment is ignored
writeFileSync(join(g2, "..", "allow-all.toml"), ALLOW_ALL);
process.env.GITLEAKS_CONFIG = join(g2, "..", "allow-all.toml");
await check("block", g2, 'git commit -m "x"');
delete process.env.GITLEAKS_CONFIG;

// a `git add` earlier in the command; the new file isn't staged yet
const g3 = repoWith("chained-add");
writeFileSync(join(g3, "new.txt"), `TOKEN=${TOK}\n`);
await check("block", g3, 'git add . && git commit -m "x"');
await check("block", g3, 'git add -A && git commit -m "x"');
await check("block", g3, 'git stage new.txt && git commit -m "x"');
await check("block", g3, 'git -C . add new.txt && git commit -m "x"');
await check("allow", g3, 'git commit -m "add the token later"'); // "add" in a message isn't a git add
rmSync(join(g3, "new.txt"));
// removing a committed secret is not refused, even by the wider scan
writeFileSync(join(g3, "old.txt"), `TOKEN=${TOK}\n`);
git(g3, "add", "old.txt");
git(g3, "commit", "-qm", "fixture: a secret committed earlier");
writeFileSync(join(g3, "old.txt"), "gone\n");
await check("allow", g3, 'git add . && git commit -m "remove token"');
await check("allow", g3, 'git commit -am "remove token"');

// commit run from a subfolder, and commands that move into the repo
const g4 = repoWith("with space");
mkdirSync(join(g4, "sub"));
writeFileSync(join(g4, "sub", "a.txt"), "x\n");
git(g4, "add", "sub");
git(g4, "commit", "-qm", "layout");
writeFileSync(join(g4, "root.txt"), `TOKEN=${TOK}\n`);
git(g4, "add", "root.txt");
const outside = join(g4, "..");
await check("block", g4, 'git commit -m "x"', { workdir: "sub" });
await check("block", g4, `cd "${g4}" && git commit -m x`, { base: outside });
await check("block", g4, `cd '${g4}'; git commit -m x`, { base: outside });
await check("block", g4, 'cd "with space" && git commit -m x', { base: outside });
await check("block", g4, `git -C "${g4}" commit -m x`, { base: outside });
await check("allow", g4, 'cd "no such folder" && git commit -m x', { base: outside });

// push of a branch other than the current one
const g5 = repoWith("pushes");
const remote = join(g5, "..", "remote.git");
execFileSync("git", ["init", "-q", "--bare", remote], { stdio: "ignore" });
git(g5, "remote", "add", "origin", remote);
git(g5, "push", "-q", "origin", "HEAD:main");
await check("allow", g5, "git push"); // everything is already on the remote
git(g5, "checkout", "-q", "-b", "feature");
writeFileSync(join(g5, "s.txt"), `TOKEN=${TOK}\n`);
git(g5, "add", "s.txt");
git(g5, "commit", "-qm", "fixture: leak commit");
git(g5, "checkout", "-q", "-");
await check("block", g5, "git push origin feature");
await check("block", g5, "git push --all");
// a push from a detached HEAD (the commit is on no branch)
git(g5, "checkout", "-q", "--detach");
writeFileSync(join(g5, "detached.txt"), `TOKEN=${TOK}\n`);
git(g5, "add", "detached.txt");
git(g5, "commit", "-qm", "fixture: leak on a detached HEAD");
git(g5, "branch", "-q", "-D", "feature");
await check("block", g5, "git push origin HEAD:main");

// a decoy cd or -C into a folder that is not a repo
const g6 = repoWith("decoy");
writeFileSync(join(g6, "s.txt"), `TOKEN=${TOK}\n`);
git(g6, "add", "s.txt");
const notRepo = join(g6, "..", "not-a-repo");
mkdirSync(notRepo);
await check("block", g6, `cd "${notRepo}" && cd "${g6}" && git commit -m x`);
await check("block", g6, `git -C "${notRepo}" status; git commit -m x`);

// a settings file that is a link to a file outside the repo
const g7 = repoWith("linked-settings");
const outsideToml = join(g7, "..", "outside.toml");
writeFileSync(outsideToml, "[extend]\nuseDefault = true\n");
symlinkSync(outsideToml, join(g7, ".gitleaks.toml"));
git(g7, "add", ".gitleaks.toml");
git(g7, "commit", "-qm", "fixture: settings as a link");
writeFileSync(outsideToml, ALLOW_ALL);
writeFileSync(join(g7, "s.txt"), `TOKEN=${TOK}\n`);
git(g7, "add", "s.txt");
await check("block", g7, 'git commit -m "x"');

// a committed settings file that pulls in a file outside the repo
const g8 = repoWith("extended-settings");
const outside2 = join(g8, "..", "outside2.toml");
writeFileSync(outside2, "[extend]\nuseDefault = true\n");
writeFileSync(join(g8, ".gitleaks.toml"), `[extend]\npath = "${outside2}"\n`);
git(g8, "add", ".gitleaks.toml");
git(g8, "commit", "-qm", "fixture: settings extend an outside file");
writeFileSync(outside2, ALLOW_ALL);
writeFileSync(join(g8, "s.txt"), `TOKEN=${TOK}\n`);
git(g8, "add", "s.txt");
await check("block", g8, 'git commit -m "x"');
git(g8, "reset", "-q");
rmSync(join(g8, "s.txt"));
// ...while one inside the repo, committed as it is, is trusted
mkdirSync(join(g8, "cfg"));
mkdirSync(join(g8, "fixtures"));
writeFileSync(join(g8, "cfg", "base.toml"), '[extend]\nuseDefault = true\n[allowlist]\npaths = ["fixtures/"]\n');
writeFileSync(join(g8, ".gitleaks.toml"), '[extend]\npath = "cfg/base.toml"\n');
git(g8, "add", "cfg", ".gitleaks.toml");
git(g8, "commit", "-qm", "fixture: settings extend a file in the repo");
writeFileSync(join(g8, "fixtures", "f.txt"), `TOKEN=${TOK}\n`);
git(g8, "add", "fixtures");
await check("allow", g8, 'git commit -m "x"');
writeFileSync(join(g8, "cfg", "base.toml"), ALLOW_ALL);
await check("block", g8, 'git commit -m "x"'); // the extended file, edited in place
git(g8, "checkout", "-q", "--", "cfg/base.toml");

// push while HEAD is a new, empty branch
const g9 = repoWith("unborn");
git(g9, "checkout", "-q", "-b", "leaky");
writeFileSync(join(g9, "s.txt"), `TOKEN=${TOK}\n`);
git(g9, "add", "s.txt");
git(g9, "commit", "-qm", "fixture: leak commit");
git(g9, "checkout", "-q", "--orphan", "empty");
await check("block", g9, "git push origin leaky");

console.log(`\npassed: ${pass}, failed: ${fail}`);
for (const dir of repos) rmSync(dir, { recursive: true, force: true });
process.exit(fail ? 1 : 0);
