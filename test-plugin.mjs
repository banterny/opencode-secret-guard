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
import { tmpdir } from "node:os";
import { join } from "node:path";

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

console.log(`\npassed: ${pass}, failed: ${fail}`);
for (const dir of repos) rmSync(dir, { recursive: true, force: true });
process.exit(fail ? 1 : 0);
