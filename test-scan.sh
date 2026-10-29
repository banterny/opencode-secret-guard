#!/usr/bin/env bash
# Test harness for the scan layer used by secret-guard.js. Builds a real
# scratch git repo and exercises the exact gitleaks commands the plugin
# shells out to — trigger-adjacent logic (commit vs commit -a vs push)
# plus clean/blocked outcomes. No network access, nothing touches real repos.
#
# NOTE: this tests the gitleaks scan commands, not the plugin itself — see
# test-plugin.mjs for that. For end-to-end (needs a running OpenCode
# session), stage a file with a fake token in a scratch repo and ask the
# agent to commit — it should be blocked with a `Blocked by secret-guard…`
# message.
set -u
pass=0
fail=0

# Hermetic: ignore the user's and the system's git config, so the fixture
# commits below are not refused by a globally installed git hook (such as
# the pre-commit hook from claude-code-secret-guard, via core.hooksPath).
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

# Generated at runtime, not a literal, so this file itself never contains a
# real token-shaped string (it would trip gitleaks/GitHub push protection).
TOK="ghp_$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)"

REPO=$(mktemp -d "${TMPDIR:-/tmp}/opencode-secret-guard-test.XXXXXX") || exit 1
cd "$REPO" || exit 1
git init -q
git config user.email test@test.com
git config user.name test
echo "hello" > README.md
git add README.md
git commit -qm init >/dev/null

check() { # $1 = expected exit (0|1), $2 = description, $3... = command
  local expected="$1" desc="$2"
  shift 2
  "$@" >/dev/null 2>&1
  local rc=$?
  if [ "$rc" = "$expected" ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    echo "FAIL expected exit=$expected got=$rc : $desc"
  fi
}

check_pipe() { # $1 = expected exit, $2 = description; the plugin's commit -a scans: staged first, then the wider scan unless a leak was already found
  local expected="$1" desc="$2" rc
  gitleaks git --pre-commit --staged --no-banner --redact --no-color >/dev/null 2>&1
  rc=$?
  if [ "$rc" != "1" ]; then
    {
      git diff --no-ext-diff --no-color
      git ls-files --others --exclude-standard -z -- ':/' | xargs -0 cat --
    } 2>/dev/null | gitleaks stdin --no-banner --redact --no-color >/dev/null 2>&1
    rc=$?
  fi
  if [ "$rc" = "$expected" ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    echo "FAIL expected exit=$expected got=$rc : $desc"
  fi
}

# ---- plain commit path: gitleaks git --pre-commit --staged ----
echo "clean content" > clean1.txt
git add clean1.txt
check 0 "clean staged -> allow" gitleaks git --pre-commit --staged --no-banner --redact --no-color
git reset -q

echo "TOKEN=$TOK" > secret1.txt
git add secret1.txt
check 1 "secret staged -> block" gitleaks git --pre-commit --staged --no-banner --redact --no-color
git reset -q
rm -f secret1.txt

# ---- commit -a path: unstaged tracked changes via pipe ----
echo "TOKEN=$TOK" >> README.md
check_pipe 1 "secret unstaged (commit -a) -> block"
git checkout -q -- README.md

echo "a harmless readme edit" >> README.md
check_pipe 0 "clean unstaged (commit -a) -> allow"
git checkout -q -- README.md

# ---- push path: tip-commit scan ----
git add clean1.txt
git commit -qm "clean history" >/dev/null 2>&1 || true
echo "TOKEN=$TOK" > leak.txt
git add leak.txt
git commit -qm "leak commit" >/dev/null
check 1 "secret tip commit (push) -> block" gitleaks git --no-banner --redact --no-color --log-opts=-1

# ==== wider-scan regressions ====
# The commit -a scan must look at the change being committed, not at the
# folder. Second scratch repo with a git-ignored build folder holding a fake
# secret (the shape of Next.js's `.next/`): nothing in it can ever be
# committed, so it must never cause a block.
#
# (The plugin also reaches this scan for commands that are not commits at
# all — e.g. a file search naming `.git` and a file with "commit" in its
# name, plus a flag such as `-name`. That is a trigger decision inside the
# plugin, which test-plugin.mjs covers; at scan level it is the same case
# as the first check below.)
REPO2=$(mktemp -d "${TMPDIR:-/tmp}/opencode-secret-guard-test.XXXXXX") || exit 1
cd "$REPO2" || exit 1
git init -q
git config user.email test@test.com
git config user.name test
echo "build/" > .gitignore
echo "hello" > README.md
git add .gitignore README.md
git commit -qm init >/dev/null
mkdir build
echo "TOKEN=$TOK" > build/generated.js

echo "clean content" > file.txt
git add file.txt
check_pipe 0 "secret only in git-ignored folder, clean staged change (commit -a) -> allow"

echo "a harmless readme edit" >> README.md
check_pipe 0 "secret only in git-ignored folder, clean unstaged change (commit -a) -> allow"
git checkout -q -- README.md

echo "TOKEN=$TOK" >> README.md
check_pipe 1 "secret unstaged, tracked file (commit -a) -> block"
git checkout -q -- README.md

echo "TOKEN=$TOK" > secret4.txt
git add secret4.txt
check 1 "secret staged -> block" gitleaks git --pre-commit --staged --no-banner --redact --no-color
check_pipe 1 "secret staged (commit -a) -> block"
git reset -q -- secret4.txt
rm -f secret4.txt

# brand-new untracked file, added earlier in the same chained command: not
# in any diff yet when the plugin fires
echo "TOKEN=$TOK" > new-secret.txt
check_pipe 1 "secret in untracked, non-ignored file (add --all && commit) -> block"
rm -f new-secret.txt

git commit -qm "clean commit" >/dev/null
check 0 "clean tip commit, secret only in git-ignored folder (push) -> allow" gitleaks git --no-banner --redact --no-color --log-opts=-1

echo "TOKEN=$TOK" > secret5.txt
git add secret5.txt
git commit -qm "leak commit" >/dev/null
check 1 "secret tip commit (push) -> block" gitleaks git --no-banner --redact --no-color --log-opts=-1
check 1 "secret in pushed range (push) -> block" gitleaks git --no-banner --redact --no-color --log-opts=HEAD~1..HEAD

# ---- repo with no commits yet (no HEAD to diff against) ----
REPO3=$(mktemp -d "${TMPDIR:-/tmp}/opencode-secret-guard-test.XXXXXX") || exit 1
cd "$REPO3" || exit 1
git init -q
git config user.email test@test.com
git config user.name test

echo "TOKEN=$TOK" > first.txt
git add first.txt
check_pipe 1 "no commits yet, secret staged (commit -a) -> block"

echo "clean" > first.txt
git add first.txt
echo "TOKEN=$TOK" >> first.txt
check_pipe 1 "no commits yet, secret unstaged in a staged file (commit -a) -> block"

echo ""
echo "passed: $pass, failed: $fail"
cd / && rm -rf "$REPO" "$REPO2" "$REPO3"
[ "$fail" -eq 0 ] || exit 1
