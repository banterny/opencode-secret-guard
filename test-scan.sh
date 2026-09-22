#!/usr/bin/env bash
# Test harness for the scan layer used by secret-guard.js. Builds a real
# scratch git repo and exercises the exact gitleaks commands the plugin
# shells out to — trigger-adjacent logic (commit vs commit -a vs push)
# plus clean/blocked outcomes. No network access, nothing touches real repos.
#
# NOTE: this tests the gitleaks scan commands, not the plugin hook itself
# (the hook needs a running OpenCode session). For end-to-end, stage a file
# with a fake token in a scratch repo and ask the agent to commit — it
# should be blocked with a `Blocked by secret-guard…` message.
set -u
pass=0
fail=0

# Generated at runtime, not a literal, so this file itself never contains a
# real token-shaped string (it would trip gitleaks/GitHub push protection).
TOK="ghp_$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)"

REPO=$(mktemp -d "${TMPDIR:-/tmp}/opencode-secret-guard-test.XXXXXX")
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

check_pipe() { # $1 = expected exit, $2 = description; reads $REPO diff via pipe
  local expected="$1" desc="$2"
  git diff HEAD 2>/dev/null | gitleaks detect --no-git --pipe --no-banner --redact --no-color >/dev/null 2>&1
  local rc=$?
  if [ "$rc" = "$expected" ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    echo "FAIL expected exit=$expected got=$rc : $desc"
  fi
}

# ---- plain commit path: gitleaks protect --staged ----
echo "clean content" > clean1.txt
git add clean1.txt
check 0 "clean staged -> allow" gitleaks protect --staged --no-banner --redact --no-color
git reset -q

echo "TOKEN=$TOK" > secret1.txt
git add secret1.txt
check 1 "secret staged -> block" gitleaks protect --staged --no-banner --redact --no-color
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
check 1 "secret tip commit (push) -> block" gitleaks detect --no-banner --redact --no-color --log-opts=-1

echo ""
echo "passed: $pass, failed: $fail"
cd / && rm -rf "$REPO"
[ "$fail" -eq 0 ] || exit 1
