#!/usr/bin/env bash
# Local simulation of the Week 2 CI gate (same rule: fail on any HIGH/CRITICAL finding).
# Semgrep + Gitleaks gate; Trivy is added in the GitHub workflow.
set -uo pipefail
cd /mnt/c/Users/super/software-security/labs/week02-sdlc-tooling || exit 2
target="${1:-./prompt-test}"
export NO_COLOR=1

echo "==> gate: semgrep (SAST) on $target"
docker run --rm -v "$PWD/$target:/src" semgrep/semgrep \
  semgrep --config p/default --config p/owasp-top-ten /src --severity ERROR --quiet
sem=$?

echo
echo "==> gate: gitleaks (secrets) on $target"
leaks=$(docker run --rm -v "$PWD/$target:/repo" zricethezav/gitleaks:latest \
  detect --no-git -s /repo -v --redact 2>&1 | grep -E "RuleID|File:|Line:|leaks found|no leaks")
echo "$leaks"

fail=0
echo "$leaks" | grep -q "leaks found: [1-9]" && fail=1
[ "$sem" -ne 0 ] && fail=1

echo
if [ "$fail" -eq 1 ]; then
  echo "SECURITY GATE: FAILED  (HIGH/CRITICAL findings present — merge blocked)"
  exit 1
else
  echo "SECURITY GATE: PASSED"
fi
