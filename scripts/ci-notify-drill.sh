#!/usr/bin/env bash
# CI 失败通知闭环演练（沉淀自 2026-08-29 drill/ci-failure-notify 演练）
#
# 背景：notify-failure/notify-recovery 只在 CI 失败/成功时执行，纯绿流水线
# 上永远不会跑到——不演练等于没测（首版 -R 缺失 bug 即由演练抓出）。
#
# 流程：临时分支注入必败测试 → dispatch 红 run → 断言自动开单 →
#       移除必败测试 → dispatch 绿 run → 断言自动关单 → 清理。
# main 历史零污染；幂等跟踪 issue 只会被本脚本开/关。
#
# 用法：scripts/ci-notify-drill.sh  （需 gh 已登录、工作区干净、可 push）
set -euo pipefail

REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"   # gh 命令用 owner/repo
GIT_REMOTE="${GIT_REMOTE:-origin}"                                 # git 命令用 remote 名
BRANCH="drill/ci-notify-$(date +%s)"
SEARCH="CI 失败跟踪 in:title"
TEST_FILE="tests/test_suites.py"
INJECT=$'\ndef test_drill_forced_failure():\n    assert False, "drill: 验证 notify 闭环，随脚本自动移除"\n'

log() { printf '\033[1;34m[drill]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[drill] FAIL:\033[0m %s\n' "$*" >&2; exit 1; }
cleanup() {
  git checkout -q "${ORIG_BRANCH:-main}" 2>/dev/null || true
  git push -q "$GIT_REMOTE" --delete "$BRANCH" 2>/dev/null || true
  git branch -q -D "$BRANCH" 2>/dev/null || true
}
trap cleanup EXIT

command -v gh >/dev/null || die "需要 gh CLI"
[ -z "$(git status --porcelain)" ] || die "工作区不干净"
ORIG_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

wait_run() {  # 等待分支最新 dispatch run 结束，输出 conclusion
  local run_id=""
  for _ in $(seq 1 30); do
    run_id="$(gh run list -R "$REPO" --branch "$BRANCH" --event workflow_dispatch \
      --limit 1 --json databaseId --jq '.[0].databaseId' 2>/dev/null || true)"
    [ -n "$run_id" ] && break
    sleep 2
  done
  [ -n "$run_id" ] || die "未发现 dispatch run"
  gh run watch "$run_id" -R "$REPO" >/dev/null 2>&1 || true
  gh run view "$run_id" -R "$REPO" --json conclusion --jq .conclusion
}

open_issue() {  # 输出当前 open 跟踪 issue 编号（空=无）
  gh issue list -R "$REPO" --state open --search "$SEARCH" --json number --jq '.[0].number // ""'
}

PRE="$(open_issue)"
[ -z "$PRE" ] || die "已有 open 跟踪 issue #$PRE，先处理再演练"

log "1/6 建演练分支并注入必败测试：$BRANCH"
git checkout -q -b "$BRANCH"
printf '%s' "$INJECT" >> "$TEST_FILE"
git add "$TEST_FILE" && git commit -q -m "drill: 注入必败测试（演练自动开单）"
git push -q "$GIT_REMOTE" "$BRANCH" --set-upstream

log "2/6 dispatch 红 run"
gh workflow run ci.yml -R "$REPO" --ref "$BRANCH"
[ "$(wait_run)" = "failure" ] || die "红 run 预期 failure"

log "3/6 断言自动开单"
sleep 5
ISSUE="$(open_issue)"
[ -n "$ISSUE" ] || die "红 run 后未见自动开单"

log "4/6 移除必败测试，dispatch 绿 run"
python3 - "$TEST_FILE" << 'PY'
import sys
p = sys.argv[1]
s = open(p).read()
bad = '\ndef test_drill_forced_failure():\n    assert False, "drill: 验证 notify 闭环，随脚本自动移除"\n'
assert bad in s, "注入的必败测试不存在"
open(p, 'w').write(s.replace(bad, ''))
PY
git add "$TEST_FILE" && git commit -q -m "drill: 移除必败测试（演练自动关单）"
git push -q "$GIT_REMOTE" "$BRANCH"

gh workflow run ci.yml -R "$REPO" --ref "$BRANCH"
[ "$(wait_run)" = "success" ] || die "绿 run 预期 success"

log "5/6 断言自动关单（issue #$ISSUE）"
sleep 5
STATE="$(gh issue view "$ISSUE" -R "$REPO" --json state --jq .state)"
[ "$STATE" = "CLOSED" ] || die "绿 run 后 issue #$ISSUE 仍为 $STATE"

log "6/6 清理演练分支"
log "PASS：开单(#$ISSUE) → 关单 闭环验证通过"
