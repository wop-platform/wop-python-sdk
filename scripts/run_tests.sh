#!/usr/bin/env bash
# 工厂测试门（移植四步之四：测试门命令本地化）——pytest 全量双套件：
#   tests/（SDK 283 用例）+ .factory/tests/（工厂自测——质检线自身也在门内）。
# 用法: scripts/run_tests.sh [--no-lock] [pytest-args...]
#   --no-lock 为工厂链约定旗标（上游 run_tests.sh 的锁语义），本仓无锁，消费并忽略。
# 工具链随仓约定（.github/workflows/ci.yml）：setuptools + pip（无 uv）；
# 本地门自动置备 .venv（.gitignore 已忽略）后以 python -m pytest 执行。
# 证据形态：pytest 逐用例输出 + 失败全栈，供 holdout 引用。
set -u -o pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

ARGS=()
for a in "$@"; do
  [ "$a" = "--no-lock" ] && continue
  ARGS+=("$a")
done

PY=".venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "run_tests.sh: 置备 .venv（一次性）..." >&2
  python3 -m venv .venv || { echo "run_tests.sh: venv 创建失败（fail-closed）" >&2; exit 1; }
  .venv/bin/pip install -q --upgrade pip || { echo "run_tests.sh: pip 升级失败（fail-closed）" >&2; exit 1; }
  .venv/bin/pip install -q -e '.[httpx,requests]' pytest pytest-bdd || { echo "run_tests.sh: 依赖安装失败（fail-closed）" >&2; exit 1; }
fi

# 双套件分段执行（各自独立解释器进程）：tests/ 与 .factory/tests/ 均为无
# __init__.py 的平铺布局、conftest.py 同名——同进程收集触发 basename 冲突
# （module conftest 相互覆盖）；分段与 CI（testpaths=tests）及单跑语义一致。
# 退出码归一门域 {0,1}：pytest 收集错误 rc=2 等一律收敛为 1（fail-closed，
# mutations/run.py judge 只认 0/1，非零即拦截）。
RC=0
"$PY" -m pytest tests "${ARGS[@]+"${ARGS[@]}"}" || RC=1
"$PY" -m pytest .factory/tests "${ARGS[@]+"${ARGS[@]}"}" || RC=1
exit "$RC"
