#!/usr/bin/env python3
"""公共 API 快照门禁（对齐 wop-typescript-sdk 的 api-extractor 模式）。

`wop_sdk` 的公共 API 面（模块/类/函数/常量的名称、签名、参数、注解、默认值、
装饰器、基类、`__all__` 导出、docstring）以 tests/api_snapshot.json 为基线；
公共 API 变化必须显式重新生成快照并随 PR 提交，防止无意识 API 漂移。

快照由 griffe（版本锁定 1.14.0，见 pyproject dev 组与 ci.yml）**纯静态分析**生成，
无需安装运行时依赖。为保证字节级确定性，序列化时剔除环境相关或非 API 面的字段：
  - git_info：含本机仓库绝对路径与 commit_hash（逐提交必变，硬阻断）
  - filepath / relative_filepath / relative_package_filepath：绝对路径随机器、
    相对路径随 CWD 漂移；模块归属已由对象树结构与各对象 path 字段完整表达
  - lineno / endlineno / source_link：源码行号与 GitHub 溯源链接属位置噪音，
    且 source_link 内嵌 commit hash（逐提交必变），均非 API 面
    （避免插入一行注释或前进一个 commit 即触发门禁）
  - imports：模块内部实现细节，非公共 API
  - 单下划线私有成员：公共 API 门禁只看公共面（语义对齐 api-extractor 只收导出面）

用法: python3 scripts/check-api-snapshot.py [--update]
  默认：重生成到临时文件，与入库快照 `git diff --no-index --exit-code` 比对
        （CI 门禁路径；不依赖快照的 git 跟踪状态，杜绝假绿）
  --update：重新生成覆盖入库快照（有意变更公共 API 后显式更新基线）
退出码: 0 = 快照与公共 API 一致（或已更新）；1 = 存在漂移。
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT = ROOT / "tests" / "api_snapshot.json"

# 与 API 面无关或环境不稳定，序列化前剔除（论证见模块 docstring）。
PRUNE_KEYS = frozenset({
    "git_info",
    "filepath",
    "relative_filepath",
    "relative_package_filepath",
    "lineno",
    "endlineno",
    "source_link",
    "imports",
})


def prune(node):
    """递归剔除不稳定字段与单下划线私有成员（dunder 如 __all__/__init__ 保留）。"""
    if isinstance(node, dict):
        return {
            k: prune(v)
            for k, v in sorted(node.items())
            if k not in PRUNE_KEYS
            and (not k.startswith("_") or k.startswith("__"))
        }
    return [prune(v) for v in node] if isinstance(node, list) else node


def generate() -> str:
    import griffe  # 延迟导入：无 griffe 环境下仍可读用法

    package = griffe.load("wop_sdk", search_paths=[str(ROOT / "src")])
    data = json.loads(package.as_json(full=True))
    return json.dumps(prune(data), indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def main() -> int:
    update = "--update" in sys.argv
    os.chdir(ROOT)  # 锁定工作目录，git diff 与残留路径敏感字段均以仓库根为基准
    text = generate()
    lines = text.count("\n")
    if update:
        SNAPSHOT.write_text(text, encoding="utf-8")
        print(f"快照已更新 → {SNAPSHOT}（{lines} 行，随 PR 提交）")
        return 0
    if not SNAPSHOT.exists():
        print(f"快照缺失: {SNAPSHOT}（用 --update 生成基线）", file=sys.stderr)
        return 1
    # 重生成到临时文件再比对：不改动工作树，且与快照的 git 跟踪状态无关
    # （untracked 场景下 `git diff -- <path>` 会假绿，--no-index 直接比文件内容）。
    tmp_fd, tmp_path = tempfile.mkstemp(prefix="wop-api-snapshot.", suffix=".json")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        proc = subprocess.run(
            ["git", "diff", "--no-index", "--exit-code", str(SNAPSHOT), tmp_path]
        )
    finally:
        os.unlink(tmp_path)
    if proc.returncode:
        print(
            "API SNAPSHOT DRIFT: 公共 API 面与入库快照不一致（见上方 git diff）。\n"
            "有意变更：python3 scripts/check-api-snapshot.py --update 后将快照随 PR 提交；\n"
            "无意漂移：还原 API 变更。",
            file=sys.stderr,
        )
    else:
        print(f"api snapshot ok ({lines} 行)")
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
