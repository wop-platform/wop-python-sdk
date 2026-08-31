#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""docstring 门检查器（wop-python-sdk，契约 2026-08-31）。

度量口径（契约 §度量口径，用户拍板）：
- 对外 API **100%**：非下划线顶层 def/class + 非下划线类方法；
- 内部 API **≥80%**（内部符号集为空 → 视为达标）：下划线顶层 def/class（非 dunder）；
- dunder（``__init__`` 等）豁免；getter/setter、override 不豁免；
- docstring 判定 = ``ast.get_docstring``（SyntaxWarning 抑制）。

反作弊（契约 §反作弊）：
- 扫描面 = ``git ls-files`` 全量输出 + 本脚本侧路径过滤（只认被跟踪文件，
  防未跟踪文件混入；不用 git pathspec ``**``——其对单层目录不匹配，
  改为 Python 侧前缀 + 后缀过滤，见 scan_surface）；
- ``ast.parse`` 抑制 SyntaxWarning（负控制 --self-test 依赖）；
- 输出逐符号缺失清单（路径:行号 符号名），不是只给汇总数字。

CLI（契约 §检查器 CLI 契约）：
- 无参数：exit 0 = 达标；exit 1 = 未达标（含源码不可解析等 fail-closed 情形）；
  stdout = 逐符号缺失清单 + 统计（对外 x/y、内部 a/b），stderr 仅错误；
- ``--self-test``：负控制——内嵌已知坏输入，断言检查逻辑返回非零；
- ``--json``：输出 JSON 统计（供外部消费）。
"""
from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_PREFIX = "src/wop_sdk/"
SCAN_SUFFIX = ".py"
EXTERNAL_TARGET = 1.0  # 对外 API 100%
INTERNAL_TARGET = 0.8  # 内部 API ≥80%（空集=达标）


@dataclass(frozen=True)
class Symbol:
    """一个被度量的声明。

    kind ∈ {"external", "internal"}；dunder 与下划线类方法不在度量面
    （契约 Python 行：内部 = 下划线**顶层** def/class 非 dunder）。
    """

    file: str
    line: int
    qualname: str
    kind: str
    has_doc: bool


def classify(name: str, *, toplevel: bool) -> str | None:
    """符号名 → external / internal / None（豁免不计）。"""
    if name.startswith("__") and name.endswith("__"):
        return None  # dunder 豁免
    if not name.startswith("_"):
        return "external"  # 非下划线：顶层 def/class 与类方法均为对外
    return "internal" if toplevel else None  # 下划线类方法不在度量面


def parse_source(path: str, source: str) -> ast.Module:
    """ast.parse 且抑制 SyntaxWarning（契约：负控制测试依赖）。"""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(source, filename=path)


def _docstring_present(node: ast.AST) -> bool:
    """docstring 判定：ast.get_docstring（契约 Python 口径）。"""
    return ast.get_docstring(node) is not None


def collect_symbols(path: str, tree: ast.Module) -> list[Symbol]:
    """收集度量符号：顶层 def/class + 顶层类的直接方法。"""
    out: list[Symbol] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            kind = classify(node.name, toplevel=True)
            if kind is not None:
                out.append(Symbol(path, node.lineno, node.name, kind,
                                  _docstring_present(node)))
            if isinstance(node, ast.ClassDef):
                for sub in node.body:
                    if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        sub_kind = classify(sub.name, toplevel=False)
                        if sub_kind is not None:
                            out.append(Symbol(path, sub.lineno,
                                              f"{node.name}.{sub.name}", sub_kind,
                                              _docstring_present(sub)))
    return out


def scan_surface() -> list[str]:
    """git ls-files 全量 + Python 侧过滤 → 扫描面（被跟踪的 src/wop_sdk/**.py）。"""
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files 失败: {proc.stderr.strip()}")
    files = [p for p in proc.stdout.split("\0")
             if p.startswith(SCAN_PREFIX) and p.endswith(SCAN_SUFFIX)]
    if not files:
        raise RuntimeError("扫描面为空：src/wop_sdk/ 下没有被跟踪的 .py 文件")
    return sorted(files)


@dataclass(frozen=True)
class Report:
    """度量结果：计数 + 逐符号缺失清单。"""

    external_total: int
    external_doc: int
    internal_total: int
    internal_doc: int
    missing: list[str]  # "路径:行号 符号名"

    @property
    def ok(self) -> bool:
        ext_ok = self.external_doc == self.external_total  # 100%
        int_ok = (self.internal_total == 0  # 空集=达标
                  or self.internal_doc / self.internal_total >= INTERNAL_TARGET)
        return ext_ok and int_ok


def evaluate(symbols: list[Symbol]) -> Report:
    """符号集 → 报告（阈值判定在 Report.ok，契约口径）。"""
    ext = [s for s in symbols if s.kind == "external"]
    inner = [s for s in symbols if s.kind == "internal"]
    missing = [f"{s.file}:{s.line} {s.qualname}"
               for s in symbols if not s.has_doc]
    return Report(len(ext), sum(1 for s in ext if s.has_doc),
                  len(inner), sum(1 for s in inner if s.has_doc), missing)


def scan(files: list[tuple[str, str]]) -> Report:
    """[(路径, 源码)] → 报告；任一文件不可解析 → fail-closed 抛出。"""
    symbols: list[Symbol] = []
    for path, source in files:
        symbols.extend(collect_symbols(path, parse_source(path, source)))
    return evaluate(symbols)


def run() -> Report:
    """主路径：扫描面 → 读文件 → 度量。"""
    files: list[tuple[str, str]] = []
    for rel in scan_surface():
        files.append((rel, (REPO_ROOT / rel).read_text(encoding="utf-8")))
    return scan(files)


# ── 负控制（契约：先红后绿）──────────────────────────────────────────

_BAD_SNIPPET = '''\
def public_api(unused):  # 对外、无 docstring → 必须被判缺失
    escape = "\\d"  # 无效转义序列：触发 SyntaxWarning，检查器必须抑制
    return escape


class PublicKind:
    def method_missing_doc(self):
        return 1

    def _underscore_method(self):  # 下划线类方法：不在度量面
        return 2

    def __dunder__(self):  # dunder：豁免
        return 3
'''

_GOOD_SNIPPET = '''\
def public_api():
    """有 docstring。"""
    return 1


def _internal_no_doc():
    return 2  # 内部无 docstring：≥80% 口径下仍达标（1/2 = 50%? 见断言）
'''


def self_test() -> int:
    """负控制：坏输入必须被判非零（缺失清单非空且不达标），好输入必须达标。

    附加断言：_BAD_SNIPPET 含无效转义序列，parse_source 必须把它吞掉
    （SyntaxWarning 不外溢——stderr 仅错误，契约 CLI 契约）。
    """
    failures: list[str] = []

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", SyntaxWarning)
        bad = scan([("selftest_bad.py", _BAD_SNIPPET)])
    syntax_leaks = [str(w.message) for w in caught
                    if issubclass(w.category, SyntaxWarning)]
    if syntax_leaks:
        failures.append(f"SyntaxWarning 外溢: {syntax_leaks}")

    if bad.ok:
        failures.append("负控制失效：坏输入（对外缺 docstring）未被判定为不达标")
    if "selftest_bad.py:1 public_api" not in bad.missing:
        failures.append(f"顶层缺失未列出: {bad.missing}")
    if "selftest_bad.py:7 PublicKind.method_missing_doc" not in bad.missing:
        failures.append(f"类方法缺失未列出: {bad.missing}")
    if any("_underscore_method" in m or "__dunder__" in m for m in bad.missing):
        failures.append("下划线类方法/dunder 不应进入度量面")

    good = scan([("selftest_good.py", _GOOD_SNIPPET)])
    # good 片段：对外 1/1，内部 0/1 → 0% < 80% 不达标——构造只断言对外侧，
    # 内部阈值单独用一个 2/2 全有 docstring 的片段验证（空集另测）。
    if good.external_total != 1 or good.external_doc != 1:
        failures.append(f"对外计数错误: {good.external_total}/{good.external_doc}")
    full = scan([("selftest_full.py",
                  'def a():\n    """d"""\n\ndef _b():\n    """d"""\n')])
    if not full.ok:
        failures.append(f"全绿样本被误判: {full}")
    empty_internal = scan([("selftest_empty.py", 'def a():\n    """d"""\n')])
    if not empty_internal.ok:
        failures.append(f"内部空集=达标被误判: {empty_internal}")

    if failures:
        for f in failures:
            print(f"self-test FAIL: {f}", file=sys.stderr)
        return 1
    print("self-test OK：负控制（坏输入判非零）+ 正控制（好输入达标）均通过")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="docstring 门检查器（契约 2026-08-31）")
    parser.add_argument("--self-test", action="store_true",
                        help="负控制测试：内嵌坏输入断言检查逻辑返回非零")
    parser.add_argument("--json", action="store_true",
                        help="输出 JSON 统计（供外部消费）")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    try:
        report = run()
    except (SyntaxError, RuntimeError, OSError) as exc:
        print(f"docstring 门 fail-closed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({
            "pass": report.ok,
            "external": {"documented": report.external_doc,
                         "total": report.external_total},
            "internal": {"documented": report.internal_doc,
                         "total": report.internal_total},
            "missing": report.missing,
        }, ensure_ascii=False, indent=2))
        return 0 if report.ok else 1

    for line in report.missing:
        print(line)
    print(f"统计: 对外 {report.external_doc}/{report.external_total}、"
          f"内部 {report.internal_doc}/{report.internal_total}")
    if not report.ok:
        print("结论: docstring 门未达标（对外须 100%，内部须 ≥80%）")
        return 1
    print("结论: docstring 门达标")
    return 0


if __name__ == "__main__":
    sys.exit(main())
