#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""docstring 门检查器（scripts/docstring_gate.py）的 pytest 测试。

与 --self-test 互补：外部驱动（pytest 直接 import 检查器模块），
覆盖 classify / parse_source / collect_symbols / scan_surface /
Report.ok / evaluate / scan / run / self_test / main 及 fail-closed 路径。
"""
from __future__ import annotations

import ast
import json
import runpy
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import docstring_gate as gate  # noqa: E402
from docstring_gate import Report, Symbol  # noqa: E402

GATE_CLI = [sys.executable, str(SCRIPTS_DIR / "docstring_gate.py")]


def _line_of(src: str, needle: str) -> int:
    """源码片段中 needle 首次出现的 1 起始行号（免手工数行）。"""
    return src[: src.index(needle)].count("\n") + 1


# ── classify：符号判定 ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "toplevel", "expected"),
    [
        ("public_fn", True, "external"),
        ("public_fn", False, "external"),
        ("public_cls", True, "external"),
        ("_private", True, "internal"),
        ("_private", False, None),        # 下划线类方法不在度量面
        ("__x", True, "internal"),        # 前置双下划线但非 dunder
        ("__init__", True, None),         # dunder 豁免
        ("__dunder__", False, None),      # dunder 方法豁免
        ("__all__", True, None),
        ("trailing_", True, "external"),  # 仅尾下划线：对外
    ],
)
def test_classify(name, toplevel, expected):
    assert gate.classify(name, toplevel=toplevel) == expected


# ── parse_source：SyntaxWarning 抑制 ─────────────────────────────────


def test_parse_source_returns_module():
    tree = gate.parse_source("m.py", "x = 1\n")
    assert isinstance(tree, ast.Module)


def test_parse_source_suppresses_syntax_warning():
    # 无效转义序列触发 SyntaxWarning，检查器契约要求吞掉（stderr 仅错误）
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", SyntaxWarning)
        gate.parse_source("m.py", 'escape = "\\d"\n')
    assert not [w for w in caught if issubclass(w.category, SyntaxWarning)]


def test_parse_source_syntax_error_raises():
    with pytest.raises(SyntaxError):
        gate.parse_source("m.py", "def broken(:\n")


# ── _docstring_present ───────────────────────────────────────────────


def test_docstring_present_true_and_false():
    tree = gate.parse_source(
        "m.py", 'def a():\n    """d"""\n\ndef b():\n    pass\n')
    fn_a, fn_b = tree.body
    assert gate._docstring_present(fn_a) is True
    assert gate._docstring_present(fn_b) is False


# ── collect_symbols：度量面收集 ───────────────────────────────────────

COLLECT_SRC = '''\
"""模块 docstring。"""
import os


def pub_fn():
    """对外函数。"""


async def pub_async():
    """对外异步函数。"""


def _priv_fn():
    pass


class PubCls:
    """对外类。"""

    flag = 1

    def method(self):
        """方法。"""

    async def amethod(self):
        """异步方法。"""

    def _hidden(self):
        pass

    def __repr__(self):
        return "PubCls"

    class Nested:
        """嵌套类：不收集其本身与内部方法。"""

        def deep(self):
            """deep。"""


class _UnderCls:
    """内部类。"""

    def m(self):
        """m。"""
'''


def test_collect_symbols_full_surface():
    symbols = gate.collect_symbols("m.py", gate.parse_source("m.py", COLLECT_SRC))
    got = [(s.qualname, s.kind, s.has_doc, s.file) for s in symbols]
    assert got == [
        ("pub_fn", "external", True, "m.py"),
        ("pub_async", "external", True, "m.py"),
        ("_priv_fn", "internal", False, "m.py"),
        ("PubCls", "external", True, "m.py"),
        ("PubCls.method", "external", True, "m.py"),
        ("PubCls.amethod", "external", True, "m.py"),
        ("_UnderCls", "internal", True, "m.py"),
        ("_UnderCls.m", "external", True, "m.py"),
    ]
    # 行号取声明行
    by_name = {s.qualname: s for s in symbols}
    assert by_name["pub_fn"].line == _line_of(COLLECT_SRC, "def pub_fn")
    assert by_name["PubCls.method"].line == _line_of(COLLECT_SRC, "def method")
    assert by_name["_UnderCls"].line == _line_of(COLLECT_SRC, "class _UnderCls")


def test_collect_symbols_class_without_docstring():
    src = 'class NoDoc:\n    def missing(self):\n        pass\n\n    def present(self):\n        """有。"""\n'
    symbols = gate.collect_symbols("m.py", gate.parse_source("m.py", src))
    assert [(s.qualname, s.has_doc) for s in symbols] == [
        ("NoDoc", False),
        ("NoDoc.missing", False),
        ("NoDoc.present", True),
    ]


def test_collect_symbols_empty_module():
    assert gate.collect_symbols("m.py", gate.parse_source("m.py", "import os\nx = 1\n")) == []




def test_collect_symbols_toplevel_dunder_exempt():
    src = ('def __dunder_top__():\n    pass\n\n\n'
           'class __Meta__:\n    def m(self):\n        """m。"""\n')
    symbols = gate.collect_symbols("m.py", gate.parse_source("m.py", src))
    # 顶层 dunder def/class 本身豁免（不 append），但 dunder 类体内仍扫描方法
    assert [(s.qualname, s.kind) for s in symbols] == [("__Meta__.m", "external")]


# ── scan_surface：git ls-files 扫描面 ─────────────────────────────────

class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_scan_surface_filters_prefix_suffix_and_sorts(monkeypatch):
    recorded = {}

    def fake_run(cmd, **kwargs):
        recorded["cmd"] = cmd
        return _FakeProc(stdout=(
            "src/wop_sdk/b.py\0README.md\0src/wop_sdk/a.py\0"
            "src/wop_sdk/c.txt\0tests/wop_sdk/x.py\0src/wop_sdk/nested/d.py\0"))

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    assert gate.scan_surface() == [
        "src/wop_sdk/a.py", "src/wop_sdk/b.py",
        "src/wop_sdk/nested/d.py",
    ]
    # 反作弊契约：全量 ls-files + 本脚本侧过滤（-z 防空白字符路径被切坏）
    assert recorded["cmd"][1:4] == ["-C", str(gate.REPO_ROOT), "ls-files"]


def test_scan_surface_git_failure_fail_closed(monkeypatch):
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, **k: _FakeProc(returncode=128, stderr="fatal: not a repo"))
    with pytest.raises(RuntimeError, match="git ls-files 失败"):
        gate.scan_surface()


def test_scan_surface_empty_after_filter(monkeypatch):
    monkeypatch.setattr(gate.subprocess, "run",
                        lambda *a, **k: _FakeProc(stdout="README.md\0docs/x.py\0"))
    with pytest.raises(RuntimeError, match="扫描面为空"):
        gate.scan_surface()


# ── Report.ok：阈值边界 ──────────────────────────────────────────────


def test_report_ok_empty_and_full_green():
    assert Report(0, 0, 0, 0, []).ok is True
    assert Report(2, 2, 2, 2, []).ok is True


def test_report_external_must_be_100_percent():
    assert Report(2, 1, 0, 0, ["m.py:1 pub"]).ok is False


def test_report_internal_empty_set_is_ok():
    assert Report(1, 1, 0, 0, []).ok is True


def test_report_internal_boundary_80_percent():
    assert Report(0, 0, 5, 4, []).ok is True    # 4/5 = 80% 恰好达标（>=）
    assert Report(0, 0, 4, 3, []).ok is False   # 3/4 = 75% 不达标


# ── evaluate / scan ──────────────────────────────────────────────────


def test_evaluate_counts_and_missing_format():
    symbols = [
        Symbol("a.py", 3, "pub", "external", False),
        Symbol("a.py", 9, "_i", "internal", False),
        Symbol("b.py", 1, "pub2", "external", True),
    ]
    report = gate.evaluate(symbols)
    assert report == Report(2, 1, 1, 0, ["a.py:3 pub", "a.py:9 _i"])


def test_scan_merges_files_and_fail_closed():
    good = 'def api():\n    """d"""\n\ndef _h():\n    """d"""\n'
    report = gate.scan([("m1.py", good), ("m2.py", 'def api2():\n    """d"""\n')])
    assert report.external_total == 2 and report.external_doc == 2
    assert report.internal_total == 1 and report.internal_doc == 1
    assert report.ok is True
    # 空输入 → 空报告，达标
    assert gate.scan([]) == Report(0, 0, 0, 0, [])
    # 任一文件不可解析 → fail-closed 抛出
    with pytest.raises(SyntaxError):
        gate.scan([("m1.py", good), ("bad.py", "def (:\n")])


# ── run：真实 git 集成（临时仓库）────────────────────────────────────


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def test_run_reads_only_tracked_files(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    pkg = tmp_path / "src" / "wop_sdk"
    pkg.mkdir(parents=True)
    (pkg / "mod.py").write_text('def api():\n    """d"""\n', encoding="utf-8")
    # 反作弊：未跟踪文件即使落在扫描前缀下也不进入度量面
    (pkg / "rogue.py").write_text("def rogue_missing():\n    pass\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", "src/wop_sdk/mod.py")

    report = gate.run()
    assert report == Report(1, 1, 0, 0, [])
    assert report.ok is True


def test_run_unreadable_file_raises_os_error(tmp_path, monkeypatch):
    monkeypatch.setattr(gate, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(gate, "scan_surface", lambda: ["src/wop_sdk/absent.py"])
    with pytest.raises(OSError):
        gate.run()


# ── self_test：负控制 ────────────────────────────────────────────────


def test_self_test_passes(capsys):
    assert gate.self_test() == 0
    assert "self-test OK" in capsys.readouterr().out


def test_self_test_reports_failures(monkeypatch, capsys):
    def fake_scan(files):
        name = files[0][0]
        if name == "selftest_bad.py":
            # ok=True → 负控制失效；缺失清单含下划线方法 → 不该进度量面；
            # 缺 top-level/类方法条目 → 缺失清单不完整
            return Report(1, 1, 0, 0, ["selftest_bad.py:2 PublicKind._underscore_method"])
        if name == "selftest_good.py":
            return Report(0, 0, 0, 0, [])   # 对外计数错
        return Report(0, 0, 1, 0, [])       # full / empty_internal 均被误判

    monkeypatch.setattr(gate, "scan", fake_scan)
    assert gate.self_test() == 1
    err = capsys.readouterr().err
    for fragment in ("负控制失效", "顶层缺失未列出", "类方法缺失未列出",
                     "不应进入度量面", "对外计数错误", "全绿样本被误判",
                     "内部空集=达标被误判"):
        assert fragment in err


@pytest.mark.filterwarnings("ignore::SyntaxWarning")
def test_self_test_detects_syntax_warning_leak(monkeypatch, capsys):
    def leaky_parse(path, source):
        warnings.warn("invalid escape sequence '\\d'", SyntaxWarning)
        return ast.parse(source, filename=path)

    monkeypatch.setattr(gate, "parse_source", leaky_parse)
    assert gate.self_test() == 1
    assert "SyntaxWarning 外溢" in capsys.readouterr().err


# ── main：CLI 行为与 exit 码 ─────────────────────────────────────────


def test_main_ok_exit0(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["docstring_gate.py"])
    monkeypatch.setattr(gate, "run", lambda: Report(1, 1, 1, 1, []))
    assert gate.main() == 0
    out = capsys.readouterr().out
    assert "统计: 对外 1/1、内部 1/1" in out
    assert "结论: docstring 门达标" in out


def test_main_not_ok_exit1(capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["docstring_gate.py"])
    monkeypatch.setattr(gate, "run",
                        lambda: Report(2, 1, 0, 0, ["a.py:3 pub", "b.py:9 Cls.m"]))
    assert gate.main() == 1
    out = capsys.readouterr().out
    assert "a.py:3 pub" in out and "b.py:9 Cls.m" in out
    assert "结论: docstring 门未达标" in out


@pytest.mark.parametrize("ok", [True, False])
def test_main_json(ok, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["docstring_gate.py", "--json"])
    monkeypatch.setattr(gate, "run",
                        lambda: Report(2, 1, 1, 0, ["a.py:3 pub"]) if not ok
                        else Report(1, 1, 1, 1, []))
    assert gate.main() == (0 if ok else 1)
    payload = json.loads(capsys.readouterr().out)
    assert payload["pass"] is ok
    assert payload["external"] == {"documented": 1, "total": 1} if ok else \
        payload["external"] == {"documented": 1, "total": 2}
    assert payload["missing"] == [] if ok else payload["missing"] == ["a.py:3 pub"]


def test_main_self_test_dispatch(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["docstring_gate.py", "--self-test"])
    monkeypatch.setattr(gate, "self_test", lambda: 7)
    assert gate.main() == 7


@pytest.mark.parametrize("exc", [SyntaxError("bad source"), RuntimeError("git dead"),
                                 OSError("read failed")])
def test_main_fail_closed(exc, capsys, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["docstring_gate.py"])

    def broken_run():
        raise exc

    monkeypatch.setattr(gate, "run", broken_run)
    assert gate.main() == 1
    assert "docstring 门 fail-closed" in capsys.readouterr().err


def test_main_unknown_argument_exits_2(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["docstring_gate.py", "--bogus"])
    with pytest.raises(SystemExit) as ei:
        gate.main()
    assert ei.value.code == 2


# ── __main__ 守卫与外部 CLI 契约 ─────────────────────────────────────


def test_script_dunder_main_runs_real_gate(monkeypatch):
    # run_name="__main__" 走 sys.exit(main())：真实仓库、真实扫描面
    monkeypatch.setattr(sys, "argv", ["docstring_gate.py"])
    with pytest.raises(SystemExit) as ei:
        runpy.run_path(str(SCRIPTS_DIR / "docstring_gate.py"), run_name="__main__")
    assert ei.value.code == 0


def test_cli_no_args_green():
    proc = subprocess.run(GATE_CLI, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "结论: docstring 门达标" in proc.stdout
    assert proc.stderr == ""


def test_cli_json_and_self_test():
    proc = subprocess.run(GATE_CLI + ["--json"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["pass"] is True
    proc = subprocess.run(GATE_CLI + ["--self-test"], capture_output=True, text=True)
    assert proc.returncode == 0
    assert "self-test OK" in proc.stdout
