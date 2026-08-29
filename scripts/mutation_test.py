#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WOP Python SDK 变异测试（PIT 为 JVM 工具、mutmut 未随环境交付 → 自研 token 级变异器）。

设计：
- 变异算子 14 类（≥10 要求），覆盖条件 / 数学 / 位运算 / 布尔 / 返回值 / 常量 / 控制流：
    1  cmp-eq-neg     == ↔ !=                        （条件）
    2  cmp-boundary   < ↔ <=，> ↔ >=                  （条件边界）
    3  bool-and-or    and ↔ or                        （布尔逻辑）
    4  not-drop       删除一元 not                    （布尔逻辑）
    5  arith-add-sub  + ↔ -                           （数学）
    6  arith-mul-div  * ↔ //，// ↔ *                  （数学）
    7  bitwise-and-or & ↔ |                           （位运算）
    8  bitwise-xor    ^ → &                           （位运算）
    9  num-inc        数值常量 n → n+1                （常量）
    10 num-zero       数值常量 n → 0                  （常量）
    11 str-mut        字符串常量 s → s + "!"          （常量）
    12 bool-flip      True ↔ False                    （常量）
    13 return-none    return EXPR → return None       （返回值）
    14 raise-drop     raise ... → pass                （控制流）
- 变异点筛选：跳过 docstring（AST 定位）、`# pragma: no cover` 行、
  覆盖率上下文未触及的行（该行没有任何测试执行则变异必存活，无度量意义）；
  `src/wop_sdk/__init__.py` 纯再导出 + __version__，无协议语义，整文件豁免。
- 测试选择：coverage `--cov-context=test` 建立 行 → 覆盖测试 映射，
  每个变异体只跑覆盖该行的测试（PIT 同思路），超时 120s 记 killed。
- 安全协议：启动前要求 `git status --porcelain -- src/` 为空；
  每个变异体执行后立即按内存中的原始字节还原并校验；
  结束时再次校验 git 干净。任何异常路径（含 Ctrl-C）都走 finally 还原。

用法：
    python3 scripts/mutation_test.py                 # 全量
    python3 scripts/mutation_test.py --list          # 只列变异点统计
    python3 scripts/mutation_test.py --max 30        # 冒烟
    python3 scripts/mutation_test.py --only-op cmp-eq-neg,return-none
输出：docs/mutation-report.md + docs/mutation-results.json + stdout 摘要。
"""
import argparse
import ast
import collections
import io
import json
import os
import subprocess
import sys
import time
import tokenize

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src", "wop_sdk")
EXEMPT_FILES = {"__init__.py"}  # 纯再导出，无协议语义
MAX_TESTS_PER_MUTANT = 40
MUTANT_TIMEOUT_S = 120

# 仅空上下文行（导入期/模块级常量，未被任何单个 test 上下文归属）的回退测试集：
# 按模块归属选择其行为契约所在的测试文件，避免逐变异体全量跑（40s+）。
FALLBACK_TESTS = {
    "client.py": ["tests/test_client.py", "tests/test_bdd.py", "tests/test_mutation_gaps.py"],
    "envelope.py": ["tests/test_envelope.py", "tests/test_interop.py"],
    "encoding.py": ["tests/test_encoding.py"],
    "keys.py": ["tests/test_keys.py", "tests/test_mutation_gaps.py"],
    "suites.py": ["tests/test_suites.py"],
    "digest.py": ["tests/test_digest.py"],
    "signature.py": ["tests/test_signature.py"],
    "canonical.py": ["tests/test_canonical.py"],
    "errors.py": ["tests/test_client.py"],
    "sm2crypto.py": ["tests/test_envelope.py", "tests/test_interop.py"],
    "sm4gcm.py": ["tests/test_envelope.py", "tests/test_mutation_gaps.py"],
    "urllib_transport.py": ["tests/test_transports.py"],
    "httpx_transport.py": ["tests/test_transports.py"],
    "requests_transport.py": ["tests/test_transports.py"],
}

OP_CMP_EQ = "cmp-eq-neg"
OP_CMP_BOUND = "cmp-boundary"
OP_BOOL = "bool-and-or"
OP_NOT = "not-drop"
OP_ADD = "arith-add-sub"
OP_MUL = "arith-mul-div"
OP_BIT_AO = "bitwise-and-or"
OP_BIT_XOR = "bitwise-xor"
OP_NUM_INC = "num-inc"
OP_NUM_ZERO = "num-zero"
OP_STR = "str-mut"
OP_BOOL_FLIP = "bool-flip"
OP_RET = "return-none"
OP_RAISE = "raise-drop"

ALL_OPS = [
    OP_CMP_EQ, OP_CMP_BOUND, OP_BOOL, OP_NOT, OP_ADD, OP_MUL,
    OP_BIT_AO, OP_BIT_XOR, OP_NUM_INC, OP_NUM_ZERO, OP_STR,
    OP_BOOL_FLIP, OP_RET, OP_RAISE,
]

CMP_PAIR = {"==": "!=", "!=": "=="}
BOUND_PAIR = {"<": "<=", "<=": "<", ">": ">=", ">=": ">"}
ADD_PAIR = {"+": "-", "-": "+"}
MUL_PAIR = {"*": "//", "//": "*"}
BIT_AO_PAIR = {"&": "|", "|": "&"}
XOR_MAP = {"^": "&"}


class ByteOffsetMap:
    """(row, col) 字符坐标 → 字节偏移。

    tokenize/AST 的列号是字符数（Unicode code point），而变异拼接必须按字节进行；
    中英文混排源码中两者不可混用——首轮运行曾因按字符偏移切字节，把变异体
    拼进中文注释（假存活）或破坏语法（假击杀），整轮作废。此修复后二进制安全。
    """

    def __init__(self, text):
        self.lines = text.splitlines(keepends=True)
        starts = [0]
        for line in self.lines:
            starts.append(starts[-1] + len(line.encode("utf-8")))
        self.byte_starts = starts

    def off(self, row, col):
        return self.byte_starts[row - 1] + len(self.lines[row - 1][:col].encode("utf-8"))


def _docstring_spans(tree, bmap):
    """AST 定位 module/class/function 的 docstring 字节偏移区间。"""
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.body and isinstance(node.body[0], ast.Expr) and \
                    isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str):
                c = node.body[0].value
                spans.append((bmap.off(c.lineno, c.col_offset), bmap.off(c.end_lineno, c.end_col_offset)))
    return spans


def _pragma_lines(lines):
    bad = set()
    for i, line in enumerate(lines, 1):
        if "pragma: no cover" in line or "# pragma" in line and "no cover" in line:
            bad.add(i)
    return bad


def gen_mutants_for_file(path):
    """生成单文件全部变异体：dict(file, rel, row, op, start, end, orig, repl)。"""
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8")
    rel = os.path.relpath(path, ROOT)
    bmap = ByteOffsetMap(text)
    lines = bmap.lines
    pragma = _pragma_lines(lines)
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    doc_spans = _docstring_spans(tree, bmap)
    toks = list(tokenize.generate_tokens(io.StringIO(text).readline))
    mutants = []

    def add(tok, repl, op):
        if tok.start[0] in pragma:
            return
        if any(s <= bmap.off(*tok.start) < e for s, e in doc_spans):
            return
        mutants.append({
            "file": rel, "row": tok.start[0], "op": op,
            "start": bmap.off(*tok.start), "end": bmap.off(*tok.end),
            "orig": tok.string, "repl": repl,
        })

    def logical_line_end(idx):
        """从 idx 起找该逻辑行最后一个有效 token 的结束偏移（遇 NEWLINE/COMMENT 止）。"""
        end_off = bmap.off(*toks[idx].end)
        j = idx + 1
        while j < len(toks) and toks[j].type not in (tokenize.NEWLINE, tokenize.COMMENT, tokenize.ENDMARKER):
            if toks[j].type not in (tokenize.NL, tokenize.INDENT, tokenize.DEDENT):
                end_off = bmap.off(*toks[j].end)
            j += 1
        return end_off, toks[idx].end[0] == toks[j - 1].end[0]

    def prev_significant(idx):
        j = idx - 1
        while j >= 0 and toks[j].type in (tokenize.NL, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT):
            j -= 1
        return toks[j] if j >= 0 else None

    def next_significant(idx):
        j = idx + 1
        while j < len(toks) and toks[j].type in (tokenize.NL, tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT):
            j += 1
        return toks[j] if j < len(toks) else None

    def add_span(start_off, end_off, row, orig, repl, op):
        if row in pragma:
            return
        if any(s <= start_off < e for s, e in doc_spans):
            return
        mutants.append({
            "file": rel, "row": row, "op": op,
            "start": start_off, "end": end_off, "orig": orig, "repl": repl,
        })

    for i, tok in enumerate(toks):
        s = tok.string
        if tok.type == tokenize.OP:
            if s in CMP_PAIR:
                add(tok, CMP_PAIR[s], OP_CMP_EQ)
            elif s in BOUND_PAIR:
                add(tok, BOUND_PAIR[s], OP_CMP_BOUND)
            elif s in ADD_PAIR:
                add(tok, ADD_PAIR[s], OP_ADD)
            elif s in MUL_PAIR and s == "*":
                # 跳过 *args 解包（前 token 为 '(' 或 ',' 且后接 NAME/说明符）
                p, n = prev_significant(i), next_significant(i)
                if not (p and p.type == tokenize.OP and p.string in ("(", ",")
                        and n and n.type == tokenize.NAME):
                    add(tok, "//", OP_MUL)
            elif s == "//":
                add(tok, "*", OP_MUL)
            elif s in BIT_AO_PAIR:
                add(tok, BIT_AO_PAIR[s], OP_BIT_AO)
            elif s in XOR_MAP:
                add(tok, XOR_MAP[s], OP_BIT_XOR)
        elif tok.type == tokenize.NAME:
            if s in ("and", "or"):
                add(tok, "or" if s == "and" else "and", OP_BOOL)
            elif s in ("True", "False"):
                add(tok, "False" if s == "True" else "True", OP_BOOL_FLIP)
            elif s == "not":
                n = next_significant(i)
                p = prev_significant(i)
                if not (n and n.string == "in") and not (p and p.string == "is"):
                    add(tok, "", OP_NOT)  # 删除 not（表达式整体否定语义翻转）
            elif s == "return":
                n = next_significant(i)
                if n is not None and n.type not in (tokenize.NEWLINE, tokenize.COMMENT,
                                                   tokenize.NL, tokenize.INDENT, tokenize.DEDENT):
                    end_off, _ = logical_line_end(i)
                    ret_end = bmap.off(*tok.end)
                    add_span(ret_end, end_off, tok.start[0],
                             raw[ret_end:end_off].decode("utf-8", "replace"), " None", OP_RET)
            elif s == "raise":
                p = prev_significant(i)
                if p is None or p.type in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT) or \
                        (p.type == tokenize.OP and p.string in (";", ":")):
                    end_off, _ = logical_line_end(i)
                    raise_start = bmap.off(*tok.start)
                    add_span(raise_start, end_off, tok.start[0],
                             raw[raise_start:end_off].decode("utf-8", "replace"), "pass", OP_RAISE)
        elif tok.type == tokenize.NUMBER:
            try:
                val = int(s, 0)
            except ValueError:
                continue
            add(tok, str(val + 1), OP_NUM_INC)
            if val != 0:
                add(tok, "0", OP_NUM_ZERO)
        elif tok.type == tokenize.STRING:
            # 字符串常量：s → s + "!"（前缀与引号保留，闭合引号前插入）
            if s.endswith(('"""', "'''")) or "\n" in s:
                continue
            add(tok, s[:-1] + '!"' if s.endswith('"') else s[:-1] + "!'", OP_STR)
    return mutants


def collect_target_files():
    files = []
    for dirpath, dirnames, filenames in os.walk(SRC):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in sorted(filenames):
            if fn.endswith(".py") and fn not in EXEMPT_FILES:
                files.append(os.path.join(dirpath, fn))
    return sorted(files)


def run_coverage_contexts():
    """跑全量测试并产出带 test 上下文的 .coverage；要求基线全绿。返回 行→测试 映射。"""
    print("[mutation] 基线：全量测试 + --cov-context=test ...", flush=True)
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--cov=wop_sdk", "--cov-branch",
         "--cov-context=test", "-q", "--cov-report="],
        cwd=ROOT, timeout=1800,
    )
    if r.returncode != 0:
        sys.exit("[mutation] 基线测试非绿（exit %d），拒绝变异" % r.returncode)
    import coverage

    cd = coverage.CoverageData(os.path.join(ROOT, ".coverage"))
    cd.read()
    contexts = sorted(c for c in cd.measured_contexts() if c)
    line_tests = collections.defaultdict(set)  # (relfile, line) -> {test}
    covered = collections.defaultdict(set)
    for measured in cd.measured_files():
        abspath = measured if os.path.isabs(measured) else os.path.abspath(os.path.join(ROOT, measured))
        rel = os.path.relpath(abspath, ROOT).replace(os.sep, "/")
        covered[rel] = set()
        for ln, ctxs in (cd.contexts_by_lineno(abspath) or {}).items():
            covered[rel].add(ln)
            for t in ctxs:
                if t:
                    line_tests[(rel, ln)].add(t)
    print("[mutation] 上下文 %d 个，覆盖行文件 %d 个" % (len(contexts), len(covered)), flush=True)
    return line_tests, covered


def git_src_dirty():
    r = subprocess.run(["git", "-C", ROOT, "status", "--porcelain", "--", "src/"],
                       capture_output=True, text=True)
    return r.stdout.strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="只列变异点统计")
    ap.add_argument("--max", type=int, default=0, help="最多执行 N 个变异体（冒烟）")
    ap.add_argument("--only-op", default="", help="逗号分隔算子过滤")
    args = ap.parse_args()

    if git_src_dirty():
        sys.exit("[mutation] src/ 工作区非净，拒绝启动：%s" % git_src_dirty())

    files = collect_target_files()
    all_mutants = []
    for f in files:
        all_mutants.extend(gen_mutants_for_file(f))

    by_op = collections.Counter(m["op"] for m in all_mutants)
    by_file = collections.Counter(m["file"] for m in all_mutants)
    print("[mutation] 变异点（未过滤覆盖）：")
    for op in ALL_OPS:
        print("  %-14s %d" % (op, by_op.get(op, 0)))
    print("  合计 %d，文件 %d 个" % (len(all_mutants), len(by_file)))
    if args.list:
        return

    if args.only_op:
        allow = {x.strip() for x in args.only_op.split(",") if x.strip()}
        all_mutants = [m for m in all_mutants if m["op"] in allow]

    line_tests, covered = run_coverage_contexts()
    excluded = []
    mutants = []
    for m in all_mutants:
        rel = m["file"].replace(os.sep, "/")
        if m["row"] not in covered.get(rel, set()):
            excluded.append(m)
        else:
            tests = sorted(line_tests.get((rel, m["row"]), ()))
            if not tests:  # 空上下文行（导入期/模块常量）→ 模块归属回退；再缺则全量兜底
                tests = list(FALLBACK_TESTS.get(os.path.basename(rel), []))
            m["tests"] = tests
            mutants.append(m)
    print("[mutation] 覆盖过滤：有效 %d，排除（无测试触及该行）%d" % (len(mutants), len(excluded)))
    if args.max:
        mutants = mutants[: args.max]

    originals = {}
    for f in files:
        with open(f, "rb") as fh:
            originals[f] = fh.read()

    results = []
    t0 = time.time()
    try:
        for idx, m in enumerate(mutants, 1):
            target = os.path.join(ROOT, m["file"])
            with open(target, "rb") as fh:
                cur = fh.read()
            mutated = cur[: m["start"]] + m["repl"].encode("utf-8") + cur[m["end"]:]
            with open(target, "wb") as fh:
                fh.write(mutated)
            tests = m["tests"][:MAX_TESTS_PER_MUTANT]  # 空列表 → pytest 无参全量兜底（防误判 SURVIVED）
            try:
                r = subprocess.run(
                    [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider",
                     "--no-cov"] + tests,
                    cwd=ROOT, timeout=MUTANT_TIMEOUT_S,
                    env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
                    capture_output=True,
                )
                status = "SURVIVED" if r.returncode == 0 else "KILLED"
            except subprocess.TimeoutExpired:
                status = "KILLED"
            finally:
                with open(target, "wb") as fh:
                    fh.write(originals[target])
                with open(target, "rb") as fh:
                    assert fh.read() == originals[target], "还原失败 %s" % target
            m2 = dict(m)
            m2["status"] = status
            m2.pop("tests", None)
            m2["n_tests"] = len(tests)
            results.append(m2)
            if idx % 25 == 0 or idx == len(mutants):
                killed = sum(1 for x in results if x["status"] == "KILLED")
                print("  [%d/%d] 击杀 %d（%.1f%%）elapsed %.0fs" % (
                    idx, len(mutants), killed, 100.0 * killed / idx, time.time() - t0), flush=True)
    finally:
        for f, data in originals.items():
            with open(f, "wb") as fh:
                fh.write(data)
        dirty = git_src_dirty()
        print("[mutation] 还原完成；src/ %s" % ("干净" if not dirty else "仍脏！！%s" % dirty))
        if dirty:
            sys.exit(1)

    killed = [x for x in results if x["status"] == "KILLED"]
    survived = [x for x in results if x["status"] == "SURVIVED"]
    kill_rate = 100.0 * len(killed) / len(results) if results else 0.0
    op_stat = collections.defaultdict(lambda: [0, 0])  # op -> [killed, total]
    for x in results:
        op_stat[x["op"]][1] += 1
        if x["status"] == "KILLED":
            op_stat[x["op"]][0] += 1

    os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
    with open(os.path.join(ROOT, "docs", "mutation-results.json"), "w", encoding="utf-8") as f:
        json.dump({"kill_rate": kill_rate, "killed": len(killed), "survived": len(survived),
                   "total": len(results), "excluded_no_coverage": len(excluded),
                   "results": results}, f, ensure_ascii=False, indent=1)

    lines = [
        "# 变异测试报告（wop-python-sdk）",
        "",
        "- 工具：`scripts/mutation_test.py`（自研 token 级变异器，PIT 不适用 Python）",
        "- 生成：%s" % time.strftime("%Y-%m-%d %H:%M:%S"),
        "- 变异体：%d（击杀 %d / 存活 %d，另有 %d 个无覆盖行变异点被排除）" % (
            len(results), len(killed), len(survived), len(excluded)),
        "- **击杀率：%.2f%%**（目标 ≥90%%）" % kill_rate,
        "",
        "## 按算子",
        "",
        "| 算子 | 击杀/总数 | 击杀率 |",
        "|---|---|---|",
    ]
    for op in ALL_OPS:
        k, t = op_stat.get(op, [0, 0])
        if t:
            lines.append("| %s | %d/%d | %.1f%% |" % (op, k, t, 100.0 * k / t))
    if survived:
        lines += ["", "## 存活变异体（%d）" % len(survived), "",
                  "| 文件:行 | 算子 | 原文 → 变异 |", "|---|---|---|"]
        for x in survived:
            snippet = ("%s → %s" % (x["orig"][:40], x["repl"][:40])).replace("|", "\\|").replace("\n", " ")
            lines.append("| %s:%d | %s | `%s` |" % (x["file"], x["row"], x["op"], snippet))
    with open(os.path.join(ROOT, "docs", "mutation-report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print("[mutation] 完成：击杀率 %.2f%%（%d/%d），存活 %d → docs/mutation-report.md"
          % (kill_rate, len(killed), len(results), len(survived)))


if __name__ == "__main__":
    main()
