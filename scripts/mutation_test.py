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
    python3 scripts/mutation_test.py                          # 全量（落盘 docs/ 报告）
    python3 scripts/mutation_test.py --list                   # 只列变异点统计
    python3 scripts/mutation_test.py --max 30                 # 冒烟（不覆盖 docs/ 报告）
    python3 scripts/mutation_test.py --only-op cmp-eq-neg     # 调试（不覆盖 docs/ 报告）
    python3 scripts/mutation_test.py --min-kill-rate 95       # 门禁：低于则 exit 1（CI）
输出：docs/mutation-report.md + docs/mutation-results.json + stdout 摘要。
计分：击杀率 = 击杀 / (总数 − 等价体)；EQUIVALENT_MUTANTS 白名单命中者自动标注并剔除，
白名单失配（行号漂移/已被击杀）启动告警。
"""
import argparse
import ast
import collections
import io
import json
import math
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
    "sm2crypto.py": ["tests/test_envelope.py", "tests/test_interop.py", "tests/test_mutation_gaps.py"],
    "sm4gcm.py": ["tests/test_envelope.py", "tests/test_mutation_gaps.py"],
    "urllib_transport.py": ["tests/test_transports.py"],
    "httpx_transport.py": ["tests/test_transports.py", "tests/test_mutation_gaps.py"],
    "requests_transport.py": ["tests/test_transports.py", "tests/test_mutation_gaps.py"],
}

# 等价变异体白名单（文件:行:算子 → 论证）：仅收录**严格不可观测**的变异体。
# 命中者标注 EQUIVALENT 并从击杀率分母剔除（score = killed / (total − equivalent)）。
# 纪律（PR #17 Sourcery 审查修正）：
# - 论证是入册硬条件——无论证的条目启动即 fail（_validate_whitelist）；
# - 概率近似（如重试上界 ±1 的 2^-2048）不是等价：csprng 可注入即可观测，
#   此类位点必须补确定性杀测试，不得入册；
# - 论证随白名单单一来源维护，每次全量运行自动写入报告等价体一节；
# - 行号漂移/已被击杀/未生成时启动告警——防白名单静默腐化或滥用。
EQUIVALENT_MUTANTS = {
    "src/wop_sdk/encoding.py:17:str-mut":
        "模块私有 _B64URL_INDEX 仅多一个永不查询的键：唯一消费点是对经字母表正则"
        "校验后的字符查表（\"!\" 已被先行拒绝），且该字典不构成公共 API——严格不可观测",
}

# 教训存档（勿再犯）：
# 1. sm2crypto.py:19 曾以「base-17 数字集包含十六进制数字 ⇒ 解析同值」入册——错在
#    混淆「数字合法」与「位值不变」：base 17 改变每位权值，_N 增大 ≈55 倍，注入
#    b"\\xff"*32 首采即合法。重试上界/边界测试补齐后当场击杀，告警机制拦截。
# 2. httpx/requests 的 __enter__ 返回类型注解字符串曾以「惰性求值不可观测」入册——
#    错在忽视注解反射：字符串写入 __annotations__ 且 get_type_hints 会解析，
#    变异后解析即抛 NameError。已补 TestAnnotationReflection 击杀（CodeRabbit 审查）。
# 凡「不可观测」论证必须穷举反射/内省面；拿不准就不入册、让变异体计入分母。

DEFAULT_MIN_KILL_RATE = 90.0

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
        starts.extend(starts[-1] + len(line.encode("utf-8")) for line in self.lines)
        self.byte_starts = starts

    def off(self, row, col):
        return self.byte_starts[row - 1] + len(self.lines[row - 1][:col].encode("utf-8"))


def _docstring_spans(tree, bmap):
    """AST 定位 module/class/function 的 docstring 字节偏移区间。"""
    spans = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and (node.body and isinstance(node.body[0], ast.Expr) and \
                            isinstance(node.body[0].value, ast.Constant) and isinstance(node.body[0].value.value, str)):
            c = node.body[0].value
            spans.append((bmap.off(c.lineno, c.col_offset), bmap.off(c.end_lineno, c.end_col_offset)))
    return spans


def _pragma_lines(lines):
    return {
        i
        for i, line in enumerate(lines, 1)
        if "pragma: no cover" in line
        or "# pragma" in line
        and "no cover" in line
    }


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
            add(tok, f'{s[:-1]}!"' if s.endswith('"') else f"{s[:-1]}!'", OP_STR)
    return mutants


def collect_target_files():
    files = []
    for dirpath, dirnames, filenames in os.walk(SRC):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        files.extend(
            os.path.join(dirpath, fn)
            for fn in sorted(filenames)
            if fn.endswith(".py") and fn not in EXEMPT_FILES
        )
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


def _assert_src_clean(allow_dirty=False):
    """安全门：src/ 工作区非净 → 拒绝启动（变异注入的前提是可原字节还原）。

    还原正确性的真正依据是运行起点的内存字节快照（逐变异体比对）；
    git 净区是第二道防线。--allow-dirty-src 供本地对未提交工作区跑变异
    （如已验证过语义的未提交修复），CI 保持默认严格。
    """
    dirty = git_src_dirty()
    if dirty and not allow_dirty:
        sys.exit(f"[mutation] src/ 工作区非净，拒绝启动：{dirty}"
                 "（确需对未提交工作区跑变异用 --allow-dirty-src）")
    if dirty:
        print(f"[mutation] 警告：src/ 存在未提交改动，仍按当前字节快照运行：\n{dirty}")


def _gen_all_mutants(files):
    """生成全部目标文件的变异点（未过滤覆盖）。"""
    all_mutants = []
    for f in files:
        all_mutants.extend(gen_mutants_for_file(f))
    return all_mutants


def _print_mutation_stats(all_mutants):
    """打印按算子的变异点统计（--list 的主体输出）。"""
    by_op = collections.Counter(m["op"] for m in all_mutants)
    by_file = collections.Counter(m["file"] for m in all_mutants)
    print("[mutation] 变异点（未过滤覆盖）：")
    for op in ALL_OPS:
        print("  %-14s %d" % (op, by_op.get(op, 0)))
    print("  合计 %d，文件 %d 个" % (len(all_mutants), len(by_file)))


def _filter_by_op(all_mutants, only_op):
    """--only-op 逗号分隔算子过滤（空 → 原样返回）。"""
    if not only_op:
        return all_mutants
    allow = {x.strip() for x in only_op.split(",") if x.strip()}
    return [m for m in all_mutants if m["op"] in allow]


def _select_covered_mutants(all_mutants):
    """跑基线覆盖率（test 上下文）：筛掉无测试触及的行，其余绑定各自要跑的测试集。"""
    line_tests, covered = run_coverage_contexts()
    excluded = []
    mutants = []
    for m in all_mutants:
        rel = m["file"].replace(os.sep, "/")
        if m["row"] not in covered.get(rel, set()):
            excluded.append(m)
        else:
            tests = sorted(line_tests.get((rel, m["row"]), ())) or list(FALLBACK_TESTS.get(os.path.basename(rel), []))
            m["tests"] = tests
            mutants.append(m)
    print("[mutation] 覆盖过滤：有效 %d，排除（无测试触及该行）%d" % (len(mutants), len(excluded)))
    return mutants, excluded


def _snapshot_originals(files):
    """原字节内存备份（还原唯一依据，绝不依赖 git 还原）。"""
    originals = {}
    for f in files:
        with open(f, "rb") as fh:
            originals[f] = fh.read()
    return originals


def _read_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def _run_mutants(mutants, originals):
    """逐变异体：注入 → 只跑覆盖该行的测试 → 原字节还原校验。

    还原守卫（CodeRabbit 审查修正——git 状态串可被并发编辑绕过）：
    - 注入前校验磁盘字节 == 运行起点快照；
    - 恢复前校验磁盘字节 == 本轮写入的变异体字节；
    - 任一不符 = 文件被外部改动：保留现场、绝不覆盖、立即 exit 2；
    - 终态按逐文件字节校验（不再依赖 git status 字符串比较）。
    """
    results = []
    t0 = time.time()
    written = {}  # file → 本工具最后一次写入的字节（守卫基准）
    preserved = []  # 被外部改动、已保留现场未覆盖的文件

    def guard_fail(path, phase):
        print(f"[mutation] 守卫触发（{phase}）：{path} 在运行期间被外部改动，"
              f"保留现场、绝不覆盖；请人工核对该文件", flush=True)
        raise SystemExit(2)

    try:
        for idx, m in enumerate(mutants, 1):
            target = os.path.join(ROOT, m["file"])
            if _read_bytes(target) != originals[target]:
                guard_fail(target, "注入前")
            cur = originals[target]
            mutated = cur[: m["start"]] + m["repl"].encode("utf-8") + cur[m["end"]:]
            with open(target, "wb") as fh:
                fh.write(mutated)
            written[target] = mutated
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
                if _read_bytes(target) != mutated:
                    guard_fail(target, "恢复前")
                with open(target, "wb") as fh:
                    fh.write(originals[target])
                written[target] = originals[target]
                assert _read_bytes(target) == originals[target], f"还原失败 {target}"
            m2 = dict(m)
            m2["status"] = status
            m2.pop("tests", None)
            m2["n_tests"] = len(tests)
            results.append(m2)
            if idx % 25 == 0 or idx == len(mutants):
                killed = sum(x["status"] == "KILLED" for x in results)
                print("  [%d/%d] 击杀 %d（%.1f%%）elapsed %.0fs" % (
                    idx, len(mutants), killed, 100.0 * killed / idx, time.time() - t0), flush=True)
    finally:
        # 终态守卫：只覆盖「当前字节 == 本工具最后一次写入」的文件；
        # 被外部改动过的文件保留现场（guard_fail 已列名），绝不覆盖。
        for f, data in originals.items():
            if f in preserved:
                continue
            now = _read_bytes(f)
            if now == data:
                continue
            if written.get(f) == now:
                with open(f, "wb") as fh:
                    fh.write(data)
            else:
                preserved.append(f)
        if preserved:
            print(f"[mutation] 终态守卫：以下文件被外部改动，已保留现场未还原：{preserved}", flush=True)
            raise SystemExit(2)
        print("[mutation] 还原完成；src/ 与运行起点逐文件字节一致")
    return results


def _write_results_json(results, excluded, killed, survived, kill_rate, equivalents=None, matched=None):
    """写 docs/mutation-results.json（机器可读结果）。"""
    os.makedirs(os.path.join(ROOT, "docs"), exist_ok=True)
    equivalents = equivalents or []
    with open(os.path.join(ROOT, "docs", "mutation-results.json"), "w", encoding="utf-8") as f:
        json.dump({"kill_rate": kill_rate, "killed": len(killed), "survived": len(survived),
                   "equivalent": len(equivalents),
                   "score_base": len(results) - len(equivalents),
                   "total": len(results), "excluded_no_coverage": len(excluded),
                   "whitelist_matched": sorted(matched or ()),
                   "results": results}, f, ensure_ascii=False, indent=1)


def _report_row(x):
    snippet = f'{x["orig"][:40]} → {x["repl"][:40]}'.replace("|", "\\|").replace("\n", " ")
    return "| %s:%d | %s | `%s` |" % (x["file"], x["row"], x["op"], snippet)


def _write_report_md(results, excluded, killed, survived, kill_rate, equivalents=None):
    """写 docs/mutation-report.md（按算子击杀率 + 存活/等价变异体清单）。"""
    equivalents = equivalents or []
    op_stat = collections.defaultdict(lambda: [0, 0])  # op -> [killed, scored]
    for x in results:
        if x["status"] == "EQUIVALENT":
            continue  # 等价体不参与算子击杀率
        op_stat[x["op"]][1] += 1
        if x["status"] == "KILLED":
            op_stat[x["op"]][0] += 1

    score_base = len(results) - len(equivalents)
    lines = [
        "# 变异测试报告（wop-python-sdk）",
        "",
        "- 工具：`scripts/mutation_test.py`（自研 token 级变异器，PIT 不适用 Python）",
        f'- 生成：{time.strftime("%Y-%m-%d %H:%M:%S")}',
        "- 变异体：%d（击杀 %d / 存活 %d / 等价（白名单）%d，另有 %d 个无覆盖行变异点被排除）"
        % (len(results), len(killed), len(survived), len(equivalents), len(excluded)),
        "- **击杀率：%.2f%%**（= 击杀 %d / 计分基数 %d；等价体已从分母剔除）"
        % (kill_rate, len(killed), score_base),
        "",
        "## 按算子（等价体不计入）",
        "",
        "| 算子 | 击杀/计分 | 击杀率 |",
        "|---|---|---|",
    ]
    for op in ALL_OPS:
        k, t = op_stat.get(op, [0, 0])
        if t:
            lines.append("| %s | %d/%d | %.1f%% |" % (op, k, t, 100.0 * k / t))
    if equivalents:
        lines += ["", "## 等价变异体（%d，白名单自动标注，论证随单一来源生成）" % len(equivalents), "",
                  "| 文件:行 | 算子 | 原文 → 变异 | 论证 |", "|---|---|---|---|"]
        for x in equivalents:
            key = f'{x["file"]}:{x["row"]}:{x["op"]}'
            rationale = EQUIVALENT_MUTANTS.get(key, "（缺失——告警已列）")
            lines.append(_report_row(x).rstrip(" |") + " | " + rationale.replace("|", "\\|") + " |")
    if survived:
        lines += ["", "## 存活变异体（%d，需逐条归因：等价论证或补杀测试）" % len(survived), "",
                  "| 文件:行 | 算子 | 原文 → 变异 |", "|---|---|---|"]
        lines.extend(_report_row(x) for x in survived)
    with open(os.path.join(ROOT, "docs", "mutation-report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _annotate_equivalents(results):
    """白名单命中者 SURVIVED → EQUIVALENT；返回（白名单命中集, 异常命中集）。

    异常命中 = 白名单条目本轮不存在（行号漂移/源码重构）或已被击杀（不再是等价体）。
    """
    matched, anomalies = set(), []
    generated = {f'{x["file"]}:{x["row"]}:{x["op"]}': x for x in results}
    for key, x in generated.items():
        if key in EQUIVALENT_MUTANTS:
            matched.add(key)
            if x["status"] == "KILLED":
                anomalies.append(("已击杀，应移出白名单", key))
            elif x["status"] == "SURVIVED":
                x["status"] = "EQUIVALENT"
    for key in sorted(EQUIVALENT_MUTANTS.keys() - matched):
        anomalies.append(("本轮未生成（行号漂移或位点消失）", key))
    return matched, anomalies



def _validate_whitelist():
    """入册硬条件：每条白名单必须携带非空论证（PR #17 Sourcery 评论 2 修正）。"""
    missing = [k for k, v in EQUIVALENT_MUTANTS.items() if not (v or "").strip()]
    if missing:
        sys.exit("[mutation] 白名单条目无论证，拒绝运行：%s" % ", ".join(missing))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="只列变异点统计")
    ap.add_argument("--max", type=int, default=0, help="最多执行 N 个变异体（冒烟；不落盘报告）")
    ap.add_argument("--only-op", default="", help="逗号分隔算子过滤（调试；不落盘报告）")
    ap.add_argument("--min-kill-rate", type=float, default=DEFAULT_MIN_KILL_RATE,
                    help="击杀率门禁（%%，等价体剔除后计）；低于则 exit 1（CI 用）")
    ap.add_argument("--allow-dirty-src", action="store_true",
                    help="允许 src/ 有未提交改动（按当前字节快照变异并还原；CI 勿用）")
    args = ap.parse_args()
    if not math.isfinite(args.min_kill_rate) or not 0 <= args.min_kill_rate <= 100:
        sys.exit("[mutation] --min-kill-rate 必须为 [0,100] 内有限数，实际 %r" % args.min_kill_rate)

    _assert_src_clean(allow_dirty=args.allow_dirty_src)
    _validate_whitelist()

    files = collect_target_files()
    all_mutants = _gen_all_mutants(files)
    _print_mutation_stats(all_mutants)
    if args.list:
        return

    all_mutants = _filter_by_op(all_mutants, args.only_op)
    mutants, excluded = _select_covered_mutants(all_mutants)
    if args.max:
        mutants = mutants[: args.max]

    originals = _snapshot_originals(files)
    results = _run_mutants(mutants, originals)
    matched, anomalies = _annotate_equivalents(results)
    for kind, key in anomalies:
        print("[mutation] 白名单告警：%s：%s" % (kind, key))

    killed = [x for x in results if x["status"] == "KILLED"]
    survived = [x for x in results if x["status"] == "SURVIVED"]
    equivalents = [x for x in results if x["status"] == "EQUIVALENT"]
    score_base = len(results) - len(equivalents)
    kill_rate = 100.0 * len(killed) / score_base if score_base else 0.0

    partial = bool(args.max or args.only_op)
    if partial:
        print("[mutation] 部分运行（--max/--only-op）：不覆盖 docs/ 报告")
    else:
        _write_results_json(results, excluded, killed, survived, kill_rate,
                            equivalents=equivalents, matched=matched)
        _write_report_md(results, excluded, killed, survived, kill_rate,
                         equivalents=equivalents)

    verdict = "达标" if kill_rate >= args.min_kill_rate else "低于门禁 %.1f%%" % args.min_kill_rate
    print("[mutation] 完成：击杀率 %.2f%%（%d/%d，等价体 %d 已剔除），存活 %d —— %s"
          % (kill_rate, len(killed), score_base, len(equivalents), len(survived), verdict))
    if kill_rate < args.min_kill_rate:
        sys.exit(1)

if __name__ == "__main__":
    main()
