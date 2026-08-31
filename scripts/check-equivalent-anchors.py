#!/usr/bin/env python3
"""等价白名单锚点漂移检测（六仓统一模式，wop-python-sdk 实例）。

白名单（scripts/mutation_test.py EQUIVALENT_MUTANTS，已论证条目随审查增删）
仅在变异运行时做失配告警，而 mutation job 为 schedule/dispatch 级——PR 间漂移不可见。
本脚本在每 PR 上独立校验两层：
  1. 白名单 (文件, 行, 算子) 与锚快照 tests/equivalent-anchors.txt 一致；
  2. 锚快照的源码行前缀与当前源码一致。
快照由本脚本 --init 生成（等价论证入册时同步重生成）。

用法: python3 scripts/check-equivalent-anchors.py [--init]
退出码: 0 = 全部锚点吻合；1 = 存在漂移（同步白名单与快照后重跑）。
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
SNAPSHOT = ROOT / "tests" / "equivalent-anchors.txt"


def load_whitelist() -> set[str]:
    from mutation_test import EQUIVALENT_MUTANTS  # noqa: PLC0415
    return set(EQUIVALENT_MUTANTS)


def source_line(file: str, line: int) -> str:
    return (ROOT / file).read_text(encoding="utf-8").split("\n")[line - 1].strip()


def main() -> int:
    keys = load_whitelist()
    if "--init" in sys.argv:
        rows = []
        for k in sorted(keys):
            file, line, op = k.rsplit(":", 2)
            rows.append(f"{k}:{source_line(file, int(line))[:24]}")
        SNAPSHOT.write_text("\n".join(rows) + "\n", encoding="utf-8")
        print(f"快照生成 {len(rows)} 条 → {SNAPSHOT}")
        return 0
    if not SNAPSHOT.exists():
        print(f"锚快照缺失: {SNAPSHOT}（先 --init）", file=sys.stderr)
        return 1
    drifted = []
    snap: dict[str, str] = {}
    for row in SNAPSHOT.read_text(encoding="utf-8").split("\n"):
        if row.count(":") >= 3 and not row.startswith("#"):
            key, anchor = row.rsplit(":", 1)
            snap[key] = anchor
    if set(snap) != keys:
        drifted.append(f"白名单与快照键集不一致：白名单 {len(keys)} 条 vs 快照 {len(snap)} 条"
                       f"（差集 {keys ^ set(snap)}）")
    for k in sorted(keys & set(snap)):
        file, line, _op = k.rsplit(":", 2)
        anchor = snap[k]
        try:
            actual = source_line(file, int(line))
        except (FileNotFoundError, IndexError):
            drifted.append(f"{k} 源码行不存在")
            continue
        if not actual.startswith(anchor):
            drifted.append(f"{k} 锚失配：快照={anchor!r} 实际={actual[:60]!r}")
    if drifted:
        for d in drifted:
            print(f"ANCHOR DRIFT: {d}", file=sys.stderr)
        return 1
    print(f"anchors ok ({len(keys)} 条)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
