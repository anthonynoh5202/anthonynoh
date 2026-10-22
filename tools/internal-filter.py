#!/usr/bin/env python3
"""
mdBook 전처리기: 내부 전용 블록을 공개판에서 제거한다.

원고에 다음처럼 쓴다.

    <!-- internal:start -->
    센터 내부에서만 보여야 할 내용 (시스템명, 연락처, 내부 규정 등)
    <!-- internal:end -->

빌드 시:
  mdbook build                 → 블록이 빠진 공개판
  INTERNAL=1 mdbook build      → 블록이 포함된 내부판 (인트라넷 배포용)

book.toml:
  [preprocessor.internal]
  command = "python3 ../../tools/internal-filter.py"
"""
import json, os, re, sys

BLOCK = re.compile(r"<!--\s*internal:start\s*-->.*?<!--\s*internal:end\s*-->\s*", re.S)
FENCE = re.compile(r"(```.*?```|~~~.*?~~~)", re.S)
NOTE = "> 🔒 _이 자리에는 센터 내부판에만 포함되는 내용이 있습니다._\n\n"


def transform(content, internal):
    """코드 펜스 밖에서만 내부 블록을 처리한다 (펜스 안의 예시는 그대로 둔다)."""
    parts = FENCE.split(content)
    for i in range(0, len(parts), 2):  # 짝수 인덱스 = 펜스 밖
        if internal:
            parts[i] = parts[i].replace("<!-- internal:start -->", "").replace("<!-- internal:end -->", "")
        else:
            parts[i] = BLOCK.sub(NOTE, parts[i])
    return "".join(parts)


def walk(items, internal):
    for it in items:
        ch = it.get("Chapter") if isinstance(it, dict) else None
        if not ch:
            continue
        ch["content"] = transform(ch["content"], internal)
        walk(ch.get("sub_items", []), internal)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "supports":
        sys.exit(0)
    ctx, book = json.load(sys.stdin)
    internal = os.environ.get("INTERNAL") == "1"
    walk(book["sections"], internal)
    json.dump(book, sys.stdout, ensure_ascii=False)
