#!/usr/bin/env bash
# 책을 빌드해서 site/ 에 둔다. 로컬과 CI가 같은 스크립트를 쓴다.
#   ./build.sh              공개판 → site/
#   INTERNAL=1 ./build.sh   내부판 (<!-- internal --> 블록 포함) → site-internal/
set -euo pipefail
cd "$(dirname "$0")"
out="site"; [[ "${INTERNAL:-}" == "1" ]] && out="site-internal"
rm -rf "$out"
(cd books/vmc-bible && mdbook build)
mv books/vmc-bible/book "$out"
echo "done: $out/ (INTERNAL=${INTERNAL:-0})"
