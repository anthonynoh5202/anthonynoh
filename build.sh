#!/usr/bin/env bash
# 모든 책을 빌드해서 site/ 에 모은다. 로컬과 CI가 같은 스크립트를 쓴다.
set -euo pipefail
cd "$(dirname "$0")"
rm -rf site && mkdir -p site
for dir in books/*/; do
  name=$(basename "$dir")
  echo "==> $name"
  (cd "$dir" && mdbook build)
  mv "$dir/book" "site/$name"
done
cp landing/index.html site/index.html
echo "done: site/"
