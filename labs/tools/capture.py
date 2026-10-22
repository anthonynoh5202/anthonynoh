#!/usr/bin/env python3
"""
실습 스크린샷 자동 캡처.

실습 앱이 떠 있는 상태에서 실행하면 책에 들어가는 스크린샷을 다시 찍는다.
앱 UI가 바뀌면 손으로 다시 찍을 필요 없이 이 스크립트만 돌린다.

사용법:
  pip install playwright && playwright install chromium   # 최초 1회
  cd labs/web-sqli && docker compose up -d
  python3 labs/tools/capture.py web-sqli

출력: books/vmc-bible/src/images/labs/<lab>/<name>.png
"""
import os
import sys
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
OUT_BASE = ROOT / "books" / "vmc-bible" / "src" / "images" / "labs"

# lab 이름 -> [(파일명, 동작 함수)]
SCENARIOS = {}


def scenario(lab, name):
    def deco(fn):
        SCENARIOS.setdefault(lab, []).append((name, fn))
        return fn
    return deco


BASE_SQLI = "http://127.0.0.1:8080"


@scenario("web-sqli", "01-login-form")
def _(page):
    page.goto(BASE_SQLI + "/")


@scenario("web-sqli", "02-login-bypass")
def _(page):
    page.goto(BASE_SQLI + "/")
    page.fill("input[name=username]", "admin'-- ")
    page.fill("input[name=password]", "anything")
    page.click("button")
    page.wait_for_selector("text=목표 1 달성")


@scenario("web-sqli", "03-search-error")
def _(page):
    page.goto(BASE_SQLI + "/search?q=%27")
    page.wait_for_selector("text=DB 오류")


@scenario("web-sqli", "04-search-union")
def _(page):
    q = "' UNION SELECT username, password FROM users-- "
    page.goto(BASE_SQLI + "/search?q=" + page.evaluate("encodeURIComponent", q))
    page.wait_for_selector("text=S3cr3t!Bible")


@scenario("web-sqli", "05-item-true-false")
def _(page):
    # 참/거짓 두 응답을 한 화면에 비교해서 보여주기 위해 작은 HTML을 조립한다
    import urllib.request
    def get(cond):
        url = BASE_SQLI + "/item?id=" + page.evaluate("encodeURIComponent", cond)
        return urllib.request.urlopen(url).read().decode()
    t = get("1 AND 1=1")
    f = get("1 AND 1=2")
    import re
    pick = lambda h: re.search(r"<p class='(ok|err)'>.*?</p>", h).group(0)
    page.set_content(f"""
    <html><body style="font-family:sans-serif;padding:1rem;max-width:720px">
    <h2>Boolean 기반 블라인드: 두 응답 비교</h2>
    <table style="border-collapse:collapse;width:100%">
    <tr><th style="text-align:left;border-bottom:1px solid #ccc">요청</th><th style="text-align:left;border-bottom:1px solid #ccc">응답</th></tr>
    <tr><td><code>/item?id=1 AND 1=1</code></td><td style="color:#080">{pick(t)}</td></tr>
    <tr><td><code>/item?id=1 AND 1=2</code></td><td style="color:#b00">{pick(f)}</td></tr>
    </table>
    <p>에러도 데이터도 없다. 응답의 <b>차이</b>만으로 참/거짓을 판정한다.</p>
    </body></html>""")


def main(labs):
    with sync_playwright() as p:
        # 시스템에 이미 Chromium이 있으면 PW_CHROMIUM=/path/to/chrome 으로 지정할 수 있다
        exe = os.environ.get("PW_CHROMIUM")
        browser = p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()
        for lab in labs:
            out = OUT_BASE / lab
            out.mkdir(parents=True, exist_ok=True)
            for name, fn in SCENARIOS.get(lab, []):
                page = browser.new_page(viewport={"width": 900, "height": 420}, device_scale_factor=1.5)
                fn(page)
                path = out / f"{name}.png"
                page.screenshot(path=str(path), full_page=False)
                print("saved", path.relative_to(ROOT))
                page.close()
        browser.close()


if __name__ == "__main__":
    labs = sys.argv[1:] or list(SCENARIOS)
    main(labs)
