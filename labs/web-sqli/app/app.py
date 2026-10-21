"""
취약점 분석 바이블 — 실습: SQL 인젝션 (3부 1장)

이 앱은 일부러 취약하게 만들어져 있다. 127.0.0.1 밖으로 노출하지 마라.
'# ❌' 표시된 함수 세 개를 파라미터화된 쿼리로 고치는 것까지가 실습이다.
"""
import sqlite3
from flask import Flask, request, render_template_string, g

app = Flask(__name__)
DB_PATH = "/tmp/lab.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS items;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT);
        CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, description TEXT);
        INSERT INTO users (username, password) VALUES
            ('admin', 'S3cr3t!Bible'),
            ('alice', 'alice2024'),
            ('bob',   'hunter2');
        INSERT INTO items (name, description) VALUES
            ('Ghidra', 'NSA가 공개한 디컴파일러'),
            ('Burp Suite', '웹 프록시의 표준'),
            ('AFL++', '커버리지 기반 퍼저'),
            ('Semgrep', '패턴 기반 정적 분석기');
        """
    )
    db.commit()
    db.close()


PAGE = """
<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>web-sqli 실습</title>
<style>body{font-family:sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem}
nav a{margin-right:1rem}form{margin:1rem 0}input{padding:.3rem}pre{background:#f4f4f4;padding:.5rem}
.err{color:#b00}.ok{color:#080}</style></head><body>
<h1>🧪 web-sqli</h1>
<nav><a href="/">로그인</a><a href="/search">검색</a><a href="/item?id=1">아이템</a></nav>
<hr>{{ body|safe }}
<hr><small>취약점 분석 바이블 · 3부 1장 · 격리된 로컬에서만 실행하세요</small>
</body></html>
"""

LOGIN_FORM = """
<h2>로그인</h2>
<form method="post" action="/login">
  <label>사용자 <input name="username" value="{{ u }}"></label><br>
  <label>비밀번호 <input name="password" type="password"></label><br>
  <button>로그인</button>
</form>
{{ msg|safe }}
"""


def page(body, **ctx):
    return render_template_string(PAGE, body=render_template_string(body, **ctx))


@app.route("/")
def index():
    return page(LOGIN_FORM, u="", msg="")


# ❌ 취약 1: 문자열 포매팅으로 쿼리 조립 (인증 우회)
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    try:
        row = get_db().execute(query).fetchone()
    except sqlite3.Error as e:
        return page(LOGIN_FORM, u=username, msg=f'<p class="err">DB 오류: {e}</p><pre>{query}</pre>')
    if row:
        return page(
            "<h2>환영합니다, {{ name }}</h2><p class='ok'>로그인 성공</p>"
            "{% if name == 'admin' %}<p>🏁 목표 1 달성: admin으로 로그인했다.</p>{% endif %}",
            name=row["username"],
        )
    return page(LOGIN_FORM, u=username, msg='<p class="err">로그인 실패</p>')


# ❌ 취약 2: 에러와 결과가 그대로 노출 (UNION 기반)
@app.route("/search")
def search():
    q = request.args.get("q", "")
    query = f"SELECT name, description FROM items WHERE name LIKE '%{q}%'"
    body = "<h2>검색</h2><form><input name='q' value='{{ q }}'><button>검색</button></form>"
    try:
        rows = get_db().execute(query).fetchall()
    except sqlite3.Error as e:
        return page(body + "<p class='err'>DB 오류: {{ e }}</p><pre>{{ query }}</pre>", q=q, e=str(e), query=query)
    body += "<ul>{% for r in rows %}<li><b>{{ r[0] }}</b> — {{ r[1] }}</li>{% endfor %}</ul>"
    return page(body, q=q, rows=rows)


# ❌ 취약 3: 숫자 컨텍스트, 에러 숨김 (Boolean 기반 블라인드)
@app.route("/item")
def item():
    item_id = request.args.get("id", "1")
    query = f"SELECT name FROM items WHERE id = {item_id}"
    try:
        row = get_db().execute(query).fetchone()
    except sqlite3.Error:
        row = None
    if row:
        return page("<h2>아이템</h2><p class='ok'>Found: {{ name }}</p>", name=row["name"])
    return page("<h2>아이템</h2><p class='err'>Not found</p>")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080, debug=False)
