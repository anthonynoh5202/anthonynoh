# web-sqli: SQL 인젝션 실습

책: [3부 1장 SQL 인젝션](../../src/part3-web/01-sql-injection.md)

```bash
docker compose up --build
# http://localhost:8080
docker compose down -v   # 초기화
```

## 목표

1. 비밀번호 없이 `admin`으로 로그인한다 (`/login`)
2. `/search` 에서 UNION으로 `users` 테이블 전체를 읽는다
3. `/item?id=` 에서 에러도 데이터도 없이, 참/거짓만으로 admin 비밀번호를 뽑는다 (`solve_blind.py` 참고)
4. `app/app.py` 의 `# ❌` 함수 세 개를 고치고 1~3이 모두 실패하는지 확인한다

## 힌트

- `/login`: 주석 `-- ` 로 뒤를 지운다. 공백 포함.
- `/search`: 컬럼 수부터. `' ORDER BY N-- `
- `/item`: 숫자 컨텍스트라 따옴표가 필요 없다. `SUBSTR`, `UNICODE`.

## 계정

| 사용자 | 비밀번호 |
|---|---|
| admin | (직접 찾아라) |
| alice | alice2024 |
