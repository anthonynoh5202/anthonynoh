# 실습 환경 (labs)

모든 실습은 `docker compose up --build` 한 줄로 뜬다. 공통 규칙은 책의 [1부 5장 실습 환경 구축](../books/vmc-bible/src/vol2-tech/part1-foundations/05-lab-setup.md)을 본다.

## ⚠️ 경고

이 디렉터리의 앱은 **일부러 취약하게** 만들어져 있다.

- `127.0.0.1`에만 바인딩되어 있다. 포트 설정을 바꾸지 마라.
- 공용 네트워크에서 띄우지 마라.
- 여기 있는 자격증명을 다른 곳에서 쓰지 마라.

## 목록

| 디렉터리 | 장 | 포트 | 상태 |
|---|---|---|---|
| [`web-sqli/`](web-sqli/) | [3부 1장 SQL 인젝션](../books/vmc-bible/src/vol2-tech/part3-web/01-sql-injection.md) | 8080 | ✅ 동작 |
| `web-xss/` | 3부 2장 XSS | 8081 | 📝 예정 |
| `web-ssrf/` | 3부 3장 SSRF | 8082 | 📝 예정 |
| `binary-base/` | 4부 공통 (gdb, pwndbg, pwntools) | - | 📝 예정 |
| `binary-stack/` | 4부 2장 스택 오버플로 | - | 📝 예정 |
| `cve-2021-44228/` | 7부 1장 Log4Shell | 8090 | 📝 예정 |

## 새 실습 추가 규칙

1. 디렉터리 이름: `<분야>-<주제>` 또는 `cve-YYYY-NNNNN`
2. 반드시 포함: `docker-compose.yml`, `README.md`(목표·힌트·초기화 방법), 취약 코드에 `# ❌` 주석
3. 포트는 위 표에서 안 쓰는 번호를 쓰고 `127.0.0.1:` 접두사를 붙인다
4. `solve_*.py` 참고 풀이는 표준 라이브러리만 쓴다 (설치 없이 실행되게)
5. 이 README의 표에 추가한다
