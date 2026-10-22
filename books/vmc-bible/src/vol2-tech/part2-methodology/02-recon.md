# 정보 수집

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟡 | 🔄 개정중 | 2026-10-22 |

> **한눈에 보기**
> 분석 대상을 '아는 만큼' 찾는다. 기술 스택, 버전, 의존성, 과거 CVE, 설정 파일이 첫 단서다.
> 순서는 정해져 있다. 무엇으로 만들어졌는지 알고, 그 구성 요소에 알려진 취약점이 있는지 맞춰 보고, 과거에 어디가 자주 깨졌는지 읽는다.
> 이 모든 것은 허가 범위 안에서, 가능하면 **내 환경에 설치한 복사본**에서 한다.

## 1. 목표와 범위

정보 수집의 산출물은 세 가지다. **기술 스택 목록**(언어, 프레임워크, 서버, DB와 각각의 버전), **의존성 목록과 알려진 취약점 매칭 결과**, **과거 취약점 히스토리에서 읽은 패턴**. 이 셋이 [위협 모델링](03-threat-modeling.md)과 [정적 분석](04-static-analysis.md)의 입력이 된다.

접근 방식은 가진 정보에 따라 다르다.

| 방식 | 가진 것 | 센터에서 흔한 경우 |
|---|---|---|
| 화이트박스 | 소스, 빌드 스크립트, 설정 | 신고된 오픈소스 제품 분석, 기술지원 점검 |
| 그레이박스 | 바이너리·설치본, 문서 | 국내 상용 소프트웨어 신고 검증 |
| 블랙박스 | 네트워크로 보이는 것만 | 허용 정책 안의 운영 서비스 점검 |

**범위를 먼저 확인한다.** 블랙박스 수집의 상당수(포트 스캔, 디렉터리 브루트포스)는 허가 없는 대상에게는 [1부 4장](../part1-foundations/04-ethics-and-law.md)의 침입·업무방해 문제가 된다. 이 장의 명령은 모두 로컬 실습 환경이나 허용 범위 안의 대상에만 쓴다.

## 2. 기술 스택 식별

### 2.1 HTTP 헤더와 배너

요청 하나로 서버 소프트웨어, 프레임워크, 세션 방식이 드러난다. 실습 환경을 띄우고 확인한다.

```bash
cd labs/web-sqli && docker compose up -d
curl -sI http://127.0.0.1:8080/
```

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.x Python/3.12.x
Content-Type: text/html; charset=utf-8
```

`Server` 헤더 한 줄이 "Flask 계열, 개발 서버, Python 3.12"를 말해 준다. 자주 보는 단서다.

| 단서 | 위치 | 알려 주는 것 |
|---|---|---|
| `Server: nginx/1.24.0`, `Apache/2.4.x` | 응답 헤더 | 웹 서버와 버전 |
| `X-Powered-By: PHP/8.2.x`, `Express` | 응답 헤더 | 언어·프레임워크 |
| `JSESSIONID`, `PHPSESSID`, `connect.sid`, `session` | `Set-Cookie` 이름 | Java 서블릿, PHP, Express, Flask |
| `X-AspNet-Version`, `__VIEWSTATE` | 헤더·본문 | ASP.NET |
| `/static/`, `/_next/`, `/wp-content/` | HTML 경로 | Flask·Django, Next.js, WordPress |
| 404·500 페이지 모양 | 본문 | 프레임워크 기본 에러 페이지는 서명과 같다 |

### 2.2 에러 메시지

에러는 가장 솔직한 정보원이다. 잘못된 파라미터 타입, 빈 값, 아주 긴 값, 잘못된 `Content-Type`을 보내 보면 스택 트레이스, 파일 경로, DB 종류, ORM 이름이 나온다. 실습 환경의 `/search?q='`는 SQLite 오류와 조립된 쿼리까지 보여 준다. [3부 1장 4.2절](../part3-web/01-sql-injection.md) 운영 서비스에서는 스택 트레이스 노출 자체가 보고 대상이다(CWE-209).

### 2.3 패키지 매니페스트

소스나 설치본이 있으면 매니페스트가 가장 정확한 목록이다. **잠금 파일**(lockfile)이 있으면 그것을 우선한다. 매니페스트는 범위(`^1.2.0`)를 말하고 잠금 파일은 실제 설치 버전을 말한다.

| 생태계 | 매니페스트 | 잠금 파일 | 비고 |
|---|---|---|---|
| Node.js | `package.json` | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | `devDependencies`는 운영에 안 들어갈 수 있다 |
| Python | `requirements.txt`, `pyproject.toml` | `poetry.lock`, `uv.lock`, `Pipfile.lock` | `requirements.txt`에 `==`가 없으면 범위다 |
| Java | `pom.xml`, `build.gradle` | (Maven은 해석 결과를 `mvn dependency:tree`로) | 전이 의존성이 많다. Log4Shell이 여기서 터졌다 |
| Go | `go.mod` | `go.sum` | `go list -m all`로 전체 |
| Ruby | `Gemfile` | `Gemfile.lock` | |
| PHP | `composer.json` | `composer.lock` | |
| 컨테이너 | `Dockerfile` | 이미지 다이제스트 | 베이스 이미지의 OS 패키지도 의존성이다 |

실습 환경의 `labs/web-sqli/app/requirements.txt`는 `flask==3.0.3` 한 줄이고, `Dockerfile`은 `python:3.12-slim`을 쓴다. 이것으로 "Flask 3.0.3과 그 전이 의존성(Werkzeug, Jinja2 등), Debian 기반 Python 3.12 이미지의 OS 패키지"가 대상 목록이 된다.

### 2.4 도구

수동으로 본 뒤 도구로 넓힌다. 도구는 "무엇이 있다"를 빠르게 찾고, 사람은 "그래서 어떤 버전이 정말 돌고 있는가"를 확인한다.

```bash
# WhatWeb: 플러그인 기반 지문. -a 3은 매칭된 플러그인에 한해 추가 요청을 보낸다
whatweb -a 3 http://127.0.0.1:8080

# httpx (projectdiscovery): 상태 코드, 제목, 서버, 기술 탐지를 한 줄로
httpx -u 127.0.0.1:8080 -sc -title -server -td

# nuclei: 기술 탐지 템플릿만 실행
nuclei -u http://127.0.0.1:8080 -t http/technologies/
```

📎 [WhatWeb 사용법](https://github.com/urbanadventurer/WhatWeb), [httpx 사용법](https://docs.projectdiscovery.io/tools/httpx/usage), [nuclei-templates http/technologies](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/technologies)

> 🟡 `-a 3` 이상, nuclei의 전체 템플릿, 디렉터리 브루트포스는 요청 수가 급격히 는다. 허용 정책에 속도 제한이 있는지 확인하고, 없으면 보수적으로 간다. 실습 환경에서는 제한이 없다.

## 3. SCA: 의존성과 알려진 취약점 매칭

**소프트웨어 구성 분석**(Software Composition Analysis, SCA)은 의존성 목록을 취약점 데이터베이스와 대조하는 일이다. 데이터 출처를 알아야 결과를 믿을 수 있다.

| 데이터베이스 | 운영 | 특징 |
|---|---|---|
| [OSV](https://osv.dev/) | Google | 오픈소스 생태계별 취약점을 공통 스키마로. 버전 범위가 정확하다. API와 스캐너 제공 |
| [GitHub Advisory Database](https://github.com/advisories) | GitHub | `GHSA-xxxx` ID. 리뷰된 권고는 OSV로도 흘러간다. Dependabot의 출처 |
| [NVD](https://nvd.nist.gov/) | NIST | CPE 기반 매칭. 오픈소스 패키지 버전 매칭은 OSV보다 거칠다 |
| 벤더·배포판 DB | Red Hat, Debian 등 | OS 패키지는 배포판이 백포트하므로 **배포판 DB가 기준**이다 |

### 3.1 생태계별 명령

```bash
# Node.js: 운영 의존성만, high 이상이면 종료 코드로 실패
npm audit --omit=dev --audit-level=high        # JSON이 필요하면 --json

# Python: requirements 파일 기준 (기본 소스는 PyPI 권고, -s osv 로 OSV 사용)
pip-audit -r requirements.txt
pip-audit -r requirements.txt -s osv -f json -o audit.json
# 설치된 환경 기준
pip-audit
```

📎 [npm audit 문서](https://docs.npmjs.com/cli/commands/npm-audit), [pip-audit](https://github.com/pypa/pip-audit)

### 3.2 생태계를 가리지 않는 도구

```bash
# OSV-Scanner: 디렉터리 안의 매니페스트·잠금 파일을 재귀로 찾아 OSV에 조회
osv-scanner scan source -r ./project
# 잠금 파일 하나만
osv-scanner scan source --lockfile=./project/package-lock.json
# 컨테이너 이미지
osv-scanner scan image python:3.12-slim

# Syft로 SBOM을 만들고 Grype로 매칭 (SBOM을 보관하면 재스캔이 빠르다)
syft ./project -o cyclonedx-json > sbom.cdx.json
grype sbom:./sbom.cdx.json

# Trivy: 파일 시스템 스캔, 취약점 스캐너만
trivy fs --scanners vuln ./project
```

📎 [OSV-Scanner 사용법](https://google.github.io/osv-scanner/usage/), [Syft](https://github.com/anchore/syft), [Grype](https://github.com/anchore/grype), [Trivy](https://trivy.dev/)

OSV는 API를 직접 부를 수도 있다. 자동화 스크립트에서 패키지 하나를 확인할 때 쓴다.

```bash
curl -s -X POST https://api.osv.dev/v1/query \
  -H 'Content-Type: application/json' \
  -d '{"package": {"name": "flask", "ecosystem": "PyPI"}, "version": "3.0.3"}' | jq '.vulns[]?.id'
```

### 3.3 결과를 읽는 법

스캐너 출력은 "후보 목록"이다. 보고서에 옮기기 전에 네 가지를 거른다.

| 질문 | 왜 | 어떻게 |
|---|---|---|
| **실제로 설치되는가** | `devDependencies`, 선택 의존성, 테스트 전용은 운영에 없을 수 있다 | `--omit=dev`, 잠금 파일 기준으로 다시 |
| **취약한 코드에 도달하는가**(reachability) | 라이브러리의 취약한 함수를 이 앱이 안 부를 수 있다 | 호출 지점 grep. [4장 정적 분석](04-static-analysis.md) |
| **버전 범위가 맞는가** | 배포판 백포트, 벤더 패치 버전은 스캐너가 모를 수 있다 | 배포판 권고 확인 |
| **중복인가** | 같은 취약점이 CVE·GHSA·OSV ID로 세 번 나온다 | 별칭(alias)으로 묶는다. `pip-audit --aliases on` |

거르고 남은 것은 그대로 "알려진 취약점 노출" 발견 사항이 된다. 그리고 그 라이브러리의 **취약점 유형**이 이 앱의 공격 표면과 만나는 지점이 다음 단계의 깊은 분석 대상이다.

## 4. 과거 CVE 히스토리에서 패턴 읽기

제품의 과거 취약점은 미래 취약점의 가장 좋은 예측 변수다. 같은 모듈, 같은 CWE, 불완전한 패치가 반복된다.

### 4.1 어디서 찾나

```bash
# NVD 키워드 검색 (제품명으로)
#   https://nvd.nist.gov/vuln/search  →  키워드, 또는 CPE 이름으로
# 벤더 보안 권고 아카이브: 보통 /security, /advisories, GitHub Security tab
# 오픈소스면 커밋 로그에서 직접
git log --oneline -i --grep='CVE-\|security\|overflow\|injection' | head -50
```

### 4.2 무엇을 보나

| 패턴 | 뜻 | 분석에서 |
|---|---|---|
| **같은 CWE 반복** | 그 팀의 습관. 파서를 손으로 짰거나, 입력 검증 지점이 흩어져 있다 | 같은 유형을 다른 입력 지점에서 찾는다 |
| **같은 모듈 반복** | 복잡하거나 오래된 코드 | 그 모듈을 먼저 읽는다 |
| **패치 우회 CVE** | 첫 패치가 증상만 막았다 | 패치 diff를 읽고 "다른 경로"를 찾는다. [8부 3장](../part8-reporting/03-patch-verification.md) |
| **권고에 "구성에 따라"가 많다** | 기본 설정이 안전하지 않다 | 설정 파일의 기본값을 본다 |

Log4j가 교과서적 사례다. 2021년 12월 열흘 사이에 패치가 세 번 나왔다.

| CVE | 수정 버전 | 내용 |
|---|---|---|
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | 2.15.0 | JNDI 조회를 통한 RCE |
| [CVE-2021-45046](https://nvd.nist.gov/vuln/detail/CVE-2021-45046) | 2.16.0 | 2.15.0의 수정이 불완전. 특정 설정에서 여전히 조회 가능 |
| [CVE-2021-45105](https://nvd.nist.gov/vuln/detail/CVE-2021-45105) | 2.17.0 | 조회 재귀로 DoS |

첫 CVE만 보고 "2.15.0이면 안전"이라고 쓰면 틀린다. 히스토리를 **끝까지** 읽는 것이 정보 수집의 일부다. 전체 분석은 [7부 1장 Log4Shell 워크스루](../part7-walkthroughs/01-cve-2021-44228-log4shell.md).

## 5. OSINT의 범위와 법적 한계

**공개 출처 정보**(open-source intelligence, OSINT)는 대상에 패킷을 보내지 않고 모으는 정보다. 수동(passive)과 능동(active)의 경계가 곧 법적 경계다.

| 수동: 대상에 닿지 않는다 | 능동: 대상에 요청을 보낸다 |
|---|---|
| 공개 문서, 채용 공고("Spring Boot 경험자"), 기술 블로그 | 포트 스캔, 디렉터리 브루트포스 |
| 공개 GitHub 저장소, 패키지 레지스트리의 메타데이터 | 에러 유발 요청, 파라미터 변조 |
| 인증서 투명성 로그(crt.sh)로 서브도메인 | 서브도메인에 실제 접속해 확인 |
| 검색 엔진(Shodan, Censys)에 **이미 수집된** 배너 | 직접 배너 수집 |
| Wayback Machine의 과거 페이지 | 현재 페이지 크롤링 |

수동 수집은 공개 정보를 읽는 것이므로 대체로 문제가 없다. 능동 수집은 **허가 범위 안에서만** 한다. 공개 검색 엔진에 수집된 정보를 "읽는" 것과 그 정보를 바탕으로 "접속하는" 것은 다르다. 상시 신고조치제의 허용 정책도 대상·방법을 한정하므로, 능동 수집 전에 정책을 다시 읽는다. [1부 4장](../part1-foundations/04-ethics-and-law.md)

유출 데이터(크리덴셜 덤프 등)를 쓰는 것은 수동 수집처럼 보여도 범위 밖이다. 버그바운티 정책 대부분이 명시적으로 금지한다.

## 6. 자동화: 스크립트화해 둘 것

반복되는 것은 스크립트로 만든다. 아래는 로컬 소스 트리와 실행 중인 실습 환경을 대상으로 1~3절을 한 번에 돌리는 최소 예시다. 대상은 **상수로 고정**한다.

```bash
#!/usr/bin/env bash
# recon.sh — 로컬 실습 환경 전용. 대상은 아래 두 상수로만 정한다.
set -euo pipefail
TARGET_URL="http://127.0.0.1:8080"
SRC_DIR="./labs/web-sqli/app"
OUT="recon-$(date +%Y%m%d).md"

{
  echo "# Recon: $TARGET_URL / $SRC_DIR"
  echo; echo "## 1. 응답 헤더"; echo '```'
  curl -sI "$TARGET_URL/" || echo "(연결 실패)"
  echo '```'

  echo; echo "## 2. 매니페스트"
  for f in package.json package-lock.json requirements.txt pyproject.toml pom.xml go.mod Dockerfile; do
    [ -f "$SRC_DIR/$f" ] && echo "- $f"
  done

  echo; echo "## 3. 입력 지점 (Flask 라우트)"; echo '```'
  grep -rnE "@app\.route|request\.(args|form|json|files|headers|cookies)" "$SRC_DIR" || true
  echo '```'

  echo; echo "## 4. SCA"; echo '```'
  if [ -f "$SRC_DIR/requirements.txt" ] && command -v pip-audit >/dev/null; then
    pip-audit -r "$SRC_DIR/requirements.txt" -s osv || true
  fi
  if command -v osv-scanner >/dev/null; then
    osv-scanner scan source -r "$SRC_DIR" || true
  fi
  echo '```'
} > "$OUT"
echo "written: $OUT"
```

출력을 Markdown으로 만드는 이유는 보고서에 그대로 붙이기 위해서다. 스크립트에 넣으면 좋은 것들이 더 있다.

- 매니페스트에서 **정확한 버전만** 뽑아 표로 만드는 파서
- 벤더 권고 페이지의 RSS·GitHub Security Advisory를 모아 "이 제품의 최근 1년 CVE" 표를 만드는 수집기
- SBOM을 날짜별로 보관하고 **새로 생긴** 취약점만 알리는 재스캔 작업. SBOM은 한 번 만들고 매칭은 매일 한다
- 공개 CVE와 KEV·EPSS를 붙여 우선순위를 매기는 후처리. [1부 2장 5절](../part1-foundations/02-cwe-cve-cvss.md)

## 7. 실습 🧪

[`labs/web-sqli/`](https://github.com/anthonynoh5202/anthonynoh/tree/main/labs/web-sqli)를 대상으로 정보 수집 보고서 한 장을 만든다.

1. `docker compose up -d` 후 `curl -sI http://127.0.0.1:8080/`로 서버 배너를 기록한다.
2. `app/requirements.txt`와 `app/Dockerfile`에서 직접 의존성과 베이스 이미지를 적는다.
3. `pip-audit -r app/requirements.txt`를 돌린다. 결과가 없으면 "알려진 취약점 없음(날짜, 데이터 소스)"이라고 적는다. 결과는 날짜에 따라 달라진다.
4. `osv-scanner scan image python:3.12-slim`으로 베이스 이미지의 OS 패키지도 본다. 결과 수와 "실제로 이 앱이 쓰는 패키지인가"를 구분해 적는다.
5. 6절 스크립트를 돌려 입력 지점 세 개(`/login`, `/search`, `/item`)가 잡히는지 확인한다.
6. 결론 한 줄을 쓴다. "알려진 취약점(SCA)은 N건, 깊은 분석 대상은 세 입력 지점의 SQL 조립." 이 한 줄이 [위협 모델링](03-threat-modeling.md)의 출발점이다.

## 체크리스트

**기술 스택**
- [ ] 언어·프레임워크·서버·DB와 각각의 **정확한 버전**을 적었는가? 범위가 아니라 잠금 파일 기준인가?
- [ ] 에러 메시지에서 얻은 정보(경로, DB 종류)를 기록했는가?
- [ ] 베이스 이미지·OS 패키지도 목록에 넣었는가?

**SCA**
- [ ] 운영에 들어가지 않는 의존성을 걸렀는가?
- [ ] 취약한 함수에 실제로 도달하는지 확인했거나, 확인하지 못했다고 적었는가?
- [ ] CVE·GHSA·OSV 별칭을 묶었는가?

**히스토리**
- [ ] 과거 CVE에서 반복되는 CWE와 모듈을 적었는가?
- [ ] 패치 우회 CVE가 있는지 확인했는가?

**범위**
- [ ] 능동 수집은 모두 허가 범위 안에서 했는가? 스크립트의 대상이 상수로 고정되어 있는가?

## 더 읽기

- [OSV 스키마와 API](https://google.github.io/osv.dev/) · 생태계별 취약점 데이터의 공통 형식
- [GitHub Advisory Database](https://github.com/advisories) · GHSA 권고와 리뷰 기준
- [OSV-Scanner 문서](https://google.github.io/osv-scanner/) · 소스·이미지·SBOM 스캔
- [pip-audit](https://github.com/pypa/pip-audit), [npm audit](https://docs.npmjs.com/cli/commands/npm-audit) · 생태계 기본 도구의 공식 문서
- [Syft](https://github.com/anchore/syft) · SBOM 생성, [Grype](https://github.com/anchore/grype) · SBOM 매칭, [Trivy](https://trivy.dev/) · 통합 스캐너
- [projectdiscovery httpx](https://docs.projectdiscovery.io/tools/httpx/usage), [nuclei](https://github.com/projectdiscovery/nuclei) · 지문·템플릿 스캔
- [OWASP Web Security Testing Guide: Information Gathering](https://owasp.org/www-project-web-security-testing-guide/) · 블랙박스 정보 수집 항목의 표준 목록

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 본문 작성. 스택 식별, SCA 명령, CVE 히스토리, OSINT 한계, 자동화 스크립트, 실습 추가 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증: pip-audit·osv-scanner·syft·grype·httpx·nuclei·WhatWeb 명령을 각 공식 README와 대조(이상 없음). Werkzeug 버전 표기(flask 3.0.3은 3.1.x 설치), npm 문서 링크 버전 고정 제거 | 검증팀 |
