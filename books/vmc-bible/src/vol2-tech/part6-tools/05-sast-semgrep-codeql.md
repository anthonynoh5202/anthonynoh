# 정적 분석기: Semgrep · CodeQL

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟡 실무 | 🔄 개정중 | 2026-10-22 |

> **한눈에 보기**
> Semgrep은 '패턴을 빨리', CodeQL은 '데이터 흐름을 깊게'. 둘 다 룰을 직접 쓸 수 있어야 진짜 가치가 나온다.
> 정적 분석의 **방법**(소스·싱크·새니타이저 모델, 리뷰 전략)은 [2부 4장](../part2-methodology/04-static-analysis.md)이 다룬다. 이 장은 **도구**다. 설치, 룰 문법, 쿼리 구조, CI 통합, 오탐 관리.
> 룰 하나를 쓰고 테스트까지 돌려 보면 두 도구의 차이가 몸으로 이해된다.

## 1. 언제 어느 것을 쓰는가

| | Semgrep (Community Edition) | CodeQL |
|---|---|---|
| 원리 | 소스 코드를 AST로 바꿔 **패턴 매칭**. 타인트(taint) 모드는 단일 파일·단일 함수 범위 | 소스 코드를 **관계형 데이터베이스**로 바꾸고 QL로 질의. 전역(함수 간, 파일 간) 데이터 흐름 추적 |
| 빌드·속도 | 빌드 불필요. 수만 줄을 초 단위로 | 컴파일 언어는 빌드를 관찰해야 한다. DB 생성에 분~시간, 쿼리에 분 단위 |
| 룰 작성 | YAML. 코드와 거의 같은 문법으로 패턴을 쓴다 | QL. 배우는 데 시간이 들지만 표현력이 크다 |
| 라이선스 | 엔진 LGPL-2.1. 공식 룰은 Semgrep Rules License v1.0 (내부 사용은 허용, 경쟁 제품·SaaS 재배포 제한) 📎 [Semgrep 공지](https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss) | 오픈소스·학술 연구는 무료. 사내 비공개 코드에는 GitHub Advanced Security 라이선스 필요 |
| 맞는 일 | "이 API를 이렇게 쓰는 곳 전부", 코딩 규칙 강제, 빠른 1차 스캔 | "사용자 입력이 이 싱크까지 도달하는가"를 호출 경계를 넘어 추적 |

순서는 보통 **Semgrep으로 넓게, CodeQL로 깊게**다. Semgrep은 벤더 스스로 Community Edition이 "단일 함수·단일 파일 경계 안에서만 분석하므로 보안 용도로는 많은 참 양성을 놓친다"고 밝힌다 📎 [Semgrep README](https://github.com/semgrep/semgrep#readme). 그 빈틈을 CodeQL의 전역 taint 추적이 메운다. 둘 다 [0장 3절](00-when-to-use-what.md)의 "도구가 못 찾는 것"은 못 찾는다.

## 2. Semgrep

### 2.1 설치와 실행

```bash
python3 -m pip install semgrep        # 또는 brew install semgrep
semgrep scan --config p/default .                      # 레지스트리 기본 룰셋
semgrep scan --config p/security-audit --config p/owasp-top-ten .
semgrep scan --config rules/ --severity ERROR --sarif -o semgrep.sarif .   # 내 룰, SARIF 출력
```

`--config`에는 레지스트리 룰셋(`p/이름`), 로컬 파일·디렉터리, URL을 여러 번 줄 수 있다. `p/python` 같은 언어별, `p/sql-injection` 같은 주제별 룰셋의 목록은 [레지스트리](https://semgrep.dev/explore)에서 찾는다. 레지스트리 룰셋을 쓰면 익명 룰 지표가 semgrep.dev로 전송되며 `--metrics=off`로 끈다.

### 2.2 룰 문법

룰 파일은 `rules:` 아래 룰 목록이다. 필수 키는 `id`, `message`, `severity`(`INFO`/`WARNING`/`ERROR`), `languages`, 그리고 패턴 연산자 하나다.

연산자는 `pattern`(일치), `patterns`(아래 항목 **모두**, AND), `pattern-either`(**하나**, OR), `pattern-inside`/`pattern-not-inside`(이 범위 안/밖에서만), `pattern-not`(제외), `pattern-regex`(정규식), `metavariable-regex`(메타변수 값이 정규식에 맞을 때만), `focus-metavariable`(매치를 메타변수 위치로 좁힘. taint에서 싱크 인자 지정에 쓴다)이다.

패턴 안에서 `$X`는 **메타변수**(무엇이든 하나), `...`는 "0개 이상의 무엇이든"(인자, 문장), `<... $X ...>`는 "`$X`를 포함하는 식"이다. 다음은 Flask 요청 값이 `os.system`에 닿는 것을 찾는 **taint 모드** 룰이다. 소스에서 싱크까지 흐름이 있으면(변수 대입을 거쳐도) 잡는다.

```yaml
# rules/flask-os-system.yaml
rules:
  - id: flask-request-to-os-system
    languages: [python]
    severity: ERROR
    message: Flask 요청 값이 os.system()에 도달한다. subprocess에 인자 리스트를 넘기고 허용 목록으로 제한하라.
    mode: taint
    pattern-sources:
      - pattern-either:
          - pattern: flask.request.args.get(...)
          - pattern: flask.request.args[...]
          - pattern: flask.request.form.get(...)
          - pattern: flask.request.form[...]
    pattern-sinks:
      - patterns:
          - pattern: os.system($CMD)
          - focus-metavariable: $CMD
    pattern-sanitizers:
      - pattern: shlex.quote(...)
```

`pattern-sources`, `pattern-sinks`, `pattern-sanitizers`는 각각 패턴 목록이며 안에서 `patterns`/`pattern-either`를 쓸 수 있다. `focus-metavariable: $CMD`는 싱크를 그 인자로 한정한다. 인자가 여럿인 함수에서 필요하다. 공식 레지스트리의 [`python.flask.security.injection.subprocess-injection`](https://github.com/semgrep/semgrep-rules/blob/develop/python/flask/security/injection/subprocess-injection.yaml)이 같은 구조의 실전 룰이다.

### 2.3 룰 테스트

룰 파일과 같은 이름의 테스트 파일(`flask-os-system.py`)에 주석으로 기대값을 적는다.

```python
# rules/flask-os-system.py
import os, shlex, flask
app = flask.Flask(__name__)

@app.route("/ping")
def ping():
    host = flask.request.args.get("host")
    # ruleid: flask-request-to-os-system
    os.system("ping -c 1 " + host)
    # ok: flask-request-to-os-system
    os.system("ping -c 1 " + shlex.quote(host))
    # ok: flask-request-to-os-system
    os.system("uptime")
```

```bash
semgrep --validate --config rules/        # 문법 검사 (semgrep.dev의 룰 린트에 접속한다)
semgrep --test rules/                     # ruleid/ok 주석과 대조
```

`--test`는 `ruleid:` 다음 줄에서 매치가 나고 `ok:` 다음 줄에서는 안 나는지 확인한다. [3부 1장](../part3-web/01-sql-injection.md)의 실습 앱 `labs/web-sqli/app/app.py`에 SQL 문자열 포매팅 룰을 같은 방식으로 써 보는 것이 좋은 연습이다.

## 3. CodeQL

### 3.1 설치와 데이터베이스 생성

CLI는 [codeql-cli-binaries 릴리스](https://github.com/github/codeql-cli-binaries/releases)에서 받아 풀고 PATH에 넣는다. 쿼리 팩은 필요할 때 내려받는다.

```bash
codeql pack download codeql/python-queries
codeql database create db-py --language=python --source-root .
```

언어 식별자는 `python`, `javascript-typescript`, `java-kotlin`, `csharp`, `cpp`, `go`, `ruby`, `swift`, `actions` 등이다. 컴파일 언어는 `--command="make"`처럼 빌드 명령을 주거나, 지원되는 언어(Java/Kotlin, C# 등)에서는 `--build-mode=none`으로 빌드 없이 추출한다. 데이터베이스는 디렉터리 하나이고, 소스가 바뀌면 다시 만든다.

### 3.2 쿼리 실행

```bash
codeql database analyze db-py codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=sarif-latest --output=results.sarif
```

스위트(`.qls`)는 쿼리 묶음이다. `python-code-scanning.qls`(기본, 정밀도 높은 것만), `python-security-extended.qls`(보안 쿼리 확대), `python-security-and-quality.qls`(품질 포함) 순으로 넓어진다. 결과 SARIF는 VS Code의 SARIF Viewer나 GitHub code scanning에서 보고, `--format=csv`로 표도 만든다. 쿼리 하나만 돌리려면 스위트 자리에 `.ql` 파일 경로를 준다. 단, `database analyze`는 `@kind` 메타데이터가 있는 쿼리만 받으므로, 3.3절처럼 메타데이터 없이 쓴 실험용 쿼리는 `codeql query run --database=db-py 파일.ql`로 돌린다.

### 3.3 QL의 기본 구조

QL은 `import` / `from` / `where` / `select`로 이루어진 SQL 비슷한 선언형 언어다. 다음은 `os.open` 호출의 첫 인자를 모두 찾는 쿼리로, [공식 문서](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/)의 예다.

```ql
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.ApiGraphs

from DataFlow::CallCfgNode call
where call = API::moduleImport("os").getMember("open").getACall()
select call.getArg(0)
```

`from`에서 변수와 타입을, `where`에서 조건을, `select`에서 출력을 쓴다. `API::moduleImport("os").getMember("open").getACall()`은 "os 모듈의 open을 호출하는 모든 지점"이다. 이것이 **API 그래프**이며, 싱크를 지정하는 표준 방법이다.

### 3.4 Taint tracking 쿼리

전역 taint 추적은 **설정 모듈**(configuration module)로 소스·싱크·차단(barrier)을 정의하고, 그것을 `TaintTracking::Global<설정>`에 넣어 흐름 모듈을 만든다. 경로를 보여 주는 `path-problem` 형식으로 쓰면 결과에 소스→싱크 경로가 붙는다.

```ql
/**
 * @name Remote input reaches os.system
 * @kind path-problem
 * @problem.severity error
 * @id kr/vmc/os-system-from-remote
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.ApiGraphs

module OsSystemConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node sink) {
    sink = API::moduleImport("os").getMember("system").getACall().getArg(0)
  }
}

module OsSystemFlow = TaintTracking::Global<OsSystemConfig>;

import OsSystemFlow::PathGraph

from OsSystemFlow::PathNode source, OsSystemFlow::PathNode sink
where OsSystemFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "os.system() 인자가 $@ 에서 온다.", source.getNode(), "원격 입력"
```

`RemoteFlowSource`는 표준 라이브러리가 정의한 "원격에서 오는 입력"(Flask·Django 요청 등)의 집합이라 프레임워크별 소스를 나열할 필요가 없다. 새니타이저는 `isBarrier(DataFlow::Node node)` 술어로 지정한다. 표준 쿼리 `py/command-line-injection`의 설정 모듈이 이 세 술어(와 증분 분석용 술어 하나)로 되어 있다 📎 [CommandInjectionQuery.qll](https://github.com/github/codeql/blob/main/python/ql/lib/semmle/python/security/dataflow/CommandInjectionQuery.qll). 경로가 필요 없으면 `@kind problem`으로 바꾸고 `OsSystemFlow::flow(source, sink)`에 `DataFlow::Node`를 쓴다. Semgrep의 taint 룰과 구조는 같고, 차이는 CodeQL이 함수와 파일 경계를 넘어 흐름을 따라간다는 것이다.

## 4. 핵심 워크플로: 룰 하나를 CI까지

순서는 다섯 단계다. (1) 이번 점검에서 가장 걱정되는 **싱크 하나**를 정한다(예: `os.system`). (2) 2.2~2.3절처럼 Semgrep taint 룰을 쓰고 `--test`가 통과할 때까지 고친다. (3) 전체에 돌려(`semgrep scan --config rules/ --sarif -o semgrep.sarif .`) 결과를 [0장 4절](00-when-to-use-what.md)의 절차로 재현·최소화한다. (4) 호출을 여러 번 거치는 흐름이 의심되면 3.4절의 CodeQL 쿼리로 다시 본다. (5) CI에 넣되 처음에는 경고만, 오탐을 정리한 뒤 실패로 바꾼다. `rules/`와 테스트 파일은 코드와 함께 버전 관리한다. **룰은 점검의 산출물이다.**

## 5. CI 통합 (GitHub Actions)

**CodeQL.** `init`에서 언어를 지정하고 `analyze`가 DB 생성·분석·SARIF 업로드를 한다. 액션의 현재 메이저 버전은 v4다 📎 [codeql-action README](https://github.com/github/codeql-action#readme).

```yaml
# .github/workflows/codeql.yml
on:
  push: { branches: [main] }
  pull_request: { branches: [main] }
permissions:
  contents: read
  security-events: write
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v4
        with:
          languages: python
          queries: security-extended
      - uses: github/codeql-action/analyze@v4
```

컴파일 언어는 `init`에 `build-mode: autobuild` 또는 `manual`(직접 빌드 단계를 둔다)을 준다. `security-events: write` 권한이 없으면 업로드가 실패한다.

**Semgrep.** 공식 컨테이너로 `semgrep ci`를 돌린다. Semgrep 계정(토큰)이 있으면 플랫폼의 정책과 분류를 따르고, 없으면 `semgrep scan`으로 룰을 직접 지정한다.

```yaml
# .github/workflows/semgrep.yml
on: [push, pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4
      - run: semgrep ci
        env:
          SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}
```

계정 없이 쓰려면 `run:`을 `semgrep scan --config p/default --config rules/ --error --sarif -o semgrep.sarif .`로 바꾸고 `github/codeql-action/upload-sarif@v4`로 올리면 두 도구의 결과가 같은 Security 탭에 모인다. `--error`는 매치가 있으면 0이 아닌 종료 코드로 작업을 실패시킨다.

## 6. 오탐률 관리

정적 분석 도입이 실패하는 이유는 거의 하나다. **처음 돌렸을 때 나온 수백 건의 경고를 아무도 보지 않게 되는 것.** 그래서 오탐 관리가 룰 작성만큼 중요하다. 범위부터 좁힌다. Semgrep은 `--exclude 'tests/**'`나 `.semgrepignore`, CodeQL은 `--source-root`로 테스트·벤더 코드를 뺀다.

| 수단 | Semgrep | CodeQL |
|---|---|---|
| 새 코드만 본다 | `--baseline-commit <sha>`: 그 커밋 이후 생긴 매치만 보고 | code scanning이 PR에서는 새로 생긴 알림만 표시 |
| 줄 단위 억제 | `# nosemgrep: rule-id` 주석 (사유를 옆에 적는다) | UI에서 알림을 "오탐"/"테스트 코드" 사유로 닫는다 |
| 룰을 고친다 | `pattern-not`, `pattern-not-inside`, `pattern-sanitizers` 추가 | `isBarrier` 추가, 싱크를 API 그래프로 더 정확히 지정 |

운영 규칙 세 가지.

1. **오탐 하나를 닫을 때마다 룰을 의심한다.** 같은 이유의 오탐이 세 번 나오면 `pattern-not`이나 `isBarrier`를 더한다. 억제 주석은 마지막 수단이다.
2. **정밀도를 잰다.** 분기마다 "검토한 알림 중 참 양성 비율"을 룰별로 기록하고, 낮은 룰은 `INFO`로 내리거나 뺀다. 숫자가 있어야 "이 도구는 시끄럽다"가 아니라 "이 룰이 시끄럽다"로 대화할 수 있다.
3. **놓친 참 양성을 테스트에 넣는다.** 수동 리뷰에서 찾았는데 도구가 못 잡은 취약점은 2.3절의 테스트 파일에 `ruleid:`로 추가하고 잡힐 때까지 룰을 고친다. 룰셋이 조직의 경험을 축적하는 자리가 된다.

## 체크리스트

**룰 작성**
- [ ] 룰에 `id`, `message`(고치는 방법 포함), `severity`, `languages`가 있고, 테스트 파일의 `ruleid:`/`ok:`가 `--test`를 통과하는가?
- [ ] taint 룰의 싱크가 `focus-metavariable`로 정확한 인자를 가리키는가?

**실행과 CI**
- [ ] 테스트·벤더 코드를 제외하고, 결과를 재현·최소화 없이 보고서에 옮기지 않았는가? [0장 4절](00-when-to-use-what.md)
- [ ] 여러 함수를 거치는 흐름은 CodeQL로도 봤는가?
- [ ] 처음에는 경고만, 오탐 정리 뒤 실패로 바꿨는가? 룰별 정밀도를 기록하는가?

## 더 읽기

- [Semgrep 문서: Rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax), [Taint mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode) · 연산자 전체, 소스·싱크·새니타이저·전파자
- [semgrep-rules 저장소](https://github.com/semgrep/semgrep-rules) · 공식 룰 원본. 룰 작성의 가장 좋은 교과서
- [CodeQL 문서: QL language reference](https://codeql.github.com/docs/ql-language-reference/) · 문법 기준
- [CodeQL 문서: Analyzing data flow in Python](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/) · 지역·전역 흐름과 설정 모듈 (다른 언어도 같은 구조)

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | Semgrep 룰 문법·taint 룰·테스트, CodeQL CLI·QL 구조·taint 설정 모듈, CI 통합, 오탐 관리 작성 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증: Semgrep 룰·테스트 파일을 semgrep 1.182에서 `--test` 통과·SARIF 1건 확인, CodeQL 쿼리 2개를 CodeQL CLI 2.27로 컴파일·실행 확인, CommandInjectionQuery.qll·codeql-action v4·README 한계 서술 대조, `--validate` 네트워크 필요 주석 추가 | 검증팀 |
