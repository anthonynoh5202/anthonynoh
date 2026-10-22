# 부록 B. 치트시트

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟢 | 🔄 개정중 | 2026-10-22 |

> **한눈에 보기**
> 자주 찾는 명령과 페이로드 문법을 한 곳에. 실습 환경에서만 사용한다.
> 명령은 2026-10 기준 현행 버전(Docker Compose v2, gdb 15, pwntools 4.15, Semgrep 1.18x, CodeQL CLI 2.x)으로 확인했다.

## 1. Docker Compose 실습 명령

```bash
cd labs/web-sqli
docker compose up --build            # 빌드 후 전면 실행. Ctrl+C 로 중지
docker compose up --build -d         # 백그라운드
docker compose ps                    # 상태
docker compose logs -f web           # 서비스 로그 따라가기
docker compose exec web sh           # 컨테이너 안 쉘
docker compose restart web           # 코드 고친 뒤 재시작 (볼륨 마운트일 때)
docker compose up --build --force-recreate   # 이미지부터 다시
docker compose down                  # 중지·삭제
docker compose down -v               # 볼륨까지 삭제 = 초기화
docker compose config                # 최종 compose 설정 확인
```

포트 충돌(8080)은 Burp 기본 포트와 겹친다. Burp 쪽을 8081로 바꾸거나 `docker-compose.yml`의 `ports`를 `"127.0.0.1:8090:8080"`으로 바꾼다. 실습 앱은 항상 `127.0.0.1`에만 바인딩한다.

## 2. gdb / pwndbg

### 2.1 gdb 기본

| 명령 | 뜻 |
|---|---|
| `gdb -q ./bin` · `gdb -q -p PID` | 시작 / 프로세스 붙기 |
| `starti` · `run < in.txt` · `run $(python3 -c 'print("A"*100)')` | 첫 명령에서 정지 / 입력 파일 / 인자 |
| `break main` · `break *0x401136` · `tbreak` · `delete` | 중단점 (주소는 `*`) / 1회용 / 삭제 |
| `watch var` · `rwatch` · `awatch` | 쓰기 / 읽기 / 둘 다 감시 |
| `catch syscall execve` · `catch signal SIGSEGV` | 시스템 콜 / 시그널 잡기 |
| `continue` `next` `step` `nexti` `stepi` `finish` | 실행 제어 (`c n s ni si fin`) |
| `x/20gx $rsp` · `x/8i $rip` · `x/s 0x4020a0` | 메모리 덤프: 8바이트 hex 20개 / 명령 8개 / 문자열 |
| `info registers` · `p $rax` · `p/x $rsp` · `p &buf` · `p sizeof(buf)` | 레지스터·값 |
| `bt` · `frame 1` · `info frame` · `info locals` | 호출 스택 |
| `disassemble main` · `set disassembly-flavor intel` | 디스어셈블 (AT&T 기본 → Intel) |
| `info proc mappings` · `info sharedlibrary` · `info functions regex` | 메모리 맵 / 라이브러리 / 심벌 찾기 |
| `set follow-fork-mode child` · `set detach-on-fork off` | fork 추적 |
| `record full` · `reverse-step` · `reverse-continue` | 되감기 디버깅 (느림, 짧은 구간용) |
| `set disable-randomization off` | gdb는 기본으로 ASLR을 끈다. 실제 환경 재현 시 |
| `display/i $pc` · `undisplay` | 멈출 때마다 자동 출력 |

### 2.2 pwndbg 추가 명령

| 명령 | 뜻 |
|---|---|
| `context` · `regs` · `stack 30` | 멈출 때 보이는 화면 다시 / 레지스터 / 스택 30줄 |
| `telescope $rsp 20` · `telescope 0x... 8` | 포인터를 따라가며 덤프 (스택, 힙, 코드 표시) |
| `vmmap` · `vmmap $rip` · `xinfo 0x...` | 메모리 맵 / 주소가 어느 영역인지 |
| `search "flag"` · `search -t qword 0xdeadbeef` | 메모리 검색 (문자열 / 8바이트 값) |
| `checksec` · `piebase` · `libcinfo` | 보호 기법 / PIE 베이스 / libc 정보 |
| `got` · `plt` · `retaddr` · `canary` | GOT·PLT 표 / 스택의 리턴 주소들 / 카나리 값 |
| `cyclic 200` · `cyclic -l 0x6161616b` | 패턴 생성 / 크래시 값으로 오프셋 찾기 |
| `heap` · `bins` · `tcachebins` · `fastbins` · `vis_heap_chunks` · `malloc_chunk ADDR` | glibc 힙 (최신 문서는 `vis-heap-chunks`처럼 하이픈 표기도 받는다) |
| `nearpc` · `procinfo` · `dumpargs` · `distance A B` | 현재 코드 근처 / 프로세스 정보 / 호출 인자 / 주소 간 거리 |

## 3. pwntools 스니펫

```python
from pwn import *
context(arch="amd64", os="linux", log_level="info")   # 기본은 i386. 반드시 지정
context.terminal = ["tmux", "splitw", "-h"]            # gdb.attach 창

elf  = ELF("./vuln")                      # checksec 자동 출력
libc = ELF("./libc.so.6")
p = process("./vuln")                     # 또는 remote("127.0.0.1", 1337)
# p = gdb.debug("./vuln", gdbscript="break *main+40\ncontinue")   # gdb 아래서 시작

p.recvuntil(b"name: ")                    # 구분자까지 읽기 (drop=False 기본)
p.sendline(b"A" * 8)
p.sendlineafter(b"> ", b"1")              # 프롬프트 기다렸다가 보내기
leak = u64(p.recvline(keepends=False)[-6:].ljust(8, b"\x00"))   # 6바이트 주소 복원
libc.address = leak - libc.symbols["puts"]
log.success(f"libc @ {libc.address:#x}")

# 오프셋 찾기
payload = cyclic(200)                     # 'aaaabaaacaaa...' (n=4 기본)
# 크래시 후 RSP 값: cyclic_find(0x6161616b) → 40

# ROP
rop = ROP([elf, libc])
rop.call("system", [next(libc.search(b"/bin/sh\x00"))])
ret = rop.find_gadget(["ret"])[0]         # 스택 정렬용
payload = flat(b"A" * 40, ret, rop.chain())   # flat/fit: 바이트·정수 섞어 직렬화

# 셸코드
sc = asm(shellcraft.sh())                 # context.arch 기준
p.send(payload)
p.interactive()
```

```bash
pwn checksec ./vuln                  # = checksec ./vuln
pwn cyclic 200 ; pwn cyclic -l 0x6161616b
pwn template ./vuln --host 127.0.0.1 --port 1337 > exploit.py
pwn shellcraft -f asm amd64.linux.sh
pwn libcdb file ./libc.so.6          # libc 식별
```

## 4. Semgrep / CodeQL

```bash
# Semgrep
semgrep scan --config auto .                              # 레지스트리 추천 룰 (로그인 필요할 수 있음)
semgrep scan --config p/default --metrics=off .           # 기본 보안·품질 룰, 텔레메트리 끔
semgrep scan --config p/sql-injection --config p/owasp-top-ten --severity ERROR .
semgrep scan --config rules/ --json -o out.json .         # 직접 쓴 룰, JSON 저장
semgrep scan --config rules/ --sarif -o out.sarif .       # SARIF (GitHub Code Scanning 업로드용)
semgrep scan -e '$DB.execute(f"...")' -l python .         # 룰 파일 없이 패턴 하나
semgrep scan --exclude tests --include 'src/**' --config p/python .
semgrep validate rules/                                   # 룰 문법 검사 (경로는 위치 인자)
semgrep test rules/                                       # 룰 테스트 (# ruleid: 주석 기반)
semgrep ci --config rules/ --baseline-commit origin/main  # 변경분만

# CodeQL
codeql resolve languages                                  # 지원 언어 목록
codeql database create db --language=python --source-root=.
codeql database create db --language=java-kotlin --command="mvn -q package"   # 컴파일 언어는 빌드 명령
codeql pack download codeql/python-queries                # 쿼리 팩 받기
codeql database analyze db codeql/python-queries \
  --format=sarif-latest --output=results.sarif --download
codeql database analyze db codeql/python-queries:codeql-suites/python-security-extended.qls \
  --format=csv --output=results.csv
codeql query run my.ql --database=db                      # 쿼리 하나만
```

Semgrep 룰 한 장의 뼈대는 [8부 3장 5절](../vol2-tech/part8-reporting/03-patch-verification.md)에 있다.

## 5. HTTP 요청 조작 체크리스트

```bash
# 요청 보기·고치기 (curl)
curl -v http://127.0.0.1:8080/item?id=1                         # 요청·응답 헤더 전부
curl -s -X POST http://127.0.0.1:8080/login \
  --data-urlencode "username=admin'-- " --data-urlencode "password=x"   # 폼, 자동 인코딩
curl -s --get --data-urlencode "q=' UNION SELECT 1,2-- " http://127.0.0.1:8080/search  # 쿼리 문자열
curl -s -H "Content-Type: application/json" -d '{"id":1}' http://127.0.0.1:8080/api   # JSON
curl -s -b "session=abc" -c jar.txt http://127.0.0.1:8080/      # 쿠키 보내기 / 저장
curl -s -H "X-Forwarded-For: 127.0.0.1" -H "Host: internal" URL # 헤더 변조
curl -s -o /dev/null -w "%{http_code} %{time_total}\n" URL      # 상태 코드·응답 시간 (블라인드용)
curl -s -F "file=@shell.php;type=image/png" URL/upload          # multipart, Content-Type 속임
```

| 확인할 것 | 방법 |
|---|---|
| 모든 입력 위치 | 경로·쿼리·헤더·쿠키·본문(폼/JSON/XML/multipart). 숨은 필드, `Referer`, `User-Agent` 포함 |
| 메서드 바꾸기 | `GET`↔`POST`, `PUT`, `DELETE`, `OPTIONS`. 접근 제어가 메서드별로 다를 때가 있다 |
| 타입 바꾸기 | 숫자→문자열, 문자열→배열(`id[]=1`), JSON 타입 변경(`"1"`→`1`→`true`→`null`) |
| 인코딩 | URL 인코딩 두 번, 유니코드 정규화, `%00`, `%0d%0a` |
| 상태 코드 비교 | 같은 요청을 인증 있음/없음, 내 ID/남의 ID로 보내 200·302·403 비교 |
| 응답 시간 | 시간 기반 블라인드. 5초 지연은 `%{time_total}` 로 |
| 캐시·중간 장비 | `Cache-Control`, `Vary`, `X-Cache` 헤더. 프록시 뒤의 경로 정규화 차이 |
| 세션 | 로그아웃 후 같은 쿠키로 재요청. 다른 브라우저에서 같은 토큰 |

## 6. checksec 결과 해석

pwntools `checksec` 출력 기준이다. 같은 이름의 셸 스크립트(checksec.sh)는 열 이름이 조금 다르다.

```
[*] '/bin/ls'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

| 항목 | 값 | 뜻 | 공격자에게 |
|---|---|---|---|
| RELRO | `No RELRO` / `Partial RELRO` / `Full RELRO` | GOT 쓰기 보호. Partial은 GOT가 쓰기 가능 | Partial 이하면 GOT 덮어쓰기 가능 |
| Stack | `Canary found` / `No canary found` | 스택 카나리 | 없으면 리턴 주소 직접 덮기. 있으면 누출 필요 |
| NX | `NX enabled` / `NX disabled` | 스택·힙 실행 금지 | 켜져 있으면 셸코드 대신 ROP |
| PIE | `PIE enabled` / `No PIE` | 코드 주소 무작위화 | 없으면 코드·GOT 주소가 고정. 있으면 누출 필요 |
| Stack: `Executable` · RWX | `Has RWX segments` | 실행 가능 스택 / RWX 세그먼트 | 있으면 셸코드 직접 실행 |
| RPATH / RUNPATH | 경로 | 라이브러리 검색 경로 하드코딩 | 쓰기 가능한 경로면 라이브러리 바꿔치기 |
| FORTIFY | `Enabled` | `_FORTIFY_SOURCE` 길이 검사 버전 사용 | `strcpy` 류 일부 차단 |
| SHSTK / IBT | `Enabled` | 인텔 CET 섀도 스택 / 간접 분기 추적 | CPU·커널이 지원할 때만 유효. ROP·JOP 제약 |
| Stripped / Debuginfo | `No` / `Yes` | 심벌·디버그 정보 유무 | 출력되면 분석이 쉬운 쪽 |
| Packer | `Packed with UPX` | 패킹 | 언패킹 먼저 |

마지막 네 줄은 해당할 때만 출력된다. 아무것도 안 나오면 "스트립됨, 디버그 정보 없음, 패킹 안 됨"이다.

## 7. CVSS 3.1 메트릭 약어표

| 그룹 | 약어 | 이름 | 값 |
|---|---|---|---|
| 기본 | AV | Attack Vector 공격 벡터 | N 네트워크 · A 인접 · L 로컬 · P 물리 |
| 기본 | AC | Attack Complexity 공격 복잡도 | L · H |
| 기본 | PR | Privileges Required 필요 권한 | N · L · H |
| 기본 | UI | User Interaction 사용자 상호작용 | N · R 필요 |
| 기본 | S | Scope 범위 | U 변화 없음 · C 변화 |
| 기본 | C / I / A | 기밀성 / 무결성 / 가용성 영향 | H · L · N |
| 시간 | E | Exploit Code Maturity | X · U 미확인 · P 개념 증명 · F 동작 · H 고도 |
| 시간 | RL | Remediation Level | X · O 공식 · T 임시 · W 우회 · U 없음 |
| 시간 | RC | Report Confidence | X · U 미확인 · R 합리적 · C 확인 |
| 환경 | CR / IR / AR | 보안 요구 수준 | X · L · M · H |
| 환경 | MAV MAC MPR MUI MS MC MI MA | 수정된 기본 메트릭 | 기본과 같음 + X |

등급: None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0. 벡터는 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` 형식. 4.0은 S가 없고 VC/VI/VA·SC/SI/SA, AT, UI N/P/A가 있다([8부 2장](../vol2-tech/part8-reporting/02-severity.md)).

## 8. 유형별 첫 탐지 입력

"따옴표 하나" 수준의 **첫 입력**과 그때 봐야 할 반응이다. 실습 환경·공개 연습 사이트 기준이며, 후보를 찾는 용도이지 증명이 아니다.

| 유형 | 첫 입력 | 보는 것 | 다음 단계 |
|---|---|---|---|
| SQLi | `'` → `' AND '1'='1` / `' AND '1'='2` | 500·DB 오류 / 두 응답의 차이 | 시간 지연, UNION. [3부 1장](../vol2-tech/part3-web/01-sql-injection.md) |
| XSS | `<u>x</u>` → `"><svg onload=alert(1)>` | 태그가 렌더링되는가 / 어떤 문맥(속성·JS·URL)인가 | 문맥별 페이로드. [3부 2장](../vol2-tech/part3-web/02-xss.md) |
| SSRF | `http://127.0.0.1:80/` · `http://127.0.0.1:22/` | 응답 내용·시간·오류 메시지 차이 | 내부 주소 대역, 메타데이터 주소. [3부 3장](../vol2-tech/part3-web/03-ssrf.md) |
| IDOR | 내 `id=1001` → `id=1000` | 남의 데이터가 오는가. 200 vs 403 | 순차/UUID, 쓰기 동작. [3부 5장](../vol2-tech/part3-web/05-access-control.md) |
| 경로 조작 | `../../../../etc/passwd` · `..%2f` | `root:x:0:0` | 인코딩 변형, 널 바이트. [3부 6장](../vol2-tech/part3-web/06-file-upload-path-traversal.md) |
| 파일 업로드 | `.php` → `.phtml` · `.php.png` · Content-Type만 이미지 | 저장 경로가 응답에 보이는가, 실행되는가 | 폴리글롯, 경로 조작 결합 |
| XXE | `<!DOCTYPE a [<!ENTITY x "t">]><r>&x;</r>` | `t`가 응답에 나오는가 | `SYSTEM "file:///etc/passwd"`. [3부 8장](../vol2-tech/part3-web/08-xxe.md) |
| SSTI | `{{7*7}}` · `${7*7}` · `<%= 7*7 %>` | `49`가 나오는가 | 엔진 식별 트리. [3부 9장](../vol2-tech/part3-web/09-ssti.md) |
| 명령 인젝션 | `;id` · `\| id` · `` `id` `` · `$(sleep 5)` | `uid=` 출력 / 5초 지연 | 블라인드면 시간·DNS |
| 역직렬화 | `rO0AB`(Java) · `O:4:`(PHP) · `gASV`(Python pickle) 로 시작하는 값 찾기 | 입력이 직렬화 객체인가 | 가젯 체인. [3부 7장](../vol2-tech/part3-web/07-deserialization.md) |
| 경쟁 조건 | 같은 요청 20개 동시 전송 (Burp Repeater 그룹, `parallel`) | 쿠폰·잔액이 두 번 적용되는가 | 창 넓히기. [3부 10장](../vol2-tech/part3-web/10-race-condition.md) |
| 스택 오버플로 | `python3 -c 'print("A"*2000)'` | SIGSEGV, RSP/RIP에 `0x4141...` | `cyclic`으로 오프셋. [4부 2장](../vol2-tech/part4-binary/02-stack-overflow.md) |
| 포맷 스트링 | `%x.%x.%x.%x` · `%s` | 스택 값이 찍히는가 / 크래시 | `%n` 쓰기. [4부 3장](../vol2-tech/part4-binary/03-format-string.md) |
| 정수 오버플로 | `-1` · `2147483648` · `4294967295` · `0` | 길이·개수 검사 우회, 큰 할당, 크래시 | [4부 6장](../vol2-tech/part4-binary/06-integer-overflow.md) |

## 체크리스트

- [ ] 실습 앱을 띄우고 내리고 초기화하는 명령 세 개를 안 보고 칠 수 있는가?
- [ ] gdb에서 특정 주소에 중단점을 걸고 스택 20줄을 덤프할 수 있는가?
- [ ] pwntools로 로컬 프로세스에 연결해 `cyclic`으로 오프셋을 찾을 수 있는가?
- [ ] Semgrep 룰 하나를 쓰고 `validate`·`test`를 통과시킬 수 있는가?
- [ ] `curl` 만으로 쿠키·헤더·JSON 본문을 조작할 수 있는가?
- [ ] checksec 출력을 보고 "어떤 공격이 막혀 있는가"를 말할 수 있는가?

## 더 읽기

- [pwntools 문서](https://docs.pwntools.com/en/stable/) · tubes, ELF, ROP, cyclic
- [pwndbg 명령 목록](https://pwndbg.readthedocs.io/en/latest/commands/) · 분류별 명령
- [GDB 매뉴얼](https://sourceware.org/gdb/current/onlinedocs/gdb/) · `x`, `catch`, `record`
- [Semgrep CLI reference](https://semgrep.dev/docs/cli-reference) · [Writing rules](https://semgrep.dev/docs/writing-rules/overview)
- [CodeQL CLI 문서](https://codeql.github.com/docs/codeql-cli/) · `database create` / `analyze`
- [Docker Compose CLI reference](https://docs.docker.com/reference/cli/docker/compose/)
- [curl 매뉴얼](https://curl.se/docs/manpage.html)
- [FIRST CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) · 유형별 페이로드 모음 (실습 환경에서만)

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 본문 작성. Compose, gdb/pwndbg, pwntools, Semgrep/CodeQL, HTTP, checksec, CVSS, 첫 탐지 입력 | @anthonynoh5202 |
