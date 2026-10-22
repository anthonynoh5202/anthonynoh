# 정수 오버플로와 타입 변환 (Integer Overflow and Type Conversion)

| 레벨 | 상태 | 최종 개정 | CWE |
|---|---|---|---|
| 🟡 | 🔄 개정중 | 2026-10-22 | [CWE-190](https://cwe.mitre.org/data/definitions/190.html) |

> **한눈에 보기**
> 고정 폭 정수는 범위를 넘으면 조용히 되감긴다(wrap). 큰 길이가 작은 수가 되고, 음수가 거대한 양수가 되고, 큰 값이 잘려 작아진다.
> 공격자는 그 "작은 수"로 할당된 버퍼에 "큰 데이터"를 넣어 힙 오버플로를 만들거나, 길이 검사를 통째로 건너뛴다.
> 막는 핵심은 **산술 결과를 쓰기 전에 오버플로를 검사하는 것**이다. `__builtin_*_overflow`, C23 `ckd_*`, 그리고 컴파일러 경고와 UBSan.

## 1. 원리

### 1.1 되감김이라는 신뢰 경계

32비트 부호 없는 정수는 0부터 4,294,967,295까지만 표현한다. 4,294,967,295에 1을 더하면 0이다. 이것은 버그가 아니라 C 표준이 정한 동작이다(모듈로 연산). 문제는 코드가 이 값을 **길이**나 **크기**로 쓸 때다.

```
 입력: count = 0x40000001 (1,073,741,825)

 size = count * 4
      = 0x1_0000_0004            ← 33비트가 필요하다
      = 0x0000_0004 (32비트로 잘림)

 buf = malloc(size)              ← 4바이트 할당
 for (i = 0; i < count; i++)     ← 10억 번 반복
     buf[i] = read_record();     ← 힙 오버플로
```

신뢰 경계는 `count`가 입력에서 들어와 `size` 계산에 쓰이는 줄에 있다. 길이 검사가 있었더라도 `size`로 검사했다면 통과한다. 검사한 값과 실제로 쓰는 값이 다르기 때문이다.

정수 오버플로는 거의 항상 **다른 취약점으로 가는 길목**이다. 혼자서는 잘못된 숫자 하나일 뿐이고, 그 숫자가 `malloc`, `memcpy`, 배열 인덱스, 루프 상한에 들어갈 때 [4장 힙 오버플로](04-heap.md)나 [2장 스택 오버플로](02-stack-overflow.md)가 된다. 반대로 말하면, 메모리 취약점의 상당수는 거슬러 올라가면 정수 계산 오류에서 시작한다.

### 1.2 C의 정수 규칙 다섯 가지

취약점을 읽으려면 컴파일러가 숫자를 어떻게 다루는지 알아야 한다. 다음 다섯 규칙이 사고의 대부분을 만든다.

| 규칙 | 내용 | 함정 |
|---|---|---|
| **정수 승격**(integer promotion) | `char`, `short`는 연산 전에 `int`로 바뀐다 | `uint16_t a = 65535; uint16_t b = a + 4;` → 계산은 `int`로 65539, 대입하며 3으로 잘린다 |
| **통상 산술 변환**(usual arithmetic conversions) | 부호 있는 수와 부호 없는 수가 만나면, 같은 폭이면 **부호 없는 쪽**으로 바뀐다 | `int len = -1; memcpy(buf, src, len);` → `len`이 `size_t`로 바뀌어 18,446,744,073,709,551,615바이트를 복사한다. 비교 `len > sizeof buf`에서도 같은 변환이 일어나 `-1`이 거대한 양수로 비교된다(2절) |
| **부호 없는 오버플로** | 모듈로 2ⁿ으로 되감긴다. 정의된 동작 | 조용하다. 새니타이저도 기본으로는 보고하지 않는다 |
| **부호 있는 오버플로** | **미정의 동작(UB)** | 컴파일러는 "일어나지 않는다"고 가정하고 최적화한다. `x + 1 > x`를 항상 참으로 접을 수 있다 |
| **축소 변환**(truncation) | 큰 타입을 작은 타입에 넣으면 상위 비트가 버려진다 | `size_t`를 `int`나 `uint16_t` 매개변수에 넘기는 순간 길이가 바뀐다 |

### 1.3 유형

| 유형 | CWE | 예 | 전형적 결과 |
|---|---|---|---|
| 오버플로·되감김 | [CWE-190](https://cwe.mitre.org/data/definitions/190.html) | `n * sizeof(T)`가 작아진다 | 작은 할당 + 큰 복사 → 힙 오버플로 |
| 언더플로 | [CWE-191](https://cwe.mitre.org/data/definitions/191.html) | `remaining = total - used`가 거대해진다 | 경계 검사 무력화 |
| 부호 오류 | [CWE-195](https://cwe.mitre.org/data/definitions/195.html) | 음수 길이가 부호 없는 비교를 통과 | `memcpy(dst, src, (size_t)-1)` |
| 축소 변환 | [CWE-197](https://cwe.mitre.org/data/definitions/197.html) | 64비트로 검사하고 32비트로 사용 | 검사와 사용의 불일치 |
| Off-by-one | [CWE-193](https://cwe.mitre.org/data/definitions/193.html) | `<=`와 `<`, NUL 종료 문자를 세지 않음 | 1바이트 오버플로. 힙 메타데이터·카나리 하위 바이트 변조 |

Off-by-one은 오버플로가 아니지만 같은 장에서 다룬다. "경계값에서 계산이 하나 틀린다"는 점에서 원인과 탐지법이 같기 때문이다. 1바이트가 작아 보여도 [7부 4장 sudo Baron Samedit](../part7-walkthroughs/04-cve-2021-3156-sudo-baron-samedit.md)처럼 루트 권한으로 이어진다.

## 2. 발생하는 코드 패턴

### 할당 크기 계산의 곱셈

```c
// ❌ 취약: nresp는 네트워크에서 온다. 곱셈이 되감기면 작은 버퍼가 나온다
uint32_t nresp = read_u32(pkt);
char **resp = malloc(nresp * sizeof(char *));
for (uint32_t i = 0; i < nresp; i++)
    resp[i] = read_string(pkt);          /* 힙 오버플로 */
```

```c
// ✅ 안전: 오버플로를 검사하는 산술을 쓰고, 상한도 둔다
#include <stdckdint.h>                   /* C23. Clang 18에서 확인 */
size_t bytes;
if (nresp > 100 || ckd_mul(&bytes, (size_t)nresp, sizeof(char *)))
    return -1;
char **resp = malloc(bytes);
```

```c
// ✅ 안전 (C23 이전): GCC/Clang 내장 함수, 또는 calloc/reallocarray
size_t bytes;
if (__builtin_mul_overflow((size_t)nresp, sizeof(char *), &bytes)) return -1;
char **resp = calloc(nresp, sizeof(char *));   /* calloc은 내부에서 곱셈 오버플로를 검사한다 */
```

8절의 CVE-2002-0639(OpenSSH)가 정확히 이 모양이었다.

### 부호 있는 길이와 부호 없는 비교

```c
// ❌ 취약: len이 음수면 int끼리의 비교는 통과하고, read()는 size_t로 받는다
int read_chunk(int fd, int len) {
    char buf[64];
    if (len > 64) return -1;        /* len = -1 → "-1 > 64"는 거짓 → 통과 */
    return read(fd, buf, len);      /* read(fd, buf, (size_t)-1) → 스택 오버플로 */
}
```

반대로 `if (len > sizeof buf)`처럼 **부호 없는 값과 비교**하면 `-1`이 `size_t`로 바뀌어 거대한 양수가 되므로 이번에는 거부된다. 같은 `-1`이 비교 상대의 타입에 따라 통과하기도 하고 거부되기도 한다. 핵심은 "부호가 섞인 코드는 읽는 사람의 직관과 다르게 동작한다"는 것이고, 그래서 `gcc -Wsign-compare`가 이런 줄에 경고를 낸다.

```c
// ✅ 안전: 길이는 처음부터 부호 없는 타입으로 받고, 경계와 같은 타입으로 비교한다
ssize_t read_chunk(int fd, size_t len) {
    char buf[64];
    if (len > sizeof buf) return -1;
    return read(fd, buf, len);
}
```

### 오프셋 + 길이 검사의 되감김

```c
// ❌ 취약: offset + len이 되감기면 작은 값이 되어 검사를 통과한다
if (offset + len > total_size) return -1;
memcpy(out, data + offset, len);
```

```c
// ✅ 안전: 뺄셈 형태로 바꾸면 되감김이 없다 (offset <= total_size를 먼저 보장)
if (offset > total_size || len > total_size - offset) return -1;
```

8절의 CVE-2022-0185(Linux `legacy_parse_param`)가 이 형태의 변형이다.

### Off-by-one

```c
// ❌ 취약: NUL 종료 문자 자리를 세지 않았다
char name[8];
if (strlen(in) <= sizeof name)    /* 8글자면 통과 */
    strcpy(name, in);             /* 9바이트 기록 (NUL 포함) */
```

```c
// ✅ 안전: strlen(in) < sizeof name, 또는 길이를 명시하는 API
if (strlen(in) < sizeof name) strcpy(name, in);
/* 또는 */ snprintf(name, sizeof name, "%s", in);
```

### 오버플로 "뒤에" 하는 검사

```c
// ❌ 취약: 부호 있는 오버플로는 UB. 컴파일러가 이 검사를 상수로 접을 수 있다
int r = a + b;
if (r < a) return -1;
```

```c
// ✅ 안전: 오버플로가 일어나기 "전에" 검사한다
if (b > 0 && a > INT_MAX - b) return -1;
/* 또는 */ if (__builtin_add_overflow(a, b, &r)) return -1;
```

방어 코드 자체가 UB에 의존하면 최적화 수준에 따라 방어가 사라진다(4절 5단계에서 확인한다).

## 3. 탐지 방법

### 3.1 코드 리뷰 / 정적 분석

**컴파일러 경고가 첫 번째 정적 분석기다.** 비용이 0이고, 부호·축소 문제의 대부분을 잡는다.

```bash
gcc -Wall -Wextra -Wconversion -Wsign-conversion -Wsign-compare -O2 -c target.c
# conv.c:9:13: warning: comparison of integer expressions of different signedness: 'int' and 'long unsigned int' [-Wsign-compare]
# conv.c:10:22: warning: conversion to 'size_t' {aka 'long unsigned int'} from 'int' may change the sign of the result [-Wsign-conversion]
# conv.c:18:14: warning: conversion from 'int' to 'char' changes value from '200' to '-56' [-Wconversion]
```

기존 코드에 `-Wconversion`을 켜면 경고가 수백 개 나온다. 전부 고칠 수 없다면 **입력을 다루는 파서·디코더 파일부터** 켠다.

**grep으로 후보를 좁힌다.** 할당 크기에 곱셈·덧셈이 있는 곳, 길이 매개변수가 `int`인 곳.

```bash
# 할당 크기에 산술이 들어간 곳
grep -rnE "(malloc|calloc|realloc|alloca|kmalloc|new\s+\w+\[)\s*\([^)]*[\*\+]" --include='*.c' --include='*.cpp' .
# 길이/크기/개수가 int로 선언된 매개변수
grep -rnE "\bint\s+(len|length|size|count|n|num|off|offset)\b" --include='*.h' .
```

**정적 분석기**

- CodeQL C/C++ 쿼리 팩에 CWE-190 계열 쿼리(할당 크기 산술, 부호 비교)가 있다. 입력에서 할당 크기까지의 흐름을 추적하므로 grep보다 오탐이 적다.
- Semgrep은 `malloc($N * $S)` 같은 구문 패턴 룰을 직접 쓰기 좋다. [6부 5장](../part6-tools/05-sast-semgrep-codeql.md)을 참고한다.

**리뷰할 때 보는 순서**

1. 외부 입력에서 오는 **숫자**를 전부 찾는다. 길이 필드, 개수, 오프셋, 인덱스, 크기, 시간.
2. 각 숫자가 산술 연산을 거치는지 본다. 곱셈과 덧셈은 오버플로, 뺄셈은 언더플로 후보다.
3. 산술 결과가 들어가는 **싱크**를 본다. `malloc`, `memcpy`, 배열 인덱스, 루프 상한, 포인터 덧셈.
4. 검사가 있다면 **검사한 타입과 사용하는 타입이 같은지**, 검사가 산술 **전**인지 본다.
5. 경계값을 머릿속으로 넣어 본다. `0`, `1`, `-1`, `INT_MAX`, `INT_MAX+1`, `UINT_MAX`, `65535`, `65536`, `SIZE_MAX / sizeof(T) + 1`.

### 3.2 동적 테스트

**UndefinedBehaviorSanitizer(UBSan)** 는 부호 있는 오버플로를 실행 시점에 잡는다.

```bash
gcc -g -fsanitize=undefined intov.c -o intov && ./intov
# intov.c:12:9: runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'
```

알아 둘 점이 세 가지다.

| 플래그 | 의미 |
|---|---|
| `-fsanitize=undefined` | UB 검사 묶음. 부호 있는 오버플로, 시프트, 배열 경계(일부), 널 역참조 등 |
| `-fsanitize=signed-integer-overflow` | 이 장의 주제만 켠다 |
| `-fsanitize=unsigned-integer-overflow` | **Clang 전용**. 부호 없는 되감김은 UB가 아니라 기본 묶음에 없다. 길이 계산 버그는 대부분 부호 없는 타입에서 나므로 퍼징 빌드에는 이 플래그를 따로 켠다 |
| `-fsanitize=implicit-conversion` | **Clang 전용**. 축소 변환·부호 변환으로 값이 바뀌는 순간을 보고한다 |
| `-fno-sanitize-recover=all` | 보고 후 계속 실행하지 않고 중단한다. 퍼징에서 크래시로 잡으려면 필수 |

UBSan은 "오버플로가 일어났다"만 알려 준다. 그것이 취약점인지는 그 값이 어디로 가는지 봐야 한다. 그래서 **ASan과 함께** 쓴다. 4절처럼 오버플로된 크기로 할당한 버퍼에 쓰면 ASan이 `heap-buffer-overflow`로 잡는다.

**경계값 테스트**는 각 숫자 입력에 3.1의 경계값 목록을 넣는 것이다. 반응은 정상 거부, 크래시, 그리고 **이상한 성공**(길이 65540을 보냈는데 4바이트만 처리됐다는 응답)으로 나뉘며 세 번째가 가장 위험한 신호다.

## 4. 실습 🧪

gcc 또는 clang만 있으면 된다. "레코드 수 + 레코드들" 형식을 읽는 파서를 만든다.

```c
/* records.c : 4바이트 count 뒤에 4바이트 레코드가 count개 온다 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
    uint32_t count;
    if (fread(&count, 4, 1, stdin) != 1) return 1;
    uint32_t size = count * 4;               /* ❌ 32비트 곱셈 오버플로 */
    uint32_t *recs = malloc(size);           /* 작게 할당 */
    if (!recs) return 1;
    for (uint32_t i = 0; i < count; i++)     /* 큰 count만큼 기록 */
        if (fread(&recs[i], 4, 1, stdin) != 1) break;
    printf("read %u records, buffer %u bytes\n", count, size);
    free(recs);
    return 0;
}
```

1. 정상 입력으로 동작을 확인한다.
   ```bash
   gcc -g -O0 -fsanitize=address records.c -o records
   python3 -c "import sys,struct; sys.stdout.buffer.write(struct.pack('<I',2)+b'AAAABBBB')" | ./records
   # read 2 records, buffer 8 bytes
   ```
2. `count = 0x40000001`을 넣는다. `0x40000001 * 4 = 0x100000004`, 32비트로는 `4`다.
   ```bash
   python3 -c "import sys,struct; sys.stdout.buffer.write(struct.pack('<I',0x40000001)+b'A'*64)" | ./records
   # ==5093==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000014 ...
   # WRITE of size 4 at 0x502000000014 thread T0
   #     #0 ... in fread
   #     #1 ... in main records.c:13
   # 0x502000000014 is located 0 bytes after 4-byte region [0x502000000010,0x502000000014)
   ```
   "4바이트 영역 바로 뒤에 4바이트 쓰기". 오버플로된 `size`가 그대로 보인다.
3. `gcc -g -fsanitize=undefined`로 UBSan만 켜고 돌려 본다. **아무것도 보고하지 않는다.** 부호 없는 곱셈의 되감김은 UB가 아니기 때문이다. 새니타이저 없이 돌리면 glibc가 `malloc(): corrupted top size`로 중단하거나, 운이 나쁘면 조용히 지나간다.
4. 고친다. `uint32_t size = count * 4;` 를 다음으로 바꾸고 2단계를 다시 돌리면 `too many records`로 거부된다.
   ```c
   uint32_t size;
   if (__builtin_mul_overflow(count, 4u, &size)) { fputs("too many records\n", stderr); return 1; }
   ```
   Clang 18 이상이면 `#include <stdckdint.h>` 후 `ckd_mul(&size, count, 4u)`로 같은 일을 한다(`-std=c23`).
5. (심화) 부호 있는 오버플로 검사가 최적화로 사라지는 것을 본다.
   ```c
   __attribute__((noinline)) int next_is_bigger(int x) { int r = x + 1; return r > x; }
   int main(void) { printf("%d\n", next_is_bigger(INT_MAX)); return 0; }
   ```
   `gcc -O2`는 `1`을, `gcc -O2 -fwrapv`는 `0`을 출력한다. `gcc -O2 -S`로 어셈블리를 보면 비교 없이 `movl $1, %eax; ret`만 남아 있다. `-fsanitize=signed-integer-overflow`를 붙이면 `runtime error: signed integer overflow: 2147483647 + 1 cannot be represented in type 'int'`가 보고된다. 덧셈과 비교를 한 식으로(`return x + 1 > x;`) 쓰면 gcc가 프런트엔드에서 미리 `1`로 접어 버려 `-O0`에서도, UBSan을 켜도 보고되지 않는다(gcc 13.3에서 확인). 방어 코드가 UB를 밟으면 "검사했다"는 흔적조차 남지 않는다는 뜻이다.

## 5. 익스플로잇 검증

| 단계 | 확인 | 심각도에 미치는 영향 |
|---|---|---|
| 1 | 외부 입력의 숫자로 오버플로·되감김을 일으킬 수 있다 (UBSan 보고, 또는 이상한 응답) | 후보. 그 자체로는 Low |
| 2 | 되감긴 값이 할당 크기·복사 길이·인덱스에 쓰인다 (ASan `heap-buffer-overflow` 등) | 메모리 손상. 최소 DoS, 보통 High |
| 3 | 손상되는 내용(복사되는 데이터)을 공격자가 정한다 | 임의 쓰기 후보. High~Critical |
| 4 | 손상 위치에 함수 포인터·힙 메타데이터·권한 플래그가 있다 | 제어 흐름 탈취 또는 권한 상승. Critical |

보고서는 2단계까지 가야 읽는 사람이 믿는다. "곱셈이 오버플로된다"는 지적에 개발자는 "그래서 뭐가 터지는가"로 되돌아오고, ASan 출력 한 장이 그 답이다. 반대로 통계 카운터나 시간 값처럼 2단계가 불가능한 되감김은 보통 취약점이 아니다.

## 6. 방어

| 계층 | 조치 | 효과 |
|---|---|---|
| 코드 | 할당·복사 길이 산술에 **검사하는 연산** 사용: `__builtin_add/sub/mul_overflow`(GCC·Clang), C23 `ckd_add/sub/mul` | 근본 제거 |
| 코드 | 개수×크기 할당은 `calloc(n, size)`, `reallocarray(p, n, size)`(glibc 2.26+) | 라이브러리가 곱셈 오버플로를 검사한다 |
| 코드 | 길이·크기·개수는 `size_t`로 통일. `int` 길이 매개변수를 없앤다 | 부호 오류 제거 |
| 코드 | 검사를 산술 **전에**, 뺄셈 형태로 쓴다 (`len > total - offset`) | 검사 자체의 오버플로 방지 |
| 코드 | 입력 숫자에 **의미 있는 상한**을 둔다 (레코드 100개, 헤더 64KB) | 극단값 차단. 가장 싸고 효과 큼 |
| 컴파일러 | `-Wall -Wextra -Wconversion -Wsign-compare`를 CI에서 오류로(`-Werror=sign-compare`) | 부호·축소 문제 예방 |
| 컴파일러 | `-ftrapv`(부호 있는 오버플로 시 중단), `-D_FORTIFY_SOURCE=2`, `-fstack-protector`([7장](07-mitigations.md)) | 오버플로 결과의 일부 차단. `-fwrapv`는 최적화 제거만 막고 되감김은 그대로다 |
| 언어 | Rust: 디버그 빌드는 오버플로 시 패닉, 릴리스는 `checked_*`/`wrapping_*`로 의도를 명시. Python·Java 등은 임의 정밀도나 예외 | 설계 수준 제거 |
| 탐지 | 퍼징·테스트 빌드에 `-fsanitize=undefined,address`, Clang이면 `unsigned-integer-overflow,implicit-conversion` 추가 | 사후 대응 |

**하지 말아야 할 것**

- "64비트로 바꾸면 끝"이라는 생각. `size_t * size_t`도 넘친다. 폭을 키우면 공격자가 넣어야 할 수가 커질 뿐이다.
- 오버플로 뒤에 `if (r < a)`로 검사하기. 부호 있는 타입에서는 UB라 최적화로 사라진다.

## 7. 우회 기법 🔴

| 방어 | 우회 |
|---|---|
| 상한 검사 `if (n > MAX)` | `n`이 부호 있는 타입이면 음수를 넣는다. 부호 없는 타입이면 `MAX`보다 작지만 곱셈 뒤에 넘치는 값을 찾는다 (`n * sizeof(T)`가 2³²을 막 넘는 `n`) |
| 64비트로 검사 | 검사 뒤에 32비트 매개변수로 넘기는 함수를 찾는다. 검사와 사용의 **타입 불일치**가 있으면 그 사이가 틈이다 |
| 덧셈 검사 `if (off + len > total)` | `off + len`이 되감기는 조합. `len = UINT_MAX - off + 1` 근처 |
| `-ftrapv`, `-fwrapv` | 전자는 부호 있는 연산만 트랩하고, 후자는 되감김을 "정의"했을 뿐 막지 않는다. 부호 없는 길이 산술은 그대로 넘친다 |
| 할당 실패 처리 `if (!p) return` | 오버플로된 크기는 **작아서** 할당이 성공한다. 실패 처리가 아니라 크기 검증이 필요 |
| Off-by-one 1바이트 | 힙에서는 다음 청크의 `size` 필드 하위 바이트, 스택에서는 저장된 `rbp`의 하위 바이트를 바꿔 더 큰 손상으로 키운다 ([4장](04-heap.md)) |

정수 취약점 사냥의 요령은 "검사가 있는가"가 아니라 **"검사한 값과 쓰는 값이 같은 타입·같은 시점인가"** 를 묻는 것이다. 다른 타입이면 변환이, 다른 시점이면 산술이 그 사이에 끼어든다.

## 8. 실제 CVE 사례

| CVE | 제품 | 핵심 | 패치 |
|---|---|---|---|
| [CVE-2002-0639](https://nvd.nist.gov/vuln/detail/CVE-2002-0639) | OpenSSH 2.9.9~3.3 sshd | 챌린지-응답 인증에서 응답 개수 `nresp`를 네트워크에서 읽어 `nresp * sizeof(char*)`로 할당. 곱셈 오버플로 → 힙 오버플로 → 원격 코드 실행 | [CERT CA-2002-18](http://www.cert.org/advisories/CA-2002-18.html) |
| [CVE-2017-7529](https://nvd.nist.gov/vuln/detail/CVE-2017-7529) | nginx 0.5.6~1.13.2 range 필터 | `Range` 헤더의 시작·끝 값 합산에서 정수 오버플로 → 캐시 파일 헤더 등 민감 메모리 누출 | [nginx 공지](http://mailman.nginx.org/pipermail/nginx-announce/2017/000200.html) |
| [CVE-2019-14287](https://nvd.nist.gov/vuln/detail/CVE-2019-14287) | sudo 1.8.28 이전 | `sudo -u#-1`(또는 `#4294967295`)로 지정한 UID가 `-1`로 변환되어 `setresuid`에 "변경 없음"으로 해석. `!root` 정책 우회로 root 명령 실행 | [sudo 권고](https://www.sudo.ws/alerts/minus_1_uid.html) |
| [CVE-2021-33909](https://nvd.nist.gov/vuln/detail/CVE-2021-33909) | Linux 커널 3.16~5.13.3 `seq_file` | 1GB가 넘는 경로를 만들어 `size_t` 오프셋을 `int`로 변환하며 음수화 → 범위 밖 쓰기 → 로컬 root ("Sequoia") | [커널 커밋 8cae8cd8](https://github.com/torvalds/linux/commit/8cae8cd89f05f6de223d63e6d15e31c8ba9cf53b) |
| [CVE-2022-0185](https://nvd.nist.gov/vuln/detail/CVE-2022-0185) | Linux 커널 `fs_context` `legacy_parse_param` | 매개변수 길이 검사 `len > PAGE_SIZE - 2 - size`에서 `size`가 커지면 우변이 언더플로 → 검사 통과 → 힙 오버플로 → 컨테이너 탈출·권한 상승 | [커널 커밋 722d9484](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=722d94847de2) |
| [CVE-2021-3156](https://nvd.nist.gov/vuln/detail/CVE-2021-3156) | sudo 1.9.5p2 이전 | 백슬래시로 끝나는 인자 처리의 off-by-one → 힙 오버플로 → 로컬 root ("Baron Samedit") | [sudo 1.9.5p2](https://www.sudo.ws/stable.html#1.9.5p2), [7부 4장 워크스루](../part7-walkthroughs/04-cve-2021-3156-sudo-baron-samedit.md) |

**CVE-2002-0639에서 배울 것**: 패치는 `nresp`에 상한(100)을 두는 검사 한 줄을 추가했다(권고문 및 공개된 수정 코드 기준). 2절 첫 패턴 그대로이며, "의미 있는 상한"이 가장 싼 방어라는 6절의 주장이 여기서 나온다.

**CVE-2019-14287에서 배울 것**: 권고문 기준으로, 패치는 사용자 지정 UID를 파싱할 때 `-1`과 `UID_MAX`(4294967295)를 거부하도록 바꿨다. 오버플로가 아니라 **"특수 의미를 가진 값"으로의 변환**이다. `uid_t`(부호 없음)에 저장된 4294967295가 `setresuid()`에는 `-1`, 즉 "바꾸지 말 것"으로 전달됐다. 정수 취약점은 산술이 없어도 생긴다는 사례다.

**CVE-2021-33909에서 배울 것**: 패치 커밋은 `seq_file` 버퍼 할당 크기에 상한(`MAX_RW_COUNT`)을 두어 `int`로 변환될 때 음수가 되는 크기를 처음부터 거부한다. 10억 바이트짜리 경로라는 극단 입력을 비특권 사용자가 만들 수 있었다. 경계값 테스트가 2³¹까지 포함해야 하는 이유다.

**CVE-2022-0185에서 배울 것**: 패치는 검사식을 `size + len + 2 > PAGE_SIZE` 형태로 고쳐(커밋 기준) 뺄셈 언더플로를 없앴다. 2절 "오프셋 + 길이 검사" 패턴과 같다. 검사식 자체가 오버플로·언더플로하지 않는지 보는 것이 리뷰의 핵심이다.

## 9. 체크리스트

**코드 리뷰할 때**
- [ ] 외부 입력에서 오는 길이·개수·오프셋·인덱스를 모두 찾았는가?
- [ ] 그 값이 곱셈·덧셈·뺄셈을 거쳐 `malloc`/`memcpy`/인덱스/루프 상한에 들어가는가?
- [ ] 검사가 산술 **전**에 있는가? 검사식 자체가 넘치지 않는가?
- [ ] 검사한 타입과 사용하는 타입이 같은가? (`size_t` → `int`, 64 → 32비트 변환)
- [ ] `int` 길이와 `size_t` 비교가 있는가? `-Wsign-compare` 경고가 0인가?
- [ ] `<=`와 `<`, NUL 종료 문자 1바이트가 경계 계산에 들어 있는가?

**테스트할 때**
- [ ] 각 숫자 입력에 `0, 1, -1, INT_MAX, INT_MAX+1, UINT_MAX, 65535, 65536` 을 넣어 봤는가?
- [ ] `-fsanitize=undefined,address`로 테스트와 퍼징을 돌렸는가? Clang이면 `unsigned-integer-overflow`도 켰는가?
- [ ] "이상한 성공" 응답(요청보다 작은 처리량)을 놓치지 않았는가?

**배포 전**
- [ ] CI에서 `-Wconversion -Wsign-compare`가 켜져 있고 새 경고가 빌드를 깨는가?
- [ ] 입력 숫자마다 문서화된 상한이 있고 코드가 그것을 검사하는가?

## 10. 더 읽기

- [CWE-190](https://cwe.mitre.org/data/definitions/190.html), [CWE-191](https://cwe.mitre.org/data/definitions/191.html), [CWE-195](https://cwe.mitre.org/data/definitions/195.html), [CWE-193](https://cwe.mitre.org/data/definitions/193.html) · 공식 정의
- [GCC: Built-in Functions to Perform Arithmetic with Overflow Checking](https://gcc.gnu.org/onlinedocs/gcc/Integer-Overflow-Builtins.html) · `__builtin_add_overflow` 계열 공식 문서
- [UndefinedBehaviorSanitizer 문서](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html) · 검사 목록, `-fno-sanitize-recover`, `UBSAN_OPTIONS`
- [SEI CERT C: INT30-C (부호 없는 되감김), INT32-C (부호 있는 오버플로)](https://wiki.sei.cmu.edu/confluence/display/c/INT30-C.+Ensure+that+unsigned+integer+operations+do+not+wrap) · 규칙별 안전한 코드 예
- Qualys, "Sequoia: A deep root in Linux's filesystem layer (CVE-2021-33909)", 2021 · `size_t`→`int` 변환 하나가 root가 되는 전 과정
- [7부 4장 CVE-2021-3156 워크스루](../part7-walkthroughs/04-cve-2021-3156-sudo-baron-samedit.md) · off-by-one에서 권한 상승까지

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 10섹션 본문 작성. 컴파일러 경고·UBSan·ASan 출력, `ckd_mul`/`__builtin_mul_overflow` 로컬 검증, CVE 6건 확인 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증: CVE 6건 cvelistV5 대조(모두 실존, 버전·패치 링크 일치). records.c(ASan·UBSan·무새니타이저·수정판), `ckd_mul`(clang 18 `-std=c23`), `-Wconversion` 계열 경고, `-fwrapv` 실험을 재실행. 통상 산술 변환 표의 예시(`len > sizeof buf`는 통과가 아니라 거부) 정정, ASan 줄 번호 정정, 5단계 예제를 UBSan이 실제로 보고하는 형태(`int r = x + 1; return r > x;`)로 교체(한 식으로 쓰면 gcc가 접어 버려 보고 안 됨) | 검증팀 |
