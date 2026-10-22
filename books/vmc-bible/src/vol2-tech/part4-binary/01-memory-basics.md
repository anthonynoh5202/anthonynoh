# 메모리 구조와 호출 규약

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟢 | 🔄 개정중 | 2026-10-22 |

> **한눈에 보기**
> 스택 프레임, 힙 청크, 호출 규약을 모르면 어떤 메모리 취약점도 이해할 수 없다. 이 장은 이 부 전체의 선수 과목이다.
> 모든 그림은 gdb에서 직접 찍은 값이다. 읽기만 하지 말고 5절의 절차대로 자기 컴퓨터에서 같은 값을 꺼내 보는 것이 이 장의 목표다.

## 1. 프로세스 메모리 레이아웃

리눅스 x86-64 프로세스 하나를 gdb에서 멈추고 `info proc mappings`로 찍으면 이런 모양이다. 주소는 [00장](00-overview.md)의 플래그(`-no-pie`)로 컴파일한 바이너리를 gdb(ASLR 해제) 안에서 본 값이다.

```
 높은 주소
 0xffffffffff600000  [vsyscall]                 --xp  (커널이 제공, 거의 안 씀)
 0x7ffffffde000      [stack]                    rwxp  ← 지역 변수, 반환 주소. 아래로 자란다 ↓
                                                      (-z execstack 이라 x가 켜져 있다)
 0x7ffff7fc5000      ld-linux-x86-64.so.2       r--p / r-xp / rw-p   동적 로더
 0x7ffff7fc3000      [vdso]                     r-xp
 0x7ffff7c00000      libc.so.6                  r--p / r-xp / r--p / rw-p
                     ─── 공유 라이브러리 영역 (mmap) ───
                     ... 빈 공간 ...
 0x405000            [heap]                     rw-p  ← malloc. 위로 자란다 ↑  (첫 malloc 뒤에 생긴다)
 0x404000            vuln  .data / .bss / GOT   rw-p  ← 전역 변수, 함수 포인터 테이블
 0x403000            vuln  .rodata / .eh_frame  r--p  ← 문자열 상수
 0x401000            vuln  .text                r-xp  ← 코드. 쓰기 불가
 0x400000            vuln  ELF 헤더             r--p
 낮은 주소
```

<figure>
<figcaption>그림 1. 프로세스 메모리 레이아웃. 권한 열(r/w/x)이 핵심이다. 공격자가 쓸 수 있는 곳(w)과 실행할 수 있는 곳(x)이 겹치면 셸코드가 가능하고, 겹치지 않으면 ROP가 필요하다.</figcaption>
</figure>

| 영역 | 무엇이 있나 | 취약점과의 관계 |
|---|---|---|
| `.text` | 기계어 | 읽고 실행만 가능. ROP 가젯의 출처 ([08장](08-rop.md)) |
| `.rodata` | 문자열 상수, 상수 테이블 | `"/bin/sh"` 같은 문자열이 여기 있으면 공격자가 그대로 쓴다 |
| `.data` / `.bss` | 초기화된 / 0으로 초기화된 전역 변수 | 주소가 고정(no-PIE)이라 쓰기 대상이 되기 쉽다 |
| GOT (`.got.plt`) | 라이브러리 함수의 실제 주소 테이블 | 덮어쓰면 `puts` 호출이 `system` 호출이 된다 ([03장](03-format-string.md)) |
| `[heap]` | `malloc`이 나눠 주는 영역 | 청크 메타데이터가 데이터와 섞여 있다 ([04장](04-heap.md)) |
| 공유 라이브러리 | libc, ld.so | `system`, `execve` 등 공격자가 빌려 쓸 코드 |
| `[stack]` | 지역 변수, 인자, 반환 주소 | 반환 주소가 데이터 바로 옆에 있다 ([02장](02-stack-overflow.md)) |

PIE를 켜면 `0x400000`이 `0x5555...`처럼 무작위 주소로 바뀌고, ASLR이 켜지면 스택·힙·라이브러리 주소도 실행마다 바뀐다. 레이아웃 자체는 같다.

## 2. 스택 프레임과 반환 주소

함수가 호출될 때마다 스택에 **프레임**(frame)이 하나 쌓인다. 아래 파일을 5절의 플래그(`gcc -g -O0 -fno-stack-protector -z execstack -no-pie -o vuln vuln.c`)로 컴파일하고 `greet` 안에서 멈춘 상태다. 파일 전체를 그대로 저장해야 아래 `break 8`의 줄 번호가 맞는다.

```c
/* vuln.c */
#include <stdio.h>
#include <unistd.h>

void greet(void) {
    char name[64];
    read(0, name, 256);
    printf("hello, %s\n", name);      /* 8번째 줄. 아래에서 break 8 */
}

int main(void) { greet(); return 0; }
```

```
$ gdb -q ./vuln
(gdb) disas greet
   0x40115a <+4>:    push   %rbp              ; 호출자의 rbp 저장
   0x40115b <+5>:    mov    %rsp,%rbp         ; 새 프레임 기준점
   0x40115e <+8>:    sub    $0x40,%rsp        ; 지역 변수 64바이트 확보
   0x401162 <+12>:   lea    -0x40(%rbp),%rax  ; name = rbp - 0x40
   ...
   0x401194 <+62>:   leave                    ; rsp = rbp; pop rbp
   0x401195 <+63>:   ret                      ; pop rip
```

`info frame`과 `x/8gx $rsp`로 실제 값을 본다. 줄 번호 대신 `break greet`로 함수 입구에 멈춘 뒤 `next`를 두 번 눌러도 같은 지점이다.

```
(gdb) break 8           # printf 줄
(gdb) run
(gdb) info frame
Stack level 0, frame at 0x7fffffffc600:
 rip = 0x401178 in greet (vuln.c:8); saved rip = 0x4011a3
 Saved registers:
  rbp at 0x7fffffffc5f0, rip at 0x7fffffffc5f8
(gdb) p &name
$1 = (char (*)[64]) 0x7fffffffc5b0
(gdb) x/2gx $rbp
0x7fffffffc5f0: 0x00007fffffffc600  0x00000000004011a3
                ^ 저장된 rbp          ^ 반환 주소 (main 안의 call 다음 명령)
```

이 값을 그림으로 옮기면 다음과 같다.

```
 높은 주소
 ┌──────────────────────────┐
 │  main의 프레임            │
 ├──────────────────────────┤  0x7fffffffc600  ← greet 호출 전 rsp
 │  반환 주소 0x4011a3       │  0x7fffffffc5f8  ← rbp + 8  (call이 push)
 ├──────────────────────────┤
 │  저장된 rbp 0x7fffffffc600│  0x7fffffffc5f0  ← rbp      (push %rbp)
 ├──────────────────────────┤
 │  name[56..63]            │  0x7fffffffc5e8
 │  name[48..55]            │  0x7fffffffc5e0
 │  ...                     │
 │  name[8..15]             │  0x7fffffffc5b8
 │  name[0..7]              │  0x7fffffffc5b0  ← rbp - 0x40 = rsp
 └──────────────────────────┘
 낮은 주소                       ▲ read()는 여기서 시작해 위로 쓴다
```

<figure>
<figcaption>그림 2. greet의 스택 프레임. name[0]에서 시작한 쓰기는 64바이트를 지나면 저장된 rbp(8바이트), 그 다음 반환 주소에 닿는다. 그래서 02장의 오프셋이 64 + 8 = 72다.</figcaption>
</figure>

기억할 것은 세 가지다.

1. **`call`이 반환 주소를 스택에 둔다.** 데이터(지역 배열)와 제어 정보(반환 주소)가 같은 스택에 섞여 있는 것이 모든 스택 취약점의 뿌리다.
2. **`ret`은 검증하지 않는다.** `[rsp]`에 무엇이 있든 그곳으로 점프한다.
3. **지역 변수의 배치는 컴파일러가 정한다.** `-O0`에서도 선언 순서와 다를 수 있다. 추측하지 말고 `p &변수`로 확인한다.

스택 카나리(`-fstack-protector`)는 저장된 rbp 바로 아래에 비밀 값을 하나 끼워 넣고 `ret` 직전에 검사한다. 배열에서 반환 주소까지 가려면 카나리를 지나야 하므로 덮어쓰기가 들킨다. 자세한 것은 [07장](07-mitigations.md)이다.

## 3. x86-64 SysV 호출 규약

함수 인자는 스택이 아니라 **레지스터**로 간다. 아래 코드로 확인한다.

```c
long add3(long a, long b, long c) { return a + b + c; }
int main(void) { long r = add3(1, 2, 3); printf("%ld\n", r); return 0; }
```

```
(gdb) disas main
   0x40116a <+12>:   mov    $0x3,%edx         ; 3번째 인자 → rdx
   0x40116f <+17>:   mov    $0x2,%esi         ; 2번째 인자 → rsi
   0x401174 <+22>:   mov    $0x1,%edi         ; 1번째 인자 → rdi
   0x401179 <+27>:   call   0x401136 <add3>
   0x40117e <+32>:   mov    %rax,-0x8(%rbp)   ; 반환값 rax → r
(gdb) break add3
(gdb) run
(gdb) info registers rdi rsi rdx
rdi            0x1                 1
rsi            0x2                 2
rdx            0x3                 3
(gdb) x/2gx $rsp
0x7fffffffc600: 0x00007fffffffc620  0x000000000040117e   ; 저장된 rbp, 반환 주소 = call 다음 줄
(gdb) finish
Value returned is $1 = 6                                  ; rax
```

| 항목 | 규칙 | 분석할 때의 의미 |
|---|---|---|
| 인자 1~6 | `rdi, rsi, rdx, rcx, r8, r9` | `call strcpy` 직전 `rdi`=목적지, `rsi`=원본 |
| 인자 7~ | 스택에 역순으로 push | 가변 인자 함수(`printf`)의 7번째 이후 인자는 스택에서 읽는다 ([03장](03-format-string.md)) |
| 반환값 | `rax` | `call malloc` 직후 `rax`가 청크 주소 |
| 보존(callee-saved) | `rbx, rbp, r12~r15` | 피호출자가 쓰려면 저장했다 복원한다 → 프롤로그에 `push rbx` |
| 비보존(caller-saved) | 나머지 전부 | 호출 뒤에는 값이 깨졌다고 가정한다 |
| 정렬 | `call` 직전 `rsp % 16 == 0` | ROP 체인에서 `system()`이 이유 없이 죽으면 대개 이것이다 ([08장](08-rop.md)) |
| `rax` (가변 인자) | 호출자가 벡터 레지스터 사용 개수를 `al`에 넣는다 | `printf` 직전의 `mov $0x0,%eax`가 그것이다 |

**`ret2libc`가 왜 가능한지**가 여기서 나온다. `system("/bin/sh")`를 부르려면 `rdi`에 `"/bin/sh"` 주소를 넣고 `system`으로 점프하면 된다. 스택에 인자를 쌓을 필요가 없는 대신, `rdi`를 채워 줄 `pop rdi; ret` 가젯이 필요하다. 32비트 시절과 가장 다른 점이다.

## 4. glibc malloc 청크 구조 개요

`malloc(24)`를 두 번 부르고 gdb에서 힙을 찍는다. 힙 주소는 PIE 바이너리라 `0x5555...`다.

```c
char *a = malloc(24);
char *b = malloc(24);
strcpy(a, "AAAAAAAA");
strcpy(b, "BBBBBBBB");
```

```
(gdb) x/8gx a-16
0x555555559290: 0x0000000000000000  0x0000000000000021   ; [prev_size] [size = 0x20 | PREV_INUSE]
0x5555555592a0: 0x4141414141414141  0x0000000000000000   ; a가 가리키는 곳 (사용자 데이터)
0x5555555592b0: 0x0000000000000000  0x0000000000000021   ; [prev_size(b)] [size(b)]
0x5555555592c0: 0x4242424242424242  0x0000000000000000   ; b
```

```
 ┌─────────────────────┬─────────────────────┐
 │ prev_size (8)       │ size (8)       |A|M|P│  ← 청크 헤더. 사용자는 모른다
 ├─────────────────────┴─────────────────────┤
 │ 사용자 데이터 (malloc이 돌려준 포인터)      │  ← a
 │ ... 24바이트 요청 → 다음 prev_size까지 사용 │
 ├─────────────────────┬─────────────────────┤
 │ prev_size           │ size           |A|M|P│  ← 다음 청크 헤더. a를 넘어 쓰면 여기부터 깨진다
 ├─────────────────────┴─────────────────────┤
 │ 사용자 데이터                               │  ← b
 └───────────────────────────────────────────┘
```

<figure>
<figcaption>그림 3. 사용 중인 청크 두 개. 메타데이터(size)와 데이터가 8바이트 간격으로 붙어 있다. a에 25번째 바이트를 쓰면 b의 size가 바뀐다.</figcaption>
</figure>

**size 필드의 하위 3비트는 플래그다.** 청크 크기는 항상 16의 배수라 하위 4비트가 0이고, 그 자리를 빌려 쓴다.

| 비트 | 이름 | 뜻 |
|---|---|---|
| 0x1 | `PREV_INUSE` (P) | 바로 앞 청크가 사용 중. 0이면 앞 청크가 해제됐고 `prev_size`가 유효하다 |
| 0x2 | `IS_MMAPPED` (M) | `mmap`으로 받은 큰 청크. `free`하면 `munmap` |
| 0x4 | `NON_MAIN_ARENA` (A) | 메인이 아닌 아레나(스레드별) 소속 |

위 예에서 `0x21` = 크기 `0x20` + `PREV_INUSE`. `malloc(24)`가 `0x20`짜리 청크가 되는 이유는 헤더 8바이트를 더하고 16으로 올림하기 때문이다. 24바이트 요청은 다음 청크의 `prev_size` 자리까지 빌려 쓴다(앞 청크가 사용 중이면 `prev_size`는 필요 없으므로).

두 청크를 `free`하면 사용자 데이터 자리에 **할당자의 연결 리스트 포인터**가 들어간다.

```
(gdb) next   # free(a); free(b);
(gdb) x/4gx a-16
0x555555559290: 0x0000000000000000  0x0000000000000021
0x5555555592a0: 0x0000000555555559  0xb2c1560763ec90e9   ; [next (safe-linking 적용)] [key]
(gdb) x/2gx b
0x5555555592c0: 0x000055500000c7f9  0xb2c1560763ec90e9   ; b.next → a (가려져 있음), key
```

작은 청크는 해제되면 **tcache**라는 스레드별 단일 연결 리스트에 들어간다. 첫 8바이트가 `next`, 다음 8바이트가 double free 탐지용 `key`다. `next`가 이상한 값인 것은 glibc 2.32부터 포인터를 `(주소 >> 12) ^ 포인터`로 가려 두기 때문(safe-linking)이다. bin의 종류, 버전별 차이, 그리고 이 리스트를 조작하는 공격은 [04장](04-heap.md)에서 다룬다. 여기서는 한 가지만 기억한다. **힙에서는 데이터와 메타데이터가 같은 바이트 열 안에 번갈아 놓여 있다.**

## 5. gdb로 직접 확인하는 절차

이 장의 모든 값은 다음 절차로 얻었다. 4부의 다른 장에서도 같은 순서로 시작한다.

```bash
gcc -g -O0 -fno-stack-protector -z execstack -no-pie -o vuln vuln.c
gdb -q ./vuln
```

| 단계 | 명령 | 보는 것 |
|---|---|---|
| 1 | `disas greet` | 프롤로그(`sub $0x40,%rsp`)에서 프레임 크기, 지역 변수 위치(`-0x40(%rbp)`) |
| 2 | `break 8`, `break greet` 또는 `break *0x401178` | 소스 줄, 함수, 주소에 중단점 |
| 3 | `run` (`run < input.txt`로 입력 지정) | 중단점까지 실행 |
| 4 | `info frame` | 저장된 rbp·rip의 **주소** |
| 5 | `x/8gx $rsp` | rsp부터 8바이트(g)씩 16진수(x) 8개. 스택 내용 그대로 |
| 6 | `p &name`, `p $rbp - (char*)&name` | 변수 주소, 반환 주소까지 거리 |
| 7 | `info registers rdi rsi rdx rax rip` | 호출 직전 인자, 직후 반환값 |
| 8 | `x/s $rdi`, `x/16xb $rsi` | 포인터가 가리키는 문자열·바이트 |
| 9 | `ni` / `si` / `finish` | 한 명령 넘기기 / 들어가기 / 현재 함수 끝까지 |
| 10 | `info proc mappings` | 1절의 메모리 지도. 권한 열을 본다 |

자주 쓰는 `x` 형식: `x/NFU 주소`. N은 개수, F는 `x`(16진) `d`(10진) `s`(문자열) `i`(명령어), U는 `b`(1) `h`(2) `w`(4) `g`(8)바이트. `x/3i $rip`는 다음 세 명령어다.

> 🟡 gdb 안과 밖의 스택 주소는 다르다. gdb는 환경 변수 `LINES`, `COLUMNS`를 추가하고, 실행 경로가 절대 경로로 바뀐다. 셸코드 주소를 gdb에서 읽어 밖에서 쓸 때는 `set exec-wrapper env -i`와 `env -i`로 환경을 맞추거나, NOP 슬레드로 오차를 흡수한다. [02장 4절](02-stack-overflow.md)에서 실제로 겪는다.

pwndbg를 얹으면 중단점마다 레지스터·스택·디스어셈블리를 한 화면에 보여 주고, `heap`, `bins`, `vis-heap-chunks`(별칭 `vis`) 명령으로 4절의 청크 구조를 색으로 구분해 보여 준다. 명령 이름은 [도구 3장](../part6-tools/03-debuggers.md)에 정리되어 있다.

## 체크리스트

이 장을 읽고 나면 다음을 자기 컴퓨터에서 재현할 수 있어야 한다.

- [ ] `info proc mappings`에서 `.text`, `.data`, `[heap]`, libc, `[stack]`의 권한(r/w/x)을 읽을 수 있는가?
- [ ] `disas` 출력의 프롤로그에서 지역 변수 영역 크기를 알아낼 수 있는가?
- [ ] `info frame`과 `x/2gx $rbp`로 저장된 rbp와 반환 주소를 찾고, 배열 시작에서 반환 주소까지의 거리를 계산할 수 있는가?
- [ ] 함수 호출 직전에 `rdi, rsi, rdx`를 찍어 인자를 확인할 수 있는가?
- [ ] `x/4gx 포인터-16`으로 청크의 size 필드를 읽고 하위 3비트 플래그를 해석할 수 있는가?
- [ ] 해제된 청크의 첫 16바이트(`next`, `key`)가 무엇인지 설명할 수 있는가?

## 더 읽기

- [System V AMD64 ABI](https://gitlab.com/x86-psABIs/x86-64-ABI) · 3절의 1차 출처. 3.2절 "Function Calling Sequence"
- [glibc Wiki: MallocInternals](https://sourceware.org/glibc/wiki/MallocInternals) · 4절의 1차 출처. 청크 구조, 아레나, bin을 glibc 개발자가 설명
- [GDB 공식 매뉴얼: Examining Memory](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Memory.html) · `x` 명령의 모든 형식
- [pwndbg Features](https://github.com/pwndbg/pwndbg#features) · `heap`, `bins`, `telescope` 등 명령 목록
- Aleph One, "Smashing The Stack For Fun And Profit", *Phrack* 49 (1996). [원문](http://phrack.org/issues/49/14.html) · 2절의 그림을 32비트로 처음 그린 글
- [Linux man-pages: proc_pid_maps(5)](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html) · `info proc mappings`가 읽는 파일의 형식

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 본문 작성: 메모리 레이아웃, 스택 프레임, SysV 호출 규약, malloc 청크, gdb 절차. 모든 출력은 glibc 2.39 / gcc 13 환경에서 실측 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증 완료, 수정 없음. 2~4절의 C 코드를 본문 플래그로 빌드해 gdb에서 재실행: 프롤로그(`sub $0x40,%rsp`), `info frame`, `add3` 디스어셈블리·레지스터, 청크 덤프(`0x21`, safe-linking 적용 `next`, `key`)가 본문 값과 일치. safe-linking(2.32)·tcache `key`(2.29/2.34)는 glibc `malloc.c` 소스로 대조 | 검증팀 |
| 2026-10-22 | 독자 테스트 반영: 2절 vuln.c를 파일 전체로 싣고 gdb 중단점·주소·스택 그림을 그 파일의 실측값(`break 8`, 반환 주소 0x4011a3)으로 교체, pwndbg 명령 `vis-heap-chunks`, 장 참조 표기 정리 | @anthonynoh5202 |
