# 완화 기법과 우회

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟡 (6·7절은 🔴) | 🔄 개정중 | 2026-10-22 |

> **한눈에 보기**
> NX, ASLR, 카나리, PIE, RELRO, CFI, CET, PAC, MTE는 각각 **한 가지 공격 단계**만 막는다. 취약점을 없애는 것이 아니라 익스플로잇을 비싸게 만든다.
> 그래서 분석의 첫 질문은 "취약점이 있는가"가 아니라 "이 바이너리에 무엇이 켜져 있고, 그래서 무엇이 **남아** 있는가"다.
> 이 장은 `checksec` 출력 한 줄을 읽고 공격 경로를 머릿속에 그리는 훈련이다.

## 1. 완화 기법이라는 사고방식

[2장 스택 오버플로](02-stack-overflow.md)의 고전적 익스플로잇은 세 단계다. (1) 반환 주소를 덮는다 (2) 스택에 셸코드를 올린다 (3) 반환 주소를 셸코드로 돌린다. 완화 기법은 이 각 단계에 하나씩 대응한다.

```mermaid
flowchart LR
    A["① 버퍼 오버플로로<br/>반환 주소 덮기"] -->|카나리가 막는다| B["② 공격 코드 배치"]
    B -->|NX가 막는다<br/>→ 기존 코드 재사용(ROP)| C["③ 그 코드로 점프"]
    C -->|ASLR·PIE가 주소를 숨긴다<br/>→ 정보 누출 필요| D["④ 셸 획득"]
    C -->|CFI·CET·PAC가<br/>잘못된 점프를 거부| D
    style A fill:#fde2e2,stroke:#b00,color:#000
```

<figure>
<figcaption>그림 1. 완화 기법은 익스플로잇의 각 단계에 하나씩 대응한다. 어느 하나도 "취약점 자체"를 없애지는 않는다.</figcaption>
</figure>

| 완화 | 막는 단계 | 비용 | 우회의 열쇠 |
|---|---|---|---|
| 스택 카나리 | ① 반환 주소 덮기 | 함수당 비교 몇 개 | 카나리 값 누출, 또는 반환 주소를 거치지 않는 경로 |
| NX / DEP | ② 주입한 코드 실행 | 거의 없음 (하드웨어) | 코드 재사용(ROP, ret2libc) |
| ASLR / PIE | ③ 점프 목적지 알기 | 거의 없음 | 주소 하나 누출 |
| RELRO | GOT 덮어쓰기 | 시작 시간 약간 (Full) | 다른 쓰기 가능 함수 포인터 |
| CFI / CFG | ③ 허용되지 않은 간접 호출 | 호출당 검사 | 허용 집합 안의 함수, 데이터 전용 공격 |
| CET 섀도 스택 | ③ 반환 주소 변조 | 하드웨어 | 간접 호출(JOP), 섀도 스택 미지원 코드 |
| PAC | ③ 포인터 변조 | 명령어 몇 개 | 서명 가젯, 키 누출, 부호 없는 포인터 |
| MTE | ① 메모리 손상 자체 | 메모리·성능 | 확률(1/16), 태그 누출 |

각 항목을 "무엇을 막는가 → 어떻게 확인하는가 → 어떻게 우회되는가" 순으로 본다.

## 2. checksec 출력 읽기

바이너리를 받으면 가장 먼저 한다. 두 가지 구현이 있고 출력 형식이 다르다.

**pwntools** (`pip install pwntools`)

```
$ pwn checksec ./vuln
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

```
$ pwn checksec /bin/ls
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    SHSTK:      Enabled
    IBT:        Enabled
```

**checksec.sh** ([slimm609/checksec](https://github.com/slimm609/checksec))

```
$ checksec --file=/bin/ls
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY    Fortified   Fortifiable   FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   No Symbols      Yes        ...
```

읽는 순서는 다음과 같다.

1. **NX**가 꺼져 있으면 셸코드가 바로 된다. 2024년 이후 빌드에서는 거의 없고, 있다면 임베디드나 일부러 꺼 둔 실습 바이너리다.
2. **카나리**가 없으면 스택 오버플로로 반환 주소를 바로 덮는다. 있으면 누출 경로가 필요하다.
3. **PIE**가 없으면 바이너리 자체의 주소(가젯, PLT, GOT)가 고정이다. 위 `./vuln`은 `0x400000`에 고정이라 ASLR이 켜져 있어도 바이너리 가젯은 그대로 쓸 수 있다.
4. **RELRO**가 Partial이면 GOT를 덮어쓸 수 있다. Full이면 다른 표적이 필요하다.
5. **SHSTK/IBT**는 바이너리가 CET 지원으로 컴파일됐다는 표시다. 실제 보호 여부는 CPU·커널·glibc가 모두 지원해야 한다(6절).
6. **Stripped**·**Debuginfo**는 분석 난이도다. 심볼이 있으면 `elf.symbols['main']`처럼 바로 쓴다.

컴파일 시 어떤 플래그가 어떤 줄을 만드는지 알아야 "왜 꺼져 있는지"를 묻을 수 있다.

| checksec 줄 | 켜는 플래그 (gcc/clang) | 끄는 플래그 |
|---|---|---|
| Stack: Canary found | `-fstack-protector-strong` (배포판 기본) | `-fno-stack-protector` |
| NX enabled | 기본값 | `-z execstack` |
| PIE enabled | `-fPIE -pie` (배포판 기본) | `-no-pie` |
| Full RELRO | `-Wl,-z,relro,-z,now` | `-Wl,-z,norelro` |
| FORTIFY | `-O2 -D_FORTIFY_SOURCE=2` (또는 3) | `-U_FORTIFY_SOURCE` |
| SHSTK / IBT | `-fcf-protection=full` (Ubuntu 등 기본) | `-fcf-protection=none` |

## 3. NX/DEP와 코드 재사용

**NX**(No-eXecute, Windows에서는 DEP)는 페이지 단위로 "쓰기 가능하면 실행 불가"를 하드웨어(x86-64의 NX 비트)로 강제한다. 스택과 힙은 쓰기 가능하므로 거기에 올린 셸코드는 실행되지 않는다.

확인은 `readelf -l`의 `GNU_STACK` 세그먼트 플래그로 한다. `RW`면 NX, `RWE`면 실행 가능 스택이다.

```
$ readelf -lW ./vuln | grep GNU_STACK
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RW  0x10
```

NX의 우회는 하나로 수렴한다. **이미 실행 가능한 코드를 재사용**한다. `system()`으로 돌아가는 ret2libc, 코드 조각을 이어 붙이는 ROP가 그것이고 [8장](08-rop.md) 전체가 이 이야기다. 그래서 NX는 "셸코드 시대"를 끝냈지만 익스플로잇을 끝내지는 못했다.

## 4. ASLR·PIE와 정보 누출

**ASLR**(Address Space Layout Randomization)은 프로세스를 시작할 때 스택, 힙, 공유 라이브러리(libc)의 위치를 무작위로 정한다. 커널 설정 `/proc/sys/kernel/randomize_va_space`가 `2`면 전부 켜진 상태다.

**PIE**(Position-Independent Executable)는 바이너리 **자신**도 무작위 위치에 올린다. PIE가 아니면 바이너리는 고정 주소(x86-64 기본 `0x400000`)에 올라가므로, ASLR이 켜져 있어도 바이너리 안의 가젯·PLT·GOT 주소는 고정이다.

```
 ASLR 켜짐, PIE 없음                     ASLR 켜짐, PIE 있음
 ┌──────────────┐ 0x400000 (고정)        ┌──────────────┐ 0x55xx_xxxx_x000 (무작위)
 │ 바이너리      │ ← 가젯 주소 고정         │ 바이너리      │ ← 하위 12비트만 고정
 ├──────────────┤                        ├──────────────┤
 │ 힙           │ (무작위)                │ 힙           │ (무작위)
 ├──────────────┤                        ├──────────────┤
 │ libc         │ 0x7fxx_xxxx_x000 (무작위)│ libc         │ (무작위)
 ├──────────────┤                        ├──────────────┤
 │ 스택          │ (무작위)                │ 스택          │ (무작위)
 └──────────────┘                        └──────────────┘
```

무작위화는 **페이지 단위**다. 하위 12비트(0x000~0xfff)는 바뀌지 않는다. 그리고 한 모듈 안의 상대 거리는 항상 같다. 이 두 성질이 우회의 전부다.

**우회 = 주소 하나 누출.** libc 안의 함수 하나(`puts`의 GOT 값 등)의 실제 주소를 알면 `libc_base = leak - offset_of_puts`로 기준 주소를 구하고, 거기서 `system`, `"/bin/sh"`, 모든 가젯의 주소가 따라 나온다. 누출 수단은 다양하다.

| 누출 수단 | 설명 | 장 |
|---|---|---|
| 포맷 스트링 `%p` | 스택에 있는 libc·바이너리 주소를 그대로 출력 | [3장](03-format-string.md) |
| 경계 밖 읽기 | 버퍼 뒤의 포인터까지 읽어 보낸다 (Heartbleed 유형) | [7부 2장](../part7-walkthroughs/02-cve-2014-0160-heartbleed.md) |
| UAF 읽기 | 해제·재할당된 객체의 포인터 필드 읽기 | [5장](05-uaf.md) |
| ROP 1단계 | `puts(GOT[puts])`를 호출해 주소를 출력하고 `main`으로 돌아간다 | [8장](08-rop.md) |
| 부분 덮어쓰기 | 하위 1~2바이트만 덮어 같은 페이지·근처 함수로 점프. 누출 없이 확률적 | 이 장 7절 |
| 포크 서버 브루트포스 | 자식마다 주소가 같으므로 바이트 단위로 시도 | 이 장 5절 |

32비트 프로세스는 무작위 비트 수가 적어 브루트포스가 현실적이다. 64비트는 누출 없이는 사실상 불가능하다. 따라서 64비트 바이너리 분석 보고서에서 "ROP 가능"이라고 쓰려면 **누출 경로**를 함께 제시해야 한다.

## 5. 스택 카나리

**카나리**(canary)는 함수 진입 시 반환 주소 **앞**에 무작위 값을 놓고, 반환 직전에 그 값이 그대로인지 비교한다. 바뀌었으면 `*** stack smashing detected ***`를 내고 중단한다.

```
 높은 주소
 ┌──────────────────┐
 │ 반환 주소          │  ← 공격 목표
 ├──────────────────┤
 │ 저장된 rbp        │
 ├──────────────────┤
 │ 카나리 (8바이트)    │  ← 순차 덮어쓰기는 여기를 반드시 지난다
 │  최하위 바이트 = 0x00│     glibc x86-64: 최하위 바이트는 항상 0 → strcpy류가 멈춘다
 ├──────────────────┤
 │ buf[64]          │  ← 오버플로 시작점
 └──────────────────┘
 낮은 주소
```

카나리는 **순차적인** 스택 오버플로만 막는다. 다음은 막지 못한다.

| 상황 | 이유 |
|---|---|
| 카나리 값 누출 | 포맷 스트링 `%p`나 경계 밖 읽기로 카나리를 읽은 뒤 같은 값을 넣어 덮으면 검사를 통과한다. 카나리는 스레드(정확히는 TLS)당 하나라 같은 프로세스 안에서는 바뀌지 않는다 |
| 포크 서버 브루트포스 | `fork()`된 자식은 부모의 카나리를 그대로 물려받는다. 1바이트씩 틀리면 죽고 맞으면 산다. 바이트당 최대 256회, 8바이트(최하위 0 제외 7바이트)에 최대 1,792회 시도로 복원된다 |
| 임의 쓰기 | 카나리를 건너뛰고 반환 주소만 쓰는 프리미티브(포맷 스트링 `%n`, 인덱스 오버플로)에는 무력하다 |
| 힙·전역 변수 | 스택 프레임에만 있다. 힙 오버플로, UAF와는 무관하다 |
| 함수 포인터·지역 변수 덮기 | 카나리보다 **낮은** 주소에 있는 같은 프레임의 지역 변수는 검사 전에 이미 쓰인다 |

`-fstack-protector-strong`은 배열이나 주소가 취해진 지역 변수가 있는 함수에만 카나리를 넣는다. `-fstack-protector-all`은 모든 함수에 넣는다. 기본값인 `strong`이 놓치는 함수가 있을 수 있으므로 디스어셈블리에서 `fs:0x28`(x86-64 glibc의 카나리 위치) 읽기가 있는지 직접 확인한다.

## 6. RELRO와 GOT

동적 링크된 바이너리는 외부 함수를 **GOT**(Global Offset Table)를 통해 호출한다. `puts()`를 부르면 PLT 스텁이 `GOT[puts]`에 적힌 주소로 점프한다. 기본 설정(lazy binding)에서는 첫 호출 때 링커가 주소를 채워 넣으므로 GOT는 **쓰기 가능**해야 한다. 그러면 공격자가 `GOT[puts]`에 `system`의 주소를 써 놓고 `puts("/bin/sh")`가 호출되게 할 수 있다. 포맷 스트링 `%n`의 전형적 표적이다.

| RELRO | 링커 옵션 | GOT 쓰기 | 설명 |
|---|---|---|---|
| None | `-z norelro` | 가능 | `.got`, `.got.plt`, `.init_array` 등이 모두 쓰기 가능 |
| **Partial** | `-z relro` (기본) | **`.got.plt`는 가능** | 비PLT 데이터(`.got`, `.init_array`, `.fini_array`)만 읽기 전용. 함수 호출용 `.got.plt`는 lazy binding 때문에 여전히 쓰기 가능 |
| **Full** | `-z relro -z now` | 불가 | 시작 시 모든 심볼을 즉시 해석(`now`)하고 GOT 전체를 읽기 전용으로 바꾼다 |

Full RELRO일 때 공격자는 다른 쓰기 가능 함수 포인터를 찾는다. 대표적인 것이 glibc 내부의 훅과 vtable이었고, 최근 glibc는 `__malloc_hook`, `__free_hook`을 제거하고(2.34) 각종 내부 포인터에 **포인터 맹글링**(mangling, 비밀 값과 XOR 후 회전)을 적용해 이 경로를 좁혔다. 그래도 `exit` 핸들러, `stdout`의 `FILE` 구조체 vtable 등 표적은 남아 있고, 공격 기법은 glibc 버전마다 바뀐다. [4장 힙](04-heap.md)에서 다룬다.

## 7. CFI, CET, PAC, MTE 🔴

여기부터는 "반환 주소·함수 포인터를 덮었다"는 전제 자체를 깨는 기법이다. 공통점은 **제어 흐름 무결성(Control-Flow Integrity)** 을 소프트웨어 또는 하드웨어로 검사한다는 것이다.

### 7.1 소프트웨어 CFI: Clang CFI, Windows CFG

**Clang CFI**(`-fsanitize=cfi`)는 간접 호출의 목적지가 **타입이 맞는 함수 집합** 안에 있는지 호출 직전에 검사한다. 가상 함수 호출(`cfi-vcall`), 함수 포인터 호출(`cfi-icall`), 잘못된 캐스트(`cfi-derived-cast`, `cfi-unrelated-cast`) 등으로 나뉘며, 전체 프로그램의 타입 정보가 필요하므로 `-flto`(또는 `-flto=thin`)와 `-fvisibility=hidden`이 함께 필요하다. Android 플랫폼과 Chrome이 대규모로 쓴다.

```bash
clang -O2 -flto -fvisibility=hidden -fsanitize=cfi -fno-sanitize-trap=all target.c
```

**Windows CFG**(Control Flow Guard, `/guard:cf`)는 간접 호출 목적지가 "유효한 함수 시작 주소" 비트맵에 있는지 검사한다. 타입까지 보지 않으므로 Clang CFI보다 느슨하지만, 비용이 낮고 OS 전체에 적용돼 있다.

CFI의 한계는 **허용 집합**에 있다. 공격자는 검사가 허용하는 함수(같은 시그니처를 가진 다른 함수, 또는 CFG에서는 아무 함수의 시작) 중 쓸모 있는 것을 고른다. 또한 CFI는 코드 포인터만 지키므로, 권한 플래그나 파일 경로 같은 **데이터**를 바꾸는 데이터 전용 공격(data-only attack)은 막지 않는다.

### 7.2 Intel CET: 섀도 스택과 IBT

**섀도 스택**(shadow stack)은 CPU가 `call`마다 반환 주소를 일반 스택과 별도의, 응용 프로그램이 직접 쓸 수 없는 스택에 **한 번 더** 저장하고, `ret`에서 둘을 비교한다. 다르면 제어 보호 예외(control-protection fault)를 낸다. 스택을 아무리 덮어도 섀도 스택의 사본은 그대로이므로, 반환 주소 기반 ROP가 원천 차단된다.

**IBT**(Indirect Branch Tracking)는 간접 `call`/`jmp`의 목적지가 `endbr64` 명령으로 시작해야 한다고 강제한다. 함수 중간으로 점프하는 가젯을 거부한다.

리눅스에서 사용자 공간 섀도 스택을 실제로 쓰려면 세 가지가 모두 맞아야 한다(커널 문서 [shstk.rst](https://github.com/torvalds/linux/blob/master/Documentation/arch/x86/shstk.rst) 기준).

| 조건 | 확인 |
|---|---|
| CPU 지원 | `grep user_shstk /proc/cpuinfo` |
| 커널 `CONFIG_X86_USER_SHADOW_STACK` | 위 플래그가 보이면 커널도 지원 |
| 바이너리·라이브러리가 `-fcf-protection`으로 빌드 | `readelf -n ./vuln \| grep SHSTK` → `x86 feature: IBT, SHSTK` |
| 로더(glibc)가 활성화 | glibc 튜너블 `GLIBC_TUNABLES=glibc.cpu.x86_shstk=on` 등으로 제어. `permissive`는 비CET 라이브러리 로드 시 끈다 |

즉 `checksec`의 `SHSTK: Enabled`는 "바이너리가 준비됐다"는 뜻이지 "지금 보호 중"이라는 뜻이 아니다. 실습 환경이 가상 머신이면 CPU 플래그가 노출되지 않는 경우가 많다.

섀도 스택이 켜진 환경의 우회는 `ret`을 쓰지 않는 방향으로 간다. 간접 점프 가젯을 잇는 **JOP**([8장 7절](08-rop.md)), 데이터 전용 공격, 그리고 섀도 스택 없이 로드된 라이브러리다.

### 7.3 ARM PAC와 MTE

**PAC**(Pointer Authentication Code, ARMv8.3)는 포인터의 상위 미사용 비트에 **서명**을 넣는다. 함수 진입 시 `paciasp`로 반환 주소에 서명하고, 반환 직전 `autiasp`로 검증한다. 서명은 포인터 값, 문맥(보통 스택 포인터), 프로세스별 비밀 키(`exec` 시 커널이 무작위 배정)로 계산된다. 커널 문서([pointer-authentication.rst](https://github.com/torvalds/linux/blob/master/Documentation/arch/arm64/pointer-authentication.rst))에 따르면 PAC 비트 수는 `55 - 가상 주소 비트 수`로, 48비트 주소 공간이면 **7비트**다. 공격자가 반환 주소를 덮으면 서명이 맞지 않아 검증에서 실패한다.

우회는 세 가지로 요약된다. (1) 7비트면 1/128 확률의 브루트포스가 가능하므로 크래시가 치명적이지 않은 대상(포크 서버, 커널 일부)에서는 시도된다. (2) 서명된 포인터를 **다른 문맥에서 재사용**하거나, 공격자 포인터에 서명해 주는 **서명 가젯**(signing gadget)을 찾는다. (3) 서명되지 않은 포인터(데이터 포인터, 일부 함수 포인터)를 표적으로 바꾼다. iOS·macOS(arm64e)와 Android 커널이 주요 적용처라 모바일 취약점 연구의 필수 지식이다.

**MTE**(Memory Tagging Extension, ARMv8.5)는 접근법이 다르다. 제어 흐름이 아니라 **메모리 손상 자체**를 잡는다. 커널 문서([memory-tagging-extension.rst](https://github.com/torvalds/linux/blob/master/Documentation/arch/arm64/memory-tagging-extension.rst))에 따르면 물리 메모리 **16바이트 단위**마다 **4비트** 할당 태그를 두고, 포인터의 상위 비트(59~56)에 든 논리 태그와 비교해 다르면 예외를 낸다. 할당자가 `malloc`마다 다른 태그를 붙이면, 이웃 청크로 넘치는 쓰기(힙 오버플로)와 해제 후 재할당된 청크 접근(UAF)이 태그 불일치로 잡힌다. ASan을 하드웨어로 구현한 셈이며, 성능 비용이 낮아 **프로덕션**에서 켤 수 있다.

MTE의 한계는 4비트라는 수에 있다. 태그는 16가지뿐이라 임의 손상이 우연히 같은 태그를 만날 확률이 1/16이고, 태그 값을 누출하는 취약점과 결합하면 무력화된다. 또한 16바이트 단위 안의 오버플로(작은 off-by-one)는 같은 태그 안에서 일어나 잡히지 않는다.

## 8. 완화 조합별 공격 가능성

실제 바이너리는 완화가 **조합**으로 켜져 있다. 아래 표는 "스택 오버플로 하나"를 가진 64비트 리눅스 바이너리를 가정했을 때, 무엇이 더 필요한지를 정리한 것이다.

| NX | 카나리 | PIE | RELRO | 추가 필요 조건 | 전형적 경로 | 난이도 |
|---|---|---|---|---|---|---|
| ✗ | ✗ | ✗ | 아무거나 | 없음 | 스택 셸코드 + 고정 주소 | 🟢 |
| ✓ | ✗ | ✗ | Partial | 없음 | ret2plt로 libc 주소 누출 → ret2libc ([8장 실습](08-rop.md)) | 🟢 |
| ✓ | ✗ | ✗ | Full | 없음 | 위와 같음. GOT 덮어쓰기만 불가 | 🟢 |
| ✓ | ✓ | ✗ | 아무거나 | **카나리 누출** 또는 포크 서버 | 누출 → 카나리 복원 → ret2libc | 🟡 |
| ✓ | ✗ | ✓ | 아무거나 | **바이너리 또는 libc 주소 누출** | 누출 → 가젯 주소 계산 → ROP | 🟡 |
| ✓ | ✓ | ✓ | Full | 카나리 **와** 주소 누출 | 두 번의 누출 또는 한 누출로 둘 다 (스택 읽기) | 🔴 |
| ✓ | ✓ | ✓ | Full + CFI | 위 + 허용 집합 안의 유용한 함수 | 데이터 전용 공격, 타입 맞는 함수로 우회 | 🔴 |
| ✓ | ✓ | ✓ | Full + CET 섀도 스택 | 위 + `ret` 없는 체인 | JOP, 데이터 전용, 비CET 라이브러리 | 🔴 |

표에서 읽을 것은 두 가지다. 첫째, **정보 누출 취약점의 가치**다. 카나리와 PIE가 켜지면 단독 스택 오버플로는 DoS로 끝나고, 누출 하나가 더해지면 코드 실행이 된다. 보고서에서 "읽기 전용 경계 밖 읽기, 심각도 Low"로 분류된 버그가 다른 버그와 결합해 Critical이 되는 이유다. 둘째, **취약점 종류에 따라 표가 달라진다**는 것이다. 힙 오버플로·UAF는 카나리와 무관하고, 포맷 스트링은 누출과 쓰기를 한 번에 주므로 거의 모든 조합을 한 취약점으로 뚫는다.

이 표가 [8부 2장 영향도 산정](../part8-reporting/02-severity.md)에서 "익스플로잇 가능성" 항목을 채우는 근거다. "완화가 다 켜져 있으니 안전"도, "오버플로가 있으니 Critical"도 아니다. 켜진 완화 목록과 필요한 추가 조건을 적는다.

## 체크리스트

**바이너리를 받았을 때**
- [ ] `pwn checksec`(또는 `checksec --file=`)을 돌려 여섯 줄(RELRO, 카나리, NX, PIE, FORTIFY, SHSTK/IBT)을 보고서에 옮겼는가?
- [ ] 각 줄이 "무엇을 막고 무엇을 남기는지" 8절 표로 대응시켰는가?
- [ ] 64비트 PIE 바이너리라면 정보 누출 경로를 찾았거나 "없음"을 확인했는가?
- [ ] 카나리가 있다면 포크 서버인지(브루트포스 가능) 확인했는가?
- [ ] CET/PAC/MTE 표시가 있다면 실행 환경(CPU·커널·로더)에서 실제로 켜지는지 확인했는가?

**빌드를 검토할 때**
- [ ] `-fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -fcf-protection`이 빌드 플래그에 있는가?
- [ ] 서드파티 라이브러리나 임베디드 툴체인이 이 기본값을 꺼 두지 않았는가?
- [ ] 완화 기법을 "취약점 수정의 대체"로 쓰고 있지 않은가? 완화는 시간을 벌 뿐이다

## 더 읽기

- [Linux 커널 문서: CET Shadow Stack (shstk.rst)](https://github.com/torvalds/linux/blob/master/Documentation/arch/x86/shstk.rst) · 사용자 공간 섀도 스택의 요구 조건과 `arch_prctl` 인터페이스
- [Linux 커널 문서: Pointer authentication in AArch64](https://github.com/torvalds/linux/blob/master/Documentation/arch/arm64/pointer-authentication.rst), [Memory Tagging Extension](https://github.com/torvalds/linux/blob/master/Documentation/arch/arm64/memory-tagging-extension.rst) · PAC 비트 수, MTE 태그 구조의 1차 자료
- [Clang: Control Flow Integrity](https://clang.llvm.org/docs/ControlFlowIntegrity.html) · `-fsanitize=cfi` 하위 검사와 LTO 요구 사항
- [glibc Tunables 매뉴얼](https://www.gnu.org/software/libc/manual/html_node/Tunables.html) · `glibc.cpu.x86_shstk`, `glibc.cpu.x86_ibt`
- [checksec (slimm609)](https://github.com/slimm609/checksec), [pwntools `checksec`](https://docs.pwntools.com/en/stable/elf/elf.html) · 두 구현의 출력 형식
- Hovav Shacham 외, "On the Effectiveness of Address-Space Randomization", CCS 2004 · 32비트 ASLR 브루트포스를 처음 정량화한 논문
- [8장 ROP와 코드 재사용](08-rop.md) · NX 우회의 실제

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 본문 8절·조합표 작성. checksec 출력·컴파일 플래그 로컬 검증, CET·PAC·MTE는 커널 문서 기준으로 기술 | @anthonynoh5202 |
