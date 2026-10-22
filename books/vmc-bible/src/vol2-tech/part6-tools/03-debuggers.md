# 디버거: gdb · pwndbg · WinDbg · Frida

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟡 실무 | 🔄 개정중 | 2026-10-22 |

> **한눈에 보기**
> 정적 분석이 '지도'라면 디버거는 '현장'이다. 특정 입력에서 메모리와 레지스터가 어떻게 변하는지 직접 본다.
> 리눅스는 gdb에 pwndbg나 GEF를 얹고, Windows 크래시 덤프는 WinDbg의 `!analyze -v`로 시작하고, 실행 중인 앱의 함수를 가로채려면 Frida를 쓴다.
> 브레이크포인트는 "입력이 들어오는 곳"과 "위험한 일이 일어나는 곳"에 건다. 나머지는 거기서 한 줄씩 걷는다.

## 1. 언제 쓰는가

디버거가 답하는 질문은 하나다. **"이 입력을 넣었을 때 실제로 무슨 일이 일어나는가."** 디컴파일러가 "덮어쓸 수 있다"고 말하면, 디버거는 "40번째 바이트가 복귀 주소의 첫 바이트를 덮는다"고 말한다.

| 상황 | 도구 | 이 장의 절 |
|---|---|---|
| 리눅스 바이너리가 특정 입력에서 죽는다 | gdb + pwndbg 또는 GEF | 2~5절 |
| 크래시는 났는데 프로세스는 이미 없다 (코어 덤프만 있다) | gdb + 코어, `coredumpctl` | 6절 |
| Windows 앱의 크래시 덤프(`.dmp`)를 받았다 | WinDbg | 7절 |
| 실행 중인 앱의 함수 인자·반환값을 보고 싶다, 소스도 심볼도 없다 | Frida | 8절 |
| Android·iOS 앱의 인증서 피닝을 우회해야 한다 | Frida | 8절, [5부 1장](../part5-extended/01-mobile.md) |

디버거를 **쓰지 않는** 경우도 있다. 입력 공간이 넓어 어떤 입력이 문제인지 모르면 [4장 퍼저](04-fuzzers.md)가 먼저다. 퍼저가 크래시 입력을 찾아 주면 그때 디버거를 연다.

## 2. gdb에 pwndbg 또는 GEF 얹기

맨 gdb는 레지스터·스택·힙을 보기에 불편하다. pwndbg와 GEF는 gdb 위에서 돌아가는 Python 확장으로, 멈출 때마다 레지스터·스택·디스어셈블리·백트레이스를 한 화면에 보여 준다. **둘 중 하나만** 설치한다. 같이 로드하면 충돌한다.

**pwndbg** (권장 설치 스크립트가 `pwndbg` 실행 파일을 설치한다. gdb 대신 `pwndbg ./target`으로 쓴다)

```bash
curl --proto '=https' --tlsv1.2 -LsSf 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
# 또는 소스에서: uv tool install git+https://github.com/pwndbg/pwndbg[gdb,lldb]
```

pwndbg-gdb는 GDB 12.1 이상과 Python 3.10 이상을 요구한다 📎 [pwndbg README](https://github.com/pwndbg/pwndbg#readme).

**GEF** (한 줄 설치. `~/.gdbinit`에 source 줄을 추가한다)

```bash
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

GEF는 GDB 10.0 이상, Python 3.10 이상이 필요하고 추가 Python 패키지는 없다 📎 [GEF 설치 문서](https://github.com/hugsy/gef/blob/main/docs/install.md). 확장 없이 gdb만 띄우려면 `gdb -nx`로 `~/.gdbinit`을 건너뛴다.

## 3. 핵심 명령 표

| 할 일 | gdb 기본 | pwndbg | GEF |
|---|---|---|---|
| 브레이크포인트 | `break main`, `b *0x401136` | 같음 | 같음 |
| 실행·계속 | `run arg`, `continue` | 같음 | 같음 |
| 한 명령 (호출 건너뜀 / 들어감) | `nexti` (`ni`), `stepi` (`si`) | 같음 | 같음 |
| 함수 끝까지 | `finish` | 같음 | 같음 |
| 메모리 보기 | `x/16gx $rsp`, `x/s $rdi`, `x/5i $pc` | 같음 | 같음 |
| 레지스터 | `info registers` | `regs` | `registers` |
| 스택을 포인터 따라가며 보기 | 없음 | `telescope $rsp 16` | `dereference $rsp -l 16` |
| 메모리 맵 (권한, 라이브러리 위치) | `info proc mappings` | `vmmap` | `vmmap` |
| 힙 청크 | 없음 | `heap`, `bins`, `vis-heap-chunks`, `tcache` | `heap chunks`, `heap bins`, `heap arenas` |
| 완화 기법 확인 | 없음 | `checksec` | `checksec` |
| 현재 상태 한 화면 | 없음 | `context` | `context` |
| 순환 패턴 만들기·찾기 | 없음 | `cyclic -n 8 200`, `cyclic -n 8 -l <값>` | `pattern create 200`, `pattern search <값>` |
| 백트레이스 | `bt` | 같음 | 같음 |

멈출 때마다 pwndbg와 GEF가 `context`를 자동으로 출력한다. 레지스터, 디스어셈블리, 스택, 백트레이스 순이다. 처음에는 이 네 블록을 읽는 연습이 전부다.

> 🟢 gdb는 기본적으로 디버기의 ASLR을 끈다. 주소가 매번 같아서 편하지만 실제 실행과 다르다. 실제 환경을 흉내내려면 `set disable-randomization off`.

## 4. 핵심 워크플로: 크래시에서 덮어쓴 오프셋까지

[2장 3절](02-ghidra-ida.md)의 `target`을 그대로 쓴다. 정적 분석의 결론은 "40바이트 이상이면 복귀 주소를 덮는다"였다. 디버거로 확인한다.

```bash
gcc -O0 -fno-stack-protector -no-pie -o target target.c
pwndbg ./target
```

```
pwndbg> checksec
    Canary: No      NX: Yes      PIE: No
pwndbg> cyclic -n 8 100                  # 8바이트 단위로 겹치지 않는 100바이트 패턴
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaaf...
pwndbg> run aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaam
```

프로그램이 SIGSEGV로 멈춘다. `context`에서 `RSP`가 가리키는 값과 `RIP`를 본다. `check`의 `ret`에서 죽었으면 `RSP`에 패턴 조각이 있다.

```
pwndbg> telescope $rsp 2
00:0000│ rsp 0x7ffe...  ◂— 0x6161616161616166 ('faaaaaaa')
pwndbg> cyclic -n 8 -l 0x6161616161616166
Found at offset 40
```

**오프셋 40.** 정적 분석의 계산과 일치한다. 이 값은 [4부 2장](../part4-binary/02-stack-overflow.md)의 익스플로잇에서 패딩 길이가 된다. `vmmap`으로 스택이 실행 불가(`NX: Yes`)임을 확인하면 셸코드가 아니라 [ROP](../part4-binary/08-rop.md)가 필요하다는 것까지 알 수 있다.

## 5. 브레이크포인트 전략

어디에 거는가가 디버깅 시간의 대부분을 결정한다.

| 어디 | 왜 | 명령 |
|---|---|---|
| **입력이 들어오는 함수** (`read`, `recv`, `fgets`, `fopen`) | 신뢰 경계. 여기서부터 데이터를 따라간다 | `break read`, `finish` 후 `x/s $rax`… |
| **위험 함수** (`strcpy`, `memcpy`, `system`, `free`) | 영향이 발생하는 지점 | `break strcpy`, 들어가서 `x/s $rsi` |
| **검증 직후 분기** | 검증이 실제로 입력을 막는지 | `break *주소` + `ni`로 분기 방향 관찰 |
| **함수 복귀** | 복귀 주소가 바뀌었는지 | `break *주소` (`ret` 명령 주소), `telescope $rsp 1` |

수백 번 호출되는 함수는 **조건부 브레이크포인트**로 걸러낸다.

```
break strcpy if $rsi == 0x4020a0          # 두 번째 인자가 특정 주소일 때만
break check if strlen($rdi) > 32          # 긴 입력일 때만
condition 2 $rdi == 0                     # 2번 브레이크포인트에 조건 추가
```

값이 **언제** 바뀌는지 모를 때는 워치포인트를 쓴다. `watch *(long*)0x7ffe1234`는 그 주소에 쓰기가 일어나면 멈춘다. `rwatch`는 읽기, `awatch`는 둘 다. 하드웨어 워치포인트는 개수 제한(x86-64는 4개)이 있다. `catch syscall write`처럼 시스템 호출에 걸 수도 있고, `tbreak`는 한 번만 멈춘다. `display/i $pc`를 해 두면 멈출 때마다 현재 명령을 보여 준다. 자식 프로세스를 따라가려면 `set follow-fork-mode child`.

원칙은 하나다. **넓게 걸고(함수), 조건으로 좁히고(if), 들어가서 한 줄씩 본다(si).**

## 6. 코어 덤프 분석

프로세스가 죽은 뒤에도 메모리 스냅샷(코어 덤프)이 있으면 분석할 수 있다. 서버에서 재현이 어려운 크래시를 받을 때 쓴다.

**1. 코어가 생기게 한다.** 기본 크기 제한이 0이면 생성되지 않는다.

```bash
ulimit -c unlimited
cat /proc/sys/kernel/core_pattern
```

`core_pattern`이 `core`나 `core.%p` 같은 파일명이면 작업 디렉터리에 파일이 생긴다. `|/usr/lib/systemd/systemd-coredump …`처럼 파이프로 시작하면 systemd가 받아 간다. 그때는 `coredumpctl`로 본다.

```bash
coredumpctl list                 # 최근 크래시 목록
coredumpctl info 12345           # PID 12345의 요약 (신호, 스택)
coredumpctl debug 12345          # gdb로 바로 연다 (기본 디버거가 gdb)
coredumpctl dump 12345 -o core   # 파일로 꺼낸다
```

**2. gdb로 연다.** 바이너리와 코어를 함께 준다. 라이브러리 버전이 크래시 당시와 같은 기계에서 여는 것이 좋다.

```bash
gdb ./target core
(gdb) bt                         # 어디서 죽었는가
(gdb) info registers
(gdb) x/5i $pc                   # 죽은 명령
(gdb) frame 1                    # 호출자로 올라가서
(gdb) info locals                # 지역 변수 (디버그 심볼이 있을 때)
```

코어 덤프는 **정지된 사진**이다. `ni`, `continue`는 안 되고 읽기만 된다. 코어로 원인을 좁힌 뒤, 재현 입력을 만들어 4절처럼 살아 있는 프로세스에서 확인한다.

> 🟡 [4장](04-fuzzers.md)의 AFL++은 `core_pattern`이 파이프로 시작하면 실행을 거부한다. 크래시를 외부 프로그램이 가져가면 퍼저가 놓치기 때문이다. 퍼징 기계에서는 `echo core | sudo tee /proc/sys/kernel/core_pattern`으로 바꾼다.

## 7. WinDbg

Windows 크래시 덤프(`.dmp`)는 WinDbg로 연다. 예전 "WinDbg Preview"가 현재의 WinDbg이고, Windows SDK에 들어 있는 것은 WinDbg (Classic)다. 둘은 같은 엔진과 명령을 쓴다 📎 [Microsoft Learn: Install WinDbg](https://learn.microsoft.com/windows-hardware/drivers/debugger/).

```powershell
winget install Microsoft.WinDbg
```

File → Open dump file로 `.dmp`를 열거나 `windbg -z crash.dmp`로 연다. 명령 순서는 정해져 있다.

```
.sympath srv*                 ; Microsoft 공개 심볼 서버
.sympath+ C:\MyApp\x64\Debug  ; 내 앱의 PDB 경로를 추가
.reload                       ; 심볼 다시 로드
!analyze -v                   ; 자동 분석 (verbose)
.ecxr                         ; 예외 발생 시점의 레지스터 컨텍스트로 전환
k                             ; 그 컨텍스트의 호출 스택
lm                            ; 로드된 모듈 목록 (버전 확인)
```

`!analyze -v`의 출력에서 먼저 읽을 항목은 **FAULTING_IP**(죽은 명령), **EXCEPTION_RECORD**(예외 코드. `c0000005`는 접근 위반, `c0000094`는 0으로 나누기), **STACK_TEXT**(스택)다. 자동 분석은 "이 크래시가 무엇인지"를 알려 주지 "왜 그 값이 거기 있었는지"는 알려 주지 않는다. 그 다음은 `.ecxr`로 예외 시점으로 돌아가 `k`와 레지스터를 직접 읽는다. 심볼이 없으면 스택이 `ntdll!…+0x1234`처럼만 나오므로, `lm`으로 모듈 버전을 확인하고 심볼부터 구한다.

## 8. Frida: 실행 중인 프로세스에 코드 넣기

Frida는 실행 중인 프로세스에 JavaScript 엔진을 주입하고, 그 안에서 함수를 가로채거나(hook) 바꾸는 도구다. 디버거와 달리 프로세스를 멈추지 않는다. 그래서 GUI 앱, 모바일 앱, 네트워크 서버처럼 멈추면 상태가 깨지는 대상에 맞다.

```bash
pip install frida-tools         # frida, frida-ps, frida-trace 등이 설치된다
```

Android는 기기(또는 에뮬레이터)에 같은 버전의 `frida-server`를 올려야 한다. [릴리스](https://github.com/frida/frida/releases)에서 기기 아키텍처에 맞는 것을 받아 `adb push frida-server /data/local/tmp/`, `adb shell "chmod 755 /data/local/tmp/frida-server"`, root로 실행한다. `frida-ps -U`에 프로세스 목록이 나오면 준비가 된 것이다.

### 8.1 frida-trace: 코드 없이 시작

어떤 함수가 불리는지 모를 때는 `frida-trace`가 먼저다. 패턴에 맞는 함수마다 핸들러 파일을 자동 생성하고 호출을 로그로 보여 준다.

```bash
frida-trace -U -f com.example.app -i "open*"            # 앱을 스폰해 libc open* 추적
frida-trace -U -n com.example.app -j '*!*certificate*/isu'   # 이름에 certificate가 든 Java 메서드 (i: 대소문자 무시, s: 시그니처, u: 사용자 클래스만)
```

`-U`는 USB 기기, `-f`는 스폰(spawn), `-n`/`-p`는 실행 중인 프로세스에 attach, `-i`/`-x`는 네이티브 함수 포함/제외(`[MODULE!]FUNCTION` glob), `-j`는 Java 메서드다. 생성된 `__handlers__/` 아래 JS 파일을 고치면 인자 출력이 바뀐다.

### 8.2 후킹 스크립트

frida-trace로 대상을 찾았으면 스크립트를 직접 쓴다. 다음은 네이티브 함수와 Java 메서드를 하나씩 가로채는 예다.

```javascript
// hook.js — 실행: frida -U -f com.example.app -l hook.js
// 네이티브: libc의 open()을 가로채 경로와 반환된 fd를 기록한다
const openImpl = Process.getModuleByName('libc.so').getExportByName('open');
Interceptor.attach(openImpl, {
  onEnter(args) {
    this.path = args[0].readUtf8String();   // this는 호출 한 번의 컨텍스트
  },
  onLeave(retval) {
    console.log(`open("${this.path}") -> ${retval.toInt32()}`);
  }
});

// Java: Activity.onResume()을 가로채고 원본을 호출한다
Java.perform(() => {
  const Activity = Java.use('android.app.Activity');
  Activity.onResume.implementation = function () {
    console.log('onResume() called');
    this.onResume();                         // 원본 호출. 빼면 앱 동작이 바뀐다
  };
});
```

`onEnter`의 `args[n]`은 `NativePointer`이고, `readUtf8String()`, `toInt32()`로 값을 읽는다. `onLeave`의 `retval.replace(0)`으로 반환값을 바꿀 수 있다. 같은 패턴으로 인증서 검증 함수의 반환값을 "성공"으로 바꾸는 것이 피닝 우회의 원리다.

> 🔴 **Frida 17(2025년 5월)에서 API가 바뀌었다.** `Module.findExportByName('libc.so', 'open')`, `Module.getExportByName(null, 'open')` 같은 정적 메서드가 제거됐다. 모듈을 먼저 찾아 `Process.getModuleByName('libc.so').getExportByName('open')`으로 쓰거나, 모듈을 모르면 `Module.getGlobalExportByName('open')`을 쓴다(느리다). 또 Java·ObjC·Swift 브리지가 런타임에 내장되지 않게 됐다. `frida` REPL과 `frida-trace`에는 여전히 포함되어 있어 위 예제는 그대로 동작하지만, Python 바인딩으로 직접 스크립트를 로드하거나 `frida-compile`로 빌드하면 `import Java from "frida-java-bridge";`를 명시해야 한다 📎 [Frida 17.0.0 릴리스 노트](https://frida.re/news/2025/05/17/frida-17-0-0-released/), [Bridges 문서](https://frida.re/docs/bridges/). 인터넷의 예제 대부분은 17 이전 문법이다.

## 체크리스트

**gdb**
- [ ] pwndbg와 GEF 중 하나만 로드되는가? (`~/.gdbinit` 확인)
- [ ] `checksec`으로 완화 기법을 먼저 확인했는가?
- [ ] 브레이크포인트를 입력 함수와 위험 함수에 걸고, 조건으로 좁혔는가?
- [ ] 정적 분석의 숫자(오프셋, 크기)를 디버거로 확인했는가?

**코어 덤프 · WinDbg**
- [ ] `ulimit -c`와 `core_pattern`을 확인했는가?
- [ ] WinDbg에서 심볼 경로를 잡고 `.reload` 후 `!analyze -v`를 돌렸는가?

**Frida**
- [ ] 기기의 frida-server 버전이 PC의 frida-tools와 맞는가?
- [ ] 후킹한 함수의 원본을 호출하는가? (빼먹으면 앱 동작이 바뀐다)
- [ ] Frida 17 이후 API(`Process.getModuleByName(...).getExportByName`)를 쓰는가?

## 더 읽기

- [GDB 공식 매뉴얼](https://sourceware.org/gdb/current/onlinedocs/gdb/) · 브레이크포인트·워치포인트·코어 파일의 기준 문서
- [pwndbg 문서](https://pwndbg.re/) · 설치, 명령 목록, 치트시트
- [GEF 문서](https://hugsy.github.io/gef/) · 설치와 명령별 설명. [coredumpctl(1)](https://www.freedesktop.org/software/systemd/man/latest/coredumpctl.html) · systemd 코어 덤프 조회·디버깅
- [Microsoft Learn: Getting started with WinDbg (user-mode)](https://learn.microsoft.com/windows-hardware/drivers/debugger/getting-started-with-windbg) · 심볼 설정부터 `!analyze -v`까지
- [Frida 공식 문서: JavaScript API](https://frida.re/docs/javascript-api/), [frida-trace](https://frida.re/docs/frida-trace/), [Android](https://frida.re/docs/android/) · 현재 API 시그니처, 옵션, frida-server 설치

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | pwndbg/GEF 설치와 명령 표, 크래시 워크플로, 브레이크포인트 전략, 코어 덤프, WinDbg, Frida 17 기준 예제 작성 | @anthonynoh5202 |
