# 퍼저: AFL++ · libFuzzer · boofuzz

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟡 실무 | 🔄 개정중 | 2026-10-22 |

> **한눈에 보기**
> 퍼저 선택은 '대상이 무엇을 먹는가'로 결정된다. 파일을 먹으면 AFL++, 함수를 먹으면 libFuzzer, 네트워크 메시지를 먹으면 boofuzz나 AFLNet이다.
> 퍼징의 원리(커버리지 피드백, 하네스, 새니타이저)는 [4부 9장](../part4-binary/09-fuzzing.md)이 다룬다. 이 장은 **조작법**이다. 설치, 계측, 실행, 병렬화, 코퍼스 관리, 크래시 재현까지.
> 퍼저가 찾은 크래시는 [3장 디버거](03-debuggers.md)로 넘긴다. 퍼저는 "죽는 입력"을 주고, 디버거는 "왜"를 준다.

## 1. 언제 어느 퍼저를 쓰는가

| 대상이 먹는 것 | 예 | 도구 | 비고 |
|---|---|---|---|
| 파일 또는 stdin | 이미지 파서, 압축 해제기, CLI 도구 | **AFL++** | 소스가 있으면 계측 컴파일, 없으면 QEMU 모드(`-Q`) |
| 라이브러리 함수 | `parse_header(buf, len)` 같은 API | **libFuzzer** (또는 AFL++로 같은 하네스 실행) | 하네스를 직접 쓴다. 프로세스 안에서 돌아 빠르다 |
| 네트워크 메시지 (상태 없음) | 단일 요청으로 끝나는 프로토콜 | AFL++ + 소켓을 파일로 바꾸는 하네스 | 가능하면 서버 코드의 파싱 함수를 떼어내 libFuzzer로 |
| 네트워크 메시지 (상태 있음) | FTP, RTSP, SMTP처럼 세션이 있는 프로토콜 | **boofuzz**(생성 기반), **AFLNet**(커버리지 + 상태 기반) | 느리다. 메시지 순서가 중요할 때만 |
| 구조화된 입력 | JSON, XML, 스크립트 언어 | AFL++ + 사전(`-x`), 문법 기반 커스텀 뮤테이터 | 무작위 바이트 변이로는 파서 입구를 못 넘는다 |

다음 질문은 "소스가 있는가"다. 소스가 있으면 계측(instrumentation)과 새니타이저를 붙일 수 있다. 없으면 AFL++의 QEMU 모드(`-Q`)나 Frida 모드(`-O`)가 있지만, 이 장의 워크플로는 소스가 있는 경우를 기준으로 한다.

## 2. AFL++ 설치

Debian/Ubuntu 계열 기준이다. LLVM은 14 이상이 필요하고 18 이상을 권장한다 📎 [AFL++ INSTALL.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/INSTALL.md).

```bash
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison \
  libglib2.0-dev libpixman-1-dev
sudo apt-get install -y lld-18 llvm-18 llvm-18-dev clang-18 \
  || sudo apt-get install -y lld llvm llvm-dev clang
git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus
make distrib && sudo make install
```

설치가 번거로우면 공식 Docker 이미지를 쓴다. 대상 소스 디렉터리를 마운트해 안에서 빌드·퍼징한다.

```bash
docker pull aflplusplus/aflplusplus
docker run -ti -v /path/to/target:/src aflplusplus/aflplusplus
```

## 3. 핵심 워크플로: 작은 파서를 첫 크래시까지

### 3.1 대상

```c
// parse.c — 실습용. 헤더 "VMC" 뒤 길이 바이트만큼 복사하는 파서
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int parse(const unsigned char *d, size_t n) {
    char name[16];
    if (n < 4 || memcmp(d, "VMC", 3) != 0) return -1;
    size_t len = d[3];                      /* 길이를 검증하지 않는다 */
    memcpy(name, d + 4, len);
    name[len] = 0;
    return (int)strlen(name);
}

int main(int argc, char **argv) {
    unsigned char buf[4096]; FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    size_t n = fread(buf, 1, sizeof buf, f); fclose(f);
    return parse(buf, n) < 0;
}
```

### 3.2 계측 컴파일

`afl-cc`는 설치된 모드 중 가장 좋은 것을 고르는 래퍼다. 명시적으로는 `afl-clang-fast`(LLVM 모드)나 `afl-clang-lto`(LTO 모드, 충돌 없는 계측으로 가장 정확하지만 컴파일이 느리다)를 쓴다. 짧은 퍼징에는 `afl-clang-fast`가 맞다.

```bash
afl-clang-fast -O2 -o parse parse.c                    # 일반 계측 바이너리
AFL_USE_ASAN=1 afl-clang-fast -O1 -o parse.asan parse.c # ASan 바이너리 (별도)
AFL_LLVM_CMPLOG=1 afl-clang-fast -O2 -o parse.cmplog parse.c  # CMPLOG 바이너리 (별도)
```

configure 기반 프로젝트는 `CC=afl-clang-fast CXX=afl-clang-fast++ ./configure --disable-shared`, CMake는 `-DCMAKE_C_COMPILER=afl-cc -DCMAKE_CXX_COMPILER=afl-c++`로 넘긴다. ASan 바이너리를 따로 두는 이유는 ASan이 실행 속도를 크게 떨어뜨리기 때문이다. 일반 바이너리로 빠르게 탐색하고, 크래시 재현과 병렬 인스턴스 하나에만 ASan을 쓴다.

### 3.3 시드와 실행

```bash
mkdir in out
printf 'VMC\x03abc' > in/seed1                 # 형식에 맞는 작은 입력
echo core | sudo tee /proc/sys/kernel/core_pattern   # 코어를 외부 프로그램이 가져가지 않게
afl-fuzz -i in -o out -- ./parse @@
```

`@@`는 "이 자리에 입력 파일 경로를 넣어라"다. 없으면 stdin으로 넣는다. 이 예제는 `d[3]`이 16을 넘는 순간 스택을 넘으므로 몇 초 안에 크래시가 난다. 화면에서 먼저 보는 항목은 넷이다. **exec speed**(초당 실행. 수백 이하면 하네스나 `-t`를 의심), **corpus count**(새 경로 수. 계속 늘어야 한다), **saved crashes**, **stability**(100%에 가까워야 한다. 낮으면 대상이 비결정적이다).

### 3.4 재현과 최소화

```bash
ls out/default/crashes/                        # id:000000,sig:06,... 파일들
./parse.asan out/default/crashes/id:000000*    # ASan 보고서로 유형 확인
afl-tmin -i out/default/crashes/id:000000* -o min.bin -- ./parse @@   # 최소 입력
xxd min.bin
```

ASan 보고서의 첫 줄(`stack-buffer-overflow on address …, WRITE of size …`)과 스택 트레이스의 첫 프레임(`parse`의 `memcpy`)이 보고서의 핵심이다. `afl-tmin`으로 줄인 입력은 보통 몇 바이트다. 이 입력을 [3장 4절](03-debuggers.md)의 디버거에 넣어 정확히 무엇이 덮이는지 본다.

## 4. afl-fuzz 옵션과 환경 변수

| 옵션 | 뜻 | 메모 |
|---|---|---|
| `-i dir` / `-o dir` | 입력 시드 / 출력 | `-i -`는 이전 실행 재개. `AFL_AUTORESUME=1`과 같다 |
| `-x file.dict` | 사전(토큰 목록) | 키워드·매직 바이트가 있는 포맷에서 필수. `dictionaries/`에 포맷별 사전이 있다 |
| `-t ms` / `-m MB` | 실행 타임아웃 / 메모리 한도 | 빠른 대상은 `-t 5`까지 내릴 수 있다. `-m`은 병적 입력이 시간을 잡아먹는 것을 막는다 |
| `-M name` / `-S name` | 병렬 메인 / 보조 인스턴스 | 5절 |
| `-c binary` | CMPLOG 바이너리 지정 | 비교 연산의 피연산자를 입력에 바로 넣는다(매직 값 통과). `-l 2AT` 같은 수준 옵션과 함께 |
| `-p schedule` | 파워 스케줄 | `explore`(기본), `fast`, `coe`, `lin`, `quad`, `exploit`, `rare` |
| `-Q` / `-O` / `-C` | QEMU 모드 / Frida 모드 / 크래시 탐색 모드 | 앞 둘은 소스 없는 바이너리. `-C`는 크래시 입력을 시드로 "계속 죽는 변형"을 찾는다 |

자주 쓰는 환경 변수는 컴파일 시 `AFL_USE_ASAN=1`/`AFL_USE_UBSAN=1`(새니타이저), `AFL_LLVM_CMPLOG=1`(CMPLOG 바이너리), 실행 시 `AFL_SKIP_CPUFREQ=1`(CPU 스케일링 검사 생략), `AFL_AUTORESUME=1`(재개), `AFL_FINAL_SYNC=1`(종료 시 다른 인스턴스 큐를 마지막으로 가져옴, 메인에 설정), `AFL_NO_UI=1`(CI·로그용)이다. `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`은 `core_pattern` 검사를 건너뛰지만 크래시를 놓칠 수 있으므로 쓰지 않는다. 전체 목록은 [env_variables.md](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/env_variables.md)에 있다.

## 5. 병렬 실행

afl-fuzz 한 프로세스는 코어 하나를 쓴다. 코어 수만큼 띄우되, 같은 출력 디렉터리를 공유하고 이름만 다르게 준다. 메인(`-M`)은 하나, 나머지는 보조(`-S`)다. 공식 문서의 권장 구성은 인스턴스마다 역할을 다르게 주는 것이다 📎 [fuzzing_in_depth](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md).

```bash
AFL_FINAL_SYNC=1 afl-fuzz -i in -o out -M main-$HOSTNAME -- ./parse @@
afl-fuzz -i in -o out -S s1 -c ./parse.cmplog -l 2AT -- ./parse @@   # CMPLOG
afl-fuzz -i in -o out -S s2 -p fast -- ./parse.asan @@              # ASan + 다른 스케줄
afl-fuzz -i in -o out -S s3 -p exploit -x fmt.dict -- ./parse @@    # 사전 + 다른 스케줄
```

진행은 `afl-whatsup -s out/`로 한 번에 본다. 여러 기계로 나누려면 `out/`를 주기적으로 동기화(rsync)한다. 각 인스턴스는 다른 인스턴스의 `queue/`를 읽어 간다.

## 6. 코퍼스와 크래시 관리

**코퍼스 최소화(afl-cmin)**: 같은 커버리지를 내는 입력을 걸러낸다. 퍼징 시작 전 시드에, 그리고 긴 퍼징 뒤 `queue/`에 쓴다. 병렬 옵션 `-T all`이 크게 빠르다.

```bash
afl-cmin -T all -i out/default/queue -o queue_min -- ./parse @@
```

**크래시 분류**: 수십 개의 크래시 파일은 대개 원인 몇 개의 변형이다. 분류 기준은 (1) ASan 보고서의 오류 유형, (2) 스택 트레이스 상위 3프레임이다. 같은 유형·같은 프레임이면 하나로 묶는다. AFL++ 문서가 소개하는 `casr-afl -i out/ -o casr_out/`은 이 분류와 심각도 추정을 자동화한다.

크래시가 대상 코드가 아니라 하네스(`main`, 입력 읽기)에서 나면 오탐이다. 스택 트레이스에 대상 함수가 없으면 하네스를 먼저 의심한다.

## 7. libFuzzer

libFuzzer는 clang에 내장된 인프로세스(in-process) 퍼저다. 프로세스를 새로 띄우지 않고 함수를 반복 호출하므로 빠르고, 라이브러리 API를 직접 퍼징하기에 맞다. 대상은 **하네스 함수** 하나다.

```c
// parse_fuzz.c — 3.1절의 parse()를 라이브러리처럼 호출하는 하네스
#include <stdint.h>
#include <stddef.h>
int parse(const unsigned char *d, size_t n);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse(data, size);
    return 0;                   /* 항상 0. 다른 값은 "이 입력을 버려라"다 */
}
```

```bash
clang -g -O1 -fsanitize=fuzzer,address -o parse_fuzz parse_fuzz.c parse_lib.c
mkdir corpus && printf 'VMC\x03abc' > corpus/seed1
./parse_fuzz corpus/ -max_len=64 -max_total_time=300
```

`parse_lib.c`는 3.1절에서 `main`을 뺀 파일이다. 하네스의 규칙은 네 가지다. **어떤 입력에도 죽지 않고(길이 0 포함), `exit()`하지 않고, 결정적이며(전역 상태를 남기지 않고), 빠르다.** 초기화가 필요하면 `LLVMFuzzerInitialize(int *argc, char ***argv)`에 둔다.

주요 플래그는 `-max_len=N`(입력 최대 길이), `-max_total_time=sec`/`-runs=N`(종료 조건), `-jobs=N -workers=M`(병렬, 출력은 `fuzz-*.log`), `-dict=file`(AFL++과 같은 형식의 사전), `-timeout=sec`/`-rss_limit_mb=MB`(한도), `-merge=1 corpus_min/ corpus/`(코퍼스 최소화, afl-cmin에 해당), `-minimize_crash=1 crash-xxx`(크래시 최소화, afl-tmin에 해당)다.

크래시가 나면 작업 디렉터리에 `crash-<sha1>` 파일이 생긴다. `./parse_fuzz crash-xxx`처럼 파일을 인자로 주면 그 입력만 실행해 재현한다. 같은 하네스를 AFL++로 돌릴 수도 있다. `afl-clang-fast -fsanitize=fuzzer`로 빌드하면 AFL++이 libFuzzer 드라이버 대신 자기 드라이버를 링크한다. 그래서 하네스는 `LLVMFuzzerTestOneInput` 형식으로 쓰는 것이 표준이다. OSS-Fuzz도 이 형식을 요구한다.

## 8. 네트워크 프로토콜 퍼징

### 8.1 boofuzz: 생성 기반

boofuzz는 프로토콜 메시지의 **구조를 사람이 기술**하고, 각 필드를 변이해 보내는 생성 기반(generation-based) 퍼저다. 커버리지 피드백이 없으므로 대상 코드를 몰라도 되고, 상태(로그인 뒤 명령)를 그래프로 표현한다. 대상은 **자기 실습 환경의 서버**로 한정한다.

```python
# ftp_fuzz.py — pip install boofuzz. 실습용 로컬 FTP 서버(127.0.0.1:2121)에만 쓴다
from boofuzz import *

session = Session(target=Target(connection=TCPSocketConnection("127.0.0.1", 2121)))

user = Request("user", children=(
    String(name="key", default_value="USER"),
    Delim(name="space", default_value=" "),
    String(name="val", default_value="anonymous"),
    Static(name="end", default_value="\r\n"),
))
passw = Request("pass", children=(
    String(name="key", default_value="PASS"),
    Delim(name="space", default_value=" "),
    String(name="val", default_value="guest"),
    Static(name="end", default_value="\r\n"),
))

session.connect(user)            # 첫 메시지
session.connect(user, passw)     # USER 다음에 PASS
session.fuzz()
```

`String`은 변이 대상, `Static`은 고정, `Delim`은 구분자용 변형이다. 실행하면 웹 UI가 열려 진행과 크래시 후보를 보여 준다. 서버가 죽었는지는 연결 실패로만 알 수 있으므로, 서버 쪽에서 ASan을 켜고 로그를 함께 본다.

### 8.2 AFLNet: 커버리지 + 상태

AFLNet은 AFL을 서버 퍼징용으로 고친 것이다. 녹화한 패킷(pcap)에서 메시지 시퀀스를 뽑아 시드로 쓰고, 서버 응답 코드로 상태를 추적하며, 커버리지 피드백을 유지한다. 지원 프로토콜은 RTSP, FTP, DTLS12, DNS, DICOM, SMTP, SSH, TLS, DAAP-HTTP, SIP다 📎 [AFLNet README](https://github.com/aflnet/aflnet#readme).

```bash
afl-fuzz -d -i in -o out -N tcp://127.0.0.1/8554 -x rtsp.dict -P RTSP \
  -D 10000 -q 3 -s 3 -E -K -R -- ./live555MediaServer 8554
```

`-N`은 서버 주소, `-P`는 프로토콜, `-D`는 서버 초기화 대기(μs), `-q`/`-s`는 상태·시드 선택 알고리즘, `-E`는 상태 인식 모드, `-K`는 메시지를 다 보낸 뒤 SIGTERM으로 종료, `-R`은 영역 단위 변이다. 서버를 매번 띄우므로 느리다. 서버 코드에서 "메시지 하나를 처리하는 함수"를 떼어낼 수 있다면 libFuzzer가 훨씬 효율적이고, AFLNet은 그것이 불가능할 때의 선택이다.

## 9. OSS-Fuzz 참여 개요

OSS-Fuzz는 Google이 운영하는 오픈소스 대상 지속 퍼징 인프라다. 하네스를 기여하면 Google의 기계에서 계속 돌고, 크래시는 프로젝트 관리자에게 보고된다. 분석가에게는 자기 기관이 의존하는 오픈소스에 기여하는 길이자 잘 만든 하네스의 교과서다.

프로젝트 디렉터리(`projects/<name>/`)에 세 파일을 둔다 📎 [New project guide](https://github.com/google/oss-fuzz/blob/master/docs/getting-started/new_project_guide.md). `project.yaml`은 메타데이터(`homepage`, `language`, `primary_contact`, `main_repo`, 선택적으로 `sanitizers`와 `fuzzing_engines`. libfuzzer는 필수), `Dockerfile`은 `FROM gcr.io/oss-fuzz-base/base-builder`로 시작하는 빌드 환경, `build.sh`는 `$CC $CFLAGS … $LIB_FUZZING_ENGINE`로 하네스를 빌드해 `$OUT/`에 두는 스크립트다.

로컬에서 검증하는 명령은 `infra/helper.py`에 모여 있다.

```bash
python3 infra/helper.py build_image <project>
python3 infra/helper.py build_fuzzers --sanitizer address <project>
python3 infra/helper.py check_build <project>
python3 infra/helper.py run_fuzzer --corpus-dir=<dir> <project> <fuzz_target>
```

좋은 통합의 조건은 하네스가 프로젝트 저장소 안에 있고, 시드 코퍼스(`<target>_seed_corpus.zip`)와 사전(`<target>.dict`)을 함께 두며, 하네스가 회귀 테스트로도 돌아가는 것이다 📎 [Ideal integration](https://github.com/google/oss-fuzz/blob/master/docs/advanced-topics/ideal_integration.md). 사내 코드에는 OSS-Fuzz를 쓸 수 없지만, 같은 구조(하네스 + 시드 + 사전 + CI에서 짧게 실행)를 그대로 가져오면 된다. [5장 6절](05-sast-semgrep-codeql.md)의 CI 통합과 함께 두면 "정적 분석 + 짧은 퍼징"이 PR마다 돈다.

## 체크리스트

**시작 전**
- [ ] 대상이 먹는 것(파일 / 함수 / 네트워크)에 맞는 퍼저를 골랐는가? 시드가 형식에 맞고 작은가?
- [ ] 계측·ASan·CMPLOG 바이너리를 따로 빌드하고, `core_pattern`을 퍼징용으로 맞췄는가?

**실행 중**
- [ ] exec speed, corpus count, stability를 봤는가? stability가 낮으면 비결정성을 제거했는가?
- [ ] 병렬 인스턴스가 역할(CMPLOG, ASan, 스케줄)을 나눠 갖고, `afl-whatsup`으로 마지막 발견 시각을 보고 있는가?

**크래시 처리**
- [ ] ASan 바이너리로 재현했는가? 하네스 버그는 아닌가?
- [ ] 최소화하고(`afl-tmin`/`-minimize_crash=1`), 유형과 스택으로 중복을 묶었는가?
- [ ] 최소 입력을 디버거로 넘겨 원인 줄을 찾았는가? [3장](03-debuggers.md)

## 더 읽기

- [AFL++ 문서: fuzzing_in_depth](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md) · 계측 모드 선택, 병렬 구성, CMPLOG, 크래시 분류의 공식 가이드
- [libFuzzer 공식 문서](https://llvm.org/docs/LibFuzzer.html) · 하네스 규칙과 플래그
- [boofuzz Quickstart](https://boofuzz.readthedocs.io/en/stable/user/quickstart.html), [AFLNet 저장소](https://github.com/aflnet/aflnet) · 프로토콜 모델, 옵션과 지원 프로토콜. AFLNet 원 논문: Pham, Böhme, Roychoudhury, ICST 2020
- [OSS-Fuzz 문서](https://google.github.io/oss-fuzz/) · 참여 절차와 ideal integration

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | AFL++ 설치·계측·실행·병렬·코퍼스, libFuzzer, boofuzz·AFLNet, OSS-Fuzz 작성 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증: AFL++ INSTALL/env_variables/fuzzing_in_depth/afl-fuzz 소스로 플래그·환경 변수 대조, AFLNet 옵션·프로토콜, OSS-Fuzz project.yaml·helper.py, boofuzz API를 공식 저장소로 확인하고 boofuzz 예제 객체 생성 실행, parse.c ASan 빌드로 크래시 재현, 수정 없음 | 검증팀 |
