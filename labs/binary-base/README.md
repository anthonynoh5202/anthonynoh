# binary-base: 바이너리 분석 공용 컨테이너

제2편 바이너리 장(스택 오버플로, 포맷 스트링, 힙, ROP, 퍼징)의 실습을 같은 환경에서 하기 위한 이미지다. 호스트에 도구를 설치하지 않고도 실습할 수 있다. 호스트에 직접 설치하려면 [제2편 기초 6장 분석 환경 구축](../../books/vmc-bible/src/vol2-tech/part1-foundations/06-analysis-workstation.md)과 `tools/setup-analyst.sh`를 본다.

```bash
docker build -t vmc-binary-base labs/binary-base
docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v "$PWD:/work" vmc-binary-base
```

컨테이너 안에서:

```bash
gcc -g -O0 -fno-stack-protector -z execstack -no-pie vuln.c -o vuln   # 완화 끄고 컴파일
checksec --file=./vuln
gdb ./vuln                       # pwndbg가 자동으로 뜬다
setarch -R ./vuln                # 이 프로세스만 ASLR 끄기
afl-fuzz -i in -o out -- ./target @@
```

## 왜 ptrace 권한이 필요한가

gdb는 `ptrace`로 다른 프로세스를 붙잡는다. Docker 기본 seccomp 프로파일은 이를 제한하므로 `--cap-add=SYS_PTRACE --security-opt seccomp=unconfined`를 준다. 이 옵션은 컨테이너 격리를 약하게 하므로 **신뢰하는 바이너리만** 이 컨테이너에서 다룬다. 출처 불명 샘플은 네트워크 없는 전용 VM에서 다룬다([기초 6장 2절](../../books/vmc-bible/src/vol2-tech/part1-foundations/06-analysis-workstation.md)).

## 아키텍처

이미지는 x86-64 기준이다. Apple Silicon에서는 `docker build --platform linux/amd64`로 빌드하면 에뮬레이션으로 돈다(느리지만 실습에는 충분하다). ARM·MIPS 바이너리는 `qemu-user`와 `gdb-multiarch`로 다룬다.
