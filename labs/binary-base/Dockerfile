# 바이너리 분석 공용 컨테이너 (제2편 바이너리 장 실습용)
# gdb + pwndbg, pwntools, ROPgadget, ropper, AFL++, radare2, 완화 기법을 끌 수 있는 gcc.
# 빌드:  docker build -t vmc-binary-base labs/binary-base
# 실행:  docker run --rm -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
#          -v "$PWD:/work" vmc-binary-base
#        (ptrace 권한은 gdb에 필요하다. 외부로 포트를 열지 않는다.)
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8
RUN apt-get update && apt-get install -y --no-install-recommends \
      gdb gdb-multiarch gcc g++ clang make nasm binutils elfutils patchelf \
      strace ltrace file xxd hexedit python3 python3-pip python3-venv git curl ca-certificates \
      afl++ radare2 qemu-user vim less \
    && rm -rf /var/lib/apt/lists/*
# pwndbg (공식 저장소의 setup.sh)
RUN git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
    && cd /opt/pwndbg && ./setup.sh \
    && echo 'source /opt/pwndbg/gdbinit.py' > /root/.gdbinit
# pwntools 계열은 전용 venv
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir \
      pwntools ropper ROPgadget
ENV PATH="/opt/venv/bin:${PATH}"
# 실습은 ASLR을 끄고 할 때가 많다. 컨테이너 안에서는 setarch -R 로 프로세스 단위로 끈다.
WORKDIR /work
CMD ["/bin/bash"]
