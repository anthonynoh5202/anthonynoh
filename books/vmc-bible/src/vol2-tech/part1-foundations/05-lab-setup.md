# 실습 환경 구축

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟢 입문 | 🔄 개정중 | 2026-10-21 |

> **한눈에 보기**
> 이 책의 모든 실습은 Docker Compose 한 줄로 뜬다.
> 이 장을 끝내면 이후 모든 장의 🧪 섹션을 바로 따라 할 수 있다.
> 실습 환경은 **일부러 취약하게** 만들어져 있다. 외부에 노출하지 마라.

## 1. 필요한 것

| 도구 | 확인 명령 | 최소 버전 |
|---|---|---|
| Docker | `docker --version` | 24+ |
| Docker Compose (v2, 플러그인) | `docker compose version` | 2.20+ |
| Git | `git --version` | 아무 버전 |
| Python 3 (풀이 스크립트용, 선택) | `python3 --version` | 3.10+ |

운영체제별 Docker 설치는 [공식 문서](https://docs.docker.com/get-docker/)를 따른다. Windows는 WSL2 위에서 쓰는 것을 권한다.

## 2. 저장소 받기

```bash
git clone https://github.com/anthonynoh5202/anthonynoh.git
cd anthonynoh/labs
ls
```

`labs/` 아래에 실습마다 디렉터리가 하나씩 있다.

```
labs/
  README.md          실습 목록과 공통 규칙 (이 책 밖의 파일이다. 저장소의 labs/README.md)
  web-sqli/          웹 1장 SQL 인젝션
    docker-compose.yml
    app/             취약한 앱 소스 (고치는 것까지가 실습)
    solve_blind.py   참고 풀이
  ...
```

## 3. 첫 실습 띄우기

```bash
cd labs/web-sqli
docker compose up --build
```

터미널에 다음이 보이면 브라우저에서 `http://localhost:8080` 을 연다(Flask 3의 실제 출력).

```
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:8080
 * Running on http://192.0.2.2:8080        ← 세 번째 줄은 그 기기의 네트워크 주소. 환경마다 다르다
```

세 번째 줄이 보이는 이유는 앱이 컨테이너 안에서 `0.0.0.0`(모든 인터페이스)에 바인딩되기 때문이다. Docker로 띄울 때는 `docker-compose.yml`의 `127.0.0.1:8080:8080` 설정이 호스트 쪽 노출을 루프백으로 제한하므로 그 주소로는 밖에서 접근할 수 없다. 반면 아래처럼 Docker 없이 직접 띄우면 그 줄의 주소가 **실제로 같은 네트워크의 다른 기기에서 열리는 주소**가 된다.

Docker를 쓸 수 없으면 앱을 직접 띄워도 된다. 앱은 Flask와 표준 라이브러리의 sqlite3만 쓴다.

```bash
cd labs/web-sqli/app
python3 -m venv .venv && . .venv/bin/activate
pip install flask && python app.py        # 같은 'Running on ...' 출력. DB는 /tmp/lab.db
```

이 경우 포트가 `0.0.0.0:8080`에 열리고 위 출력의 세 번째 줄 주소로 같은 네트워크의 누구나 접속할 수 있으므로, 5절의 격리 규칙(공용 네트워크에서 띄우지 않기)을 더 엄격히 지킨다. 루프백에만 열고 싶으면 `app.py`의 `app.run(host="0.0.0.0", ...)`을 `host="127.0.0.1"`로 바꿔 띄운다. 코드를 고친 뒤 반영하려면 Docker는 `docker compose up --build`로 다시 빌드하고, 직접 띄운 경우는 프로세스를 다시 시작한다.

끝낼 때:

```bash
docker compose down        # 컨테이너 정리
docker compose down -v     # 데이터(볼륨)까지 초기화
```

## 4. 공통 규칙

모든 실습 환경은 다음을 지킨다.

- **포트**: `127.0.0.1`에만 바인딩한다. 같은 네트워크의 다른 기기에서 접근할 수 없다.
- **초기화**: `docker compose down -v && docker compose up --build` 로 언제든 처음 상태로 돌아간다.
- **고치기**: 취약 코드에 `# ❌` 주석이 있다. 그것을 고치고 공격이 실패하는지 확인하는 것까지가 실습이다.
- **풀이**: `solve_*.py` 는 막혔을 때만 본다.

## 5. 격리

실습 환경은 Docker의 기본 브리지 네트워크 안에서만 통신한다. 그래도 다음은 지킨다.

- 공용 Wi-Fi나 회사 네트워크에서 실습 환경을 띄우지 않는다.
- `docker-compose.yml`의 포트 설정에서 `127.0.0.1:` 접두사를 지우지 않는다.
- 실습 앱의 자격증명(`admin / admin123` 등)을 다른 곳에서 재사용하지 않는다.

## 6. 최소 도구 세트

Kali Linux가 없어도 된다. 이 책에서 쓰는 도구는 대부분 개별 설치가 가능하다.

| 분야 | 도구 | 설치 |
|---|---|---|
| 웹 프록시 | Burp Suite Community 또는 ZAP | 각 공식 사이트 |
| HTTP 클라이언트 | curl, httpie | 패키지 매니저 |
| SQLi 자동화 | sqlmap | `pip install sqlmap` 또는 git clone |
| 바이너리 | gdb + pwndbg, pwntools, checksec | [6장](06-analysis-workstation.md)의 설치 스크립트로 설치. 빌드 플래그와 checksec 읽는 법은 [바이너리 부 개요](../part4-binary/00-overview.md) |
| 디컴파일러 | Ghidra | [공식 릴리스](https://github.com/NationalSecurityAgency/ghidra/releases) |
| 정적 분석 | semgrep | `pip install semgrep` |

바이너리 실습은 공용 컨테이너 `labs/binary-base/`(gdb+pwndbg, pwntools, AFL++, radare2. 사용법은 저장소의 `labs/binary-base/README.md`, [GitHub](https://github.com/anthonynoh5202/anthonynoh/blob/main/labs/binary-base/README.md))를 쓸 수 있다. 실제 제보와 바이너리를 다루는 **분석 환경**(VM 격리, 영역별 도구 세트, 설치 스크립트)은 [6장](06-analysis-workstation.md)에서 다룬다.

## 7. 문제 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| `port is already allocated` | 8080 포트를 다른 프로그램이 쓴다 | `docker-compose.yml`에서 `127.0.0.1:8081:8080` 으로 바꾼다 |
| `permission denied` (Linux) | 사용자가 docker 그룹에 없다 | `sudo usermod -aG docker $USER` 후 재로그인 |
| Apple Silicon에서 바이너리 실습이 안 뜬다 | x86-64 이미지 | `DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose up --build` 또는 compose 파일의 `platform: linux/amd64` 설정 확인 |
| 빌드가 너무 느리다 | 캐시 없음 | 처음 한 번만 느리다. 두 번째부터는 캐시를 쓴다 |
| 앱이 떴는데 DB가 비어 있다 | 초기화 스크립트 실패 | `docker compose down -v` 후 다시 `up --build` |

## 체크리스트

- [ ] `docker compose version` 이 2.20 이상을 출력한다
- [ ] `labs/web-sqli` 가 `http://localhost:8080` 에서 뜬다
- [ ] `docker compose down -v` 로 정리하고 다시 띄울 수 있다
- [ ] 포트가 `127.0.0.1` 에만 열려 있는지 `docker compose ps` 로 확인했다

## 더 읽기

- [Docker Compose 공식 문서](https://docs.docker.com/compose/)
- [labs/README.md](https://github.com/anthonynoh5202/anthonynoh/blob/main/labs/README.md) · 실습 환경 전체 목록. 저장소를 받았다면 `labs/README.md`를 바로 열면 된다(mdBook 밖의 파일이라 책 안 링크로는 걸 수 없다)

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안 작성 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증: `docker compose up`에는 `--platform` 옵션이 없어 `DOCKER_DEFAULT_PLATFORM` 환경변수로 정정 | 검증팀 |
| 2026-10-22 | 독자 테스트 반영: 3절 기동 문구를 Flask 3 실제 출력(`Running on all addresses (0.0.0.0)`)으로, Docker 없이 `pip install flask && python app.py`로 띄우는 대안과 재빌드 안내 추가, 바이너리 도구 설치 참조를 6장으로 정정 | @anthonynoh5202 |
| 2026-10-23 | 독자 테스트 2차 반영: 기동 출력의 세 번째 줄(`Running on http://<외부IP>:8080`)과 0.0.0.0 바인딩 주의를 보강(Flask 3.0.3 실행 확인). GitHub URL로만 걸려 있던 `labs/README.md`·`labs/binary-base/README.md`에 저장소 경로 텍스트 병기 | @anthonynoh5202 |
