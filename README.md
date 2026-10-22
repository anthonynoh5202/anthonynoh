# 취약점, 발견에서 조치까지

> 분석 기술과 대응 체계의 교과서. 취약점관리센터 구성원을 위한 한 권. **센터와 제도**(제1편), **분석 기술**(제2편), **현장 적용**(제3편).
> 계속 개정되는 책. 어디를 펴도 같은 구조, 모든 장에 상태 배지, 누구나 고칠 수 있는 편집 링크.

- 📖 온라인: https://anthonynoh5202.github.io/anthonynoh/
- 🧪 실습 환경: [`labs/`](labs/), `docker compose up` 한 줄
- ✍️ 기여하기: [CONTRIBUTING.md](CONTRIBUTING.md)
- 🗓️ 변경 이력: [CHANGELOG.md](CHANGELOG.md)

## 구성

```
제1편 센터와 제도    왜 생겼고, 어디에 있고, 무엇을 하는가. 신고포상제, 상시 신고조치제, 포털, AI, 협업, 법
제2편 분석 기술      취약점 원리, 방법론, 웹·바이너리·확장, 도구, 실제 CVE 워크스루, 보고서
제3편 현장 적용      센터 업무 네 단계(입수·분석 → 검증 → 조치 → 공지) × 제2편 기술. 온보딩
부록                용어집, 치트시트, 연표, FAQ, 출처, 내부 확인 목록, 기여, 참고 자료
```

## 공개판과 내부판

같은 원고에서 두 판이 나옵니다. 원고에 `<!-- internal:start -->` … `<!-- internal:end -->` 블록을 두면 공개판에서는 빠지고 내부판에만 들어갑니다.

```bash
./build.sh              # 공개판 → site/        (GitHub Pages가 배포하는 것)
INTERNAL=1 ./build.sh   # 내부판 → site-internal/ (인트라넷에 올릴 것)
```

## 원칙

1. **모든 장은 같은 템플릿**을 따른다. → [`templates/`](templates/)
2. **사례는 실제**만 쓴다. 기술은 실제 CVE와 패치 diff, 조직은 출처 있는 공개 자료(📎).
3. **실습은 코드로 제공**한다.
4. **레벨을 표시**한다. 🟢 입문 · 🟡 실무 · 🔴 시니어
5. **계속 개정**한다. 상태 배지(📝 초안 · 🔄 개정중 · ✅ 검수완료)와 변경 이력을 장마다.
6. **모르는 것은 모른다고 쓴다.** 🔎 표시는 내부 확인이 필요한 항목. [부록 F](books/vmc-bible/src/appendix/f-verify.md)

## 로컬에서 빌드하기

```bash
cargo install mdbook --version 0.4.40   # 또는 릴리스 바이너리
./build.sh
(cd books/vmc-bible && mdbook serve --open)   # 실시간 미리보기
```

다이어그램은 Mermaid 코드 블록(라이브러리 번들, 오프라인 동작). 실습 스크린샷은 `labs/tools/capture.py`로 자동 생성.

## 구조

```
books/vmc-bible/     책 본문 (mdBook). src/SUMMARY.md 가 목차
  theme/             Mermaid 번들, 스타일
tools/               internal-filter.py (내부 블록 전처리기)
labs/                취약 실습 환경 (Docker Compose) + 스크린샷 캡처 도구
templates/           새 장을 쓸 때 복사하는 템플릿
build.sh             빌드 → site/ 또는 site-internal/
.github/workflows/   main 푸시 시 공개판을 GitHub Pages로 자동 배포
```

## 라이선스

본문 CC BY-SA 4.0 · 코드와 실습 환경 MIT

## ⚠️ 고지

- 제1편과 제3편의 센터 관련 서술은 공개 자료 기반 **비공식 초안**입니다. KISA 공식 문서가 아니며, 내부 규정과 다르면 내부 자료가 우선합니다.
- 제2편의 모든 기법은 **본인이 소유하거나 명시적으로 허가받은 시스템**에서만 사용해야 합니다.
