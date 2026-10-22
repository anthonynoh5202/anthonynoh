# 살아있는 보안 책들

> 계속 개정되는 책. 어디를 펴도 같은 구조, 모든 장에 상태 배지, 누구나 고칠 수 있는 편집 링크.

| 책 | 대상 | 읽기 |
|---|---|---|
| **취약점 분석 바이블** | 입문자부터 시니어까지. 취약점 분석 기술 | [`books/vulnerability-bible/`](books/vulnerability-bible/) · [온라인](https://anthonynoh5202.github.io/anthonynoh/vulnerability-bible/) |
| **취약점관리센터 직원 안내서** | KISA 취약점관리센터 신입·기존·전입 직원. 공개 자료 기반 비공식 초안 | [`books/kisa-vmc-handbook/`](books/kisa-vmc-handbook/) · [온라인](https://anthonynoh5202.github.io/anthonynoh/kisa-vmc-handbook/) |

온라인 주소는 GitHub Pages 활성화(Settings → Pages → Source: GitHub Actions) 후 동작합니다.

- 🧪 실습 환경: [`labs/`](labs/) 디렉터리, `docker compose up` 한 줄로 실행
- ✍️ 기여하기: [CONTRIBUTING.md](CONTRIBUTING.md)
- 🗓️ 변경 이력: [CHANGELOG.md](CHANGELOG.md)

## 두 책의 관계

바이블은 **분석가가 손을 움직이는 방법**을, 안내서는 **센터가 조직으로서 움직이는 방법**을 다룹니다. 안내서 4부 "공통 역량"에서 바이블로 연결되고, 바이블 실습이 안내서의 온보딩 과제로 쓰입니다.

## 공통 원칙

1. **모든 장은 같은 템플릿**을 따른다. → [`templates/`](templates/)
2. **사례는 실제**만 쓴다. 바이블은 실제 CVE와 패치 diff, 안내서는 출처 있는 공개 자료(📎)만.
3. **실습은 코드로 제공**한다. 환경 구축에 막히지 않게.
4. **레벨을 표시**한다. 🟢 입문 · 🟡 실무 · 🔴 시니어
5. **계속 개정**한다. 상태 배지(📝 초안 · 🔄 개정중 · ✅ 검수완료)와 변경 이력을 장마다.
6. **모르는 것은 모른다고 쓴다.** 안내서의 🔎 표시는 내부 확인이 필요한 항목이며 [부록 E](books/kisa-vmc-handbook/src/appendix/e-verify.md)에 목록이 있다.

## 로컬에서 빌드하기

```bash
# mdBook 설치 (Rust가 있다면)
cargo install mdbook --version 0.4.40
# 또는 릴리스 바이너리: https://github.com/rust-lang/mdBook/releases

./build.sh                                     # 두 책 모두 → site/
(cd books/vulnerability-bible && mdbook serve --open)   # 한 책만 실시간 미리보기
```

다이어그램은 Mermaid 코드 블록으로 쓰며 브라우저에서 CDN으로 렌더링됩니다. 실습 스크린샷은 `labs/tools/capture.py`로 자동 생성합니다 ([CONTRIBUTING.md](CONTRIBUTING.md#이미지와-다이어그램)).

## 구조

```
books/
  vulnerability-bible/     취약점 분석 바이블 (mdBook)
  kisa-vmc-handbook/       취약점관리센터 직원 안내서 (mdBook)
labs/                      취약 실습 환경 (Docker Compose) + 스크린샷 캡처 도구
templates/                 새 장을 쓸 때 복사하는 템플릿
landing/                   site/ 루트 페이지
build.sh                   모든 책 빌드 → site/
.github/workflows/         main 푸시 시 GitHub Pages 자동 배포
```

## 라이선스

본문: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.ko) · 코드와 실습 환경: MIT

## ⚠️ 고지

- 바이블의 모든 기법은 **본인이 소유하거나 명시적으로 허가받은 시스템**에서만 사용해야 합니다. 실습 환경은 격리된 로컬에서만 실행하세요.
- 안내서는 KISA의 공식 문서가 아닙니다. 내부 규정과 다르면 내부 자료가 우선합니다.
