# 취약점 분석 바이블

> 입문자가 처음부터 따라오고, 시니어가 옆에 두고 찾아보는 **살아있는 취약점 분석 레퍼런스**.

- 📖 온라인 읽기: https://anthonynoh5202.github.io/anthonynoh/ (GitHub Pages 활성화 후)
- 🧪 실습 환경: [`labs/`](labs/) 디렉터리, `docker compose up` 한 줄로 실행
- ✍️ 기여하기: [CONTRIBUTING.md](CONTRIBUTING.md)
- 🗓️ 변경 이력: [CHANGELOG.md](CHANGELOG.md)

## 이 책의 원칙

1. **모든 장은 같은 템플릿**을 따른다. 어디를 펴도 같은 방식으로 읽힌다. → [`templates/chapter-template.md`](templates/chapter-template.md)
2. **사례는 실제 CVE**만 쓴다. 가상 예제 대신 실제 패치 diff를 보여준다.
3. **실습은 코드로 제공**한다. 환경 구축에 막혀 포기하는 독자가 없게 한다.
4. **레벨을 표시**한다. 🟢 입문 · 🟡 실무 · 🔴 시니어
5. **계속 개정**한다. 상태 배지(📝 초안 · 🔄 개정중 · ✅ 검수완료)와 변경 이력을 장마다 둔다.

## 로컬에서 빌드하기

```bash
# mdBook 설치 (Rust가 있다면)
cargo install mdbook --version 0.4.40
# 또는 릴리스 바이너리: https://github.com/rust-lang/mdBook/releases

mdbook serve --open   # http://localhost:3000 에서 실시간 미리보기
mdbook build          # book/ 디렉터리에 정적 사이트 생성
```

## 구조

```
src/            책 본문 (mdBook)
  SUMMARY.md    목차. 여기 적힌 순서대로 책이 구성된다
templates/      새 장을 쓸 때 복사해서 쓰는 템플릿
labs/           취약 실습 환경 (Docker Compose)
.github/        main 브랜치 push 시 GitHub Pages로 자동 배포
```

## 라이선스

본문: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.ko) · 코드와 실습 환경: MIT

## ⚠️ 윤리 고지

이 책의 모든 기법은 **본인이 소유하거나 명시적으로 허가받은 시스템**에서만 사용해야 합니다. 실습 환경은 격리된 로컬 네트워크에서만 실행하세요.
