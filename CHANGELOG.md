# 변경 이력

형식: [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/) · 태그: `vYYYY.Qn`

## [Unreleased]

### Added
- 두 번째 책: 취약점관리센터 직원 안내서 (`books/kisa-vmc-handbook/`). 16개 장 + 부록 5개, 공개 자료 기반
- 이미지 체계: Mermaid 다이어그램(CDN 로더), 실습 스크린샷 자동 캡처(`labs/tools/capture.py`), 기여 가이드에 이미지 규칙
- SQL 인젝션 장에 다이어그램 2개, 스크린샷 4장
- 다중 책 구조: `books/`, `build.sh`, 랜딩 페이지, 배포 워크플로 갱신

### Changed
- 바이블을 `books/vulnerability-bible/`로 이동

- 책 뼈대 생성: 8개 파트, 부록, 장 템플릿, 기여 가이드
- 모범 장(기준 장) 작성: 3부 1장 SQL 인젝션
- 실습 환경 `labs/web-sqli` (Docker Compose)
- GitHub Pages 자동 배포 워크플로
