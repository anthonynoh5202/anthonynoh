# 변경 이력

형식: [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/) · 태그: `vYYYY.Qn`

## [Unreleased]

### Changed
- **두 책을 한 권으로 통합**: 취약점관리센터 바이블 (`books/vmc-bible/`). 제1편 센터와 제도, 제2편 분석 기술, 제3편 현장 적용
- 기존 주소(`/vulnerability-bible/...`, `/kisa-vmc-handbook/...`)는 새 위치로 리다이렉트
- 용어집·부록 통합

### Added
- 제3편 "업무 흐름 × 기술" 4개 장: 입수·분석, 검증, 조치, 공유·공지 단계에서 쓰는 기술
- 내부판 빌드: `<!-- internal -->` 블록 전처리기(`tools/internal-filter.py`), `INTERNAL=1 ./build.sh`
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
