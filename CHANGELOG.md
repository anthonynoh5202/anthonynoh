# 변경 이력

형식: [Keep a Changelog](https://keepachangelog.com/ko/1.1.0/) · 태그: `vYYYY.Qn`

## [Unreleased]

### Added
- 기초 6장 "분석 환경 구축: 워크스테이션과 도구" (세 겹 구조, 영역별 도구 세트, 설치 절차), 설치 스크립트 `tools/setup-analyst.sh`, 바이너리 분석 공용 컨테이너 `labs/binary-base/`
- **제2편 분석 기술 전 장 본문 작성** (기초·방법론·웹·바이너리·확장·도구·워크스루·보고 55개 장, 부록 B·H). 집필 에이전트 10팀 병렬 작성
- **기술 검증**: 검증 에이전트 5팀이 CVE 170여 건을 CVE 공식 레코드(cvelistV5)와 전수 대조, 모든 C·Python 예제를 컴파일·실행 재현, 패치 커밋 원문 대조, 도구 명령을 공식 문서와 대조. 수정 내용은 각 장 변경 이력의 "검증팀" 행에 기록

### Changed
- 책 제목을 《취약점, 발견에서 조치까지》로 확정. 본문 말투를 책의 문어체로 통일
- **두 책을 한 권으로 통합**: 취약점관리센터 바이블(가제) (`books/vmc-bible/`). 제1편 센터와 제도, 제2편 분석 기술, 제3편 현장 적용
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
