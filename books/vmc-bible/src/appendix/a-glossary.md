# 부록 A. 용어집

가나다순, 그다음 알파벳순. 원어를 병기하고 자세한 설명이 있는 장으로 연결한다. 센터 내부 용어(시스템 이름, 양식 이름)는 🔎 내부 확인 후 내부 블록으로 추가한다.

## 센터·제도 용어

| 용어 | 뜻 | 장 |
|---|---|---|
| **118** | KISA 전화 상담·신고 창구. 외부 신고가 센터로 들어오는 입구 중 하나 | [2부 7장](../vol1-center/02-programs/07-portal-advisory.md) |
| **공동운영사** | 신고포상제에 참여해 자사 제품 취약점 포상금을 직접 부담하는 기업 | [2부 5장](../vol1-center/02-programs/05-bug-bounty.md) |
| **국가AI전략위원회** | 국가인공지능전략위원회. 상시 신고조치제 총괄 | [3부 11장](../vol1-center/03-partners/11-external.md) |
| **기반시설** | 주요정보통신기반시설. 정보통신기반 보호법상 지정된 시설 | [2부 8장](../vol1-center/02-programs/08-assessment-support.md) |
| **보호나라** | boho.or.kr. KISA의 보안공지와 침해사고 신고 사이트(KrCERT/CC) | [2부 7장](../vol1-center/02-programs/07-portal-advisory.md) |
| **상시 신고조치제** | 보안취약점 상시 신고조치제. 2026.5 시범사업 시작한 CVD/VDP 제도 | [2부 6장](../vol1-center/02-programs/06-cvd-vdp.md) |
| **신고포상제** | 보안 취약점 신고포상제. 2012년부터 운영하는 SW 신규 취약점 신고·포상 제도 | [2부 5장](../vol1-center/02-programs/05-bug-bounty.md) |
| **취약점 정보 포털** | 사이버 보안 취약점 정보 포털, knvd.krcert.or.kr. 신고 접수 창구 | [2부 7장](../vol1-center/02-programs/07-portal-advisory.md) |
| **클리닝 서비스** | 보안 취약점 클리닝 서비스. 백신 연계로 구버전 SW 패치를 안내 | [2부 7장](../vol1-center/02-programs/07-portal-advisory.md) |
| **파급도** | 취약점이 국내에서 미치는 영향의 넓이. 사용 규모, 분야 | [1부 4장](../vol1-center/01-understanding/04-workflow.md) |
| **허용 정책** | 기관이 사전에 공개하는 취약점 탐색 허용 범위. VDP의 핵심 | [3부 12장](../vol1-center/03-partners/12-legal.md) |
| **CNA** | CVE Numbering Authority. CVE 번호를 부여할 권한이 있는 기관. KISA는 포괄적 범위 CNA | [3부 11장](../vol1-center/03-partners/11-external.md) |
| **CVD** | Coordinated Vulnerability Disclosure, 조율된(협력적) 취약점 공개. 발견자·조정자·제조사가 조율해 조치 후 공개 | [2부 6장](../vol1-center/02-programs/06-cvd-vdp.md) |
| **CVE** | Common Vulnerabilities and Exposures. 전 세계 공통 취약점 식별자 | 제2편 [1부 2장](../vol2-tech/part1-foundations/02-cwe-cve-cvss.md) |
| **CVSS** | Common Vulnerability Scoring System. 취약점 심각도 점수 체계 | 제2편 [1부 2장](../vol2-tech/part1-foundations/02-cwe-cve-cvss.md) |
| **CWE** | Common Weakness Enumeration. 취약점 유형 분류 | 제2편 [1부 2장](../vol2-tech/part1-foundations/02-cwe-cve-cvss.md) |
| **FIRST** | Forum of Incident Response and Security Teams. 국제 CERT 협의체, CVSS 관리 | [3부 11장](../vol1-center/03-partners/11-external.md) |
| **GTAC** | OpenAI의 정부·기관용 신뢰 기반 접근 프로그램. 2026.5 과기정통부·KISA 참여 | [2부 9장](../vol1-center/02-programs/09-ai.md) |
| **KrCERT/CC** | KISA 인터넷침해대응센터. 침해사고 대응 | [3부 10장](../vol1-center/03-partners/10-internal.md) |
| **N2SF** | 국가망 보안체계. 디지털위협예방본부 소관 | [3부 10장](../vol1-center/03-partners/10-internal.md) |
| **NCSC** | 국가정보원 국가사이버안보센터 | [3부 11장](../vol1-center/03-partners/11-external.md) |
| **NHI** | Non-Human Identity. 사람이 아닌 계정·키·토큰. 센터장이 AI 시대 핵심 관리 대상으로 꼽음 | [1부 1장](../vol1-center/01-understanding/01-why.md) |
| **PoC** | Proof of Concept. 취약점이 실제임을 보이는 최소 증명 | 제2편 [2부 6장](../vol2-tech/part2-methodology/06-exploit-verification.md) |
| **TF** | 태스크포스. 센터 출범 시 형태 | [1부 2장](../vol1-center/01-understanding/02-where.md) |
| **VDP** | Vulnerability Disclosure Policy, 취약점 공개 정책. 기관이 "여기까지는 찾아도 된다"를 사전 공개 | [2부 6장](../vol1-center/02-programs/06-cvd-vdp.md) |

## 기술 용어

| 용어 | 뜻 | 장 |
|---|---|---|
| **가젯 체인** (gadget chain) | 역직렬화 시 기존 클래스의 메서드를 연쇄 호출해 임의 코드 실행에 이르는 경로 | [역직렬화](../vol2-tech/part3-web/07-deserialization.md) |
| **경쟁 조건** (race condition) | 확인과 사용 사이에 상태가 바뀌어 생기는 취약점 | [경쟁 조건](../vol2-tech/part3-web/10-race-condition.md) |
| **공격 표면** (attack surface) | 외부 입력이 들어오는 모든 지점 | [공격 표면](../vol2-tech/part1-foundations/03-attack-surface.md) |
| **신뢰 경계** (trust boundary) | 신뢰 수준이 달라지는 지점. 취약점은 거의 항상 여기서 생긴다 | [취약점이란](../vol2-tech/part1-foundations/01-what-is-vulnerability.md) |
| **블라인드 인젝션** (blind injection) | 결과가 직접 보이지 않고 참/거짓이나 시간 차이로만 알 수 있는 인젝션 | [SQL 인젝션](../vol2-tech/part3-web/01-sql-injection.md) |
| **완화 기법** (mitigation) | ASLR, NX, Canary, PIE, RELRO, CFI 등 익스플로잇을 어렵게 하는 장치 | [완화 기법](../vol2-tech/part4-binary/07-mitigations.md) |
| **익스플로잇** (exploit) | 취약점을 실제로 이용하는 코드나 절차 | [취약점이란](../vol2-tech/part1-foundations/01-what-is-vulnerability.md) |
| **역직렬화** (deserialization) | 직렬화된 데이터를 객체로 되돌리는 것. 입력을 신뢰하면 코드 실행 | [역직렬화](../vol2-tech/part3-web/07-deserialization.md) |
| **퍼징** (fuzzing) | 예상 밖 입력을 자동으로 대량 주입해 결함을 찾는 기법 | [퍼징](../vol2-tech/part4-binary/09-fuzzing.md) |
| **파라미터화된 쿼리** (parameterized query) | 쿼리와 입력을 분리해 전달하는 방식. SQL 인젝션의 근본 방어 | [SQL 인젝션](../vol2-tech/part3-web/01-sql-injection.md) |
| **ASLR** | Address Space Layout Randomization. 메모리 주소 무작위화 | [완화 기법](../vol2-tech/part4-binary/07-mitigations.md) |
| **IDOR** | Insecure Direct Object Reference. ID만 바꿔 남의 자원에 접근 | [접근 제어](../vol2-tech/part3-web/05-access-control.md) |
| **N-day** | 패치가 나왔지만 적용되지 않은 취약점. 실제 침해의 대부분 | [취약점이란](../vol2-tech/part1-foundations/01-what-is-vulnerability.md) |
| **ROP** | Return-Oriented Programming. 기존 코드 조각을 이어 붙여 실행 | [ROP](../vol2-tech/part4-binary/08-rop.md) |
| **SAST** | Static Application Security Testing. 정적 분석 (Semgrep, CodeQL) | [정적 분석기](../vol2-tech/part6-tools/05-sast-semgrep-codeql.md) |
| **SSRF** | Server-Side Request Forgery. 서버가 공격자 지정 URL로 요청 | [SSRF](../vol2-tech/part3-web/03-ssrf.md) |
| **UAF** | Use-After-Free. 해제된 메모리를 계속 사용 | [UAF](../vol2-tech/part4-binary/05-uaf.md) |
| **XSS** | Cross-Site Scripting. 입력이 브라우저에서 스크립트로 실행 | [XSS](../vol2-tech/part3-web/02-xss.md) |
| **0-day** | 벤더가 모르거나 패치가 없는 취약점 | [취약점이란](../vol2-tech/part1-foundations/01-what-is-vulnerability.md) |
