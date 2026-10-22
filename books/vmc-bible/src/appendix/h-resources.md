# 부록 H. 참고 자료

| 레벨 | 상태 | 최종 개정 |
|---|---|---|
| 🟢 | 🔄 개정중 | 2026-10-22 |

> **한눈에 보기**
> 1차 자료 우선. 책, 표준 문서, 연습 플랫폼, 커뮤니티를 분야별로 정리한다.
> 각 항목에 "언제 보는가"를 붙였다. 전부 읽는 목록이 아니라 **필요할 때 찾는** 목록이다.

## 1. 표준과 분류 체계

| 자료 | 무엇 | 언제 보는가 |
|---|---|---|
| [CWE](https://cwe.mitre.org/) | 취약점 **유형** 사전. MITRE 운영 | 보고서에 유형 번호를 적을 때. [CWE Top 25](https://cwe.mitre.org/top25/)는 연간 통계 |
| [CVE](https://www.cve.org/) | 취약점 **사례** 식별자. CNA가 할당 | 특정 제품의 알려진 취약점을 찾을 때 |
| [NVD](https://nvd.nist.gov/) | CVE에 CVSS·CPE·참고 링크를 붙인 미국 DB | CVSS 벡터와 영향 버전 확인 |
| [CVSS](https://www.first.org/cvss/) | 심각도 점수 체계. FIRST 관리. 3.1과 4.0 병행 | [8부 2장](../vol2-tech/part8-reporting/02-severity.md) |
| [EPSS](https://www.first.org/epss/) | 30일 내 악용 확률 예측. FIRST | 패치 우선순위 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 실제 악용 확인된 CVE 목록 | "진짜 급한 것" 필터 |
| [CAPEC](https://capec.mitre.org/) | 공격 **패턴** 사전 | CWE가 약점이라면 CAPEC은 그 약점을 치는 방법 |
| [MITRE ATT&CK](https://attack.mitre.org/) | 침해 후 공격자 **행동** 분류 | 취약점이 침해로 이어진 뒤의 단계를 설명할 때 |
| [OWASP Top 10](https://owasp.org/www-project-top-ten/) | 웹 위험 10대 분류. 2021판·2025판 | [3부 개요](../vol2-tech/part3-web/00-overview.md) |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | 웹 보안 요구사항 검증 표준 | 점검 항목표가 필요할 때 |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) | 유형별 방어 코드 모음 | 수정 제안을 쓸 때 |
| ISO/IEC 29147:2018 | 취약점 **공개**(disclosure) 표준. 벤더가 신고를 받고 권고를 내는 방법 | CVD 정책 설계. 유료 |
| ISO/IEC 30111:2019 | 취약점 **처리**(handling) 표준. 접수부터 수정까지 내부 절차 | 29147과 한 쌍. 유료 |
| [CERT Guide to CVD](https://vuls.cert.org/confluence/display/CVD) | 조율 공개의 실무 가이드 (CERT/CC, 2017) | 다자간 공개 조율 |

## 2. 연습 플랫폼

| 플랫폼 | 분야 | 특징 | 비용 |
|---|---|---|---|
| [PortSwigger Web Security Academy](https://portswigger.net/web-security) | 웹 | 유형별 설명 + 브라우저에서 바로 푸는 랩. 3부 각 장의 실습 대상 | 무료 |
| [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) | 웹 | 일부러 취약하게 만든 현대적 웹 앱(Node.js). Docker 한 줄로 띄운다 | 무료 |
| [DVWA](https://github.com/digininja/DVWA) | 웹 | 고전. PHP. 난이도 단계별 같은 취약점 | 무료 |
| [pwn.college](https://pwn.college/) | 바이너리·시스템 | 애리조나 주립대 강의 기반. 브라우저 안의 리눅스 환경에서 단계별 | 무료 |
| [pwnable.kr](https://pwnable.kr/) | 바이너리 | 한국에서 만든 고전 워게임. SSH로 접속 | 무료 |
| [picoCTF](https://picoctf.org/) | 종합 입문 | 카네기 멜런대 운영. 상시 연습장 | 무료 |
| [Hack The Box](https://www.hackthebox.com/) | 종합·실전 | 머신 단위 침투. 보고서 쓰기 연습에도 좋다 | 일부 유료 |
| [Dreamhack](https://dreamhack.io/) | 종합 | 티오리 운영. 한국어 강의 + 워게임 + 정기 CTF | 일부 유료 |

순서 제안: 웹은 PortSwigger → Juice Shop, 바이너리는 pwn.college → pwnable.kr. 이 책의 [4부](../vol2-tech/part4-binary/00-overview.md)는 pwn.college의 단계 이름을 실습 지정에 쓴다.

## 3. 책

연도는 해당 판의 출간 연도다. 오래된 책이 많지만 원리는 바뀌지 않았고, 도구 부분만 걸러 읽는다.

**취약점 분석 일반**
- Mark Dowd, John McDonald, Justin Schuh, *The Art of Software Security Assessment* (Addison-Wesley, 2006) · 코드 감사의 교과서. 1,200쪽. C 코드 리뷰 방법론은 지금도 이 책이 기준이다
- Tobias Klein, *A Bug Hunter's Diary* (No Starch, 2011) · 실제 취약점 7건의 발견 일지. 짧고 구체적

**웹**
- Dafydd Stuttard, Marcus Pinto, *The Web Application Hacker's Handbook* 2판 (Wiley, 2011) · 방법론 부분은 여전히 유효. 저자들이 만든 것이 Burp Suite와 Web Security Academy
- Michal Zalewski, *The Tangled Web* (No Starch, 2011) · 브라우저 보안 모델(SOP, 쿠키, 인코딩)을 가장 정확히 설명한 책
- Peter Yaworski, *Real-World Bug Hunting* (No Starch, 2019) · 공개된 버그바운티 보고서로 배우는 유형별 사례
- Vickie Li, *Bug Bounty Bootcamp* (No Starch, 2021) · 정찰부터 보고서까지 버그바운티 입문

**바이너리**
- Jon Erickson, *Hacking: The Art of Exploitation* 2판 (No Starch, 2008) · C와 어셈블리부터 스택 오버플로까지. 4부 1~2장의 전제
- Chris Anley, John Heasman, Felix Lindner, Gerardo Richarte, *The Shellcoder's Handbook* 2판 (Wiley, 2007) · 플랫폼별 익스플로잇 기법의 고전
- Dennis Andriesse, *Practical Binary Analysis* (No Starch, 2018) · ELF 구조, 디스어셈블리, 동적 오염 분석, 계측. 4부의 도구 배경
- Chris Eagle, Kara Nance, *The Ghidra Book* (No Starch, 2020) · Ghidra 공식에 가까운 해설서
- James Forshaw, *Attacking Network Protocols* (No Starch, 2018) · 프로토콜 분석과 퍼징. 저자는 Project Zero 연구원

**설계·조직**
- Ross Anderson, *Security Engineering* 3판 (Wiley, 2020) · 신뢰 경계와 시스템 설계. [저자가 무료 공개](https://www.cl.cam.ac.uk/~rja14/book.html)
- Betsy Beyer 외, *Site Reliability Engineering* (O'Reilly, 2016) · 15장 사후 분석 문화. [무료 공개](https://sre.google/sre-book/table-of-contents/)

## 4. 블로그·뉴스레터·컨퍼런스

**읽을 곳**

| 자료 | 특징 |
|---|---|
| [Google Project Zero](https://googleprojectzero.blogspot.com/) | 0-day 분석의 기준. [RCA 모음](https://googleprojectzero.github.io/0days-in-the-wild/)은 변형 분석 교재 |
| [PortSwigger Research](https://portswigger.net/research) | 웹 공격 기법의 새 연구. 매년 "Top 10 Web Hacking Techniques" 선정 |
| [Phrack](https://phrack.org/) | 1985년부터의 해커 저널. 힙·커널 기법의 원전 다수 |
| [tl;dr sec](https://tldrsec.com/) | Clint Gibler의 주간 뉴스레터. 도구·논문·발표 요약 |
| [Risky Business](https://risky.biz/) | 보안 뉴스 팟캐스트·뉴스레터. 업계 맥락 |
| [LWN.net](https://lwn.net/) | 리눅스 커널 변경 추적. 커널 취약점 배경 |

**컨퍼런스**

| 행사 | 성격 |
|---|---|
| Black Hat USA / DEF CON | 매년 8월 라스베이거스. 발표 자료가 공개된다 |
| USENIX Security, IEEE S&P, ACM CCS, NDSS | 학술 4대 보안 학회. 논문은 무료 공개 |
| OffensiveCon, REcon, Hexacon | 익스플로잇·리버싱 전문 |
| Pwn2Own | 실제 제품 대상 익스플로잇 대회. 결과가 CVE로 이어진다 |
| [CODEGATE](https://www.codegate.org/) | 한국 국제 해킹방어대회·컨퍼런스. 과기정통부 주최 |
| [POC (Power of Community)](https://powerofcommunity.net/) | 2006년부터 서울에서 열리는 국제 보안 컨퍼런스. 매년 11월 |

## 5. 한국어 자료

| 자료 | 무엇 |
|---|---|
| [KISA 보호나라&KrCERT/CC](https://www.boho.or.kr/) | 보안 공지, 침해사고 신고, 경보 단계. 센터 공지가 올라가는 곳 |
| [사이버 보안 취약점 정보 포털 (KNVD)](https://knvd.krcert.or.kr/) | 국내 취약점 정보·보안 공지·신고포상제 접수. [1편 7장](../vol1-center/02-programs/07-portal-advisory.md) |
| [KISA 홈페이지](https://www.kisa.or.kr/) | 제도·보도자료·가이드라인 |
| [Dreamhack](https://dreamhack.io/) | 한국어 강의·워게임·CTF. 2절 참조 |
| [pwnable.kr](https://pwnable.kr/) | 한국에서 만든 바이너리 워게임 |
| CODEGATE · POC | 4절 참조. 발표 자료 일부 한국어 |
| [보안뉴스](https://www.boannews.com/) · [데일리시큐](https://www.dailysecu.com/) | 국내 보안 업계 뉴스. 센터 관련 보도 추적 |

이 책 자체의 출처 목록은 [부록 E](e-sources.md)에 있다.

## 체크리스트

- [ ] 보고서에 CWE·CVE·CVSS를 적을 때 각각 어디서 확인하는지 아는가?
- [ ] 자기 분야(웹/바이너리)의 연습 플랫폼 하나에 계정이 있고 이번 달에 한 문제 이상 풀었는가?
- [ ] 뉴스레터 하나를 구독하고 있는가?
- [ ] 국내 취약점 공지가 어디에 올라오는지 아는가?

## 더 읽기

- [부록 E. 출처](e-sources.md) · 이 책이 인용한 자료
- [부록 B. 치트시트](b-cheatsheets.md) · 도구 명령 요약
- [3편 2부 16장 공통 역량과 학습 자료](../vol3-practice/02-onboarding/16-skills.md) · 직급별 학습 경로

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 본문 작성. 표준·플랫폼·책·블로그·컨퍼런스·한국어 자료 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증 완료, 수정 없음 (책 제목·저자·판·출판사·연도 검토) | 검증팀 |
