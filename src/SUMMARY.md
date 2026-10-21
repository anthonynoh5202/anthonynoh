# 목차

[이 책에 대하여](introduction.md)
[이 책을 읽는 법](how-to-read.md)

# 1부. 기초

- [취약점이란 무엇인가](part1-foundations/01-what-is-vulnerability.md)
- [CWE · CVE · CVSS 체계](part1-foundations/02-cwe-cve-cvss.md)
- [공격 표면과 신뢰 경계](part1-foundations/03-attack-surface.md)
- [윤리와 법적 범위](part1-foundations/04-ethics-and-law.md)
- [실습 환경 구축](part1-foundations/05-lab-setup.md)

# 2부. 방법론

- [분석 방법론 개요](part2-methodology/01-overview.md)
- [정보 수집](part2-methodology/02-recon.md)
- [위협 모델링](part2-methodology/03-threat-modeling.md)
- [정적 분석](part2-methodology/04-static-analysis.md)
- [동적 분석](part2-methodology/05-dynamic-analysis.md)
- [익스플로잇 검증](part2-methodology/06-exploit-verification.md)
- [보고와 커뮤니케이션](part2-methodology/07-reporting.md)

# 3부. 웹 취약점

- [웹 취약점 개요](part3-web/00-overview.md)
- [SQL 인젝션](part3-web/01-sql-injection.md)
- [크로스 사이트 스크립팅 (XSS)](part3-web/02-xss.md)
- [서버 측 요청 위조 (SSRF)](part3-web/03-ssrf.md)
- [인증과 세션 관리](part3-web/04-auth-session.md)
- [접근 제어 (IDOR · 권한 상승)](part3-web/05-access-control.md)
- [파일 업로드와 경로 조작](part3-web/06-file-upload-path-traversal.md)
- [안전하지 않은 역직렬화](part3-web/07-deserialization.md)
- [XML 외부 개체 (XXE)](part3-web/08-xxe.md)
- [서버 측 템플릿 인젝션 (SSTI)](part3-web/09-ssti.md)
- [경쟁 조건과 로직 취약점](part3-web/10-race-condition.md)

# 4부. 바이너리 취약점

- [바이너리 취약점 개요](part4-binary/00-overview.md)
- [메모리 구조와 호출 규약](part4-binary/01-memory-basics.md)
- [스택 버퍼 오버플로](part4-binary/02-stack-overflow.md)
- [포맷 스트링](part4-binary/03-format-string.md)
- [힙 취약점](part4-binary/04-heap.md)
- [Use-After-Free와 수명 오류](part4-binary/05-uaf.md)
- [정수 오버플로와 타입 변환](part4-binary/06-integer-overflow.md)
- [완화 기법과 우회](part4-binary/07-mitigations.md)
- [ROP와 코드 재사용](part4-binary/08-rop.md)
- [퍼징으로 취약점 찾기](part4-binary/09-fuzzing.md)

# 5부. 확장 영역

- [모바일 (Android · iOS)](part5-extended/01-mobile.md)
- [클라우드와 컨테이너](part5-extended/02-cloud.md)
- [IoT와 펌웨어](part5-extended/03-iot-firmware.md)
- [공급망 취약점](part5-extended/04-supply-chain.md)
- [AI/LLM 애플리케이션](part5-extended/05-ai-llm.md)

# 6부. 도구

- [언제 무엇을 쓰는가](part6-tools/00-when-to-use-what.md)
- [Burp Suite와 웹 프록시](part6-tools/01-burp-proxy.md)
- [Ghidra와 IDA: 디스어셈블러·디컴파일러](part6-tools/02-ghidra-ida.md)
- [디버거: gdb · pwndbg · WinDbg · Frida](part6-tools/03-debuggers.md)
- [퍼저: AFL++ · libFuzzer · boofuzz](part6-tools/04-fuzzers.md)
- [정적 분석기: Semgrep · CodeQL](part6-tools/05-sast-semgrep-codeql.md)

# 7부. 실전 워크스루

- [워크스루 읽는 법](part7-walkthroughs/00-overview.md)
- [CVE-2021-44228 Log4Shell: JNDI 조회를 통한 RCE](part7-walkthroughs/01-cve-2021-44228-log4shell.md)
- [CVE-2014-0160 Heartbleed: 경계 검사 누락으로 메모리 누출](part7-walkthroughs/02-cve-2014-0160-heartbleed.md)
- [CVE-2017-5638 Apache Struts: OGNL 인젝션](part7-walkthroughs/03-cve-2017-5638-struts.md)
- [CVE-2021-3156 sudo Baron Samedit: 힙 오버플로로 로컬 권한 상승](part7-walkthroughs/04-cve-2021-3156-sudo-baron-samedit.md)
- [CVE-2024-3094 xz 백도어: 공급망 공격](part7-walkthroughs/05-cve-2024-3094-xz-backdoor.md)

# 8부. 보고서와 커뮤니케이션

- [보고서 구조](part8-reporting/01-report-structure.md)
- [영향도 산정](part8-reporting/02-severity.md)
- [패치 검증과 재발 방지](part8-reporting/03-patch-verification.md)

# 부록

- [부록 A. 치트시트](appendix/a-cheatsheets.md)
- [부록 B. 용어집](appendix/b-glossary.md)
- [부록 C. 참고 자료](appendix/c-resources.md)
- [부록 D. 이 책에 기여하기](appendix/d-contributing.md)

---

[변경 이력](changelog.md)
