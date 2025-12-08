# 🍓 Embedded Multi-threaded Web Server (Raspberry Pi Optimized)

## 📌 프로젝트 개요
이 모듈은 단일 스레드 기반이었던 이전 버전들의 한계를 극복하고, **라즈베리파이(Raspberry Pi)**와 같은 임베디드 리눅스 환경에서 다중 클라이언트 접속을 효율적으로 처리하기 위해 설계된 멀티스레드 HTTPS 웹 서버입니다.  
`pthread` 라이브러리를 이용한 동시성 프로그래밍(Concurrency Programming)을 적용하여 I/O 블로킹 문제를 해결했으며, 데이터 분석 용이성을 위해 **JSON 포맷의 구조화된 로깅 시스템**을 도입했습니다.

---

## 🛠️ 기술적 특징 (Concurrency & Optimization)

### 1️⃣ 멀티스레딩 (Multi-threading) 아키텍처
- **Thread-per-Request 모델**: `pthread_create`를 사용하여 클라이언트 연결마다 별도의 작업 스레드를 생성합니다.  
- **Non-blocking Accept**: 메인 스레드는 `accept()` 루프를 돌며 연결 수립 즉시 워커 스레드에게 소켓 제어권을 넘겨, 새로운 연결 요청에 즉각 반응할 수 있도록 설계했습니다.  
- **Resource Management**: `pthread_detach`를 사용하여 스레드 종료 시 시스템 자원(메모리, 스택 등)이 자동으로 회수되도록 하여, 장시간 가동 시 **메모리 누수(Memory Leak)**를 방지했습니다.

### 2️⃣ 구조화된 로깅 (Structured Logging via cJSON)
- 단순 텍스트 로그 대신, `cJSON` 라이브러리를 사용하여 요청 정보를 **JSON 포맷**으로 기록합니다.  
- **데이터 필드**: 타임스탬프, 클라이언트 IP, HTTP 메서드, 경로, 응답 바이트 수 등.  
- 이를 통해 추후 **Python 기반 데이터 분석**이나 **ELK 스택 연동**이 용이하도록 확장성을 확보했습니다.

### 3️⃣ 임베디드 최적화 (Embedded Optimization)
- **경량화된 의존성**: 라즈베리파이의 제한된 자원을 고려하여 불필요한 동적 할당을 줄였습니다.  
- **SSL 컨텍스트 재사용**: 전역적으로 관리되는 SSL 컨텍스트를 재사용하여 **핸드셰이크 오버헤드 최소화**.

---

## 🏗️ 아키텍처 및 파일 구조
이 단계에서는 스레드 관리와 JSON 로깅 모듈이 핵심적으로 추가되었습니다.

```plaintext
3_raspberry/
├── main.c              # 메인 서버: 스레드 생성(pthread_create) 및 분리(detach) 관리
├── logger.c            # 로깅 모듈: cJSON을 이용한 로그 포맷팅 및 파일 기록
├── response_builder.c  # 응답 생성: HTTP 헤더 및 바디 구성
├── router.c            # 라우터: URL 경로 파싱 및 정적 파일 매핑
├── ssl_handler.c       # 보안: SSL/TLS 컨텍스트 초기화 및 관리
├── webserver.h         # 헤더: 공통 상수 및 구조체 정의
└── web/                # 웹 리소스: HTML, CSS 파일 등
```

---

## ⚙️ 빌드 및 실행 방법

### 1️⃣ 필수 라이브러리 설치
이 버전부터는 JSON 처리를 위해 `cJSON` 라이브러리가 필요합니다.
```bash
sudo apt-get update
sudo apt-get install libssl-dev libcjson-dev
```

---

### 2️⃣ 컴파일
```bash
make
```
`Makefile`에는 `-pthread`와 `-lcjson` 옵션이 포함되어 있어 스레딩과 JSON 기능이 링크됩니다.

---

### 3️⃣ 서버 실행
```bash
./webserver
```
서버는 **8443 포트**에서 HTTPS로 동작합니다.  
접속 주소: `https://<RaspberryPi_IP>:8443`

---

### 4️⃣ 로그 확인
서버 실행 후 생성되는 `webserver.log` 파일에서 **JSON 형태의 로그**를 확인할 수 있습니다.
```bash
tail -f webserver.log
```

**로그 예시**
```json
{"timestamp":"2023-10-27T10:00:00+0900", "client_ip":"192.168.0.5", "request_method":"GET", "request_path":"/index.html", "bytes":1024}
```

---

## 📝 학습 포인트 (Learning Objectives)
- **Concurrency Control**: `pthread`를 활용하여 여러 요청을 병렬로 처리할 때 발생하는 동기화 이슈와 스레드 생명주기(Lifecycle) 관리 방법 습득.  
- **Resource Detachment**: Joinable 스레드와 Detached 스레드의 차이를 이해하고, 서버 데몬(Daemon) 구현에 적합한 Detached 모드 활용.  
- **Structured Data**: 비정형 텍스트 로그의 한계를 이해하고, 기계가 읽기 쉬운(Machine-Readable) JSON 포맷을 C언어 환경에서 생성하는 방법 실습.  
- **Cross-Compilation (Optional)**: x86 개발 환경에서 ARM 기반 라즈베리파이용으로 바이너리를 빌드하는 **크로스 컴파일** 개념 이해.
