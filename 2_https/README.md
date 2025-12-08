# 🔒 HTTPS/TLS Web Server (OpenSSL Integrated)

## 📌 프로젝트 개요
이 모듈은 1_http의 평문 통신 서버에 OpenSSL 라이브러리를 이식하여, 산업 표준 보안 프로토콜인 TLS(Transport Layer Security) 1.2/1.3을 지원하도록 업그레이드한 버전입니다.  
IoT 및 임베디드 장비에서 필수적인 **데이터 기밀성(Confidentiality)**과 **무결성(Integrity)**을 보장하기 위해, 단순한 라이브러리 호출을 넘어 Cipher Suite 최적화와 보안 정책 강화를 직접 구현했습니다.

---

## 🛠️ 기술적 특징 (Security & Optimization)

### 1️⃣ TLS 1.2+ 강제 및 보안 정책 강화
- **Protocol Versioning**: 다운그레이드 공격 방지를 위해 `SSL_CTX_set_min_proto_version`을 사용하여 TLS 1.2 미만의 취약한 프로토콜(SSLv3, TLS 1.0/1.1)을 원천 차단했습니다.  
- **Cipher Suite Filtering**:  
  - `!aNULL:!eNULL:!MD5:!RC4` 설정을 통해 취약한 암호화 알고리즘을 비활성화했습니다.  
  - 임베디드 장비의 성능을 고려하여 **AES-GCM** 및 **ChaCha20-Poly1305**를 우선순위로 설정했습니다.

### 2️⃣ PFS (Perfect Forward Secrecy) 보장
- **ECDHE Key Exchange**: 고정된 RSA 키 교환 대신, ECDHE(Elliptic Curve Diffie-Hellman Ephemeral) 방식을 강제하여, 향후 개인키가 유출되더라도 과거의 통신 내용을 복호화할 수 없도록 설계했습니다.  
- 사용 곡선: `P-256`, `X25519`.

### 3️⃣ OpenSSL API의 구조적 통합
기존 소켓 코드(`read`/`write`)를 OpenSSL BIO 인터페이스(`SSL_read`/`SSL_write`)로 래핑(Wrapping)하여,  
기존 비즈니스 로직의 변경을 최소화하면서 보안 계층을 추가했습니다.

---

## 🏗️ 아키텍처 및 파일 구조
이 단계에서는 보안 컨텍스트(SSL Context) 초기화와 핸드셰이크(Handshake) 과정이 추가되었습니다.

```plaintext
2_https/
├── server.c         # 메인 서버: TCP 연결 수락 후 SSL 핸드셰이크 수행
├── ssl_init.c       # 보안 모듈: OpenSSL 초기화, Cipher Suite 설정, 인증서 로드
├── ssl_init.h       # 보안 모듈 헤더
├── path_response.c  # 라우터: SSL 포인터를 통해 암호화된 응답 전송
├── logger.c         # 로깅: 요청 로그 기록
├── client.c         # 클라이언트: HTTPS 연결 테스트용 클라이언트 (OpenSSL 사용)
└── Makefile         # 빌드 스크립트 (OpenSSL 링크 포함)
```

---

## ⚙️ 빌드 및 실행 방법

### 1️⃣ 사전 준비 (OpenSSL 설치)
임베디드 보드(또는 리눅스)에 OpenSSL 개발 라이브러리가 필요합니다.
```bash
sudo apt-get install libssl-dev
```

---

### 2️⃣ SSL 인증서 생성 (Self-Signed)
서버 실행을 위해 개인키(`server.key`)와 인증서(`server.crt`)가 필요합니다.

**ECDSA 기반 인증서 생성 (SHA256, prime256v1 curve)**
```bash
openssl req -x509 -nodes -days 365 -newkey ec:<(openssl ecparam -name prime256v1)   -keyout server.key -out server.crt -subj "/CN=localhost"
```

---

### 3️⃣ 컴파일 및 실행
```bash
make
./server
```
서버는 기본적으로 **8443 포트**에서 실행됩니다.  
접속 주소: [https://localhost:8443](https://localhost:8443)

---

### 4️⃣ 클라이언트 테스트
웹 브라우저로 접속하거나, 포함된 클라이언트 프로그램을 사용하여 테스트할 수 있습니다.
```bash
# 클라이언트 빌드 및 실행
make client
./client 127.0.0.1 8443
```

---

## 📝 학습 포인트 (Learning Objectives)
- **SSL/TLS Handshake**: Client Hello부터 Finished까지의 핸드셰이크 과정을 코드로 제어하며 이해.  
- **Context Management**: `SSL_CTX` 구조체를 통한 전역 보안 설정과 세션별 `SSL` 구조체 관리 방법 습득.  
- **Crypto Offloading Consideration**: 임베디드 CPU 부하를 줄이기 위해 ChaCha20과 같은 경량 암호화 알고리즘을 선택하는 엔지니어링적 의사결정.  
- **Certificate Chain**: PKI(Public Key Infrastructure) 기반의 인증서 로드 및 검증 과정 실습.
