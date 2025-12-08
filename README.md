# 🛡️ AI & WAF 기반 임베디드 보안 웹 서버 (Capstone Design)

## 📌 프로젝트 개요
본 프로젝트는 라즈베리파이와 같은 임베디드 환경에서 동작하는 **경량화된 고성능 보안 웹 서버**입니다.  
기본적인 웹 서비스 기능뿐만 아니라, **OpenSSL 기반의 HTTPS 통신**, **룰 기반 웹 방화벽(WAF)**, **AI 위협 탐지를 위한 로그 파이프라인**, 그리고 **사용자 인증 시스템**을 C 언어로 직접 구현하였습니다.

---

## 🚀 프로젝트 진화 단계 (Directory Structure)

이 저장소는 프로젝트의 개발 단계를 따라 4개의 메인 디렉토리로 구성되어 있습니다.

- **`1_http/`**  
  기본적인 HTTP/1.1 프로토콜을 구현한 단일 스레드 기반 웹 서버

- **`2_https/`**  
  OpenSSL 라이브러리를 적용하여 TLS 1.2/1.3 암호화 통신을 지원하는 HTTPS 서버

- **`3_raspberry/`**  
  라즈베리파이 환경에 맞춰 멀티스레딩(`pthread`)과 JSON 로깅을 적용한 최적화 버전

- **`4_waf_ai_server/` (🔥 Final Version)**  
  WAF, DB 연동, AI 로그 전송, Slack 알림 등 모든 기능이 통합된 최종 결과물

---

## 🛠️ 주요 기능 및 기술 스택 (Final Version 기준)

### 1. 보안 통신 (HTTPS)
- **OpenSSL 기반 TLS 적용**  
  - TLS 1.2 이상 강제
  - ECDHE(Elliptic Curve Diffie-Hellman) 키 교환으로 **PFS(Perfect Forward Secrecy)** 보장
- **Cipher Suite 최적화**  
  - AES-GCM, CHACHA20과 같은 보안성이 높은 암호화를 우선적으로 사용
  - 취약하거나 오래된 Cipher Suite 비활성화

---

### 2. 웹 애플리케이션 방화벽 (WAF)

- **룰 기반 탐지 (`rule_checker.c`)**
  - `rules.json` 파일에 정의된 패턴을 기반으로 실시간 요청 검사
  - 주요 탐지 대상:
    - SQL Injection (예: `' OR '1'='1`, `UNION SELECT` 등)
    - XSS (예: `<script>`, `javascript:` 등)
    - Path Traversal (예: `../`, `/etc/passwd` 접근 시도 등)

- **IP 차단 관리 (`ip_manager.c`)**
  - **Whitelist / Blacklist**  
    - 파일 기반 정적 IP 관리
  - **Dynamic Graylist**
    - 짧은 시간 내 과도한 요청 또는 공격 패턴 탐지 시
    - 해당 IP를 일정 시간 **일시 차단 (Rate Limiting & Ban)**
  - **Background Monitoring**
    - 별도 스레드가 차단 리스트 파일 변경을 감지하여 실시간 리로드

---

### 3. 지능형 로그 분석 파이프라인

- **JSON 구조화 로깅**
  - `cJSON` 라이브러리를 사용하여 모든 요청 정보를 구조화된 JSON 포맷으로 기록
  - 예: 요청 메서드, URL, IP, User-Agent, WAF 탐지 결과 등

- **AI 서버 연동 (`logger.c`)**
  - 별도의 스레드를 통해 AI 분석 서버(`172.20.10.2:5140`)로 로그를 **비동기 SSL 전송**
  - 웹 서버 성능에 영향을 최소화하면서 실시간 위협 분석 수행

- **Slack 실시간 알림**
  - `log-to-slack.sh` 스크립트가 공격 로그를 감지
  - 관리자 Slack 채널로 **실시간 보안 알림** 전송

---

### 4. 사용자 인증 및 데이터베이스

- **SQLite3 연동 (`db_manager.c`)**
  - 경량 데이터베이스(SQLite3)를 내장하여 회원/세션 정보를 관리
  - 웹 서버와 동일 호스트에서 파일 기반으로 운영

- **보안 로그인**
  - 비밀번호 저장 시 **PBKDF2-HMAC-SHA256 + Salt** 적용
  - 반복 횟수(Iteration): **100,000회**
  - 단순 해시(MD5/SHA1 등) 대신, 연산 비용이 높은 KDF를 사용하여 크래킹 난이도 상승

---

### 5. 아키텍처 특징

- **Multi-Threading**
  - `pthread` 기반 멀티스레딩으로 각 클라이언트 요청을 비동기적으로 처리
  - 동시 접속 시에도 안정적인 응답 성능 확보

- **Modular Design**
  - 주요 모듈:
    - `server.c` : 소켓 통신 및 SSL 핸들링
    - `router.c` : URL 라우팅 및 요청 분기
    - `rule_checker.c` : WAF 룰 매칭 엔진
    - `ip_manager.c` : IP 차단/허용 정책 관리
    - `db_manager.c` : SQLite3 기반 데이터 관리
    - `logger.c` : 로깅 및 AI 서버 전송
  - 기능별로 소스를 분리하여 유지보수성과 확장성을 고려한 설계

---

## ⚙️ 설치 및 실행 방법

### 1. 필수 라이브러리 설치

Ubuntu/Debian 기준:

```bash
sudo apt-get update
sudo apt-get install gcc make libssl-dev libsqlite3-dev libcjson-dev jq
```

---

### 2. 빌드 및 실행 (최종 버전: `4_waf_ai_server/`)

```bash
cd 4_waf_ai_server
make clean
make
./webserver
```

---

### 3. Slack 알림 설정 (선택 사항)

Slack 알림을 받으려면 `config.sh` 파일을 생성하고 Webhook URL을 설정해야 합니다.  
(`config.sh`는 보안상 `.gitignore`에 포함하는 것을 권장합니다.)

```bash
# 4_waf_ai_server/config.sh 생성
echo 'export WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"' > config.sh

# 실행 권한 부여 및 백그라운드 실행
chmod +x log-to-slack.sh
./log-to-slack.sh &
```

---

## 📁 파일 구조 (4_waf_ai_server/)

```plaintext
4_waf_ai_server/
├── include/             # 헤더 파일 (.h)
├── src/                 # 소스 코드 (.c)
│   ├── main.c           # 서버 진입점 및 스레드 풀 관리
│   ├── server.c         # 소켓 통신 및 SSL 핸들링
│   ├── router.c         # URL 라우팅 및 요청 분기
│   ├── rule_checker.c   # WAF 룰 매칭 엔진
│   ├── ip_manager.c     # IP 차단/허용 정책 관리
│   ├── db_manager.c     # SQLite3 DB 핸들러
│   ├── logger.c         # 로깅 및 AI 서버 전송
│   └── ...
├── web/                 # 정적 웹 리소스 (HTML, CSS)
├── templates/           # Slack 알림 템플릿 (JSON)
├── certs/               # SSL 인증서 (server.crt, server.key)
├── rules.json           # WAF 보안 규칙 정의 파일
├── Makefile             # 빌드 스크립트
└── log-to-slack.sh      # Slack 알림 쉘 스크립트
```

---

## 🛡️ 적용된 보안 기술 상세

### 1. Transport Layer

- TLS 1.3/1.2 강제 사용
- 취약한 Cipher Suite 비활성화
- ECDHE 기반 키교환으로 Perfect Forward Secrecy 보장

### 2. Application Layer (WAF 룰)

- **SQL Injection 방어**
  - 예시 패턴:  
    - `' OR '1'='1`  
    - `UNION SELECT`  
    - `sleep(`, `benchmark(` 등의 Time-based SQLi 패턴
- **XSS 방어**
  - `<script>`, `</script>`, `javascript:` 스킴, `<img onerror=...>` 등의 스크립트 삽입 차단
- **Path Traversal 방어**
  - `../`, `/etc/passwd`, 시스템 파일 및 상위 디렉터리 접근 시도 탐지 및 차단

### 3. Data Layer (계정/비밀번호 보호)

- 비밀번호 저장 시:
  - Salt + PBKDF2-HMAC-SHA256
  - Iteration: 100,000회
- 평문 비밀번호 저장 금지
- 향후 Argon2 등 고급 KDF로 확장 가능한 구조

---

## 👥 팀원 및 역할

- **Network / Server**
  - HTTP/HTTPS 서버 코어 구현
  - 소켓 통신, SSL 핸드셰이크, 멀티스레딩 아키텍처 설계

- **Security / WAF**
  - 룰 기반 WAF(`rule_checker.c`) 및 IP 매니저(`ip_manager.c`) 구현
  - AI 로그 분석 시스템 및 Slack 알림 연동

- **Database / Embedded**
  - SQLite3 기반 사용자 인증 및 데이터 모델 설계
  - Raspberry Pi 환경 최적화 및 임베디드 튜닝

---

## 📎 기타

- 개발 언어: **C**
- 타깃 플랫폼: **Linux (Ubuntu), Raspberry Pi OS**
- 주요 라이브러리: **OpenSSL, SQLite3, cJSON, pthread, jq**
