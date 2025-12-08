Markdown

# 🛡️ AI & WAF 기반 임베디드 보안 웹 서버 (Capstone Design)

## 📌 프로젝트 개요
본 프로젝트는 라즈베리파이와 같은 임베디드 환경에서 동작하는 **경량화된 고성능 보안 웹 서버**입니다.  
기본적인 웹 서비스 기능뿐만 아니라, **OpenSSL 기반의 HTTPS 통신**, **룰 기반의 웹 방화벽(WAF)**, **AI 위협 탐지를 위한 로그 파이프라인**, 그리고 **사용자 인증 시스템**을 C언어로 직접 구현하였습니다.

---

## 🚀 프로젝트 진화 단계 (Directory Structure)

이 저장소는 프로젝트의 개발 단계를 따라 4개의 메인 디렉토리로 구성되어 있습니다.

* **`1_http/`**: 기본적인 HTTP/1.1 프로토콜을 구현한 단일 스레드 기반 웹 서버
* **`2_https/`**: OpenSSL 라이브러리를 적용하여 TLS 1.2/1.3 암호화 통신을 지원하는 HTTPS 서버
* **`3_raspberry/`**: 라즈베리파이 환경에 맞춰 멀티스레딩(`pthread`)과 JSON 로깅을 적용한 최적화 버전
* **`4_waf_ai_server/` (🔥 Final Version)**: WAF, DB 연동, AI 로그 전송, Slack 알림 등 모든 기능이 통합된 최종 결과물

---

## 🛠️ 주요 기능 및 기술 스택 (Final Version 기준)

### 1. 보안 통신 (HTTPS)
* **OpenSSL 기반 TLS 적용**: TLS 1.2 이상을 강제하고, ECDHE(Elliptic Curve Diffie-Hellman) 키 교환을 사용하여 PFS(Perfect Forward Secrecy)를 보장합니다.
* **Cipher Suite 최적화**: 보안성이 높은 암호화 제품군(AES-GCM, CHACHA20)을 우선적으로 사용하도록 설정되었습니다.

### 2. 웹 어플리케이션 방화벽 (WAF)
* **룰 기반 탐지 (`rule_checker.c`)**: `rules.json` 파일에 정의된 패턴(SQL Injection, XSS, Path Traversal 등)을 요청에서 실시간으로 검사합니다.
* **IP 차단 관리 (`ip_manager.c`)**:
    * **Whitelist/Blacklist**: 파일 기반의 정적 IP 관리.
    * **Dynamic Graylist**: 짧은 시간 내 과도한 요청이나 공격 탐지 시 해당 IP를 동적으로 일시 차단(Rate Limiting & Ban)합니다.
    * **Background Monitoring**: 별도 스레드가 차단 리스트 파일 변경을 실시간 감지하여 리로드합니다.

### 3. 지능형 로그 분석 파이프라인
* **JSON 구조화 로깅**: 모든 요청 정보를 cJSON을 사용하여 구조화된 포맷으로 기록합니다.
* **AI 서버 연동 (`logger.c`)**: 수집된 로그를 별도의 스레드를 통해 AI 분석 서버(`172.20.10.2:5140`)로 비동기 SSL 전송합니다.
* **Slack 실시간 알림**: `log-to-slack.sh` 스크립트가 공격 로그를 감지하면 관리자 슬랙으로 즉시 알림을 발송합니다.

### 4. 사용자 인증 및 데이터베이스
* **SQLite3 연동 (`db_manager.c`)**: 경량 데이터베이스를 내장하여 회원 정보를 관리합니다.
* **보안 로그인**: PBKDF2-HMAC-SHA256 알고리즘과 Salt를 사용하여 비밀번호를 안전하게 해싱하여 저장합니다.

### 5. 아키텍처
* **Multi-Threading**: `pthread`를 사용하여 클라이언트 요청을 비동기적으로 처리, 동시 접속 성능을 확보했습니다.
* **Modular Design**: 라우터, 로거, DB 매니저, 응답 빌더 등 기능별 모듈화 설계.

---

## ⚙️ 설치 및 실행 방법

### 1. 필수 라이브러리 설치
이 프로젝트는 OpenSSL, SQLite3, cJSON 라이브러리에 의존합니다. (Ubuntu/Debian 기준)


sudo apt-get update
sudo apt-get install gcc make libssl-dev libsqlite3-dev libcjson-dev jq
2. 빌드 및 실행 (최종 버전)
4_waf_ai_server 디렉토리로 이동하여 빌드합니다.

Bash

cd 4_waf_ai_server
make clean
make
./webserver
3. Slack 알림 설정 (선택)
Slack 알림을 받으려면 config.sh 파일을 생성하고 Webhook URL을 설정해야 합니다 (보안상 gitignore 처리됨).

Bash

# 4_waf_ai_server/config.sh 생성
echo 'export WEBHOOK_URL="[https://hooks.slack.com/services/YOUR/WEBHOOK/URL](https://hooks.slack.com/services/YOUR/WEBHOOK/URL)"' > config.sh
chmod +x log-to-slack.sh
./log-to-slack.sh &  # 백그라운드 실행
📁 파일 구조 (4_waf_ai_server/)
4_waf_ai_server/
├── include/            # 헤더 파일 (.h)
├── src/                # 소스 코드 (.c)
│   ├── main.c          # 서버 진입점 및 스레드 풀 관리
│   ├── server.c        # 소켓 통신 및 SSL 핸들링
│   ├── router.c        # URL 라우팅 및 요청 분기
│   ├── rule_checker.c  # WAF 룰 매칭 엔진
│   ├── ip_manager.c    # IP 차단/허용 정책 관리
│   ├── db_manager.c    # SQLite3 DB 핸들러
│   ├── logger.c        # 로깅 및 AI 서버 전송
│   └── ...
├── web/                # 정적 웹 리소스 (HTML, CSS)
├── templates/          # Slack 알림 템플릿 (JSON)
├── certs/              # SSL 인증서 (server.crt, server.key)
├── rules.json          # WAF 보안 규칙 정의 파일
├── Makefile            # 빌드 스크립트
└── log-to-slack.sh     # Slack 알림 쉘 스크립트
🛡️ 적용된 보안 기술 상세
Transport Layer: TLS 1.3/1.2 강제, 취약한 Cipher Suite 비활성화.

Application Layer:

SQL Injection: ' OR '1'='1', UNION SELECT 등의 패턴 차단.

XSS: <script>, javascript: 등의 스크립트 삽입 시도 차단.

Path Traversal: ../, /etc/passwd 등 시스템 파일 접근 시도 차단.

Data Layer: 비밀번호 저장 시 Salt + PBKDF2(Iter: 100,000) 적용.

👥 팀원 및 역할
Network/Server: HTTP/HTTPS 서버 코어 구현, 멀티스레딩 아키텍처 설계

Security/WAF: WAF(룰/IP매니저) 구현, AI 로그 분석 시스템 연동

Database/Embedded: DB 설계 및 사용자 인증 구현, Raspberry Pi 최적화
