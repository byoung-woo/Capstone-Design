# Capstone Design Project

## 📌 프로젝트 개요
본 프로젝트는 **임베디드 환경에서 동작하는 경량 웹 서버**를 구현하고,  
**HTTP → HTTPS**로의 확장 및 **Raspberry Pi 배포**까지 실습하는 것을 목표로 한다.  

- **1차 목표:** HTTP 프로토콜 기반 서버 구현  
- **2차 목표:** OpenSSL을 활용한 HTTPS(TLS) 기반 보안 서버 구현  
- **3차 목표:** Raspberry Pi 환경에서 서버 실행 및 최적화  

---

## 🛠 주요 기능
- 클라이언트 요청(HTTP/HTTPS) 처리
- 정적 파일(HTML, CSS 등) 응답
- 폼 입력(GET/POST) 처리
- 로깅 기능 (클라이언트 IP, 요청 경로, 응답 상태 등 기록)
- TLS 1.3 기반 보안 통신(HTTPS)
- 라즈베리파이 배포 및 실습 환경 구축

---

## 📂 프로젝트 구조
```
Capstone-Design/
│
├── 1_http/           # HTTP 서버 구현
│   ├── main.c
│   ├── server.c
│   ├── Makefile
│   └── static/       # 정적 HTML/CSS 파일
│
├── 2_https/          # HTTPS 서버 구현 (OpenSSL 기반)
│   ├── main.c
│   ├── server.c
│   ├── certs/        # server.crt, server.key
│   └── Makefile
│
├── 3_raspberry/      # Raspberry Pi 환경 실행 스크립트 및 설정
│   ├── setup.sh
│   └── service/      # systemd 서비스 파일
│
└── README.md
```

---

## 🚀 실행 방법

### 1. HTTP 서버 실행
```bash
cd 1_http
make
./server
```
웹 브라우저에서 `http://localhost:8080` 접속

### 2. HTTPS 서버 실행
```bash
cd 2_https
make
./server
```
웹 브라우저에서 `https://localhost:8443` 접속  
(자체 서명 인증서 사용 시 브라우저 경고 확인 필요)

### 3. Raspberry Pi 배포
```bash
cd 3_raspberry
bash setup.sh
```
systemd 서비스 등록 후 자동 실행 가능

---

## 🔒 보안 고려사항
- OpenSSL을 활용한 TLS 1.3 지원
- 안전한 암호화 알고리즘 및 키 길이 설정
- 로그 및 민감정보 보호
- HTTPS 기본 적용 및 HTTP → HTTPS 리다이렉션 계획

---

## 📈 향후 개선 계획
- 관리자 페이지 구현 (로그 확인, 서버 상태 모니터링)
- JSON 기반 API 응답 지원
- 비정상 트래픽 탐지(IDS) 기능 확장
- 클라우드 환경(AWS, Azure) 배포 테스트

---

## 👥 팀 구성 및 역할
- **네트워크/서버 담당**: HTTP/HTTPS 서버 구현
- **보안 담당**: TLS 적용, 인증서 관리
- **임베디드 담당**: Raspberry Pi 환경 구축 및 최적화

---

## 📚 참고 자료
- [RFC 2616 - HTTP/1.1](https://www.rfc-editor.org/rfc/rfc2616)
- [RFC 8446 - TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [OpenSSL Documentation](https://www.openssl.org/docs/)

---
