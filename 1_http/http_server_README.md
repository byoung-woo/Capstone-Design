# 🌐 HTTP/1.1 Web Server (Pure C Implementation)

## 📌 프로젝트 개요
이 모듈은 외부 라이브러리나 프레임워크의 도움 없이, C언어 표준 라이브러리와 POSIX 소켓 API만을 사용하여 구현한 경량 웹 서버입니다.  
임베디드 시스템 엔지니어가 갖춰야 할 네트워크 프로토콜의 로우 레벨 이해와 시스템 콜 제어 능력을 배양하기 위해 바닥부터(Scratch) 설계되었습니다.

---

## 🛠️ 기술적 특징 (Embedded & System Programming Focus)

### 1️⃣ Zero Dependency (무의존성)
libevent, nginx 등 무거운 외부 라이브러리를 사용하지 않고, 오직 리눅스 커널이 제공하는 System Call(socket, bind, listen, accept, read, write)만으로 통신을 구현했습니다.  
제한된 메모리 환경의 임베디드 보드에서도 이식 가능하도록 최소한의 리소스만 사용합니다.

### 2️⃣ HTTP/1.1 프로토콜 직접 파싱
HTTP 요청 헤더와 바디를 문자열 조작 함수(sscanf, strtok 등)를 통해 직접 파싱합니다.

**구현된 메서드**
- GET: 정적 파일 조회, 동적 데이터(시간) 조회, 쿼리 스트링 파싱  
- PUT: 클라이언트로부터 파일 업로드 처리 (/upload/ 경로)

### 3️⃣ 정적 및 동적 콘텐츠 처리
- **Static File Serving**: 파일 시스템에 직접 접근(fopen, fread)하여 HTML 파일을 버퍼로 읽어 전송합니다.  
- **Dynamic Response**
  - Server Time: 현재 서버 시간을 계산하여 HTML에 동적으로 삽입합니다.  
  - Query Parameter: URL 쿼리 스트링(?name=...)을 파싱하여 사용자 입력을 반영한 응답을 생성합니다.

---

## 🏗️ 아키텍처 및 파일 구조
이 서버는 단일 스레드(Single-Threaded) 반복 서버 구조입니다.  
한 번에 하나의 요청을 처리하며, 이는 멀티스레딩(3번 단계)으로 가기 전의 기준점(Baseline) 역할을 합니다.

```plaintext
1_http/
├── server.c           # 메인 엔트리 포인트: 소켓 생성 및 클라이언트 연결 대기 루프
├── path_response.c    # 라우터: URL 경로 및 HTTP 메서드에 따른 분기 처리
├── static_file.c      # 파일 I/O: index.html 등 정적 파일 읽기 및 전송
├── header_time.c      # 동적 기능: 현재 시간 생성 및 응답
├── form_input.c       # 동적 기능: GET 쿼리 스트링 파싱
├── fixed_response.c   # 단순 응답: 하드코딩된 HTML 응답 전송
├── logger.c           # 로깅: 표준 출력(stdout)으로 요청 로그 출력
├── client.c           # 테스트용: 단순 TCP/HTTP 클라이언트
└── Makefile           # 빌드 스크립트
```

---

## ⚙️ 빌드 및 실행 방법

### 1️⃣ 컴파일
```bash
make
```

### 2️⃣ 서버 실행
서버는 기본적으로 8080 포트에서 동작합니다.
```bash
./webserver
```

### 3️⃣ 기능 테스트
웹 브라우저 또는 curl을 사용하여 테스트할 수 있습니다.

- 메인 페이지: [http://localhost:8080/](http://localhost:8080/)
- 현재 시간 확인: [http://localhost:8080/time](http://localhost:8080/time)
- 쿼리 파싱: [http://localhost:8080/greet?name=Professor&lang=C](http://localhost:8080/greet?name=Professor&lang=C)

**파일 업로드 (PUT):**
```bash
curl -X PUT -d "Hello Embedded" http://localhost:8080/upload/test.txt
```

---

## 📝 학습 포인트 (Learning Objectives)
- **Buffer Management**: 네트워크 패킷 수신을 위한 정적 버퍼(BUFFER_SIZE) 관리 및 오버플로우 방지.  
- **String Manipulation**: C언어에서의 Raw String 처리를 통한 HTTP 헤더 파싱 로직 이해.  
- **File Descriptor**: 소켓과 파일 시스템을 File Descriptor로 다루는 리눅스 VFS(Virtual File System) 개념 실습.  
- **Blocking I/O**: accept()와 read() 함수에서의 블로킹 동작 이해 (향후 멀티스레딩의 필요성 체감).
