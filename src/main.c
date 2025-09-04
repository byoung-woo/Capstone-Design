// main.c
// 임베디드 HTTPS 웹서버의 메인 파일.
// 서버 초기화, 클라이언트 연결 수락 및 요청 처리를 담당합니다.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

// 프로젝트의 모든 헤더 파일 포함
#include "webserver.h"
#include "ssl_handler.h"
#include "router.h"
#include "response_builder.h"
#include "logger.h"
#include "db_manager.h"

// HTTP 요청을 파싱하는 함수 (새로 추가)
void parse_http_request(const char* buffer, HttpRequest* request) {
    char* buffer_copy = strdup(buffer);
    char* request_line = strtok(buffer_copy, "\r\n");
    
    if (request_line) {
        // 요청 라인 파싱: METHOD PATH VERSION
        char* method = strtok(request_line, " ");
        char* path = strtok(NULL, " ");
        char* version = strtok(NULL, " ");

        if (method && path && version) {
            request->method = strdup(method);
            request->path = strdup(path);
            request->version = strdup(version);
        }
    }
    
    // POST 요청의 경우, 본문(body)을 파싱
    char* body_start = strstr(buffer, "\r\n\r\n");
    if (body_start) {
        body_start += 4; // 헤더와 본문을 구분하는 빈 줄 다음으로 이동
        request->body = strdup(body_start);
    } else {
        request->body = NULL;
    }

    // headers는 이 예제에서는 파싱하지 않음
    request->headers = NULL;

    free(buffer_copy);
}

// 스레드에서 클라이언트 요청을 처리하는 함수
// 모든 클라이언트 연결은 이 함수를 통해 별도의 스레드에서 처리됩니다.
void* handle_client(void* arg) {
    int client_socket = *((int*)arg);
    free(arg); // 힙 메모리 해제

    // SSL/TLS 핸들러를 사용하여 보안 연결 수립
    SSL_CTX* ssl_ctx = get_ssl_context();
    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_socket);

    // SSL 연결 수락 및 핸드셰이크
    if (SSL_accept(ssl) <= 0) {
        // 오류 발생 시 오류 로그 기록 및 연결 종료
        log_error("SSL handshake failed");
        SSL_free(ssl);
        close(client_socket);
        return NULL;
    }

    char buffer[BUFFER_SIZE];
    int bytes_read;

    // 클라이언트의 HTTP 요청 읽기 (HTTPS 보안 통신)
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0'; // 문자열 끝 표시

        // 요청 로그 기록 (AI 학습을 위한 핵심 부분)
        log_request(client_socket, buffer, bytes_read);

        // HTTP 요청 파싱
        HttpRequest request;
        memset(&request, 0, sizeof(request)); // 구조체 초기화
        parse_http_request(buffer, &request);
        
        // 요청에 맞는 응답 생성 및 전송
        HttpResponse response;
        memset(&response, 0, sizeof(response)); // 구조체 초기화
        
        // 라우팅 함수를 호출하여 GET/POST 요청을 분기 처리
        handle_request_routing(&request, &response);
        
        // 응답 전송 (HTTPS 보안 통신)
        SSL_write(ssl, response.content, strlen(response.content));
        
        // 메모리 해제
        free_http_request(&request);
        free_http_response(&response);
    }

    // SSL 연결 종료 및 소켓 닫기
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);

    return NULL;
}

// 메인 함수: 웹서버 초기화 및 실행
int main() {
    int server_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_size;
    
    // SSL/TLS 컨텍스트 초기화
    init_ssl();
    
    // 로거 모듈 초기화
    init_logger();

    init_database();

    // TCP 소켓 생성
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        log_error("Socket creation failed");
        return 1;
    }
    
    // 주소 재사용 설정 (서버 재시작 시 포트 충돌 방지)
    int option = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    // 서버 주소 구조체 초기화
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // 모든 IP 주소에서 접속 허용
    server_addr.sin_port = htons(SERVER_PORT); // 443 포트 사용 (HTTPS 기본)

    // 소켓에 주소 바인딩
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        log_error("Bind failed");
        close(server_socket);
        return 1;
    }

    // 클라이언트 연결 대기 (최대 5개 동시 대기)
    if (listen(server_socket, 5) == -1) {
        log_error("Listen failed");
        close(server_socket);
        return 1;
    }

    printf("HTTPS Web Server is running on port %d...\n", SERVER_PORT);

    // 무한 루프: 클라이언트 연결 수락
    while (1) {
        client_addr_size = sizeof(client_addr);
        int* client_socket_ptr = malloc(sizeof(int));
        *client_socket_ptr = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_size);

        if (*client_socket_ptr == -1) {
            log_error("Accept failed");
            free(client_socket_ptr);
            continue;
        }

        // 새로운 클라이언트 연결을 스레드로 분리하여 처리
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, (void*)client_socket_ptr) != 0) {
            log_error("Thread creation failed");
            close(*client_socket_ptr);
            free(client_socket_ptr);
        }
        pthread_detach(thread_id); // 스레드가 종료되면 자동으로 자원 해제
    }

    // 서버 종료
    close(server_socket);
    cleanup_ssl();
    return 0;
}
