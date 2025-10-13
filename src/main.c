// main.c
// 임베디드 HTTPS 웹서버의 메인 파일.
// 서버 초기화, 클라이언트 연결 수락 및 요청 처리를 담당합니다.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>

// 프로젝트의 모든 헤더 파일 포함
#include "webserver.h"
#include "ssl_handler.h"
#include "router.h"
#include "response_builder.h"
#include "logger.h"
#include "db_manager.h"
#include "rule_checker.h"
#include "ip_manager.h"

// --- WAF/인증 기능 관련 헬퍼 함수 ---

// URL 디코딩 헬퍼 함수
static int hex_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

// URL 디코딩 함수: 문자열을 In-place로 디코딩합니다.
void url_decode(char *str) {
    char *p = str;
    char *q = str;
    while (*p) {
        if (*p == '%') {
            if (*(p + 1) && *(p + 2)) {
                *q++ = hex_to_int(*(p + 1)) * 16 + hex_to_int(*(p + 2));
                p += 3;
            } else {
                *q++ = *p++;
            }
        } else if (*p == '+') {
            *q++ = ' ';
            p++;
        } else {
            *q++ = *p++;
        }
    }
    *q = '\0';
}

// 폼 데이터에서 특정 키의 값을 안전하게 추출하고 URL 디코딩까지 수행하는 함수
char* get_form_value(const char* body, const char* key, char* output, size_t output_size) {
    if (!body || !key || !output) return NULL;

    char key_with_equals[128];
    snprintf(key_with_equals, sizeof(key_with_equals), "%s=", key);

    const char* start = strstr(body, key_with_equals);
    if (!start) return NULL;
    
    start += strlen(key_with_equals);
    
    const char* end = strchr(start, '&');
    size_t len;
    if (end) {
        len = end - start;
    } else {
        len = strlen(start);
    }

    if (len >= output_size) {
        len = output_size - 1;
    }

    strncpy(output, start, len);
    output[len] = '\0';

    url_decode(output);

    return output;
}

// HTTP 요청을 파싱하는 함수
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
            url_decode(request->path); 
            request->version = strdup(version);
        }
    }
    
    // POST 요청의 경우, 본문(body)을 파싱
    char* body_start = strstr(buffer, "\r\n\r\n");
    if (body_start) {
        body_start += 4; 
        request->body = strdup(body_start); 
    } else {
        request->body = NULL;
    }

    request->headers = NULL;
    request->keep_alive = 0; // [추가] 기본값 설정

    // Connection 헤더 파싱 (Keep-Alive 확인)
    if (strstr(buffer, "Connection: keep-alive") || strstr(buffer, "Connection: Keep-Alive")) {
        request->keep_alive = 1;
    }

    free(buffer_copy);
}

// --- 클라이언트 요청 처리 함수 ---

void* handle_client(void* arg) {
    int client_socket = *((int*)arg);
    free(arg); 

    // SSL/TLS 핸들러를 사용하여 보안 연결 수립
    SSL_CTX* ssl_ctx = get_ssl_context();
    SSL* ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, client_socket);

    // SSL 연결 수락 및 핸드셰이크
    if (SSL_accept(ssl) <= 0) {
        log_error("SSL handshake failed");
        SSL_free(ssl);
        close(client_socket);
        return NULL;
    }
    // --- 시간 측정 및 카운팅 변수 초기화 ---
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL); // 연결 시작 시간 기록

    HttpRequest request;
    memset(&request, 0, sizeof(request));
    request.flow_start_time_sec = start_time.tv_sec;
    request.flow_start_time_usec = start_time.tv_usec;
    request.fwd_packets = 0;
    request.bwd_packets = 0;
    request.fwd_bytes = 0;
    request.bwd_bytes = 0;


    char buffer[BUFFER_SIZE];
    int bytes_read;
    
    memset(buffer, 0, sizeof(buffer));

    // 클라이언트의 HTTP 요청 읽기 (HTTPS 보안 통신)
    bytes_read = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0'; 

        request.bwd_packets++;
        request.bwd_bytes += bytes_read;

        HttpRequest request;
        memset(&request, 0, sizeof(request)); 
        
        request.client_socket = client_socket;
        request.raw_buffer = buffer;
        request.bytes_read = bytes_read;

        parse_http_request(buffer, &request);
        
        HttpResponse response;
        memset(&response, 0, sizeof(response)); 
        
        // 라우팅 함수를 호출하여 GET/POST 요청을 분기 처리 (로그 기록은 이 내부에서 비동기적으로 처리됨)
        handle_request_routing(&request, &response); 
        
        // 응답 전송
        int bytes_written = SSL_write(ssl, response.content, strlen(response.content));
        
        // --- 송신 정보 업데이트 ---
        if (bytes_written > 0) {
            request.fwd_packets++;
            request.fwd_bytes += bytes_written;
        }

        // --- 최종 연결 시간 계산 및 로그 기록 ---
        gettimeofday(&end_time, NULL);
        request.flow_duration = ((end_time.tv_sec - request.flow_start_time_sec) * 1000000) + (end_time.tv_usec - request.flow_start_time_usec);
        log_request(&request); 

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

// --- 메인 함수 ---

// 메인 함수: 웹서버 초기화 및 실행
int main() {
    int server_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_size;
    
    // SSL/TLS 컨텍스트 초기화
    init_ssl();
    
    // 로거 모듈 초기화 (파일 열기)
    init_logger();

    // [성능 개선] 로그 큐 초기화 및 로그 전송 스레드 시작
    init_log_queue();
    pthread_t log_thread_id;
    if (pthread_create(&log_thread_id, NULL, log_sender_thread, NULL) != 0) {
        log_error("Log sender thread creation failed");
        return 1;
    }
    pthread_detach(log_thread_id); // 서버 종료 시 자동으로 자원 해제

    init_database();

    // [추가] WAF 룰셋 파일 로드
    load_rules_from_file("rules.json");
    init_ip_manager();

        // [추가] IP 리스트 파일 감시 스레드 시작
    pthread_t ip_monitor_thread_id;
    if (pthread_create(&ip_monitor_thread_id, NULL, ip_list_monitor_thread, NULL) != 0) {
        log_error("IP list monitor thread creation failed");
    } else {
        pthread_detach(ip_monitor_thread_id); // 메인 스레드와 분리
        log_error("IP list monitor thread started.");
    }

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
    cleanup_database();
    cleanup_ssl();
    cleanup_rules();
    cleanup_ip_manager();
    return 0;
}