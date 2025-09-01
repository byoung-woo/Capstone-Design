// webserver.h
// 프로젝트 전반에서 사용되는 공통 정의들을 포함하는 헤더 파일입니다.
// 상수, 매크로, 구조체 선언 등이 포함됩니다.

#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <stdlib.h> // size_t 사용을 위해 포함
#include <openssl/ssl.h> // SSL_CTX 사용을 위해 추가

// --- 상수 및 매크로 ---
#define SERVER_PORT 443
#define BUFFER_SIZE 4096
#define LOG_FILE "webserver.log"
#define CERT_FILE "certs/server.crt"
#define KEY_FILE "certs/server.key"

// --- HTTP 요청 및 응답 구조체 ---
// HttpRequest: 클라이언트의 HTTP 요청을 담는 구조체
typedef struct {
    char* method;
    char* path;
    char* version;
    char* body;
    char* headers;
} HttpRequest;

// HttpResponse: 서버의 HTTP 응답을 담는 구조체
typedef struct {
    char* header;
    char* content;
} HttpResponse;


// --- 함수 선언 (프로토타입) ---
// 다른 모듈의 함수를 여기서 선언하여 외부에서 접근 가능하게 합니다.
// logger.c 함수
void init_logger();
void log_error(const char* message);
void log_request(int client_socket, const char* request_buffer, int bytes_read);
void cleanup_logger();

// ssl_handler.c 함수
void init_ssl();
SSL_CTX* get_ssl_context();
void cleanup_ssl();

// router.c 함수
void get_file_path(const char* url_path, char* file_path, int file_path_size);

// response_builder.c 함수
void build_response(HttpRequest* request, HttpResponse* response);
void free_http_request(HttpRequest* request);
void free_http_response(HttpResponse* response);

#endif