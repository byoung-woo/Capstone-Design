// webserver.h
#ifndef WEBSERVER_H
#define WEBSERVER_H

#include <stdlib.h>
#include <openssl/ssl.h>

// --- 상수 및 매크로 ---
#define SERVER_PORT 8443
#define BUFFER_SIZE 4096
// 로그 파일을 두 종류로 분리
#define ACCESS_LOG_FILE "webserver_access.log"
#define ATTACK_LOG_FILE "webserver_attack.log"
#define DB_FILE "webserver.db" 
#define CERT_FILE "certs/server.crt"
#define KEY_FILE "certs/server.key"

typedef struct {
    char* method;
    char* path;
    char* version;
    char* body;
    char* headers;
    int client_socket;
    const char* raw_buffer;
    int bytes_read;
} HttpRequest;

typedef struct {
    char* header;
    char* content;
} HttpResponse;

// --- 함수 선언 ---
void init_logger();
void log_error(const char* message);
void log_request(int client_socket, const char* request_buffer, int bytes_read);
void cleanup_logger();

void init_ssl();
SSL_CTX* get_ssl_context();
void cleanup_ssl();

void handle_request_routing(HttpRequest* request, HttpResponse* response);

void build_response_from_file(HttpResponse* response, const char* file_path);
void free_http_request(HttpRequest* request);
void free_http_response(HttpResponse* response);

void init_database();
int authenticate_user(const char* username, const char* password);
int insert_user(const char* username, const char* password);

void handle_login(HttpRequest* request, HttpResponse* response);
void handle_signup(HttpRequest* request, HttpResponse* response);

int is_attack_detected(HttpRequest* request);

void url_decode(char *str); 
char* get_form_value(const char* body, const char* key, char* output, size_t output_size);

#endif