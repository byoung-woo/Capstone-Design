// src/logger.c (TLS/SSL 암호화 적용)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cjson/cJSON.h>
#include <unistd.h>
// OpenSSL 헤더 추가
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "logger.h"
#include "webserver.h"

#define ANALYZER_IP "172.20.10.2" // AI 분석 서버 IP 주소
#define ANALYZER_PORT 5140

static FILE* access_log_file;
static FILE* attack_log_file;

void init_logger() {
    access_log_file = fopen(ACCESS_LOG_FILE, "a");
    attack_log_file = fopen(ATTACK_LOG_FILE, "a");
    if (access_log_file == NULL || attack_log_file == NULL) {
        perror("Failed to open log files");
        exit(1);
    }
}

void log_error(const char* message) {
    if (!attack_log_file) return;
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(attack_log_file, "[%s] %s\n", time_str, message);
    fflush(attack_log_file);
}

// 이 함수가 핵심적으로 변경됩니다.
void send_log_to_analyzer(const char* log_with_newline) {
    int sock;
    struct sockaddr_in serv_addr;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;

    // 1. SSL 클라이언트 컨텍스트 생성
    //    SSLv23_client_method()는 최신 프로토콜을 자동으로 협상합니다.
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (!ctx) {
        log_error("Failed to create SSL context for analyzer client.");
        return;
    }

    // 2. TCP 소켓 생성 및 연결 (기존과 동일)
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_error("Socket creation error for analyzer");
        SSL_CTX_free(ctx);
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(ANALYZER_PORT);
    if (inet_pton(AF_INET, ANALYZER_IP, &serv_addr.sin_addr) <= 0) {
        log_error("Invalid address/ Address not supported");
        close(sock);
        SSL_CTX_free(ctx);
        return;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_error("Connection Failed to analyzer server");
        close(sock);
        SSL_CTX_free(ctx);
        return;
    }

    // 3. SSL 객체 생성 및 소켓과 연결
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    // 4. SSL 핸드셰이크 수행 (암호화 채널 수립)
    if (SSL_connect(ssl) <= 0) {
        log_error("SSL handshake failed with analyzer server.");
        ERR_print_errors_fp(stderr);
    } else {
        // 5. 암호화된 채널로 데이터 전송 (send -> SSL_write)
        SSL_write(ssl, log_with_newline, strlen(log_with_newline));
    }

    // 6. 자원 해제
    if(ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    close(sock);
    SSL_CTX_free(ctx);
}


// --- 이하 로직은 기존과 동일합니다 ---
char* get_query(char* url) {
    char* query = strchr(url, '?');
    if (query) { *query = '\0'; return query + 1; }
    return "";
}

int get_path_depth(const char* path) {
    int depth = 0;
    for (int i = 0; path[i] != '\0'; i++) {
        if (path[i] == '/') depth++;
    }
    return depth > 0 ? depth : 1;
}

void log_request(int client_socket, const char* request_buffer, int bytes_read) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char iso_time_str[64];
    strftime(iso_time_str, sizeof(iso_time_str), "%Y-%m-%dT%H:%M:%S%z", t);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_socket, (struct sockaddr*)&addr, &addr_len);
    char* client_ip = inet_ntoa(addr.sin_addr);

    char* request_copy = strdup(request_buffer);
    char* request_line = strtok(request_copy, "\n");
    if (!request_line) { free(request_copy); return; }

    char* http_version_end = strstr(request_line, "HTTP/1.1");
    if (http_version_end != NULL && (http_version_end = strchr(http_version_end, '\r')) != NULL) { *http_version_end = '\0'; }

    char* method = strtok(request_line, " ");
    char* path_and_query = strtok(NULL, " ");
    char* version = strtok(NULL, " ");

    if (!method || !path_and_query || !version) { free(request_copy); return; }


    cJSON* log_json = cJSON_CreateObject();
    cJSON_AddStringToObject(log_json, "timestamp", iso_time_str);
    cJSON_AddStringToObject(log_json, "client_ip", client_ip);
    cJSON_AddStringToObject(log_json, "request_method", method);
    cJSON_AddStringToObject(log_json, "request_path", path_and_query);
    cJSON_AddStringToObject(log_json, "http_version", version);
    cJSON_AddNumberToObject(log_json, "bytes", bytes_read);

    const char* user_agent_start = strstr(request_buffer, "User-Agent: ");
    if (user_agent_start) {
        user_agent_start += strlen("User-Agent: ");
        const char* user_agent_end = strchr(user_agent_start, '\r');
        if (user_agent_end) {
            char user_agent_str[256];
            int len = user_agent_end - user_agent_start;
            strncpy(user_agent_str, user_agent_start, len);
            user_agent_str[len] = '\0';
            cJSON_AddStringToObject(log_json, "user_agent", user_agent_str);
        }
    }

    // POST 요청 본문을 찾아서 JSON에 추가
    if (strcmp(method, "POST") == 0) {
        const char* body_start = strstr(request_buffer, "\r\n\r\n");
        if (body_start) {
            body_start += 4; // 헤더와 본문을 구분하는 빈 줄 다음으로 이동
            cJSON_AddStringToObject(log_json, "request_body", body_start);
        } else {
            cJSON_AddStringToObject(log_json, "request_body", "");
        }
    }

    char* json_string = cJSON_PrintUnformatted(log_json);
    if (json_string) {
        fprintf(access_log_file, "%s\n", json_string);
        fflush(access_log_file);
        
        char* log_to_send = malloc(strlen(json_string) + 2);
        if (log_to_send) {
            strcpy(log_to_send, json_string);
            strcat(log_to_send, "\n");
            
            send_log_to_analyzer(log_to_send);
            
            free(log_to_send);
        }
        
        free(json_string);
    }
    
    cJSON_Delete(log_json);
    free(request_copy);

}

void cleanup_logger() {
    if (access_log_file) fclose(access_log_file);
    if (attack_log_file) fclose(attack_log_file);
}