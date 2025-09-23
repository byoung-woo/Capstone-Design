// src/logger.c (최종 수정본)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cjson/cJSON.h>
#include <unistd.h>

#include "logger.h"
#include "webserver.h"

#define ANALYZER_IP "172.20.10.2" // 윈도우 Wi-Fi IP 주소
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

void send_log_to_analyzer(const char* log_with_newline) {
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_error("Socket creation error for analyzer");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(ANALYZER_PORT);

    if (inet_pton(AF_INET, ANALYZER_IP, &serv_addr.sin_addr) <= 0) {
        log_error("Invalid address/ Address not supported");
        close(sock);
        return;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_error("Connection Failed to analyzer server");
        close(sock);
        return;
    }

    // ★★★ 이제 \n이 포함된 데이터를 보냅니다 ★★★
    send(sock, log_with_newline, strlen(log_with_newline), 0);
    
    // sleep()은 더 이상 필요 없을 수 있지만, 안정성을 위해 그대로 둡니다.
    sleep(1);
    
    close(sock);
}

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
    // ... (이 함수 상단의 JSON 객체 생성 부분은 이전과 동일) ...
    
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

    char* path_copy = strdup(path_and_query);
    char* query = get_query(path_copy);
    char* path = path_copy;

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

    cJSON* features = cJSON_CreateObject();
    cJSON_AddNumberToObject(features, "path_len", strlen(path));
    cJSON_AddNumberToObject(features, "path_depth", get_path_depth(path));
    cJSON_AddNumberToObject(features, "query_len", strlen(query));
    cJSON_AddItemToObject(log_json, "features", features);

    char* json_string = cJSON_PrintUnformatted(log_json);
    if (json_string) {
        // 파일에 기록 (기존과 동일)
        fprintf(access_log_file, "%s\n", json_string);
        fflush(access_log_file);
        
        // ★★★ 해결책: \n 문자를 포함한 새로운 문자열을 만들어 전송 ★★★
        // 1. json_string 길이에 \n과 널 문자(\0) 공간(2)을 더한 만큼 메모리 할당
        char* log_to_send = malloc(strlen(json_string) + 2);
        if (log_to_send) {
            // 2. 새로운 공간에 json_string 복사
            strcpy(log_to_send, json_string);
            // 3. 문자열 끝에 \n 추가
            strcat(log_to_send, "\n");
            
            // 4. \n이 추가된 최종본을 AI 서버로 전송
            send_log_to_analyzer(log_to_send);
            
            // 5. 할당한 메모리 해제
            free(log_to_send);
        }
        
        free(json_string);
    }
    
    cJSON_Delete(log_json);
    free(request_copy);
    free(path_copy);
}

void cleanup_logger() {
    if (access_log_file) fclose(access_log_file);
    if (attack_log_file) fclose(attack_log_file);
}