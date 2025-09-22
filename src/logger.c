// src/logger.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cjson/cJSON.h>

#include "logger.h"
#include "webserver.h"

// 로그 파일을 두 종류로 분리
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

// 오류 및 공격 탐지 로그는 attack_log_file에 기록
void log_error(const char* message) {
    if (!attack_log_file) return;
    time_t now = time(NULL);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(attack_log_file, "[%s] %s\n", time_str, message);
    fflush(attack_log_file); // 즉시 파일에 쓰도록 강제
}

// URL에서 쿼리 문자열 분리
char* get_query(char* url) {
    char* query = strchr(url, '?');
    if (query) {
        *query = '\0';
        return query + 1;
    }
    return "";
}

// 경로 깊이 계산
int get_path_depth(const char* path) {
    int depth = 0;
    for (int i = 0; path[i] != '\0'; i++) {
        if (path[i] == '/') depth++;
    }
    return depth > 0 ? depth : 1;
}

// 정상적인 요청(JSON) 로그는 access_log_file에 기록
void log_request(int client_socket, const char* request_buffer, int bytes_read) {
    if (!access_log_file) {
        log_error("Access log file is not open.");
        return;
    }
    
    // (이하 JSON 로그를 생성하는 코드는 이전과 동일)
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
    if (!request_line) {
        free(request_copy);
        return;
    }

    char* http_version_end = strstr(request_line, "HTTP/1.1");
    if (http_version_end != NULL && (http_version_end = strchr(http_version_end, '\r')) != NULL) {
        *http_version_end = '\0';
    }

    char* method = strtok(request_line, " ");
    char* path_and_query = strtok(NULL, " ");
    char* version = strtok(NULL, " ");

    if (!method || !path_and_query || !version) {
        free(request_copy);
        return;
    }

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

    char* json_string = cJSON_PrintUnformatted(log_json); // 한 줄로 출력
    if (json_string) {
        fprintf(access_log_file, "%s\n", json_string);
        fflush(access_log_file);
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