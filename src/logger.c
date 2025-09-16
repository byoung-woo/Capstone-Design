// logger.c
// 웹서버의 로그 기록 모듈.
// JSON 포맷으로 클라이언트 요청 정보를 파일에 기록합니다.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cjson/cJSON.h>

#include "logger.h"
#include "webserver.h"

// 로그 파일 포인터
static FILE* log_file;

// 로거 모듈 초기화
void init_logger() {
    log_file = fopen(LOG_FILE, "a");
    if (log_file == NULL) {
        perror("Failed to open log file");
        exit(1);
    }
}

// 오류 로그 기록
void log_error(const char* message) {
    // 기존 코드와 동일
}

// URL 경로에서 쿼리 문자열을 분리하는 함수
char* get_query(char* url) {
    char* query = strchr(url, '?');
    if (query) {
        *query = '\0';
        return query + 1;
    }
    return "";
}

// URL 경로 깊이를 계산하는 함수
int get_path_depth(const char* path) {
    int depth = 0;
    for (int i = 0; path[i] != '\0'; i++) {
        if (path[i] == '/') {
            depth++;
        }
    }
    return depth > 0 ? depth : 1;
}

// 클라이언트 요청을 JSON 형식으로 기록하는 함수
void log_request(int client_socket, const char* request_buffer, int bytes_read) {
    if (!log_file) {
        log_error("Log file is not open.");
        return;
    }
    
    // 시간 정보 포맷팅 (ISO 8601)
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    char iso_time_str[64];
    strftime(iso_time_str, sizeof(iso_time_str), "%Y-%m-%dT%H:%M:%S%z", t);

    // 클라이언트 IP 주소 가져오기
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(client_socket, (struct sockaddr*)&addr, &addr_len);
    char* client_ip = inet_ntoa(addr.sin_addr);

    // HTTP 요청 라인 파싱
    char* request_copy = strdup(request_buffer);
    char* request_line = strtok(request_copy, "\n");
    if (!request_line) {
        free(request_copy);
        return;
    }

    // HTTP 버전 끝에 있는 '\r' 문자를 제거하여 파싱 오류 방지
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

    // JSON 객체 생성
    cJSON* log_json = cJSON_CreateObject();
    
    cJSON_AddStringToObject(log_json, "timestamp", iso_time_str);
    cJSON_AddStringToObject(log_json, "client_ip", client_ip);
    cJSON_AddStringToObject(log_json, "request_method", method);
    cJSON_AddStringToObject(log_json, "request_path", path_and_query);
    cJSON_AddStringToObject(log_json, "http_version", version);
    cJSON_AddNumberToObject(log_json, "bytes", bytes_read);

    // User-Agent 헤더 추출
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

    // features 객체 생성 및 추가
    cJSON* features = cJSON_CreateObject();
    cJSON_AddNumberToObject(features, "path_len", strlen(path));
    cJSON_AddNumberToObject(features, "path_depth", get_path_depth(path));
    cJSON_AddNumberToObject(features, "query_len", strlen(query));
    cJSON_AddItemToObject(log_json, "features", features);

    // 최종 JSON 문자열로 변환 및 파일에 기록
    char* json_string = cJSON_Print(log_json);
    if (json_string) {
        fprintf(log_file, "%s\n", json_string);
        fflush(log_file);
        free(json_string);
    }
    
    cJSON_Delete(log_json);
    free(request_copy);
    free(path_copy);
}

// 로거 모듈 정리
void cleanup_logger() {
    if (log_file) {
        fclose(log_file);
    }
}