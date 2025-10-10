// src/rule_checker.c
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>
#include <stdlib.h>
#include <cjson/cJSON.h> // cJSON 라이브러리 포함

#include "rule_checker.h"
#include "logger.h"

// --- 1. [수정] 동적 룰 관리를 위한 구조체 및 전역 변수 ---

typedef struct {
    char* rule_name;    // "SQL Injection", "XSS" 등
    char** patterns;    // 패턴 문자열 배열 (동적 할당)
    int num_patterns; // 패턴의 개수
} RuleGroup;

// [수정] 모든 룰 그룹을 담는 동적 배열
static RuleGroup* rule_groups = NULL;
static int num_rule_groups = 0;


// --- 2. [추가] JSON 파일 로딩 및 메모리 해제 함수 ---

// 파일 내용을 읽어오는 헬퍼 함수
static char* read_file_content(const char* filepath) {
    FILE* file = fopen(filepath, "rb");
    if (!file) {
        log_error("Failed to open rule file.");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* content = (char*)malloc(length + 1);
    if (content) {
        fread(content, 1, length, file);
        content[length] = '\0';
    }
    fclose(file);
    return content;
}

// JSON 파일에서 룰을 파싱하고 메모리에 로드하는 함수
void load_rules_from_file(const char* filepath) {
    char* file_content = read_file_content(filepath);
    if (!file_content) return;

    cJSON* root = cJSON_Parse(file_content);
    if (!root) {
        log_error("Failed to parse rule JSON file.");
        free(file_content);
        return;
    }

    cJSON* rules_array = cJSON_GetObjectItem(root, "rules");
    if (!cJSON_IsArray(rules_array)) {
        log_error("'rules' array not found in JSON.");
        cJSON_Delete(root);
        free(file_content);
        return;
    }

    num_rule_groups = cJSON_GetArraySize(rules_array);
    rule_groups = (RuleGroup*)malloc(num_rule_groups * sizeof(RuleGroup));

    for (int i = 0; i < num_rule_groups; i++) {
        cJSON* rule_item = cJSON_GetArrayItem(rules_array, i);
        cJSON* rule_name_item = cJSON_GetObjectItem(rule_item, "rule_name");
        cJSON* patterns_array = cJSON_GetObjectItem(rule_item, "patterns");

        rule_groups[i].rule_name = strdup(cJSON_GetStringValue(rule_name_item));
        rule_groups[i].num_patterns = cJSON_GetArraySize(patterns_array);
        rule_groups[i].patterns = (char**)malloc(rule_groups[i].num_patterns * sizeof(char*));

        for (int j = 0; j < rule_groups[i].num_patterns; j++) {
            cJSON* pattern_item = cJSON_GetArrayItem(patterns_array, j);
            rule_groups[i].patterns[j] = strdup(cJSON_GetStringValue(pattern_item));
        }
    }
    
    log_error("WAF rules loaded successfully.");
    cJSON_Delete(root);
    free(file_content);
}

// 로드된 룰 관련 동적 메모리를 해제하는 함수
void cleanup_rules() {
    if (rule_groups) {
        for (int i = 0; i < num_rule_groups; i++) {
            for (int j = 0; j < rule_groups[i].num_patterns; j++) {
                free(rule_groups[i].patterns[j]);
            }
            free(rule_groups[i].patterns);
            free(rule_groups[i].rule_name);
        }
        free(rule_groups);
        rule_groups = NULL;
        num_rule_groups = 0;
        log_error("WAF rules cleaned up successfully.");
    }
}


// --- 3. 기존 함수 수정 ---

// 문자열을 소문자로 변환하는 헬퍼 함수 (기존과 동일)
static char* to_lower_string(const char* str) {
    if (!str) return NULL;
    char* lower_str = strdup(str);
    if (!lower_str) return NULL;
    for (int i = 0; lower_str[i]; i++) {
        lower_str[i] = tolower(lower_str[i]);
    }
    return lower_str;
}

// [수정] 동적으로 로드된 룰을 사용하여 공격을 탐지하는 함수
int is_attack_detected(HttpRequest* request) {
    if (!rule_groups) return 0; // 룰이 로드되지 않았으면 검사하지 않음

    char log_buffer[512];
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(request->client_socket, (struct sockaddr*)&addr, &addr_len);
    char* client_ip = inet_ntoa(addr.sin_addr);

    char* lower_path = to_lower_string(request->path);
    char* lower_body = to_lower_string(request->body);

    int attack_found = 0;

    for (int i = 0; i < num_rule_groups; i++) {
        const RuleGroup* group = &rule_groups[i];
        for (int j = 0; j < group->num_patterns; j++) {
            const char* pattern = group->patterns[j];
            const char* location = NULL;

            if (lower_path && strstr(lower_path, pattern)) {
                location = "PATH";
            } else if (lower_body && strstr(lower_body, pattern)) {
                location = "BODY";
            }

            if (location) {
                snprintf(log_buffer, sizeof(log_buffer),
                         "[ATTACK DETECTED] client_ip=\"%s\" request_path=\"%s\" attack_type=\"%s\" rule=\"%s\" location=\"%s\"",
                         client_ip, request->path, group->rule_name, pattern, location);
                log_error(log_buffer);
                attack_found = 1;
                goto cleanup;
            }
        }
    }

cleanup:
    free(lower_path);
    free(lower_body);
    return attack_found;
}