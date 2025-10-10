// src/rule_checker.c
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>
#include <stdlib.h>

#include "rule_checker.h"
#include "logger.h"

// --- 1. 공격 기법별로 룰셋을 명확하게 분리 ---

// SQL Injection 룰셋
const char* sql_injection_patterns[] = {
    "' OR '1'='1'", "UNION SELECT", "--", "SLEEP(", NULL
};

// Cross-Site Scripting (XSS) 룰셋
const char* xss_patterns[] = {
    "<script>", "onerror=", "javascript:", NULL
};

// Path Traversal (디렉터리 탐색) 및 기타 시스템 명령어 관련 룰셋
const char* path_traversal_patterns[] = {
    "../", "/etc/passwd", NULL
};


// --- 2. 각 룰셋을 이름과 함께 구조체로 묶어서 관리 ---

typedef struct {
    const char* rule_name; // "SQL Injection", "XSS" 등
    const char** patterns; // 위에서 정의한 패턴 배열
} RuleGroup;

// 모든 룰 그룹을 담는 배열
const RuleGroup rule_groups[] = {
    {"SQL Injection", sql_injection_patterns},
    {"Cross-Site Scripting", xss_patterns},
    {"Path Traversal", path_traversal_patterns},
    {NULL, NULL} // 배열의 끝
};

// [추가] 문자열을 소문자로 변환하는 헬퍼 함수
static char* to_lower_string(const char* str) {
    if (!str) return NULL;
    char* lower_str = strdup(str);
    if (!lower_str) return NULL;
    for (int i = 0; lower_str[i]; i++) {
        lower_str[i] = tolower(lower_str[i]);
    }
    return lower_str;
}

// --- 3. 개선된 룰 검사 함수 ---

int is_attack_detected(HttpRequest* request) {
    char log_buffer[512];

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(request->client_socket, (struct sockaddr*)&addr, &addr_len);
    char* client_ip = inet_ntoa(addr.sin_addr);

    // [추가] 요청 경로와 본문을 소문자로 변환
    char* lower_path = to_lower_string(request->path);
    char* lower_body = to_lower_string(request->body);

    int attack_found = 0; // 공격 탐지 여부 플래그

    for (int i = 0; rule_groups[i].rule_name != NULL; i++) {
        const RuleGroup* group = &rule_groups[i];

        for (int j = 0; group->patterns[j] != NULL; j++) {
            const char* pattern = group->patterns[j];
            const char* location = NULL;

            // [수정] 소문자로 변환된 문자열에서 패턴을 검사
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
                attack_found = 1; // 공격 탐지됨
                goto cleanup; // [추가] 검사 종료를 위해 cleanup으로 이동
            }
        }
    }

cleanup: // [추가] 메모리 해제를 위한 레이블
    free(lower_path);
    free(lower_body);
    return attack_found;
}
