// src/rule_checker.c
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/socket.h>

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


// --- 3. 개선된 룰 검사 함수 ---

int is_attack_detected(HttpRequest* request) {
    char log_buffer[512];

    // 클라이언트 IP 주소 가져오기
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(request->client_socket, (struct sockaddr*)&addr, &addr_len);
    char* client_ip = inet_ntoa(addr.sin_addr);

    // 모든 룰 그룹을 순회
    for (int i = 0; rule_groups[i].rule_name != NULL; i++) {
        const RuleGroup* group = &rule_groups[i];

        // 현재 그룹에 속한 모든 패턴을 순회
        for (int j = 0; group->patterns[j] != NULL; j++) {
            const char* pattern = group->patterns[j];
            const char* location = NULL;

            // 요청의 경로(path) 또는 본문(body)에 패턴이 있는지 확인
            if (request->path && strstr(request->path, pattern)) {
                location = "PATH";
            } else if (request->body && strstr(request->body, pattern)) {
                location = "BODY";
            }

            // 공격이 탐지된 경우
            if (location) {
                // 로그에 탐지된 공격 유형(rule_name)을 추가하여 기록
                snprintf(log_buffer, sizeof(log_buffer),
                         "[ATTACK DETECTED] client_ip=\"%s\" request_path=\"%s\" attack_type=\"%s\" rule=\"%s\" location=\"%s\"",
                         client_ip, request->path, group->rule_name, pattern, location);
                log_error(log_buffer);
                return 1; // 공격 탐지됨
            }
        }
    }

    return 0; // 모든 룰을 통과 (안전함)
}