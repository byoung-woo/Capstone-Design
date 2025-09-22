// src/rule_checker.c
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h> // IP 주소 변환을 위해 추가
#include <sys/socket.h> // 소켓 관련 함수를 위해 추가

#include "rule_checker.h"
#include "logger.h"

const char* attack_patterns[] = {
    "' OR '1'='1'", "UNION SELECT", "--", "SLEEP(",
    "<script>", "onerror=", "javascript:",
    "../", "/etc/passwd", "&",
    NULL
};

// is_attack_detected 함수는 이제 HttpRequest 포인터를 받습니다.
int is_attack_detected(HttpRequest* request) {
    char log_buffer[512]; // 로그 버퍼 크기 증가

    // 클라이언트 IP 주소 가져오기
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(request->client_socket, (struct sockaddr*)&addr, &addr_len);
    char* client_ip = inet_ntoa(addr.sin_addr);

    for (int i = 0; attack_patterns[i] != NULL; i++) {
        // 검사할 위치(location)와 검사할 대상(target)을 설정
        const char* location = NULL;
        const char* target = NULL;

        if (request->path && strstr(request->path, attack_patterns[i])) {
            location = "PATH";
            target = request->path;
        } else if (request->body && strstr(request->body, attack_patterns[i])) {
            location = "BODY";
            target = request->body;
        }

        // 공격이 탐지된 경우
        if (location) {
            // "Key=Value" 형태의 구조적인 로그 생성
            snprintf(log_buffer, sizeof(log_buffer),
                     "[ATTACK DETECTED] client_ip=\"%s\" request_path=\"%s\" rule=\"%s\" location=\"%s\"",
                     client_ip, request->path, attack_patterns[i], location);
            log_error(log_buffer);
            return 1; // 공격 탐지됨
        }
    }
    return 0; // 안전함
}