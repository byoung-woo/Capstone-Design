// src/router.c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "webserver.h"
#include "router.h"
#include "login_handler.h"
#include "signup_handler.h"
#include "response_builder.h"
#include "logger.h"
#include "rule_checker.h"
#include "ip_manager.h"

// 과도한 요청 발생 시 429(Too Many Requests) 응답 메시지를 생성하는 함수
void build_too_many_requests_response(HttpResponse* response) {
    const char* body = "<h1>429 Too Many Requests</h1><p>Your IP has been temporarily blocked due to excessive requests.</p>";
    size_t body_len = strlen(body);
    char header_buffer[512];
    sprintf(header_buffer,
            "HTTP/1.1 429 Too Many Requests\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n\r\n",
            body_len);
    response->content = (char*)malloc(strlen(header_buffer) + body_len + 1);
    strcpy(response->content, header_buffer);
    strcat(response->content, body);
}

// 클라이언트가 요청한 URL 경로를 서버의 정적 파일 경로로 변환하는 함수
void get_static_file_path(const char* url_path, char* file_path, int file_path_size) {
    char temp_path[BUFFER_SIZE];
    strncpy(temp_path, url_path, BUFFER_SIZE - 1);
    temp_path[BUFFER_SIZE - 1] = '\0';
    char* query_start = strchr(temp_path, '?');
    if (query_start != NULL) {
        *query_start = '\0';
    }
    strcpy(file_path, "web");
    if (strstr(temp_path, "..") != NULL) {
        strcpy(file_path, "web/403.html");
        return;
    }
    if (strcmp(temp_path, "/") == 0) {
        strcat(file_path, "/index.html");
    } else {
        strcat(file_path, temp_path);
    }
}

// 클라이언트 요청을 분석하여 보안 정책을 적용하고 적절한 핸들러로 연결하는 메인 라우팅 함수
void handle_request_routing(HttpRequest* request, HttpResponse* response) {
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(request->client_socket, (struct sockaddr*)&addr, &addr_len);
    char* client_ip = inet_ntoa(addr.sin_addr);
    char log_msg[256];

    // --- 3단계 IP 정책 적용 ---
    IPStatus status = check_ip_status(client_ip);

    // 1순위: 화이트리스트 처리
    if (status == IP_WHITELISTED) {
        // 화이트리스트 IP는 모든 검사를 통과
        goto process_normal_request;
    }

    // 2순위: 블랙리스트 처리
    if (status == IP_BLACKLISTED) {
        snprintf(log_msg, sizeof(log_msg), "[REQUEST DENIED] client_ip=\"%s\" is permanently blocked by blacklist.", client_ip);
        log_error(log_msg);
        request->blocked_by_waf = 1;
        build_response_from_file(request, response, "web/403.html");
        return;
    }

    // 3순위: 동적 차단(Graylist) 처리
    if (status == IP_DYNAMICALLY_BLOCKED) {
        snprintf(log_msg, sizeof(log_msg), "[REQUEST DENIED] client_ip=\"%s\" is temporarily blocked. Sending 429.", client_ip);
        log_error(log_msg);
        request->blocked_by_waf = 1;
        build_too_many_requests_response(response);
        return;
    }

    if (strncmp(request->path, "/unblock", 8) == 0) {
        char ip_to_unblock[INET_ADDRSTRLEN] = {0};
        char* query_string = strchr(request->path, '?');
        if (query_string != NULL && get_form_value(query_string + 1, "ip", ip_to_unblock, sizeof(ip_to_unblock))) {
             unblock_ip(ip_to_unblock);
             build_response_from_file(request, response, "web/unblock_success.html");
             return;
        }
    }

    // 4순위: WAF 룰 기반 공격 탐지
    if (is_attack_detected(request)) {
        snprintf(log_msg, sizeof(log_msg), "[IP BLOCKED] client_ip=\"%s\" dynamically blocked by WAF rule.", client_ip);
        log_error(log_msg);
        block_ip_dynamically(client_ip); // IP를 동적 차단 목록에 추가
        request->blocked_by_waf = 1;
        build_response_from_file(request, response, "web/403.html");
        return;
    }
process_normal_request:

    if (strcmp(request->method, "POST") == 0) {
        if (strcmp(request->path, "/login") == 0) {
            handle_login(request, response);
            return;
        } else if (strcmp(request->path, "/signup") == 0) {
            handle_signup(request, response);
            return;
        }
    }

    if (strcmp(request->method, "GET") == 0) {
        char file_path[256];
        get_static_file_path(request->path, file_path, sizeof(file_path));
        build_response_from_file(request, response, file_path);
        return;
    }

    build_response_from_file(request, response, "web/404.html");
}