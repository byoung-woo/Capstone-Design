// src/router.c
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "webserver.h"
#include "router.h"
#include "login_handler.h"
#include "signup_handler.h"
#include "response_builder.h"
#include "logger.h"
#include "rule_checker.h" // 룰 검사기 헤더 추가

// 정적 파일 경로를 결정하는 함수 (기존 로직 유지)
void get_static_file_path(const char* url_path, char* file_path, int file_path_size) {
    strcpy(file_path, "web");

    if (strcmp(url_path, "/") == 0) {
        strcat(file_path, "/index.html");
    } else {
        // Path Traversal 공격 방지
        if (strstr(url_path, "..") != NULL) {
            strcpy(file_path, "web/403.html"); // ../ 시도가 있으면 403 페이지로
            return;
        }
        strcat(file_path, url_path);
    }
}

// HTTP 요청을 라우팅하고 응답을 생성하는 메인 함수
void handle_request_routing(HttpRequest* request, HttpResponse* response) {
    // 1. 요청 로그 기록 (AI 분석을 위해 원본 요청을 먼저 기록)
    log_request(request->client_socket, request->raw_buffer, request->bytes_read); 

    // 2. 룰 기반 1차 보안 검사 수행
    if (is_attack_detected(request)) {
        // 공격이 탐지되면 403 Forbidden 응답을 보내고 즉시 처리 종료
        build_response_from_file(response, "web/403.html");
        return;
    }

    // 3. 정상적인 요청에 대한 라우팅 처리
    // POST 요청 처리
    if (strcmp(request->method, "POST") == 0) {
        if (strcmp(request->path, "/login") == 0) {
            handle_login(request, response);
            return;
        } else if (strcmp(request->path, "/signup") == 0) {
            handle_signup(request, response);
            return;
        }
    }

    // GET 요청 처리 (정적 파일)
    if (strcmp(request->method, "GET") == 0) {
        char file_path[256];
        get_static_file_path(request->path, file_path, sizeof(file_path));
        build_response_from_file(response, file_path);
        return;
    }

    // 지원하지 않는 메서드나 경로
    build_response_from_file(response, "web/404.html");
}