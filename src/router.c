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
#include "rule_checker.h"

void get_static_file_path(const char* url_path, char* file_path, int file_path_size) {
    // [기존 쿼리 파라미터 제거 로직 유지]
    char temp_path[BUFFER_SIZE];
    strncpy(temp_path, url_path, BUFFER_SIZE - 1);
    temp_path[BUFFER_SIZE - 1] = '\0';

    char* query_start = strchr(temp_path, '?');
    if (query_start != NULL) {
        *query_start = '\0'; // '?'를 NULL 문자로 대체하여 쿼리 스트링을 잘라냄
    }
    
    strcpy(file_path, "web");

    // Path Traversal 방어
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

void handle_request_routing(HttpRequest* request, HttpResponse* response) {
    // 1. 룰 기반 1차 보안 검사 수행
    if (is_attack_detected(request)) {
        // 공격이 탐지되면 403 Forbidden 응답을 보내고 즉시 처리 종료
        // [수정] build_response_from_file에 request 인자 추가
        build_response_from_file(request, response, "web/403.html");
        return;
    }

    // 2. (1차 통과 시) 요청 로그 기록 및 AI 서버로 비동기 전송
    // [수정] log_request 함수의 파라미터를 HttpRequest*로 변경
    log_request(request); 

    // 3. 정상적인 요청에 대한 라우팅 처리
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
        // [수정] build_response_from_file에 request 인자 추가
        build_response_from_file(request, response, file_path);
        return;
    }

    // [수정] build_response_from_file에 request 인자 추가
    build_response_from_file(request, response, "web/404.html");
}