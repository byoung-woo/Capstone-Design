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
    strcpy(file_path, "web");

    if (strcmp(url_path, "/") == 0) {
        strcat(file_path, "/index.html");
    } else {
        if (strstr(url_path, "..") != NULL) {
            strcpy(file_path, "web/403.html");
            return;
        }
        strcat(file_path, url_path);
    }
}

void handle_request_routing(HttpRequest* request, HttpResponse* response) {
    // // 1. 룰 기반 1차 보안 검사 수행
    // if (is_attack_detected(request)) {
    //     // 공격이 탐지되면 403 Forbidden 응답을 보내고 즉시 처리 종료
    //     build_response_from_file(response, "web/403.html");
    //     return;
    // }

    // 2. (1차 통과 시) 요청 로그 기록 및 AI 서버로 전송
    // log_request 함수는 이제 파일 기록과 네트워크 전송을 모두 담당합니다.
    log_request(request->client_socket, request->raw_buffer, request->bytes_read); 

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
        build_response_from_file(response, file_path);
        return;
    }

    build_response_from_file(response, "web/404.html");
}