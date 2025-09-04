// router.c
// 요청된 URL 경로와 HTTP 메서드에 따라 적절한 핸들러를 호출하는 모듈.

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "webserver.h"
#include "router.h"
#include "login_handler.h" // 로그인 핸들러 추가
#include "signup_handler.h" // 회원가입 핸들러 추가
#include "response_builder.h"
#include "logger.h"

// 정적 파일 경로를 결정하는 함수 (이전 로직 유지)
void get_static_file_path(const char* url_path, char* file_path, int file_path_size) {
    strcpy(file_path, "web");

    if (strcmp(url_path, "/") == 0) {
        strcat(file_path, "/index.html");
    } 
    else {
        if (strstr(url_path, "..") != NULL) {
            strcpy(file_path, "web/404.html");
            return;
        }
        strcat(file_path, url_path);
    }
}

// HTTP 요청을 라우팅하고 응답을 생성하는 메인 함수
void handle_request_routing(HttpRequest* request, HttpResponse* response) {
    // 요청 로그 기록 (보안 규칙 검사를 위해 먼저 실행)
    log_request(request->client_socket, request->raw_buffer, request->bytes_read); 

    // POST 요청 처리
    if (strcmp(request->method, "POST") == 0) {
        if (strcmp(request->path, "/login") == 0) {
            handle_login(request, response);
            return;
        } else if (strcmp(request->path, "/signup") == 0) {
            // 회원가입 요청 처리
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