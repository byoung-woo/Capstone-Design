#include "login_handler.h"
#include "db_manager.h"
#include "response_builder.h"
#include <stdio.h>
#include <string.h>

void handle_login(HttpRequest* request, HttpResponse* response) {
    char username[100] = {0,};
    char password[100] = {0,};
    
    // POST 요청의 본문(body)에서 사용자명과 비밀번호 파싱
    char* body = request->body;
    
    // key=value 형태로 값을 찾아 파싱
    char* username_start = strstr(body, "username=");
    char* password_start = strstr(body, "password=");

    if (username_start != NULL && password_start != NULL) {
        // username 파싱
        username_start += 9; // "username=" 길이
        char* username_end = strchr(username_start, '&');
        if (username_end != NULL) {
            int len = username_end - username_start;
            if (len < sizeof(username)) {
                strncpy(username, username_start, len);
                username[len] = '\0';
            }
        }
        
        // password 파싱
        password_start += 9; // "password=" 길이
        int len = strlen(password_start);
        if (len < sizeof(password)) {
            strcpy(password, password_start);
        }
    }

    // 데이터베이스를 통해 사용자 인증
    if (authenticate_user(username, password)) {
        // 인증 성공 시, 대시보드 페이지 응답
        build_response_from_file(response, "web/dashboard.html");
    } else {
        // 인증 실패 시, 다시 로그인 페이지 응답
        build_response_from_file(response, "web/login.html");
    }
}