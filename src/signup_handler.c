// signup_handler.c
// 회원가입 요청을 처리하는 모듈.
// 사용자 정보를 파싱하여 데이터베이스에 저장합니다.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "signup_handler.h"
#include "db_manager.h"
#include "response_builder.h"

// 새로운 사용자를 데이터베이스에 추가하는 함수
static int add_user_to_db(const char* username, const char* password) {
    // 이 부분은 db_manager.c에 추가될 구현 함수를 호출합니다.
    return insert_user(username, password);
}

// 회원가입 요청을 처리하는 함수
void handle_signup(HttpRequest* request, HttpResponse* response) {
    char username[100] = {0,};
    char password[100] = {0,};
    
    // POST 요청의 본문(body)에서 사용자명과 비밀번호 파싱
    char* body = request->body;

    // key=value 형태로 값을 찾아 파싱
    char* username_start = strstr(body, "username=");
    char* password_start = strstr(body, "password=");

    if (username_start != NULL && password_start != NULL) {
        // username 파싱
        username_start += 9; 
        char* username_end = strchr(username_start, '&');
        if (username_end != NULL) {
            int len = username_end - username_start;
            if (len < sizeof(username)) {
                strncpy(username, username_start, len);
                username[len] = '\0';
            }
        }
        
        // password 파싱
        password_start += 9;
        int len = strlen(password_start);
        if (len < sizeof(password)) {
            strcpy(password, password_start);
        }
    }

    // 새로운 사용자를 데이터베이스에 추가
    if (add_user_to_db(username, password)) {
        // 회원가입 성공 시 로그인 페이지로 리디렉션 또는 성공 메시지 응답
        build_response_from_file(response, "web/login.html");
    } else {
        // 회원가입 실패 시 다시 회원가입 페이지 응답
        // (예: 사용자 이름 중복)
        build_response_from_file(response, "web/signup.html");
    }
}
