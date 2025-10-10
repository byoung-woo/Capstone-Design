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
    return insert_user(username, password);
}

// 회원가입 요청을 처리하는 함수
void handle_signup(HttpRequest* request, HttpResponse* response) {
    char username[100]; 
    char password[100];
    
    char* body = request->body;

    if (get_form_value(body, "username", username, sizeof(username)) == NULL ||
        get_form_value(body, "password", password, sizeof(password)) == NULL) 
    {
        // 파싱 실패 시: 회원가입 실패 알림을 위해 리다이렉션
        build_redirect_response(response, "/signup.html?error=fail");
        return;
    }

    // 새로운 사용자를 데이터베이스에 추가
    if (add_user_to_db(username, password)) {
        // [수정] 회원가입 성공 시: 로그인 페이지로 리다이렉션하며 성공 알림 파라미터 전달
        build_redirect_response(response, "/login.html?status=success");
    } else {
        // [수정] 회원가입 실패 시 (예: 사용자 이름 중복): 실패 알림 파라미터를 추가하여 리다이렉션
        build_redirect_response(response, "/signup.html?error=duplicate");
    }
}