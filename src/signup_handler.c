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
    char username[100]; 
    char password[100];
    
    char* body = request->body;

    // [수정] 안전한 get_form_value 함수를 사용하여 사용자명과 비밀번호 파싱 및 URL 디코딩
    if (get_form_value(body, "username", username, sizeof(username)) == NULL ||
        get_form_value(body, "password", password, sizeof(password)) == NULL) 
    {
        // 파싱 실패 시 처리
        build_response_from_file(response, "web/signup.html");
        return;
    }

    // 새로운 사용자를 데이터베이스에 추가
    if (add_user_to_db(username, password)) {
        // 회원가입 성공 시 로그인 페이지로 리디렉션 또는 성공 메시지 응답
        build_response_from_file(response, "web/login.html");
    } else {
        // 회원가입 실패 시 다시 회원가입 페이지 응답
        build_response_from_file(response, "web/signup.html");
    }
}