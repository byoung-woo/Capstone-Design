#include "login_handler.h"
#include "db_manager.h"
#include "response_builder.h"


#include <stdio.h>
#include <string.h>

void handle_login(HttpRequest* request, HttpResponse* response) {
    char username[100]; 
    char password[100];
    
    char* body = request->body;
    
    // [수정: 보안/견고성] 안전한 get_form_value 함수를 사용하여 사용자명과 비밀번호 파싱 및 URL 디코딩
    if (get_form_value(body, "username", username, sizeof(username)) == NULL ||
        get_form_value(body, "password", password, sizeof(password)) == NULL) 
    {
        // 파싱 실패 시: 알림을 위해 리다이렉션
        build_redirect_response(response, "/login.html?error=fail");
        return;
    }

    // 데이터베이스를 통해 사용자 인증
    if (authenticate_user(username, password)) {
        // [수정: UX/404 Fix] 인증 성공 시: 대시보드로 리다이렉션 (302)
        build_redirect_response(response, "/dashboard.html");
    } else {
        // [수정: UX/404 Fix] 인증 실패 시: 로그인 실패 알림을 위해 쿼리 파라미터를 추가하여 리다이렉션
        build_redirect_response(response, "/login.html?error=fail");
    }
}