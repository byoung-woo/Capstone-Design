#include "login_handler.h"
#include "db_manager.h"
#include "response_builder.h"


#include <stdio.h>
#include <string.h>

void handle_login(HttpRequest* request, HttpResponse* response) {
    char username[100]; 
    char password[100];
    
    // POST 요청의 본문(body)
    char* body = request->body;
    
    // [수정] 안전한 get_form_value 함수를 사용하여 사용자명과 비밀번호 파싱 및 URL 디코딩
    // get_form_value는 request->body에서 값을 추출하고 URL 디코딩까지 완료합니다.
    if (get_form_value(body, "username", username, sizeof(username)) == NULL ||
        get_form_value(body, "password", password, sizeof(password)) == NULL) 
    {
        // 파싱 실패 시 처리
        build_response_from_file(response, "web/login.html");
        return;
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