// signup_handler.h
#ifndef SIGNUP_HANDLER_H
#define SIGNUP_HANDLER_H

#include "webserver.h"

// 회원가입 요청을 처리하는 함수
void handle_signup(HttpRequest* request, HttpResponse* response);

#endif
