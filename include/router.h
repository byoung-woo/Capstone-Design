// router.h
#ifndef ROUTER_H
#define ROUTER_H

#include "webserver.h"

// HTTP 요청을 라우팅하고 응답을 생성하는 함수
void handle_request_routing(HttpRequest* request, HttpResponse* response);
void get_static_file_path(const char* url_path, char* file_path, int file_path_size);

#endif
