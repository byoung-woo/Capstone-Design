// response_builder.h
#ifndef RESPONSE_BUILDER_H
#define RESPONSE_BUILDER_H

#include "webserver.h"

void build_response(HttpRequest* request, HttpResponse* response);
void free_http_response(HttpResponse* response);

#endif