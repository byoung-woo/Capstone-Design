
#ifndef PATH_RESPONSE_H
#define PATH_RESPONSE_H

#include <openssl/ssl.h>

/* 요청 문자열(request) 분석 → 대응 응답을 SSL로 전송 */
void handle_request_path(SSL *ssl, const char *request);

#endif

