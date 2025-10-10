// include/logger.h
#ifndef LOGGER_H
#define LOGGER_H

#include <cjson/cJSON.h>
#include "webserver.h" // HttpRequest 구조체 사용을 위해 포함

void init_logger();
void log_error(const char* message);
// [수정] log_request 함수의 파라미터를 HttpRequest*로 변경
void log_request(HttpRequest* request); 
void cleanup_logger();

// [추가] AI 분석 서버로 로그를 비동기적으로 전송하기 위한 함수 선언
void init_log_queue();
void* log_sender_thread(void* arg); 

#endif