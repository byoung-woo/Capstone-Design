// include/logger.h
#ifndef LOGGER_H
#define LOGGER_H

#include <cjson/cJSON.h>

void init_logger();
void log_error(const char* message);
// log_request 함수의 파라미터를 cJSON 객체 포인터로 변경
void log_request(int client_socket, const char* request_buffer, int bytes_read); 
void cleanup_logger();

// AI 분석 서버로 로그를 전송하는 함수의 선언을 추가
void send_log_to_analyzer(const char* json_log);

#endif