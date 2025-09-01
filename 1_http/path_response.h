
#ifndef PATH_RESPONSE_H
#define PATH_RESPONSE_H

// 요청 경로에 따라 알맞은 응답을 선택하여 전송하는 함수
void handle_request_path(int client_fd, const char *request);

#endif

