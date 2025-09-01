
#ifndef STATIC_FILE_H
#define STATIC_FILE_H

// 정적 파일을 읽어 클라이언트에 전송하는 함수
void serve_static_file(int client_fd, const char *filename);

#endif

