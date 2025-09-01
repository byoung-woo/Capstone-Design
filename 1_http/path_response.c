#include "path_response.h"
#include "fixed_response.h"
#include "static_file.h"
#include "header_time.h"
#include "form_input.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

void handle_request_path(int client_fd, const char *request) {
    char method[8], url[256], protocol[16];

    // 요청의 첫 번째 줄에서 메소드, URL, 프로토콜 파싱
    sscanf(request, "%s %s %s", method, url, protocol);
    printf("DEBUG: Method: %s, URL: %s, Protocol: %s\n", method, url, protocol);

    // 1) PUT /upload/<filename> 처리
    if (strcmp(method, "PUT") == 0 && strncmp(url, "/upload/", 8) == 0) {
        // Content-Length 헤더에서 바디 길이 추출
        const char *cl_header = strstr(request, "Content-Length:");
        int content_length = 0;
        if (cl_header) {
            sscanf(cl_header, "Content-Length: %d", &content_length);
        }

        // 헤더 끝("\r\n\r\n") 이후가 바디
        const char *body = strstr(request, "\r\n\r\n");
        if (body) body += 4;

        // 파일명 안전하게 처리 (경로 탈출 방지)
        const char *raw_name = url + 8;  // "/upload/" 이후
        char filename[256];
        int i;
        for (i = 0; i < (int)sizeof(filename)-1 && raw_name[i]; ++i) {
            // 슬래시나 백슬래시는 언더스코어로 대체
            if (raw_name[i] == '/' || raw_name[i] == '\\') filename[i] = '_';
            else filename[i] = raw_name[i];
        }
        filename[i] = '\0';

        // uploads 디렉터리에 저장
        char path[512];
        snprintf(path, sizeof(path), "uploads/%s", filename);

        int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            // 파일 생성 실패 시 500 응답
            const char *resp = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
            write(client_fd, resp, strlen(resp));
            return;
        }
        // 바디를 파일에 쓰기
        write(fd, body, content_length);
        close(fd);

        // 성공 시 201 Created 응답
        const char *resp = "HTTP/1.1 201 Created\r\n\r\n";
        write(client_fd, resp, strlen(resp));
        return;
    }

    // 2) GET /greet?... 처리
    if (strncmp(url, "/greet?", 7) == 0) {
        handle_form_input(client_fd, url);
        return;
    }

    // 3) 나머지 GET 요청 분기
    if (strcmp(url, "/") == 0) {
        send_fixed_response(client_fd);
    } else if (strcmp(url, "/hello") == 0) {
        const char *response_body = "<html><body><h1>Hello, User!</h1></body></html>";
        int body_len = strlen(response_body);
        char response[512];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: text/html; charset=UTF-8\r\n"
                 "Content-Length: %d\r\n"
                 "\r\n%s",
                 body_len, response_body);
        write(client_fd, response, strlen(response));
    } else if (strcmp(url, "/index.html") == 0) {
        serve_static_file(client_fd, "index.html");
    } else if (strcmp(url, "/time") == 0) {
        send_response_with_time(client_fd);
    } else {
        const char *response_body = "<html><body><h1>404 - Page Not Found</h1></body></html>";
        int body_len = strlen(response_body);
        char response[512];
        snprintf(response, sizeof(response),
                 "HTTP/1.1 404 Not Found\r\n"
                 "Content-Type: text/html; charset=UTF-8\r\n"
                 "Content-Length: %d\r\n"
                 "\r\n%s",
                 body_len, response_body);
        write(client_fd, response, strlen(response));
    }
}
