// response_builder.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "response_builder.h"
#include "webserver.h"
#include "logger.h"
#include "router.h"

static void build_response_header(HttpResponse* response, const char* content_type, size_t content_length, int status_code) {
    char status_message[64];
    
    if (status_code == 200) {
        strcpy(status_message, "OK");
    } else if (status_code == 404) {
        strcpy(status_message, "Not Found");
    } else if (status_code == 403) { // 403 상태 코드 메시지 추가
        strcpy(status_message, "Forbidden");
    } else {
        strcpy(status_message, "Internal Server Error");
    }

    char header_buffer[512];
    sprintf(header_buffer, 
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n", 
            status_code, status_message, content_type, content_length);

    response->header = strdup(header_buffer);
}

static char* get_file_content(const char* file_path, size_t* content_length) {
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    *content_length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* content = (char*)malloc(*content_length + 1);
    if (content == NULL) {
        fclose(file);
        return NULL;
    }

    fread(content, 1, *content_length, file);
    content[*content_length] = '\0';
    fclose(file);
    
    return content;
}

// [추가] HTTP 302 리다이렉션 응답을 만드는 함수
void build_redirect_response(HttpResponse* response, const char* location_url) {
    char header_buffer[512];
    
    // 302 Found 헤더와 Location 헤더를 포함합니다.
    int status_code = 302;
    const char* status_message = "Found";
    
    // 응답 본문은 비어 있습니다.
    sprintf(header_buffer, 
            "HTTP/1.1 %d %s\r\n"
            "Location: %s\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n", 
            status_code, status_message, location_url);

    // 전체 응답(헤더만)을 response->content에 저장
    response->content = strdup(header_buffer);
}

void free_http_response(HttpResponse* response) {
    if (response->content) {
        free(response->content);
        response->content = NULL;
    }
}

void free_http_request(HttpRequest* request) {
    if (request->method) free(request->method);
    if (request->path) free(request->path);
    if (request->version) free(request->version);
    if (request->body) free(request->body);
    if (request->headers) free(request->headers);
}

void build_response_from_file(HttpResponse* response, const char* file_path) {
    char* file_content = NULL;
    size_t content_length = 0;
    int status_code = 200;
    const char* content_type = "text/html";

    // 403 페이지 요청 시 status_code를 403으로 설정
    if (strstr(file_path, "403.html")) {
        status_code = 403;
    }

    file_content = get_file_content(file_path, &content_length);

    if (file_content == NULL) {
        status_code = 404;
        file_content = get_file_content("web/404.html", &content_length);
        if (file_content == NULL) {
            status_code = 500;
            file_content = strdup("<h1>500 Internal Server Error</h1>");
            content_length = strlen(file_content);
        }
    }

    const char* ext = strrchr(file_path, '.');
    if (ext) {
        if (strcmp(ext, ".css") == 0) content_type = "text/css";
        // 다른 파일 타입들...
    }

    build_response_header(response, content_type, content_length, status_code);

    size_t total_length = strlen(response->header) + content_length;
    response->content = (char*)malloc(total_length + 1);
    if (response->content == NULL) {
        log_error("Failed to allocate memory for response.");
        free(response->header);
        free(file_content);
        return;
    }
    strcpy(response->content, response->header);
    memcpy(response->content + strlen(response->header), file_content, content_length);
    response->content[total_length] = '\0';

    free(file_content);
    free(response->header);
}