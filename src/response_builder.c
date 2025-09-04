// response_builder.c
// 웹서버의 응답 생성 모듈.
// 파일 내용을 읽어와 HTTP 응답 메시지를 구성합니다.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "response_builder.h"
#include "webserver.h"
#include "logger.h"
#include "router.h" // get_static_file_path 함수 선언을 위해 추가

// HTTP 응답 헤더를 생성하는 함수
static void build_response_header(HttpResponse* response, const char* content_type, size_t content_length, int status_code) {
    char status_message[64];
    
    // 상태 코드에 따른 메시지 설정
    if (status_code == 200) {
        strcpy(status_message, "OK");
    } else if (status_code == 404) {
        strcpy(status_message, "Not Found");
    } else {
        strcpy(status_message, "Internal Server Error");
    }

    // 응답 헤더 포맷팅
    // 동적 할당을 위해 충분한 크기로 버퍼 생성
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

// HTTP 응답 본문을 파일에서 읽어오는 함수
static char* get_file_content(const char* file_path, size_t* content_length) {
    FILE* file = fopen(file_path, "rb"); // 바이너리 모드로 파일 열기
    if (file == NULL) {
        return NULL; // 파일이 없으면 NULL 반환
    }

    // 파일 크기 계산
    fseek(file, 0, SEEK_END);
    *content_length = ftell(file);
    fseek(file, 0, SEEK_SET);

    // 파일 내용을 담을 버퍼 할당
    char* content = (char*)malloc(*content_length + 1);
    if (content == NULL) {
        fclose(file);
        return NULL;
    }

    // 파일 내용 읽기
    fread(content, 1, *content_length, file);
    content[*content_length] = '\0';
    fclose(file);
    
    return content;
}

// 요청에 맞는 전체 HTTP 응답을 생성하는 함수
void build_response(HttpRequest* request, HttpResponse* response) {
    char file_path[256];
    char* file_content = NULL;
    size_t content_length = 0;
    int status_code = 200;
    const char* content_type = "text/plain";

    // URL 경로에 따라 파일 경로 결정
    get_static_file_path(request->path, file_path, sizeof(file_path));
    
    // 파일 내용 읽기
    file_content = get_file_content(file_path, &content_length);

    if (file_content == NULL) {
        // 파일이 없으면 404 에러 페이지 처리
        status_code = 404;
        content_type = "text/html";
        file_content = get_file_content("web/404.html", &content_length);
        if (file_content == NULL) {
            // 404 페이지도 없으면 기본 에러 메시지 반환
            status_code = 500;
            file_content = strdup("<h1>500 Internal Server Error</h1>");
            content_length = strlen(file_content);
        }
    }
    
    // 파일 확장자에 따라 Content-Type 결정
    const char* ext = strrchr(file_path, '.');
    if (ext) {
        if (strcmp(ext, ".html") == 0) content_type = "text/html";
        else if (strcmp(ext, ".css") == 0) content_type = "text/css";
        else if (strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) content_type = "image/jpeg";
        else if (strcmp(ext, ".png") == 0) content_type = "image/png";
        else if (strcmp(ext, ".js") == 0) content_type = "application/javascript";
    }

    // 응답 헤더 생성
    build_response_header(response, content_type, content_length, status_code);
    
    // 응답 본문과 헤더를 결합하여 최종 응답 생성
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
    
    // 메모리 해제
    free(file_content);
    free(response->header);
}

// HttpResponse 구조체 메모리를 해제하는 함수
void free_http_response(HttpResponse* response) {
    if (response->content) {
        free(response->content);
        response->content = NULL; // Dangling pointer 방지
    }
}

// HttpRequest 구조체 메모리를 해제하는 함수 (새로 추가)
void free_http_request(HttpRequest* request) {
    if (request->method) free(request->method);
    if (request->path) free(request->path);
    if (request->version) free(request->version);
    if (request->body) free(request->body);
    if (request->headers) free(request->headers);
}
// 특정 파일을 읽어 HTTP 응답을 생성하는 새로운 함수
void build_response_from_file(HttpResponse* response, const char* file_path) {
    char* file_content = NULL;
    size_t content_length = 0;
    int status_code = 200;
    const char* content_type = "text/html";

    // 파일 내용 읽기
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

    // 파일 확장자에 따라 Content-Type 결정
    const char* ext = strrchr(file_path, '.');
    if (ext && strcmp(ext, ".css") == 0) {
        content_type = "text/css";
    }

    // 응답 헤더 생성
    build_response_header(response, content_type, content_length, status_code);

    // 응답 본문과 헤더를 결합하여 최종 응답 생성
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

    // 메모리 해제
    free(file_content);
    free(response->header);
}