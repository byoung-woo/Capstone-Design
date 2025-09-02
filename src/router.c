// router.c
// 요청된 URL 경로에 따라 적절한 웹 콘텐츠 파일을 매핑하는 모듈입니다.

#include <string.h>
#include <stdio.h>

#include "webserver.h"
#include "router.h"

// URL 경로에 따라 파일 경로를 결정하는 함수
void get_file_path(const char* url_path, char* file_path, int file_path_size) {
    // 기본 경로를 "web/" 디렉토리로 설정
    strcpy(file_path, "web");

    // 경로가 루트("/")일 경우 기본 페이지(index.html)를 반환
    if (strcmp(url_path, "/") == 0) {
        strcat(file_path, "/index.html");
    } 
    // 그 외의 경우, URL 경로를 그대로 파일명으로 사용
    else {
        // 경로 유효성 검사 (상위 디렉토리 접근 방지)
        if (strstr(url_path, "..") != NULL) {
            // 잘못된 접근 시도 시, 404 페이지로 라우팅
            strcpy(file_path, "web/404.html");
            return;
        }
        strcat(file_path, url_path);
    }
}