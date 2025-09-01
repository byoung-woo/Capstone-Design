#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "logger.h"
#include "path_response.h"   // URL별 핸들러 분기 함수

#define PORT 8080
#define BUFFER_SIZE 4096


void handle_client(int client_fd, struct sockaddr_in *client_addr) {
    char buffer[BUFFER_SIZE];
    int bytes_read = read(client_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_read < 0) {
        perror("요청 읽기 실패");
        return;
    }
    buffer[bytes_read] = '\0';

    // 클라이언트 IP 문자열화
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), client_ip, INET_ADDRSTRLEN);

    // 요청 로그
    log_request(client_ip, buffer);

    // 경로별 분기 처리 (path_response.c 의 handle_request_path)
    handle_request_path(client_fd, buffer);
}

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    // 1. 소켓 생성
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("소켓 생성 실패");
        exit(EXIT_FAILURE);
    }

    // 2. 주소 재사용 옵션
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt 실패");
        exit(EXIT_FAILURE);
    }

    // 3. 서버 주소 설정
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // 4. 바인딩
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("바인드 실패");
        exit(EXIT_FAILURE);
    }

    // 5. 리스닝
    if (listen(server_fd, 10) < 0) {
        perror("리스닝 실패");
        exit(EXIT_FAILURE);
    }
    printf("웹서버가 포트 %d에서 실행 중...\n", PORT);

    // 6. 연결 처리 루프
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            perror("클라이언트 연결 수락 실패");
            continue;
        }
        handle_client(client_fd, &client_addr);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
